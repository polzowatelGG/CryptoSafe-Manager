import sys
from pathlib import Path
from PyQt6.QtWidgets import QApplication, QDialog, QMessageBox
from core.config import ConfigManager
from database.db import DatabasePool
from core.crypto.key_storage import KeyStorage
from core.key_manager import KeyManager
from core.crypto.authentication import Authenticator
from core.state_manager import StateManager
from core.events import EventBus
from core.vault.entry_manager import EntryManager
from gui.main_window import MainWindow
from gui.login_dialog import LoginDialog
from gui.vault_selector_dialog import VaultSelectorDialog
from core.clipboard.platform_adapter import get_platform_clipboard_adapter
from core.clipboard.clipboard_service import ClipboardService
from core.clipboard.clipboard_monitor import ClipboardMonitor
from core.audit.log_verifier import LogVerifier
from core.audit.log_signer import LogSigner
from core.audit.audit_logger import AuditLogger
from core.import_export.exporter import VaultExporter
from core.import_export.importer import VaultImporter
from core.import_export.sharing_service import SharingService
from core.import_export.key_exchange import QRCodeService
import os
os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "1")
os.environ.setdefault("QT_QPA_PLATFORM", "windows:fontengine=freetype")


KDF_CONFIG = {
    "argon2_time":        3,
    "argon2_memory":      65536,
    "argon2_parallelism": 4,
    "pbkdf2_iterations":  100000,
}


def _init_new_vault(db_path: str, password: str) -> tuple:
    """Создаёт новую БД, инициализирует KeyManager. Возвращает (pool, key_manager)."""
    pool = DatabasePool(db_path)
    pool.migrate()
    key_storage = KeyStorage(pool)
    key_manager = KeyManager(key_storage, config=KDF_CONFIG)
    key_manager.initialize(password)
    key_manager.unlock(password)
    return pool, key_manager


def _open_existing_vault(db_path: str) -> tuple:
    """Открывает существующую БД. Возвращает (pool, key_manager) — ключ ещё не разблокирован."""
    pool = DatabasePool(db_path)
    pool.migrate()
    key_storage = KeyStorage(pool)
    key_manager = KeyManager(key_storage, config=KDF_CONFIG)
    return pool, key_manager


def main():
    app = QApplication(sys.argv)
    config = ConfigManager()
    event_bus = EventBus()

    # ------------------------------------------------------------------ #
    # Шаг 1: выбор / создание хранилища
    # ------------------------------------------------------------------ #
    selector = VaultSelectorDialog(config)

    # Если в конфиге есть последняя БД — добавляем в список недавних
    last_db = config.get_database_path()
    if last_db and Path(last_db).exists():
        selector.add_to_recent(last_db)
        selector._load_recent()

    if selector.exec() != QDialog.DialogCode.Accepted:
        sys.exit(0)

    db_path = selector.selected_db_path
    new_vault_password = selector.get_new_vault_password()

    # ------------------------------------------------------------------ #
    # Шаг 2: инициализация KeyManager
    # ------------------------------------------------------------------ #
    if new_vault_password is not None:
        # Только что создано новое хранилище — KeyManager уже инициализирован
        pool, key_manager = _init_new_vault(db_path, new_vault_password)
        state_manager = StateManager(config, key_manager=key_manager, event_bus=event_bus)
        authenticator = Authenticator(key_manager, event_bus, state_manager)
        state_manager.unlock()
        event_bus.publish("UserLoggedIn")
    else:
        # Открываем существующее — нужен логин
        pool, key_manager = _open_existing_vault(db_path)
        state_manager = StateManager(config, key_manager=key_manager, event_bus=event_bus)
        authenticator = Authenticator(key_manager, event_bus, state_manager)

        login_dialog = LoginDialog(authenticator)
        if login_dialog.exec() != QDialog.DialogCode.Accepted:
            sys.exit(0)

    # Сохраняем путь к БД и добавляем в недавние
    config.set_database_path(db_path)
    config.save()
    selector.add_to_recent(db_path)

    # ------------------------------------------------------------------ #
    # Шаг 3: остальные сервисы (без изменений)
    # ------------------------------------------------------------------ #
    entry_manager = EntryManager(pool, key_manager)

    clipboard_adapter = get_platform_clipboard_adapter()
    clipboard_service = ClipboardService(
        platform_adapter=clipboard_adapter,
        event_system=event_bus,
        config=config,
        state_manager=state_manager,
    )
    monitor = ClipboardMonitor(clipboard_service, clipboard_adapter)
    clipboard_service.set_monitor(monitor)
    monitor.start()

    signer = LogSigner(key_manager)
    audit_logger = AuditLogger(pool, signer, event_bus)
    log_verifier = LogVerifier(pool, signer)

    # Верификация целостности лога при старте
    try:
        with pool.connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) as cnt FROM audit_log"
            ).fetchone()
        total_entries = row["cnt"] if row else 0

        if total_entries > 1000:
            startup_result = log_verifier._verify_last_n(n=1000)
            checked_label = f"последние 1000 из {total_entries}"
        else:
            startup_result = log_verifier.verify_log(start_seq=0)
            checked_label = f"все {total_entries}"

        if not startup_result["verified"]:
            QMessageBox.critical(
                None,
                "⚠️ Нарушение целостности журнала аудита",
                f"Обнаружены повреждённые записи при запуске!\n\n"
                f"Проверено записей: {checked_label}\n"
                f"Повреждённых подписей: "
                f"{len(startup_result.get('invalid_entries', []))}\n"
                f"Разрывов цепочки: "
                f"{len(startup_result.get('chain_breaks', []))}\n\n"
                f"Рекомендуется выполнить полную верификацию\n"
                f"через меню Вид → Проверить целостность логов."
            )
            audit_logger.log_event(
                event_type="AUDIT_INTEGRITY_FAILED",
                severity="CRITICAL",
                source="startup",
                details={
                    "invalid_entries": len(startup_result.get("invalid_entries", [])),
                    "chain_breaks":    len(startup_result.get("chain_breaks", [])),
                    "checked":         checked_label,
                }
            )
    except Exception as e:
        try:
            audit_logger.log_event(
                event_type="AUDIT_STARTUP_VERIFY_ERROR",
                severity="ERROR",
                source="startup",
                details={"error": str(e)[:200]}
            )
        except Exception:
            pass

    exporter = VaultExporter(
        entry_manager=entry_manager,
        key_manager=key_manager,
        db=pool,
    )
    importer = VaultImporter(
        entry_manager=entry_manager,
        key_manager=key_manager,
        db=pool,
    )
    sharing_service = SharingService(
        entry_manager=entry_manager,
        key_manager=key_manager,
        db=pool,
        audit_logger=audit_logger,
    )
    
    qr_service = QRCodeService(ttl_seconds=300)

    event_bus.publish("AppStartup")

    window = MainWindow(
        entry_manager=entry_manager,
        key_manager=key_manager,
        authenticator=authenticator,
        state_manager=state_manager,
        clipboard_service=clipboard_service,
        log_verifier=log_verifier,
        exporter=exporter,
        importer=importer,
        sharing_service=sharing_service,
        qr_service=qr_service,
        config=config,       
        db_pool=pool,        
    )
    
    clipboard_service.subscribe(window.show_toast)
    window._config = config
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()