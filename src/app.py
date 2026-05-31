# Главный модуль приложения — точка входа, инициализация всех компонентов,
# управление жизненным циклом и взаимодействие между частями системы.

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
from gui.setup_wizard import SetupWizard
from gui.login_dialog import LoginDialog
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


def main():
    app = QApplication(sys.argv)
    config = ConfigManager()
    db_path = config.get_database_path()


    # EventBus создаётся первым — все остальные компоненты его используют
    event_bus = EventBus()

    # БД и миграции
    if not db_path or not Path(db_path).exists():
        # первый запуск — запускаем мастер настройки
        wizard = SetupWizard()
        if wizard.exec() != QDialog.DialogCode.Accepted:
            sys.exit(0)

        db_path = wizard.db_path
        config.set_database_path(db_path)
        config.save()

        pool = DatabasePool(db_path)
        pool.migrate()

        key_storage = KeyStorage(pool)
        key_manager = KeyManager(key_storage, config={
            "argon2_time":        3,
            "argon2_memory":      65536,
            "argon2_parallelism": 4,
            "pbkdf2_iterations":  100000,
        })

        password = wizard.password_entry.text()
        key_manager.initialize(password)
        key_manager.unlock(password)

        state_manager = StateManager(config,event_bus=event_bus)
        authenticator = Authenticator(key_manager, event_bus, state_manager)
        authenticator.failed_attempts = 0
        state_manager.unlock()
        event_bus.publish("UserLoggedIn")

    else:
        # повторный запуск — показываем диалог входа
        pool = DatabasePool(db_path)
        pool.migrate()

        key_storage = KeyStorage(pool)
        key_manager = KeyManager(key_storage, config={
            "argon2_time":        3,
            "argon2_memory":      65536,
            "argon2_parallelism": 4,
            "pbkdf2_iterations":  100000,
        })

        state_manager = StateManager(config, key_manager=key_manager, event_bus=event_bus)
        authenticator = Authenticator(key_manager, event_bus, state_manager)

        login_dialog = LoginDialog(authenticator)
        if login_dialog.exec() != QDialog.DialogCode.Accepted:
            sys.exit(0)

    # EntryManager
    entry_manager = EntryManager(pool, key_manager)

    # Clipboard
    clipboard_adapter = get_platform_clipboard_adapter()

    clipboard_service = ClipboardService(
        platform_adapter=clipboard_adapter,
        event_system=event_bus,
        config=config,
        state_manager=state_manager,
    )

    monitor = ClipboardMonitor(clipboard_service, clipboard_adapter)
    clipboard_service.set_monitor(monitor)
    # запускаем монитор один раз (ранее вызывался дважды — баг исправлен)
    monitor_available = monitor.start()
    if not monitor_available:
        # мониторинг недоступен — продолжаем без него
        # пользователь уже получил уведомление через _show_notification()
        pass

    # Audit — signer → audit_logger → log_verifier
    # порядок важен: LogSigner требует разблокированный key_manager,
    # AuditLogger требует signer, LogVerifier требует pool и signer
    # исправлена опечатка: было singer, стало signer
    # исправлен аргумент: LogSigner требует key_manager
    signer = LogSigner(key_manager)

    audit_logger = AuditLogger(pool, signer, event_bus)

    log_verifier = LogVerifier(pool, signer)

    # верификация целостности лога при старте
    try:
        with pool.connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) as cnt FROM audit_log"
            ).fetchone()
        total_entries = row["cnt"] if row else 0

        if total_entries > 1000:
            # большой лог — проверяем последние 1000 (выборка)
            startup_result = log_verifier._verify_last_n(n=1000)
            checked_label = f"последние 1000 из {total_entries}"
        else:
            # маленький лог — проверяем все записи целиком
            startup_result = log_verifier.verify_log(start_seq=0)
            checked_label = f"все {total_entries}"

        if not startup_result['verified']:
            # показываем предупреждение ДО открытия главного окна
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
            # логируем факт обнаружения tampering
            audit_logger.log_event(
                event_type="AUDIT_INTEGRITY_FAILED",
                severity="CRITICAL",
                source="startup",
                details={
                    "invalid_entries": len(
                        startup_result.get('invalid_entries', [])
                    ),
                    "chain_breaks": len(
                        startup_result.get('chain_breaks', [])
                    ),
                    "checked": checked_label,
                }
            )

    except Exception as e:
        # верификация упала — не блокируем запуск но логируем
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
        database=pool,
        event_bus=event_bus,
    )
 
    importer = VaultImporter(
        entry_manager=entry_manager,
        database=pool,
        event_bus=event_bus,
    )
 
    sharing_service = SharingService(
        entry_manager=entry_manager,
        key_manager=key_manager,
        db=pool,
        audit_logger=audit_logger,
    )
 
    qr_service = QRCodeService(ttl_seconds=300)

    # публикуем AppStartup после верификации
    event_bus.publish("AppStartup")

    # главное окно
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
    )

    # подписываем toast-уведомления через Observer 
    clipboard_service.subscribe(window.show_toast)

    # сохраняем ссылку на config для SettingsDialog
    window._config = config

    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()