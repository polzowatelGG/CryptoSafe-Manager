# Главный модуль приложения — точка входа, инициализация всех компонентов.
# Sprint 7: добавлены ActivityMonitor и PanicMode.

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
# Sprint 7
from core.security.activity_monitor import ActivityMonitor
from core.security.panic_mode import PanicMode


def main():
    app = QApplication(sys.argv)
    config = ConfigManager()
    db_path = config.get_database_path()

    event_bus = EventBus()

    if not db_path or not Path(db_path).exists():
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

        state_manager = StateManager(config, event_bus=event_bus)
        authenticator = Authenticator(key_manager, event_bus, state_manager)
        authenticator.failed_attempts = 0
        state_manager.unlock()
        event_bus.publish("UserLoggedIn")

    else:
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
    monitor.start()

    # Audit
    signer = LogSigner(key_manager)
    audit_logger = AuditLogger(pool, signer, event_bus)
    log_verifier = LogVerifier(pool, signer)

    # Верификация при старте
    try:
        with pool.connection() as conn:
            row = conn.execute("SELECT COUNT(*) as cnt FROM audit_log").fetchone()
        total_entries = row["cnt"] if row else 0

        if total_entries > 1000:
            startup_result = log_verifier._verify_last_n(n=1000)
            checked_label = f"последние 1000 из {total_entries}"
        else:
            startup_result = log_verifier.verify_log(start_seq=0)
            checked_label = f"все {total_entries}"

        if not startup_result['verified']:
            QMessageBox.critical(
                None, "⚠️ Нарушение целостности журнала аудита",
                f"Обнаружены повреждённые записи при запуске!\n\n"
                f"Проверено записей: {checked_label}\n"
                f"Повреждённых подписей: {len(startup_result.get('invalid_entries', []))}\n"
                f"Разрывов цепочки: {len(startup_result.get('chain_breaks', []))}")
            audit_logger.log_event(
                event_type="AUDIT_INTEGRITY_FAILED", severity="CRITICAL",
                source="startup",
                details={"invalid_entries": len(startup_result.get('invalid_entries', [])),
                         "chain_breaks": len(startup_result.get('chain_breaks', [])),
                         "checked": checked_label})
    except Exception as e:
        try:
            audit_logger.log_event(
                event_type="AUDIT_STARTUP_VERIFY_ERROR", severity="ERROR",
                source="startup", details={"error": str(e)[:200]})
        except Exception:
            pass

    # Import/Export/Sharing
    exporter = VaultExporter(entry_manager=entry_manager, database=pool)
    importer = VaultImporter(entry_manager=entry_manager, database=pool)
    sharing_service = SharingService(entry_manager=entry_manager, key_manager=key_manager,
                                      db=pool, audit_logger=audit_logger)
    qr_service = QRCodeService(ttl_seconds=300)

    # ── Sprint 7: ActivityMonitor ──────────────────────────────────────
    inactivity_timeout = config.get_preference('inactivity_timeout') or 300
    activity_monitor = ActivityMonitor(
        lock_callback=lambda: _do_lock(state_manager, key_manager),
        config={
            'inactivity_timeout': int(inactivity_timeout),
            'check_interval': 1.0,
        }
    )
    # Привязываем к StateManager для делегирования reset_inactivity_timer
    state_manager.activity_monitor = activity_monitor
    activity_monitor.start_monitoring()

    event_bus.publish("AppStartup")

    # ── Sprint 7: MainWindow (передаём activity_monitor) ───────────────
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
        activity_monitor=activity_monitor,
    )

    # ── Sprint 7: PanicMode (создаётся ПОСЛЕ window) ───────────────────
    panic_mode = PanicMode(
        config=config.config if hasattr(config, 'config') else {},
        key_manager=key_manager,
        state_manager=state_manager,
        clipboard_service=clipboard_service,
        audit_logger=audit_logger,
        main_window=window,
    )
    window.panic_mode = panic_mode

    clipboard_service.subscribe(window.show_toast)
    window._config = config

    # Если мы уже разблокированы до создания окна — загрузим записи.
    if not state_manager.is_locked():
        window._on_vault_unlocked()

    # Sprint 7: запуск свёрнутым если задано в настройках
    start_minimized = config.get_preference('start_minimized') or False
    if start_minimized:
        window.hide()
    else:
        window.show()

    sys.exit(app.exec())


def _do_lock(state_manager: StateManager, key_manager):
    """Обратный вызов авто-блокировки: блокирует сессию и ключи."""
    try:
        state_manager.lock()
    except Exception:
        pass
    try:
        key_manager.lock()
    except Exception:
        pass


if __name__ == "__main__":
    main()