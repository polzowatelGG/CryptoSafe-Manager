import sys
from pathlib import Path
from PyQt6.QtWidgets import QApplication, QDialog
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

def main():
    app = QApplication(sys.argv)
    config = ConfigManager()
    db_path = config.get_database_path()

    if not db_path or not Path(db_path).exists():
        wizard = SetupWizard()
        if wizard.exec() != QDialog.DialogCode.Accepted:
            sys.exit(0)
        db_path = wizard.db_path
        config.set_database_path(db_path)
        pool = DatabasePool(db_path)
        pool.migrate()
        key_storage = KeyStorage(pool)
        key_manager = KeyManager(key_storage, config={
            "argon2_time": 3,
            "argon2_memory": 65536,
            "argon2_parallelism": 4,
            "pbkdf2_iterations": 100000,
        })
        password = wizard.password_entry.text()
        key_manager.initialize(password)
        # разблокируем хранилище после создания
        key_manager.unlock(password)
        
        # создаём state_manager и authenticator (как в else)
        state_manager = StateManager(config)
        event_bus = EventBus()
        authenticator = Authenticator(key_manager, event_bus, state_manager)
        # сбрасываем счётчик неудачных попыток и устанавливаем состояние
        authenticator.failed_attempts = 0
        state_manager.unlock()
        event_bus.publish("UserLoggedIn")   # оповещаем о входе
    else:
        pool = DatabasePool(db_path)
        pool.migrate()
        key_storage = KeyStorage(pool)
        key_manager = KeyManager(key_storage, config={
            "argon2_time": 3,
            "argon2_memory": 65536,
            "argon2_parallelism": 4,
            "pbkdf2_iterations": 100000,
        })
        state_manager = StateManager(config)
        event_bus = EventBus()
        authenticator = Authenticator(key_manager, event_bus, state_manager)
        login_dialog = LoginDialog(authenticator)
        if login_dialog.exec() != QDialog.DialogCode.Accepted:
            sys.exit(0)

    entry_manager = EntryManager(pool, key_manager)
    window = MainWindow(
        entry_manager=entry_manager,
        key_manager=key_manager,
        authenticator=authenticator,
        state_manager=state_manager
    )
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()