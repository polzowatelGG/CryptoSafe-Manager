import sys
from pathlib import Path
from PyQt6.QtWidgets import QApplication, QDialog
from core.config import ConfigManager
from database.db import DatabasePool
from core.crypto.key_storage import KeyStorage
from core.key_manager import KeyManager
from core.vault.entry_manager import EntryManager
from gui.main_window import MainWindow
from gui.setup_wizard import SetupWizard

def main():
    app = QApplication(sys.argv)
    config = ConfigManager()
    db_path = config.get_database_path()

    if not db_path or not Path(db_path).exists():
        wizard = SetupWizard()
        if wizard.exec() != QDialog.DialogCode.Accepted:
            sys.exit(0)

        db_path = getattr(wizard, "db_path", None)
        if not db_path:
            sys.exit(0)

        config.set_database_path(db_path)

    pool = DatabasePool(db_path)
    pool.migrate()

    key_storage = KeyStorage(pool)

    key_manager = KeyManager(
        storage=key_storage,
        config={
            "argon2_time": 3,
            "argon2_memory": 65536,
            "argon2_parallelism": 4,
            "pbkdf2_iterations": 100000,
        }
    )

    entry_manager = EntryManager(pool, key_manager)
    params = key_storage.get_pbkdf2_params()
    password = "test_password_123!"

    if not params:
        key_manager.initialize(password)
        print("[INIT] Key initialized")
    else:
        if not key_manager.unlock(password):
            print("Invalid password")
            sys.exit(1)

    try:
        test_id = entry_manager.create_entry({
            "title": "Test",
            "login": "admin",
            "password": "secret"
        })

        print("Created:", test_id)

        data = entry_manager.get_entry(test_id)
        print("Decrypted:", data)

    except Exception as e:
        print("ERROR:", e)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())

if __name__ == "__main__":
    main()