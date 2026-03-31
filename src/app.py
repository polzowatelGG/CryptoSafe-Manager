from email.mime import application
from pathlib import Path
import sys
from core.config import ConfigManager
from database.db import DatabasePool
from core.crypto.key_storage import KeyStorage
from core.key_manager import KeyManager
from core.vault.entry_manager import EntryManager
from gui.main_window import MainWindow
from gui.setup_wizard import SetupWizard

def main():
    app = application(sys.argv)

    config = ConfigManager()
    db_path = config.get_database_path()

    # первичная настройка (если БД ещё нет)
    if not Path(db_path).exists():
        wizard = SetupWizard()
        if wizard.exec() != wizard.DialogCode.Accepted:
            sys.exit(0)

        if getattr(wizard, "db_path", None):
            config.set_database_path(wizard.db_path)
            db_path = wizard.db_path

    # дб коннект и миграция
    pool = DatabasePool(db_path)
    pool.migrate()

    # ключевое хранилище (для параметров PBKDF2)
    key_storage = KeyStorage(pool)

    # ключевой менеджер (логика логина, кэширования ключа, блокировки)
    key_manager = KeyManager(
        storage=key_storage,
        config={
            "argon2_time": 3,
            "argon2_memory": 65536,
            "argon2_parallelism": 4,
            "pbkdf2_iterations": 100000,
        }
    )

    # менеджер записей (логика создания, получения, обновления, удаления записей) - использует ключевой менеджер для доступа к ключу
    entry_manager = EntryManager(pool, key_manager)

    # проверяем, есть ли уже инициализация (наличие параметров PBKDF2)
    params = key_storage.get_pbkdf2_params()

    if not params:
        # первый запуск (регистрация)
        password = "test_password_123!"  #  временно
        key_manager.initialize(password)
        print("[INIT] Key initialized")

    else:
        # 🔓 логин
        password = "test_password_123!"  #  временно
        if not key_manager.unlock(password):
            print("Invalid password")
            sys.exit(1)

    # ТЕСТ 
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

    # гуишка
    window = MainWindow()
    window.show()

    sys.exit(app.exec())