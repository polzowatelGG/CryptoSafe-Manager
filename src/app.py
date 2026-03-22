import sys
from pathlib import Path
from PyQt6.QtWidgets import QApplication
from gui.main_window import MainWindow
from gui.setup_wizard import SetupWizard
from core.config import ConfigManager
from database.db import DatabasePool

def main():
    app = QApplication(sys.argv)

    config = ConfigManager()
    db_path = config.get_database_path()

    # если БД ещё не создана — запускаем мастер настройки
    if not Path(db_path).exists():
        wizard = SetupWizard()
        if wizard.exec() != wizard.DialogCode.Accepted:
            sys.exit(0)
        # если мастер вернул путь к базе — сохраним его
        if getattr(wizard, "db_path", None):
            config.set_database_path(wizard.db_path)
            db_path = wizard.db_path

    # инициализируем пул соединений и применяем миграции
    pool = DatabasePool(db_path)
    pool.migrate()

    window = MainWindow()
    window.show()

    sys.exit(app.exec())

if __name__ == "__main__":
    main()
