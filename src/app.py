import sys
from PyQt6.QtWidgets import QApplication

from gui.main_window import MainWindow
from gui.setup_wizard import SetupWizard

def main():
    app = QApplication(sys.argv)

    # Проверка: существует ли файл конфигурации
    # Пока делаем заглушку
    first_run = True

    if first_run:
        wizard = SetupWizard()
        if wizard.exec() != wizard.DialogCode.Accepted:
            sys.exit(0)  # Если отменили — приложение не запускается

    window = MainWindow()
    window.show()

    sys.exit(app.exec())

if __name__ == "__main__":
    main()

