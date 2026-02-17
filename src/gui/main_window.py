from PyQt6.QtWidgets import (
    QMainWindow,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QMessageBox,
    QDialog,
    QVBoxLayout
)
from PyQt6.QtGui import QAction   
from gui.widgets.audit_log_viewer import AuditLogViewer
from gui.widgets.secure_table import SecureTable
from gui.settings_dialog import SettingsDialog




class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Secure Vault")
        self.resize(900, 600)

        self._create_menu()
        self._create_central_table()
        self._create_status_bar()

    # ------------------------
    # Меню
    # ------------------------
    def _create_menu(self):
        menu_bar = self.menuBar()

        # Файл
        file_menu = menu_bar.addMenu("Файл")
        new_action = QAction("Создать", self)
        open_action = QAction("Открыть", self)
        backup_action = QAction("Резервная копия", self)
        exit_action = QAction("Выход", self)
        exit_action.triggered.connect(self.close)
        file_menu.addActions([new_action, open_action, backup_action])
        file_menu.addSeparator()
        file_menu.addAction(exit_action)

        # Правка
        edit_menu = menu_bar.addMenu("Правка")
        add_action = QAction("Добавить", self)
        edit_action = QAction("Изменить", self)
        delete_action = QAction("Удалить", self)
        edit_menu.addActions([add_action, edit_action, delete_action])

        # Вид
        view_menu = menu_bar.addMenu("Вид")
        logs_action = QAction("Логи", self)
        logs_action.triggered.connect(self._show_audit_log)
        settings_action = QAction("Настройки", self)
        settings_action.triggered.connect(self._show_settings)
        view_menu.addActions([logs_action, settings_action])

        # Справка
        help_menu = menu_bar.addMenu("Справка")
        about_action = QAction("О программе", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    # ------------------------
    # Центральная таблица (SecureTable)
    # ------------------------
    def _create_central_table(self):
        self.table = SecureTable()
        # Пример тестовых данных
        self.table.add_entry("Google", "user@gmail.com", "https://google.com")
        self.table.add_entry("GitHub", "dev_user", "https://github.com")
        self.table.add_entry("Bank", "client_01", "https://bank.com")
        self.setCentralWidget(self.table)

    # ------------------------
    # Статус-бар
    # ------------------------
    def _create_status_bar(self):
        self.status_bar = QStatusBar()
        self.login_status = "Не выполнен вход"
        self.clipboard_status = "Буфер: --"
        self.status_bar.showMessage(f"{self.login_status} | {self.clipboard_status}")
        self.setStatusBar(self.status_bar)

    # ------------------------
    # О программе
    # ------------------------
    def _show_about(self):
        QMessageBox.information(
            self,
            "О программе",
            "Secure Vault\nВерсия 0.1\nУчебный проект"
        )

    # ------------------------
    # Открытие AuditLogViewer
    # ------------------------
    def _show_audit_log(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Логи")
        layout = QVBoxLayout()
        layout.addWidget(AuditLogViewer())
        dialog.setLayout(layout)
        dialog.resize(600, 400)
        dialog.exec()

    # ------------------------
    # Заглушка для настроек
    # ------------------------
    def _show_settings(self):
        dialog = SettingsDialog()
        dialog.exec()

