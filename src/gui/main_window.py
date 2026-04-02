from PyQt6.QtWidgets import (
    QMainWindow, QStatusBar, QMessageBox, QDialog, QVBoxLayout,
    QFormLayout, QLineEdit, QTextEdit, QDialogButtonBox, QApplication,
    QTableWidgetItem 
)
from PyQt6.QtGui import QAction   
from datetime import datetime
import uuid
import re
from core.crypto.key_derivation import PasswordValidator
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
    # Вспомогательные методы
    # ------------------------
    @staticmethod
    def sanitize_text(text: str, max_len: int = 500) -> str:
        """Очистка текста от управляющих символов и ограничение длины"""
        if not isinstance(text, str):
            return ""
        cleaned = re.sub(r'[\x00-\x1f\x7f]', '', text)
        return cleaned[:max_len]

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
        self.add_action = QAction("Добавить", self)
        self.add_action.triggered.connect(self._on_add_entry)
        self.edit_action = QAction("Изменить", self)
        self.edit_action.triggered.connect(self._on_edit_entry)
        self.delete_action = QAction("Удалить", self)
        self.delete_action.triggered.connect(self._on_delete_entry)
        edit_menu.addActions([self.add_action, self.edit_action, self.delete_action])

        # Вид
        view_menu = menu_bar.addMenu("Вид")
        logs_action = QAction("Логи", self)
        logs_action.triggered.connect(self._show_audit_log)
        settings_action = QAction("Настройки", self)
        settings_action.triggered.connect(self._show_settings)
        view_menu.addActions([logs_action, settings_action])
        
        self.toggle_pass_action = QAction("Показать пароли", self)
        self.toggle_pass_action.setCheckable(True)
        self.toggle_pass_action.triggered.connect(self._toggle_passwords)
        view_menu.addSeparator()
        view_menu.addAction(self.toggle_pass_action)

        # Справка
        help_menu = menu_bar.addMenu("Справка")
        about_action = QAction("О программе", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    # ------------------------
    # Центральная таблица
    # ------------------------
    def _create_central_table(self):
        self.table = SecureTable()
        
        test_entries = [
            ("1", "Google", "user@gmail.com", "https://google.com", "2026-02-28", "MySecretPass123!"),
            ("2", "GitHub", "dev_user", "https://github.com", "2026-02-28", "GhP@ssw0rd456"),
            ("3", "Bank", "client_01", "https://bank.com", "2026-02-28", "B@nkSecure789"),
        ]
        
        for entry_id, title, username, url, updated_at, password in test_entries:
            self.table.add_entry(entry_id, title, username, url, updated_at, password)
        
        self.table.entry_edit_requested.connect(self._on_edit_entry_by_id)
        self.table.entry_delete_requested.connect(self._on_delete_entry_by_id)
        
        self.setCentralWidget(self.table)

    # ------------------------
    # Статус-бар
    # ------------------------
    def _create_status_bar(self):
        self.status_bar = QStatusBar()
        self.login_status = "Не выполнен вход"
        self.clipboard_status = "Буфер: ---"
        self.status_bar.showMessage(f"{self.login_status} | {self.clipboard_status}")
        self.setStatusBar(self.status_bar)

    # ------------------------
    # Показать/скрыть пароли
    # ------------------------
    def _toggle_passwords(self, checked):
        self.table.update_password_visibility(checked)
        self.toggle_pass_action.setText("Скрыть пароли" if checked else "Показать пароли")

    # ------------------------
    # Добавление записи
    # ------------------------
    def _on_add_entry(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Добавить запись")
        dialog.resize(400, 350)
        
        layout = QVBoxLayout(dialog)
        form_layout = QFormLayout()
        
        title_edit = QLineEdit()
        username_edit = QLineEdit()
        password_edit = QLineEdit()
        password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        url_edit = QLineEdit()
        notes_edit = QTextEdit()
        notes_edit.setMaximumHeight(80)
        
        form_layout.addRow("Название:", title_edit)
        form_layout.addRow("Логин:", username_edit)
        form_layout.addRow("Пароль:", password_edit)
        form_layout.addRow("URL:", url_edit)
        form_layout.addRow("Заметки:", notes_edit)
        
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        
        layout.addLayout(form_layout)
        layout.addWidget(buttons)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # Получаем и санитируем ввод
            title_raw = title_edit.text().strip()
            username_raw = username_edit.text()
            url_raw = url_edit.text()
            password = password_edit.text()
            
            title = self.sanitize_text(title_raw, max_len=100)
            username = self.sanitize_text(username_raw, max_len=255)
            url = self.sanitize_text(url_raw, max_len=500)
            
            # Валидация
            if not title:
                QMessageBox.warning(self, "Ошибка", "Название не может быть пустым")
                return
            if not password:
                QMessageBox.warning(self, "Ошибка", "Пароль обязателен")
                return
            
            # Проверка сложности пароля через существующий PasswordValidator
            if not PasswordValidator.validate_password_strength(password):
                reply = QMessageBox.question(
                    self, 
                    "Слабый пароль",
                    "Пароль не соответствует требованиям (мин. 12 символов, заглавные, строчные, цифры, спецсимволы, не из списка распространённых).\nВсё равно использовать?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if reply == QMessageBox.StandardButton.No:
                    return
            
            entry_id = str(uuid.uuid4())
            self.table.add_entry(
                entry_id=entry_id,
                title=title,
                username=username,
                url=url,
                updated_at=datetime.now().strftime("%Y-%m-%d %H:%M"),
                password=password
            )
            QMessageBox.information(self, "Успех", "Запись добавлена")

    # ------------------------
    # Редактирование
    # ------------------------
    def _on_edit_entry(self):
        entry_id = self.table.get_selected_entry_id()
        if not entry_id:
            QMessageBox.warning(self, "Ошибка", "Выберите запись для редактирования")
            return
        self._on_edit_entry_by_id(entry_id)

    def _on_edit_entry_by_id(self, entry_id: str):
        entry = None
        for e in self.table.entries:
            if e["id"] == entry_id:
                entry = e
                break
        if not entry:
            QMessageBox.warning(self, "Ошибка", "Запись не найдена")
            return
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Редактировать запись")
        dialog.resize(400, 350)
        
        layout = QVBoxLayout(dialog)
        form_layout = QFormLayout()
        
        title_edit = QLineEdit(entry["title"])
        username_edit = QLineEdit(entry["username"])
        password_edit = QLineEdit(entry["password"])
        password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        url_edit = QLineEdit(entry["url"])
        notes_edit = QTextEdit()
        notes_edit.setPlainText(entry.get("notes", ""))
        notes_edit.setMaximumHeight(80)
        
        form_layout.addRow("Название:", title_edit)
        form_layout.addRow("Логин:", username_edit)
        form_layout.addRow("Пароль:", password_edit)
        form_layout.addRow("URL:", url_edit)
        form_layout.addRow("Заметки:", notes_edit)
        
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        
        layout.addLayout(form_layout)
        layout.addWidget(buttons)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            new_title_raw = title_edit.text().strip()
            new_username_raw = username_edit.text()
            new_url_raw = url_edit.text()
            new_password = password_edit.text()
            
            new_title = self.sanitize_text(new_title_raw, max_len=100)
            new_username = self.sanitize_text(new_username_raw, max_len=255)
            new_url = self.sanitize_text(new_url_raw, max_len=500)
            
            if not new_title:
                QMessageBox.warning(self, "Ошибка", "Название не может быть пустым")
                return
            if not new_password:
                QMessageBox.warning(self, "Ошибка", "Пароль обязателен")
                return
            
            # Опциональная проверка пароля при редактировании (можно предупредить)
            if not PasswordValidator.validate_password_strength(new_password):
                reply = QMessageBox.question(
                    self, 
                    "Слабый пароль",
                    "Пароль не соответствует требованиям безопасности.\nВсё равно сохранить?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if reply == QMessageBox.StandardButton.No:
                    return
            
            # Обновляем данные
            entry["title"] = new_title
            entry["username"] = new_username
            entry["password"] = new_password
            entry["url"] = new_url
            entry["notes"] = notes_edit.toPlainText()
            entry["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M")
            
            row = self.table.entries.index(entry)
            self.table.setItem(row, 0, QTableWidgetItem(entry["title"]))
            self.table.setItem(row, 1, QTableWidgetItem(self.table._mask_login(entry["username"])))
            self.table.setItem(row, 2, QTableWidgetItem(self.table._get_domain(entry["url"])))
            self.table.setItem(row, 3, QTableWidgetItem(entry["updated_at"]))
            pw_text = entry["password"] if self.table.show_passwords else "••••••••"
            self.table.setItem(row, 4, QTableWidgetItem(pw_text))
            
            QMessageBox.information(self, "Успех", "Запись обновлена")

    # ------------------------
    # Удаление
    # ------------------------
    def _on_delete_entry(self):
        entry_id = self.table.get_selected_entry_id()
        if not entry_id:
            QMessageBox.warning(self, "Ошибка", "Выберите запись для удаления")
            return
        self._on_delete_entry_by_id(entry_id)

    def _on_delete_entry_by_id(self, entry_id: str):
        reply = QMessageBox.question(
            self, 
            "Подтверждение", 
            "Удалить выбранную запись?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            for i, e in enumerate(self.table.entries):
                if e["id"] == entry_id:
                    self.table.removeRow(i)
                    self.table.entries.pop(i)
                    break
            QMessageBox.information(self, "Удаление", "Запись удалена")

    # ------------------------
    # О программе
    # ------------------------
    def _show_about(self):
        QMessageBox.information(
            self,
            "О программе",
            "Secure Vault\nВерсия 0.2\nУчебный проект"
        )

    # ------------------------
    # Логи и настройки
    # ------------------------
    def _show_audit_log(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Логи")
        layout = QVBoxLayout()
        layout.addWidget(AuditLogViewer())
        dialog.setLayout(layout)
        dialog.resize(600, 400)
        dialog.exec()

    def _show_settings(self):
        dialog = SettingsDialog()
        dialog.exec()