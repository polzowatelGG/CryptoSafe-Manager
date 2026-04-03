from PyQt6.QtWidgets import QDialog, QVBoxLayout, QFormLayout, QMessageBox, QProgressBar ,QPushButton
from PyQt6.QtCore import Qt
from gui.widgets.password_entry import PasswordEntry
from core.crypto.key_derivation import PasswordValidator

class ChangePasswordDialog(QDialog):
    def __init__(self, key_manager, entry_manager, parent=None):
        super().__init__(parent)
        self.key_manager = key_manager
        self.entry_manager = entry_manager
        self.setWindowTitle("Смена мастер-пароля")
        self.setModal(True)
        self.resize(400, 200)
        
        layout = QVBoxLayout(self)
        form = QFormLayout()
        
        self.old_pass = PasswordEntry("Текущий пароль")
        self.new_pass = PasswordEntry("Новый пароль")
        self.confirm_pass = PasswordEntry("Подтверждение")
        
        form.addRow("Текущий пароль:", self.old_pass)
        form.addRow("Новый пароль:", self.new_pass)
        form.addRow("Подтверждение:", self.confirm_pass)
        
        layout.addLayout(form)
        
        self.change_btn = QPushButton("Сменить пароль")
        self.change_btn.clicked.connect(self._do_change)
        layout.addWidget(self.change_btn, alignment=Qt.AlignmentFlag.AlignCenter)
    
    def _do_change(self):
        old = self.old_pass.text()
        new = self.new_pass.text()
        confirm = self.confirm_pass.text()
        
        if not old or not new:
            QMessageBox.warning(self, "Ошибка", "Все поля обязательны")
            return
        if new != confirm:
            QMessageBox.warning(self, "Ошибка", "Новый пароль и подтверждение не совпадают")
            return
        if not PasswordValidator.validate_password_strength(new):
            QMessageBox.warning(self, "Слабый пароль",
                "Пароль не соответствует требованиям: минимум 12 символов, заглавные, строчные, цифры, спецсимволы, не из списка распространённых.")
            return
        
        try:
            # показываем прогресс (можно добавить QProgressBar, но для простоты – без)
            self.key_manager.change_password(old, new, self.entry_manager)
            QMessageBox.information(self, "Успех", "Пароль успешно изменён. Все записи перешифрованы.")
            self.accept()
        except ValueError as e:
            QMessageBox.warning(self, "Ошибка", str(e))
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сменить пароль: {e}")