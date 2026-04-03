from PyQt6.QtWidgets import QDialog, QVBoxLayout, QFormLayout, QLineEdit, QPushButton, QMessageBox
from PyQt6.QtCore import Qt
from gui.widgets.password_entry import PasswordEntry

class LoginDialog(QDialog):
    def __init__(self, authenticator, parent=None):
        super().__init__(parent)
        self.authenticator = authenticator
        self.setWindowTitle("Вход в хранилище")
        self.setModal(True)
        self.resize(350, 150)
        
        layout = QVBoxLayout(self)
        form = QFormLayout()
        
        self.password_input = PasswordEntry("Введите мастер-пароль")
        form.addRow("Мастер-пароль:", self.password_input)
        
        layout.addLayout(form)
        
        self.login_btn = QPushButton("Войти")
        self.login_btn.clicked.connect(self._do_login)
        layout.addWidget(self.login_btn, alignment=Qt.AlignmentFlag.AlignCenter)
    
    def _do_login(self):
        password = self.password_input.text()
        if self.authenticator.login(password):
            self.accept()
        else:
            QMessageBox.warning(self, "Ошибка", "Неверный мастер-пароль")
            self.password_input.clear()