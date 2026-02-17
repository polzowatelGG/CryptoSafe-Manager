# src/gui/widgets/password_entry.py
from PyQt6.QtWidgets import QWidget, QLineEdit, QPushButton, QHBoxLayout


class PasswordEntry(QWidget):
    def __init__(self, placeholder="Введите пароль"):
        super().__init__()

        self.line_edit = QLineEdit()
        self.line_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.line_edit.setPlaceholderText(placeholder)

        self.toggle_btn = QPushButton("Показать")
        self.toggle_btn.setCheckable(True)
        self.toggle_btn.toggled.connect(self._toggle_password)

        layout = QHBoxLayout()
        layout.addWidget(self.line_edit)
        layout.addWidget(self.toggle_btn)
        layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(layout)

    def _toggle_password(self, checked):
        if checked:
            self.line_edit.setEchoMode(QLineEdit.EchoMode.Normal)
            self.toggle_btn.setText("Скрыть")
        else:
            self.line_edit.setEchoMode(QLineEdit.EchoMode.Password)
            self.toggle_btn.setText("Показать")

    def text(self):
        return self.line_edit.text()

    def clear(self):
        self.line_edit.clear()

