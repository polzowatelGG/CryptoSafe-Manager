from PyQt6.QtWidgets import QWidget, QHBoxLayout, QLineEdit, QPushButton


class PasswordEntry(QWidget):
    """
    Переиспользуемый виджет поля пароля.

    Используется:
    - в мастере создания мастер-пароля
    - в формах входа
    - при изменении пароля

    Зависимости:
    - только PyQt6
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        # горизонтальный layout
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # поле ввода
        self.edit = QLineEdit()

        # режим маскировки текста
        self.edit.setEchoMode(QLineEdit.EchoMode.Password)

        # кнопка показа/скрытия
        self.toggle_btn = QPushButton("👁")
        self.toggle_btn.setCheckable(True)
        self.toggle_btn.setFixedWidth(35)

        # сигнал нажатия
        self.toggle_btn.clicked.connect(self.toggle_visibility)

        layout.addWidget(self.edit)
        layout.addWidget(self.toggle_btn)

    def toggle_visibility(self):
        """
        Переключает режим отображения пароля
        """
        if self.toggle_btn.isChecked():
            self.edit.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.edit.setEchoMode(QLineEdit.EchoMode.Password)

    def text(self):
        """
        Получить введённый пароль
        """
        return self.edit.text()

    def setText(self, value):
        """
        Установить текст извне
        """
        self.edit.setText(value)
