from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QLabel


class AuditLogViewer(QWidget):
    """
    Окно просмотра логов действий пользователя.

    В будущем будет зависеть от:
    - events.py
    - audit logger
    - database
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QVBoxLayout(self)

        title = QLabel("Audit Logs")
        self.logs = QTextEdit()
        self.logs.setReadOnly(True)

        # тестовые записи
        self.logs.append("System started")
        self.logs.append("User authenticated")

        layout.addWidget(title)
        layout.addWidget(self.logs)
