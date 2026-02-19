# src/gui/widgets/audit_log_viewer.py
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QLabel


class AuditLogViewer(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout()

        self.info_label = QLabel("Audit Log (заглушка)")
        layout.addWidget(self.info_label)

        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Время", "Событие", "Пользователь"])
        layout.addWidget(self.table)

        # Тестовые данные
        test_data = [
            ("12:00", "Вход выполнен", "admin"),
            ("12:05", "Добавлена запись", "admin"),
        ]
        self.table.setRowCount(len(test_data))
        for row, (time, event, user) in enumerate(test_data):
            self.table.setItem(row, 0, QTableWidgetItem(time))
            self.table.setItem(row, 1, QTableWidgetItem(event))
            self.table.setItem(row, 2, QTableWidgetItem(user))

        self.setLayout(layout)

