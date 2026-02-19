# src/gui/widgets/secure_table.py
from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem


class SecureTable(QTableWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setColumnCount(3)
        self.setHorizontalHeaderLabels(["Название", "Логин", "URL"])
        self.setRowCount(0)

    def add_entry(self, name: str, login: str, url: str):
        """Добавляет запись в таблицу"""
        row = self.rowCount()
        self.insertRow(row)
        self.setItem(row, 0, QTableWidgetItem(name))
        self.setItem(row, 1, QTableWidgetItem(login))
        self.setItem(row, 2, QTableWidgetItem(url))

    def clear_entries(self):
        """Очищает таблицу"""
        self.setRowCount(0)

