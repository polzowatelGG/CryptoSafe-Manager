# src/gui/widgets/secure_table.py
from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import (
    QTableWidget,
    QTableWidgetItem,
    QMenu,
    QHeaderView,
)


class SecureTable(QTableWidget):
    entry_edit_requested = pyqtSignal(str)
    entry_delete_requested = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)

        self.entries = []
        self.show_passwords = False

        self.setColumnCount(5)
        self.setHorizontalHeaderLabels(["Название", "Логин", "URL", "Последнее изменение", "Пароль"])

        self.setRowCount(0)
        self.setSelectionBehavior(self.SelectionBehavior.SelectRows)
        self.setSelectionMode(self.SelectionMode.ExtendedSelection)

        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.horizontalHeader().setSortIndicatorShown(True)
        self.setSortingEnabled(True)

        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_context_menu)

    def _mask_login(self, login: str) -> str:
        if len(login) <= 4:
            return "*" * len(login)
        return login[:4] + "*" * (len(login) - 4)

    def _get_domain(self, url: str) -> str:
        try:
            if "//" in url:
                domain = url.split("//", 1)[1].split("/", 1)[0]
            else:
                domain = url.split("/", 1)[0]
            return domain
        except Exception:
            return url

    def add_entry(self, entry_id: str, title: str, username: str, url: str, updated_at: str, password: str):
        row = self.rowCount()
        self.insertRow(row)

        self.entries.append({
            "id": entry_id,
            "title": title,
            "username": username,
            "url": url,
            "updated_at": updated_at,
            "password": password,
        })

        self.setItem(row, 0, QTableWidgetItem(title))
        self.setItem(row, 1, QTableWidgetItem(self._mask_login(username)))
        self.setItem(row, 2, QTableWidgetItem(self._get_domain(url)))
        self.setItem(row, 3, QTableWidgetItem(updated_at))

        pw_text = password if self.show_passwords else "••••••••"
        self.setItem(row, 4, QTableWidgetItem(pw_text))

        self.setRowHidden(row, False)

    def update_password_visibility(self, show: bool):
        self.show_passwords = show
        for row in range(self.rowCount()):
            password = self.entries[row]["password"]
            pw_text = password if show else "••••••••"
            self.setItem(row, 4, QTableWidgetItem(pw_text))

    def _show_context_menu(self, pos):
        item = self.itemAt(pos)
        if item is None:
            return

        row = item.row()
        entry_id = self.entries[row]["id"]

        menu = QMenu(self)
        edit_action = QAction("Изменить", self)
        delete_action = QAction("Удалить", self)
        menu.addAction(edit_action)
        menu.addAction(delete_action)

        edit_action.triggered.connect(lambda: self.entry_edit_requested.emit(entry_id))
        delete_action.triggered.connect(lambda: self.entry_delete_requested.emit(entry_id))

        menu.exec(self.viewport().mapToGlobal(pos))

    def clear_entries(self):
        self.entries.clear()
        self.setRowCount(0)
        
        # Добавьте этот метод в класс SecureTable (после __init__ или в любом месте)

def get_selected_entry_id(self):
    """Возвращает ID выбранной записи или None"""
    selected = self.selectedItems()
    if not selected:
        return None
    row = selected[0].row()
    if row < len(self.entries):
        return self.entries[row]["id"]
    return None