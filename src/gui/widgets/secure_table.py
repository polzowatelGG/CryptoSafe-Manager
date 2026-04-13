from PyQt6.QtCore import pyqtSignal, Qt, QTimer
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem, QMenu, QHeaderView, QMessageBox

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

        show_pw_action = QAction("👁️ Показать пароль", self)
        show_pw_action.triggered.connect(lambda: self._show_single_password(entry_id))
        menu.addAction(show_pw_action)

        menu.exec(self.viewport().mapToGlobal(pos))

    def _show_single_password(self, entry_id: str):
        entry = None
        for e in self.entries:
            if e["id"] == entry_id:
                entry = e
                break
        if not entry:
            return

        password = entry.get("password", "")
        if not password:
            QMessageBox.information(self, "Информация", "Пароль не задан")
            return

        msg = QMessageBox(self)
        msg.setWindowTitle("Пароль")
        msg.setText(f"Пароль для записи:\n\n{password}")
        msg.setInformativeText("Это окно закроется автоматически через 30 секунд.")
        msg.setStandardButtons(QMessageBox.StandardButton.Ok)
        QTimer.singleShot(30000, msg.accept)
        msg.exec()

    def clear_entries(self):
        self.entries.clear()
        self.setRowCount(0)
        
    def get_selected_entry_id(self):
        selected = self.selectedItems()
        if not selected:
            return None
        row = selected[0].row()
        if row < len(self.entries):
            return self.entries[row]["id"]
        return None
    
    def filter_entries(self, search_text: str):
        if not search_text.strip():
            for row in range(self.rowCount()):
                self.setRowHidden(row, False)
            return

        # разбор фильтров
        filters = {}
        words = search_text.split()
        for word in words:
            if ':' in word:
                field, value = word.split(':', 1)
                if field in ('title', 'username', 'url', 'notes'):
                    filters[field] = value.lower()
            else:
                filters.setdefault('any', []).append(word.lower())

        for row, entry in enumerate(self.entries):
            visible = True
            # проверка фильтров по конкретным полям
            for field, val in filters.items():
                if field == 'any':
                    continue
                field_value = entry.get(field, '').lower()
                if val not in field_value:
                    visible = False
                    break
            if visible and 'any' in filters:
                # полнотекстовый поиск по всем полям
                haystack = (entry.get('title', '') + ' ' +
                            entry.get('username', '') + ' ' +
                            entry.get('url', '') + ' ' +
                            entry.get('notes', '')).lower()
                if not any(any_word in haystack for any_word in filters['any']):
                    visible = False

            self.setRowHidden(row, not visible)