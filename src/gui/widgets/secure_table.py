from PyQt6.QtCore import pyqtSignal, Qt, QTimer
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem, QMenu, QHeaderView, QMessageBox
from difflib import SequenceMatcher
from PyQt6.QtGui import QColor, QBrush
from typing import Optional

class SecureTable(QTableWidget):
    entry_edit_requested = pyqtSignal(str)
    entry_delete_requested = pyqtSignal(str)

    def __init__(self, parent=None, clipboard_service=None):
        super().__init__(parent)
        self.clipboard_service = clipboard_service

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
        
    @staticmethod
    def _fuzzy_match(query: str, text: str, threshold: float = 0.6) -> bool:
        # точное вхождение подстроки — проверяем первым, это быстрее
        if query in text:
            return True

        # нечёткое соответствие через SequenceMatcher —
        # сравниваем запрос с каждым словом из текста отдельно,
        # чтобы опечатка в одном слове не размывалась по всей строке.
        # порог 0.6: "Gogle" → "Google" даёт ~0.67, проходит.
        # "goo" → "Google" даёт 0.5, не проходит — слишком короткий фрагмент.
        for word in text.split():
            ratio = SequenceMatcher(None, query, word).ratio()
            if ratio >= threshold:
                return True

        return False
    
    def highlight_clipboard_entry(self, entry_id: Optional[str]):
        # подсвечиваем строку запись которой сейчас в буфере обмена (UI-2)
        # снимаем подсветку со всех строк и подсвечиваем нужную
        for row in range(self.rowCount()):
            is_highlighted = (
                entry_id is not None and
                row < len(self.entries) and
                self.entries[row].get("id") == entry_id
            )

            # голубой фон для строки в буфере, стандартный для остальных
            color = QColor(173, 216, 230) if is_highlighted else QColor(255, 255, 255, 0)
            brush = QBrush(color)

            for col in range(self.columnCount()):
                item = self.item(row, col)
                if item:
                    item.setBackground(brush)


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

        # Редактирование / удаление
        edit_action = QAction("Изменить", self)
        delete_action = QAction("Удалить", self)
        edit_action.triggered.connect(lambda: self.entry_edit_requested.emit(entry_id))
        delete_action.triggered.connect(lambda: self.entry_delete_requested.emit(entry_id))
        menu.addAction(edit_action)
        menu.addAction(delete_action)

        menu.addSeparator()

        copy_pw_action = QAction("📋 Копировать пароль", self)
        copy_pw_action.triggered.connect(lambda: self._copy_password(entry_id))
        menu.addAction(copy_pw_action)

        copy_user_action = QAction("📋 Копировать логин", self)
        copy_user_action.triggered.connect(lambda: self._copy_username(entry_id))
        menu.addAction(copy_user_action)

        copy_all_action = QAction("📋 Копировать всё (пароль)", self)
        copy_all_action.triggered.connect(lambda: self._copy_password(entry_id))
        menu.addAction(copy_all_action)

        menu.addSeparator()

        show_pw_action = QAction("👁️ Показать пароль", self)
        show_pw_action.triggered.connect(lambda: self._show_single_password(entry_id))
        menu.addAction(show_pw_action)

        menu.exec(self.viewport().mapToGlobal(pos))

    def _get_entry(self, entry_id: str) -> dict:
        for e in self.entries:
            if e["id"] == entry_id:
                return e
        return None

    def _copy_password(self, entry_id: str):
        entry = self._get_entry(entry_id)
        if not entry:
            return
        
        if entry.get("never_copy_to_clipboard", False):
            QMessageBox.warning(
            self, "Запрещено",
            "Для этой записи запрещено копирование пароля в буфер обмена."
            )
            return
        
        password = entry.get("password", "")
        if not password:
            QMessageBox.information(self, "Информация", "Пароль не задан")
            return
        if self.clipboard_service:
            try:
                self.clipboard_service.copy_to_clipboard(
                    data=password,
                    data_type="password",
                    source_entry_id=entry_id
                )
            except RuntimeError as e:
                QMessageBox.warning(self, "Ошибка", str(e))
        else:
            from PyQt6.QtWidgets import QApplication
            QApplication.clipboard().setText(password)

    def _copy_username(self, entry_id: str):
        entry = self._get_entry(entry_id)
        if not entry:
            return
        username = entry.get("username", "")
        if not username:
            QMessageBox.information(self, "Информация", "Логин не задан")
            return
        if self.clipboard_service:
            try:
                self.clipboard_service.copy_to_clipboard(
                    data=username,
                    data_type="username",
                    source_entry_id=entry_id
                )
            except RuntimeError as e:
                QMessageBox.warning(self, "Ошибка", str(e))
        else:
            from PyQt6.QtWidgets import QApplication
            QApplication.clipboard().setText(username)

    def _show_single_password(self, entry_id: str):
        entry = self._get_entry(entry_id)
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

        # разбираем запрос на field-фильтры (title:gogle) и свободный текст
        field_filters = {}
        any_words = []

        for word in search_text.split():
            if ':' in word:
                field, value = word.split(':', 1)
                if field in ('title', 'username', 'url', 'notes', 'category'):
                    field_filters[field] = value.lower()
            else:
                any_words.append(word.lower())

        for row, entry in enumerate(self.entries):
            visible = True

            # проверяем field-фильтры (title:gogle)
            for field, val in field_filters.items():
                field_value = entry.get(field, '').lower()
                if not self._fuzzy_match(val, field_value):
                    visible = False
                    break

            # проверяем свободный текст по всем полям
            if visible and any_words:
                haystack = (
                    entry.get('title',    '') + ' ' +
                    entry.get('username', '') + ' ' +
                    entry.get('url',      '') + ' ' +
                    entry.get('notes',    '') + ' ' +
                    entry.get('category', '')
                ).lower()
                if not any(self._fuzzy_match(w, haystack) for w in any_words):
                    visible = False

            self.setRowHidden(row, not visible)