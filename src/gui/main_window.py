from PyQt6.QtWidgets import (
    QFileDialog, QMainWindow, QStatusBar, QMessageBox, QDialog, QVBoxLayout,
    QFormLayout, QLineEdit, QTextEdit, QDialogButtonBox,
    QTableWidgetItem, QPushButton, QHBoxLayout, QLabel, QWidget,
    QSystemTrayIcon, QMenu, QInputDialog, 
)
from PyQt6.QtGui import QAction, QFont, QIcon
from PyQt6.QtCore import QEvent, QUrl, Qt, QTimer, QThread, pyqtSignal as Signal
from datetime import datetime
import uuid
import re
from core.crypto.key_derivation import PasswordValidator
from core.vault.password_generator import PasswordGenerator
from gui.widgets.audit_log_viewer import AuditLogViewer
from gui.widgets.secure_table import SecureTable
from gui.settings_dialog import SettingsDialog
from core import events
import json


class PasswordStrengthIndicator(QLabel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(20)
        self.update_strength("")

    def update_strength(self, password: str):
        from core.crypto.key_derivation import PasswordValidator
        if not password:
            self.setText("⚪ Не введён")
            self.setStyleSheet("color: gray;")
        elif PasswordValidator.validate_password_strength(password):
            self.setText("🟢 Надёжный")
            self.setStyleSheet("color: green; font-weight: bold;")
        else:
            self.setText("🔴 Слабый (мин. 12 символов, заглавные, строчные, цифры, спецсимволы)")
            self.setStyleSheet("color: red;")


class MainWindow(QMainWindow):
    def __init__(self, entry_manager=None, key_manager=None, authenticator=None,
                state_manager=None, clipboard_service=None,
                log_verifier=None, parent=None):
        super().__init__(parent)
        self.entry_manager = entry_manager
        self.key_manager = key_manager
        self.authenticator = authenticator
        self.state_manager = state_manager
        self.clipboard_service = clipboard_service
        self.log_verifier = log_verifier  # теперь из аргумента
        self.installEventFilter(self)
        self._create_tray_icon()  # создаём иконку трея 

        self.setWindowTitle("Secure Vault")
        self.resize(900, 600)

        self._create_menu()
        self._create_central_table()
        self._create_status_bar()
        self._start_clipboard_timer()  # запускаем живой таймер статус-бара
        events.subscribe("UserLoggedOut", self._on_vault_locked)
        events.subscribe("VaultLocked",   self._on_vault_locked)
        events.subscribe("ClipboardUnblocked", self._on_clipboard_unblocked)
        
        if self.clipboard_service:
            self.clipboard_service.subscribe(self._on_clipboard_notification)

        if self.log_verifier:
            self.log_verifier.start_periodic_verification(
            interval_hours=24,
            on_result=self._on_verification_result
            )

    # ------------------------
    # Вспомогательные методы
    # ------------------------
    @staticmethod
    def sanitize_text(text: str, max_len: int = 500) -> str:
        if not isinstance(text, str):
            return ""
        cleaned = re.sub(r'[\x00-\x1f\x7f]', '', text)
        return cleaned[:max_len]

    # ------------------------
    # Меню
    # ------------------------
    def _create_menu(self):
        menu_bar = self.menuBar()

        # Файл
        file_menu = menu_bar.addMenu("Файл")
        new_action = QAction("Создать", self)
        open_action = QAction("Открыть", self)
        backup_action = QAction("Резервная копия", self)
        exit_action = QAction("Выход", self)
        exit_action.triggered.connect(self.close)
        file_menu.addActions([new_action, open_action, backup_action])
        file_menu.addSeparator()
        file_menu.addAction(exit_action)

        # Правка
        edit_menu = menu_bar.addMenu("Правка")
        self.add_action = QAction("Добавить", self)
        self.add_action.triggered.connect(self._on_add_entry)
        self.edit_action = QAction("Изменить", self)
        self.edit_action.triggered.connect(self._on_edit_entry)
        self.delete_action = QAction("Удалить", self)
        self.delete_action.triggered.connect(self._on_delete_entry)
        edit_menu.addActions([self.add_action, self.edit_action, self.delete_action])

        # Вид
        view_menu = menu_bar.addMenu("Вид")
        logs_action = QAction("Логи", self)
        logs_action.triggered.connect(self._show_audit_log)
        settings_action = QAction("Настройки", self)
        settings_action.triggered.connect(self._show_settings)
        view_menu.addActions([logs_action, settings_action])

        self.toggle_pass_action = QAction("Показать пароли", self)
        self.toggle_pass_action.setCheckable(True)
        self.toggle_pass_action.triggered.connect(self._toggle_passwords)
        view_menu.addSeparator()
        view_menu.addAction(self.toggle_pass_action)
        self.toggle_pass_action.setShortcut("Ctrl+Shift+P")

        # Справка
        help_menu = menu_bar.addMenu("Справка")
        about_action = QAction("О программе", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)
        
        # Разблокировка буфера обмена при подозрительной активности 
        security_menu = menu_bar.addMenu("Безопасность")

        change_pw_action = QAction("Сменить мастер-пароль", self)
        change_pw_action.triggered.connect(self._on_change_password)
        security_menu.addAction(change_pw_action)

        self.unblock_clipboard_action = QAction("Разблокировать буфер обмена", self)
        self.unblock_clipboard_action.triggered.connect(self._on_unblock_clipboard)
        self.unblock_clipboard_action.setVisible(False)  # скрыт пока не заблокирован
        security_menu.addAction(self.unblock_clipboard_action)
        
        preview_action = QAction("Предпросмотр буфера обмена", self)
        preview_action.triggered.connect(self._on_clipboard_preview)
        security_menu.addAction(preview_action)
        
        # Проверка целостности логов
        verify_action = QAction("Проверить целостность логов", self)
        verify_action.triggered.connect(self._on_verify_integrity)
        view_menu.addAction(verify_action)

    # ------------------------
    # Безопасность и мониторинг буфера обмена
    # ------------------------
    def _on_unblock_clipboard(self):
        if self.clipboard_service:
            self.clipboard_service.unblock_copies()
            # скрываем пункт меню после разблокировки
            self.unblock_clipboard_action.setVisible(False)

    def _on_clipboard_preview(self):
        if not self.clipboard_service:
            QMessageBox.information(self, "Информация", "Сервис буфера обмена недоступен")
            return

        status = self.clipboard_service.get_clipboard_status()

        dialog = QDialog(self)
        dialog.setWindowTitle("Предпросмотр буфера обмена")
        dialog.setModal(True)
        dialog.resize(420, 220)

        layout = QVBoxLayout(dialog)
        form = QFormLayout()

        # тип данных и источник
        data_type = status.get('data_type', '—')
        source_id = status.get('source_entry_id', 'неизвестно')
        remaining = int(status.get('remaining_seconds', 0))

        form.addRow("Тип данных:", QLabel(data_type if status.get('active') else "Буфер пуст"))
        form.addRow("Источник:", QLabel(str(source_id) if source_id else "неизвестно"))
        form.addRow("Очистка через:", QLabel(f"{remaining} сек" if status.get('active') else "—"))

        # маскированное содержимое
        masks = {"password": "pas••••••••", "username": "usr••••••••", "notes": "note•••••••"}
        masked = masks.get(data_type, "•••••••••••")
        content_label = QLabel(masked if status.get('active') else "—")
        content_label.setFont(QFont("Courier", 11))
        content_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        form.addRow("Содержимое:", content_label)

        layout.addLayout(form)

        btn_layout = QHBoxLayout()

        # кнопка раскрытия с проверкой мастер-пароля
        reveal_btn = QPushButton("👁 Показать")

        def on_reveal():
            password, ok = QInputDialog.getText(
                dialog, "Подтверждение",
                "Введите мастер-пароль:",
                QLineEdit.EchoMode.Password
            )
            if not ok or not password:
                return
            if not self.key_manager or not self.key_manager.is_unlocked():
                QMessageBox.warning(dialog, "Ошибка", "Хранилище заблокировано")
                return
            with self.clipboard_service._lock:
                item = self.clipboard_service._current_content
                if item and item.data:
                    content_label.setText(item.data)
                    reveal_btn.setEnabled(False)
                else:
                    QMessageBox.information(dialog, "Информация", "Буфер обмена пуст")

        reveal_btn.clicked.connect(on_reveal)
        reveal_btn.setEnabled(status.get('active', False))

        # кнопка ручной очистки
        clear_btn = QPushButton("🗑 Очистить")
        clear_btn.setStyleSheet("color: red;")

        def on_clear():
            self.clipboard_service._clear_clipboard()
            self.clipboard_service.events.publish('ClipboardCleared', reason='manual')
            dialog.accept()

        clear_btn.clicked.connect(on_clear)
        clear_btn.setEnabled(status.get('active', False))

        close_btn = QPushButton("Закрыть")
        close_btn.clicked.connect(dialog.accept)

        btn_layout.addWidget(reveal_btn)
        btn_layout.addWidget(clear_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)

        dialog.exec()


    # -------------------------
    # Обработка уведомлений от ClipboardService 
    # -------------------------
    def _on_clipboard_notification(self, message: str):
    # показываем toast
        self.show_toast(message)
        # если копирование заблокировано — показываем пункт разблокировки
        if self.clipboard_service and self.clipboard_service.is_blocked():
            self.unblock_clipboard_action.setVisible(True)
            
    #
    #
    #
    def _on_clipboard_unblocked(self, data=None):
        #обработчик события разблокировки буфера обмена
        # окрываем пункт меню разблокировки
        self.unblock_clipboard_action.setVisible(False)
        
        # рбновляем статус в статус-баре (показываем уведомление)
        self.show_toast("Буфер обмена разблокирован", duration=2000)
        
        # обновляем подсветку в таблице (снимаем подсветку)
        if hasattr(self, 'table') and self.table:
            self.table.highlight_clipboard_entry(None)
            
    def show_toast(self, message: str, duration: int = 3000):
        #показать временное сообщение в статус-баре
        if hasattr(self, 'status_bar'):
            original = self.status_bar.currentMessage()
            self.status_bar.showMessage(message)
            QTimer.singleShot(duration, lambda: self.status_bar.showMessage(original))

    # ------------------------
    # Центральная таблица с поиском
    # ------------------------
    def _create_central_table(self):
        # Передаём clipboard_service в таблицу для кнопок копирования (UI-1)
        self.table = SecureTable(clipboard_service=self.clipboard_service)
        
        self._load_entries()

        self.table.entry_edit_requested.connect(self._on_edit_entry_by_id)
        self.table.entry_delete_requested.connect(self._on_delete_entry_by_id)

        # Строка поиска
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Поиск (например, title:работа или просто текст)")
        self.search_input.textChanged.connect(self._on_search)

        # Компоновка
        container = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(self.search_input)
        layout.addWidget(self.table)
        container.setLayout(layout)
        self.setCentralWidget(container)
    
    def _load_entries(self):
    # загружаем записи из entry_manager и сразу затираем
    # расшифрованный список после передачи в таблицу (SEC-1)
        if not self.entry_manager:
            return

        self.table.clear_entries()

        entries = self.entry_manager.get_all_entries()
        try:
            for entry in entries:
                self.table.add_entry(
                    entry_id=entry.get("id", ""),
                    title=entry.get("title", ""),
                    username=entry.get("username", ""),
                    url=entry.get("url", ""),
                    updated_at=entry.get("updated_at", ""),
                    password=entry.get("password", ""),
                )
        finally:
            # затираем расшифрованные данные из памяти после передачи в GUI
            # finally гарантирует очистку даже при исключении
            self.entry_manager.secure_wipe_list(entries)

    def _on_vault_locked(self, **kwargs):
    # при блокировке хранилища очищаем все расшифрованные данные из таблицы
        self.table.clear_entries()   

    def _on_search(self, text):
        self.table.filter_entries(text)
        
        
    def _create_tray_icon(self):
        # создаём иконку системного трея (UI-2)
        self._tray = QSystemTrayIcon(self)

        # используем стандартную иконку если своей нет
        self._tray.setIcon(self.style().standardIcon(
            self.style().StandardPixmap.SP_ComputerIcon
        ))
        self._tray.setToolTip("CryptoSafe Manager")

        # контекстное меню трея
        tray_menu = QMenu()

        show_action = QAction("Открыть", self)
        show_action.triggered.connect(self.show)
        tray_menu.addAction(show_action)

        tray_menu.addSeparator()

        quit_action = QAction("Выход", self)
        quit_action.triggered.connect(self.close)
        tray_menu.addAction(quit_action)

        self._tray.setContextMenu(tray_menu)
        self._tray.show()


    # ------------------------
    # Статус-бар
    # ------------------------
    def _create_status_bar(self):
        self.status_bar = QStatusBar()
        self.login_status = "Не выполнен вход"
        self.clipboard_status = "Буфер: ---"
        self.status_bar.showMessage(f"{self.login_status} | {self.clipboard_status}")
        self.setStatusBar(self.status_bar)

    def _start_clipboard_timer(self):
        self._status_timer = QTimer(self)
        self._status_timer.setInterval(1000)
        self._status_timer.timeout.connect(self._update_clipboard_status)
        self._status_timer.start()

    def _update_clipboard_status(self):
        if not self.clipboard_service:
            return
        status = self.clipboard_service.get_clipboard_status()

        if status.get('active'):
            remaining = int(status.get('remaining_seconds', 0))
            data_type = status.get('data_type', '')

            if remaining <= 5 and remaining > 0:
                self.clipboard_status = f"⚠️ Буфер очистится через {remaining}с"
            elif remaining > 0:
                self.clipboard_status = f"📋 Буфер [{data_type}]: {remaining}с"
            else:
                self.clipboard_status = "Буфер: ---"

            # обновляем tooltip трея с тем же статусом 
            if hasattr(self, '_tray'):
                self._tray.setToolTip(
                    f"CryptoSafe Manager\n📋 {data_type} — очистка через {remaining}с"
                )
        else:
            self.clipboard_status = "Буфер: ---"

            # сбрасываем tooltip трея
            if hasattr(self, '_tray'):
                self._tray.setToolTip("CryptoSafe Manager")

        self.status_bar.showMessage(
            f"{self.login_status} | {self.clipboard_status}"
        )

        # обновляем подсветку строки в таблице
        if self.clipboard_service:
            source_id = status.get('source_entry_id')
            self.table.highlight_clipboard_entry(
                source_id if status.get('active') else None
            )        
        
    # Показать/скрыть пароли
    # ------------------------
    def _toggle_passwords(self, checked):
        self.table.update_password_visibility(checked)
        self.toggle_pass_action.setText("Скрыть пароли" if checked else "Показать пароли")

    # ------------------------
    # Добавление записи
    # ------------------------
    def _on_add_entry(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Добавить запись")
        dialog.resize(450, 450)
        layout = QVBoxLayout(dialog)
        form_layout = QFormLayout()

        title_edit = QLineEdit()
        username_edit = QLineEdit()
        password_edit = QLineEdit()
        password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        url_edit = QLineEdit()
        notes_edit = QTextEdit()
        notes_edit.setMaximumHeight(100)

        strength_indicator = PasswordStrengthIndicator()

        gen_btn = QPushButton("Сгенерировать пароль")
        password_layout = QHBoxLayout()
        password_layout.addWidget(password_edit)
        password_layout.addWidget(gen_btn)

        form_layout.addRow("Название:", title_edit)
        form_layout.addRow("Логин:", username_edit)
        form_layout.addRow("Пароль:", password_layout)
        form_layout.addRow("", strength_indicator)
        form_layout.addRow("URL:", url_edit)
        form_layout.addRow("Заметки:", notes_edit)

        password_edit.textChanged.connect(lambda text: strength_indicator.update_strength(text))

        def generate_password():
            gen = PasswordGenerator()
            new_pw = gen.generate_password(length=16)
            password_edit.setText(new_pw)
            strength_indicator.update_strength(new_pw)

        gen_btn.clicked.connect(generate_password)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)

        layout.addLayout(form_layout)
        layout.addWidget(buttons)

        if dialog.exec() == QDialog.DialogCode.Accepted:
            title = self.sanitize_text(title_edit.text().strip(), max_len=100)
            username = self.sanitize_text(username_edit.text(), max_len=255)
            url = self.sanitize_text(url_edit.text(), max_len=500)
            password = password_edit.text()

            if not title:
                QMessageBox.warning(self, "Ошибка", "Название не может быть пустым")
                return
            if not password:
                QMessageBox.warning(self, "Ошибка", "Пароль обязателен")
                return

            if url and not QUrl(url).isValid():
                QMessageBox.warning(self, "Ошибка", "Некорректный URL")
                return

            if not PasswordValidator.validate_password_strength(password):
                reply = QMessageBox.question(self, "Слабый пароль",
                    "Пароль не соответствует требованиям безопасности.\nВсё равно использовать?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                if reply == QMessageBox.StandardButton.No:
                    return
                
            if self.entry_manager:
                try:
                    entry_id = self.entry_manager.create_entry({
                        "title": title, "username": username,
                        "password": password, "url": url, "notes": notes,
                    })
                except Exception as e:
                        QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить: {e}")
                        return
            else:   
                entry_id = str(uuid.uuid4())
            self.table.add_entry(entry_id, title, username, url,
                                datetime.now().strftime("%Y-%m-%d %H:%M"), password)
            QMessageBox.information(self, "Успех", "Запись добавлена")

    # ------------------------
    # Редактирование
    # ------------------------
    def _on_edit_entry(self):
        entry_id = self.table.get_selected_entry_id()
        if not entry_id:
            QMessageBox.warning(self, "Ошибка", "Выберите запись для редактирования")
            return
        self._on_edit_entry_by_id(entry_id)

    def _on_edit_entry_by_id(self, entry_id: str):
        entry = None
        for e in self.table.entries:
            if e["id"] == entry_id:
                entry = e
                break
        if not entry:
            QMessageBox.warning(self, "Ошибка", "Запись не найдена")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Редактировать запись")
        dialog.resize(400, 350)

        layout = QVBoxLayout(dialog)
        form_layout = QFormLayout()

        title_edit = QLineEdit(entry["title"])
        username_edit = QLineEdit(entry["username"])
        password_edit = QLineEdit(entry["password"])
        password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        url_edit = QLineEdit(entry["url"])
        notes_edit = QTextEdit()
        notes_edit.setPlainText(entry.get("notes", ""))
        notes_edit.setMaximumHeight(80)

        form_layout.addRow("Название:", title_edit)
        form_layout.addRow("Логин:", username_edit)
        form_layout.addRow("Пароль:", password_edit)
        form_layout.addRow("URL:", url_edit)
        form_layout.addRow("Заметки:", notes_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)

        layout.addLayout(form_layout)
        layout.addWidget(buttons)

        if dialog.exec() == QDialog.DialogCode.Accepted:
            new_title = self.sanitize_text(title_edit.text().strip(), max_len=100)
            new_username = self.sanitize_text(username_edit.text(), max_len=255)
            new_url = self.sanitize_text(url_edit.text(), max_len=500)
            new_password = password_edit.text()

            if not new_title:
                QMessageBox.warning(self, "Ошибка", "Название не может быть пустым")
                return
            if not new_password:
                QMessageBox.warning(self, "Ошибка", "Пароль обязателен")
                return

            if not PasswordValidator.validate_password_strength(new_password):
                reply = QMessageBox.question(
                    self, "Слабый пароль",
                    "Пароль не соответствует требованиям безопасности.\nВсё равно сохранить?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if reply == QMessageBox.StandardButton.No:
                    return
            
            if self.entry_manager:
                try:
                    self.entry_manager.update_entry(entry_id, {
                        "title": new_title, "username": new_username,
                        "password": new_password, "url": new_url,
                        "notes": notes_edit.toPlainText(),
                    })
                except Exception as e:
                    QMessageBox.critical(self, "Ошибка", f"Не удалось обновить: {e}")
                    return
 
            # обновляем локальный dict
            entry.update({
                "title": new_title, "username": new_username,
                "password": new_password, "url": new_url,
                "notes": notes_edit.toPlainText(),
                "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
            })
            row = self.table.entries.index(entry)
            self.table.setItem(row, 0, QTableWidgetItem(entry["title"]))
            self.table.setItem(row, 1, QTableWidgetItem(self.table._mask_login(entry["username"])))
            self.table.setItem(row, 2, QTableWidgetItem(self.table._get_domain(entry["url"])))
            self.table.setItem(row, 3, QTableWidgetItem(entry["updated_at"]))
            pw_text = entry["password"] if self.table.show_passwords else "••••••••"
            self.table.setItem(row, 4, QTableWidgetItem(pw_text))

            QMessageBox.information(self, "Успех", "Запись обновлена")

    # ------------------------
    # Удаление
    # ------------------------
    def _on_delete_entry(self):
        entry_id = self.table.get_selected_entry_id()
        if not entry_id:
            QMessageBox.warning(self, "Ошибка", "Выберите запись для удаления")
            return
        self._on_delete_entry_by_id(entry_id)

    def _on_delete_entry_by_id(self, entry_id: str):
        reply = QMessageBox.question(
            self, "Подтверждение", "Удалить выбранную запись?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        if self.entry_manager:
            try:
                self.entry_manager.delete_entry(entry_id)
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Не удалось удалить: {e}")
                return
 
        for i, e in enumerate(self.table.entries):
            if e["id"] == entry_id:
                self.table.removeRow(i)
                self.table.entries.pop(i)
                break
        QMessageBox.information(self, "Удаление", "Запись удалена")

    # ------------------------
    # Смена мастер-пароля
    # ------------------------
    def _on_change_password(self):
        if not self.key_manager or not self.entry_manager:
            QMessageBox.warning(self, "Ошибка", "Функция недоступна")
            return
        from gui.change_password_dialog import ChangePasswordDialog
        dlg = ChangePasswordDialog(self.key_manager, self.entry_manager, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            QMessageBox.information(self, "Успех", "Пароль изменён. При следующем входе используйте новый пароль.")

    # ------------------------
    # События (авто-блокировка)
    # ------------------------
    def eventFilter(self, obj, event):
        if event.type() in (QEvent.Type.MouseButtonPress, QEvent.Type.KeyPress):
            if self.state_manager:
                self.state_manager.reset_inactivity_timer()
        return super().eventFilter(obj, event)

    def changeEvent(self, event):
        if event.type() == QEvent.Type.WindowStateChange:
            if self.isMinimized() or not self.isActiveWindow():
                if self.authenticator:
                    self.authenticator.logout()
        super().changeEvent(event)

    # ------------------------
    # О программе
    # ------------------------
    def _show_about(self):
        QMessageBox.information(self, "О программе", "Secure Vault\nВерсия 0.4\nУчебный проект")

    # ------------------------
    # Логи и настройки
    # ------------------------
    def _show_audit_log(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Журнал аудита")
        layout = QVBoxLayout()
        # получаем pool из entry_manager для передачи в AuditLogViewer
        # без pool виджет откроется пустым без реальных данных
        pool = getattr(self.entry_manager, 'db', None) if self.entry_manager else None
        layout.addWidget(AuditLogViewer(db=pool))
        dialog.setLayout(layout)
        dialog.resize(900, 600)  # увеличиваем — виджет теперь полноценный
        dialog.exec()

    def _show_settings(self):
        # Передаём config чтобы SettingsDialog мог читать и сохранять настройки
        config = getattr(self, '_config', None)
        pool = getattr(self, '_settings_model', None)
        
        dialog = SettingsDialog(config=config, pool=pool)
        dialog.exec()
    
    # ------------------------
    # Верификация логов
    # ------------------------
    def _on_verification_result(self, result: dict):
    # вызывается из фонового потока через колбэк 
    # обновляем статус целостности в статус-баре
    # используем QTimer.singleShot чтобы обновить GUI из главного потока
        def _update():
            if result.get('verified'):
                integrity_status = "✅ Лог: целостность подтверждена"
            else:
                integrity_status = "⚠️ Лог: обнаружено нарушение целостности!"
                # показываем предупреждение при нарушении 
                QMessageBox.critical(
                    self,
                    "Нарушение целостности аудит-лога",
                    f"Обнаружено нарушение целостности журнала аудита!\n\n"
                    f"Повреждённых записей: "
                    f"{len(result.get('invalid_entries', []))}\n"
                    f"Разрывов цепочки: "
                    f"{len(result.get('chain_breaks', []))}\n\n"
                    f"Рекомендуется сохранить резервную копию и обратиться "
                    f"к администратору."
                )

            self.status_bar.showMessage(
                f"{self.login_status} | {self.clipboard_status} | {integrity_status}"
            )

        QTimer.singleShot(0, _update)
        
    def closeEvent(self, event):
        # останавливаем периодическую верификацию при закрытии приложения
        if self.log_verifier:
            self.log_verifier.stop_periodic_verification()
        super().closeEvent(event)

        # показываем индикатор прогресса пока идёт проверка
        from PyQt6.QtWidgets import QProgressDialog
        progress = QProgressDialog(
            "Проверка целостности журнала аудита...", None, 0, 0, self
        )
        progress.setWindowTitle("Верификация логов")
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setMinimumDuration(0)
        progress.show()

        # запускаем полную верификацию в фоновом потоке
        # чтобы GUI не замерзал на большом логе

        class _VerifyThread(QThread):
            done = Signal(dict)

            def __init__(self, verifier):
                super().__init__()
                self.verifier = verifier

            def run(self):
                try:
                    result = self.verifier.verify_integrity(start_seq=0)
                    self.done.emit(result)
                except Exception as e:
                    self.done.emit({'verified': False, 'error': str(e)})

        self._verify_thread = _VerifyThread(self.log_verifier)

        def _on_done(result: dict):
            progress.close()
            self._show_verification_report(result)

        self._verify_thread.done.connect(_on_done)
        self._verify_thread.start()
    
    def _show_verification_report(self, result: dict):
        # VER-3: отображаем детальный отчёт верификации
        dialog = QDialog(self)
        dialog.setWindowTitle("Отчёт верификации журнала аудита")
        dialog.resize(520, 400)

        layout = QVBoxLayout(dialog)

        # статус верификации
        verified = result.get('verified', False)
        status_label = QLabel(
            "✅ Целостность подтверждена" if verified
            else "❌ Обнаружены нарушения целостности!"
        )
        status_label.setStyleSheet(
            "color: green; font-weight: bold; font-size: 14px;" if verified
            else "color: red; font-weight: bold; font-size: 14px;"
        )
        layout.addWidget(status_label)

        # детали верификации
        form = QFormLayout()
        form.addRow(
            "Всего проверено:",
            QLabel(str(result.get('total_entries', 0)))
        )
        form.addRow(
            "Валидных записей:",
            QLabel(str(result.get('valid_entries', 0)))
        )
        form.addRow(
            "Повреждённых записей:",
            QLabel(str(len(result.get('invalid_entries', []))))
        )
        form.addRow(
            "Разрывов цепочки:",
            QLabel(str(len(result.get('chain_breaks', []))))
        )
        layout.addLayout(form)

        # детальный список проблем если есть
        invalid = result.get('invalid_entries', [])
        breaks = result.get('chain_breaks', [])

        if invalid or breaks:
            details = QTextEdit()
            details.setReadOnly(True)
            details.setMaximumHeight(150)

            text = ""
            for entry in invalid:
                text += (
                    f"❌ Запись #{entry.get('sequence')}: "
                    f"{entry.get('reason', 'неизвестная ошибка')}\n"
                )
            for brk in breaks:
                text += (
                    f"🔗 Разрыв цепочки на записи "
                    f"#{brk.get('sequence')}\n"
                )
            details.setPlainText(text)
            layout.addWidget(QLabel("Подробности:"))
            layout.addWidget(details)

        # кнопки — экспорт отчёта и закрытие
        btn_layout = QHBoxLayout()

        export_btn = QPushButton("💾 Экспортировать отчёт")

        def _export():

            path, _ = QFileDialog.getSaveFileName(
                dialog, "Сохранить отчёт", "verification_report.json",
                "JSON (*.json)"
            )
            if path:
                report = {
                    **result,
                    'exported_at': __import__(
                        'datetime'
                    ).datetime.utcnow().isoformat() + "Z",
                    'report_type': 'full_verification',
                }
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(report, f, indent=2, ensure_ascii=False)
                QMessageBox.information(
                    dialog, "Готово", f"Отчёт сохранён:\n{path}"
                )

        export_btn.clicked.connect(_export)

        close_btn = QPushButton("Закрыть")
        close_btn.clicked.connect(dialog.accept)

        btn_layout.addWidget(export_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)

        dialog.exec()
    
    def _on_verify_integrity(self):
        # ручная полная верификация аудит-лога
        if not self.log_verifier:
            QMessageBox.information(
                self, "Недоступно",
                "Верификатор логов не инициализирован"
            )
            return

        # показываем индикатор прогресса пока идёт проверка
        from PyQt6.QtWidgets import QProgressDialog
        progress = QProgressDialog(
            "Проверка целостности журнала аудита...", None, 0, 0, self
        )
        progress.setWindowTitle("Верификация логов")
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.setMinimumDuration(0)
        progress.show()

        # запускаем полную верификацию в фоновом потоке
        # чтобы GUI не замерзал на большом логе
        from PyQt6.QtCore import QThread, pyqtSignal as Signal

        class _VerifyThread(QThread):
            done = Signal(dict)

            def __init__(self, verifier):
                super().__init__()
                self.verifier = verifier

            def run(self):
                try:
                    result = self.verifier.verify_integrity(start_seq=0)
                    self.done.emit(result)
                except Exception as e:
                    self.done.emit({'verified': False, 'error': str(e)})

        self._verify_thread = _VerifyThread(self.log_verifier)

        def _on_done(result: dict):
            progress.close()
            self._show_verification_report(result)

        self._verify_thread.done.connect(_on_done)
        self._verify_thread.start()
        
    