# Диалог для безопасного обмена отдельными записями хранилища.
# выбор получателя, метод шифрования, права, история шарингов.

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLabel, QLineEdit, QPushButton, QComboBox,
    QFileDialog, QMessageBox, QGroupBox,
    QSpinBox, QCheckBox, QTabWidget, QWidget,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QTextEdit, QRadioButton, QButtonGroup,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont
from datetime import datetime
from typing import Optional, Dict, Any


class _ShareThread(QThread):
    finished = pyqtSignal(object)   # share_result dict
    error    = pyqtSignal(str)

    def __init__(self, service, entry_id, method, recipient,
                 permissions, expires_days, password, public_key_pem):
        super().__init__()
        self.service          = service
        self.entry_id         = entry_id
        self.method           = method
        self.recipient        = recipient
        self.permissions      = permissions
        self.expires_days     = expires_days
        self.password         = password
        self.public_key_pem   = public_key_pem

    def run(self):
        try:
            result = self.service.share_entry(
                entry_id=self.entry_id,
                encryption_method=self.method,
                recipient=self.recipient or None,
                permissions=self.permissions,
                expires_in_days=self.expires_days,
                password=self.password or None,
                recipient_public_key_pem=self.public_key_pem,
            )
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class SharingDialog(QDialog):
    # Диалог шаринга записи (UI-3).

    # Вкладки:
    # - Поделиться  — создать новый шаринг
    # - История     — активные и истёкшие шаринги
    # - Получить    — расшифровать полученный пакет
    def __init__(self, sharing_service, entry_id: Optional[str] = None,
                 entry_title: str = "", parent=None):
        super().__init__(parent)
        self.service     = sharing_service
        self.entry_id    = entry_id
        self.entry_title = entry_title
        self._thread     = None
        self._last_result: Optional[Dict[str, Any]] = None

        self.setWindowTitle("Управление шарингом")
        self.setModal(True)
        self.resize(620, 520)

        self._init_ui()
        self._load_contacts()
        self._load_history()

    # ------------------------------------------------------------------ #
    # Построение UI
    # ------------------------------------------------------------------ #

    def _init_ui(self):
        layout = QVBoxLayout(self)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_share_tab(),   "📤 Поделиться")
        self.tabs.addTab(self._build_history_tab(), "📋 История")
        self.tabs.addTab(self._build_receive_tab(), "📥 Получить")
        layout.addWidget(self.tabs)

        close_btn = QPushButton("Закрыть")
        close_btn.clicked.connect(self.accept)
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)

    def _build_share_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Запись
        entry_group = QGroupBox("Запись для шаринга")
        entry_layout = QFormLayout(entry_group)
        self.entry_label = QLabel(
            self.entry_title or self.entry_id or "Не выбрана"
        )
        self.entry_label.setFont(QFont("", 10, QFont.Weight.Bold))
        entry_layout.addRow("Запись:", self.entry_label)
        layout.addWidget(entry_group)

        # Получатель
        recipient_group = QGroupBox("Получатель")
        recipient_layout = QFormLayout(recipient_group)

        self.recipient_input = QLineEdit()
        self.recipient_input.setPlaceholderText("Имя или email получателя")
        recipient_layout.addRow("Получатель:", self.recipient_input)

        # Контакты из БД
        self.contacts_combo = QComboBox()
        self.contacts_combo.addItem("— выбрать из контактов —", None)
        self.contacts_combo.currentIndexChanged.connect(self._on_contact_selected)
        recipient_layout.addRow("Из контактов:", self.contacts_combo)

        layout.addWidget(recipient_group)

        # Метод шифрования
        method_group = QGroupBox("Метод шифрования")
        method_layout = QVBoxLayout(method_group)

        self.method_btn_group = QButtonGroup(self)
        self.password_radio   = QRadioButton("🔒 Пароль (AES-256-GCM + PBKDF2)")
        self.pubkey_radio     = QRadioButton("🔑 Публичный ключ (RSA-OAEP + AES-GCM)")
        self.password_radio.setChecked(True)
        self.method_btn_group.addButton(self.password_radio)
        self.method_btn_group.addButton(self.pubkey_radio)
        self.password_radio.toggled.connect(self._on_method_changed)

        method_layout.addWidget(self.password_radio)
        method_layout.addWidget(self.pubkey_radio)

        # Поле пароля
        self.share_password_input = QLineEdit()
        self.share_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.share_password_input.setPlaceholderText("Пароль для получателя")

        self.share_password_confirm = QLineEdit()
        self.share_password_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self.share_password_confirm.setPlaceholderText("Подтверждение")

        self.password_fields = QWidget()
        pw_layout = QFormLayout(self.password_fields)
        pw_layout.setContentsMargins(16, 0, 0, 0)
        pw_layout.addRow("Пароль:", self.share_password_input)
        pw_layout.addRow("Подтверждение:", self.share_password_confirm)
        method_layout.addWidget(self.password_fields)

        # Кнопка загрузки публичного ключа
        self.pubkey_widget = QWidget()
        pk_layout = QHBoxLayout(self.pubkey_widget)
        pk_layout.setContentsMargins(16, 0, 0, 0)
        self.pubkey_path_label = QLabel("Ключ не загружен")
        self.pubkey_path_label.setStyleSheet("color: #888;")
        self._pubkey_data: Optional[bytes] = None
        load_key_btn = QPushButton("Загрузить ключ (.pem)")
        load_key_btn.clicked.connect(self._load_public_key)
        pk_layout.addWidget(self.pubkey_path_label, stretch=1)
        pk_layout.addWidget(load_key_btn)
        self.pubkey_widget.hide()
        method_layout.addWidget(self.pubkey_widget)

        layout.addWidget(method_group)

        # Настройки
        settings_group = QGroupBox("Параметры")
        settings_layout = QFormLayout(settings_group)

        self.expires_spin = QSpinBox()
        self.expires_spin.setRange(1, 30)
        self.expires_spin.setValue(7)
        self.expires_spin.setSuffix(" дней")
        settings_layout.addRow("Срок действия:", self.expires_spin)

        self.allow_edit_check = QCheckBox("Разрешить редактирование")
        settings_layout.addRow("Права:", self.allow_edit_check)

        layout.addWidget(settings_group)

        # Кнопки
        btn_layout = QHBoxLayout()
        self.share_btn = QPushButton("📤 Создать пакет шаринга")
        self.share_btn.clicked.connect(self._do_share)
        self.share_btn.setEnabled(bool(self.entry_id))
        btn_layout.addStretch()
        btn_layout.addWidget(self.share_btn)
        layout.addLayout(btn_layout)

        layout.addStretch()
        return tab

    def _build_history_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.history_table = QTableWidget()
        self.history_table.setColumnCount(5)
        self.history_table.setHorizontalHeaderLabels(
            ["Share ID", "Получатель", "Метод", "Истекает", "Статус"]
        )
        self.history_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.history_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.history_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.history_table.verticalHeader().setVisible(False)
        layout.addWidget(self.history_table)

        btn_layout = QHBoxLayout()
        refresh_btn = QPushButton("🔄 Обновить")
        refresh_btn.clicked.connect(self._load_history)
        revoke_btn  = QPushButton("🚫 Отозвать выбранный")
        revoke_btn.clicked.connect(self._revoke_selected)
        btn_layout.addWidget(refresh_btn)
        btn_layout.addWidget(revoke_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        return tab

    def _build_receive_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Загрузка пакета
        file_group = QGroupBox("Файл пакета шаринга")
        file_layout = QHBoxLayout(file_group)
        self.receive_path_label = QLabel("Файл не выбран")
        self.receive_path_label.setStyleSheet("color: #888;")
        load_pkg_btn = QPushButton("📂 Загрузить пакет")
        load_pkg_btn.clicked.connect(self._load_package)
        file_layout.addWidget(self.receive_path_label, stretch=1)
        file_layout.addWidget(load_pkg_btn)
        layout.addWidget(file_group)

        # Расшифровка
        decrypt_group = QGroupBox("Расшифровка")
        decrypt_layout = QFormLayout(decrypt_group)

        self.receive_password_input = QLineEdit()
        self.receive_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.receive_password_input.setPlaceholderText(
            "Пароль (если пакет зашифрован паролем)"
        )
        decrypt_layout.addRow("Пароль:", self.receive_password_input)

        self.receive_privkey_label = QLabel("Ключ не загружен")
        self.receive_privkey_label.setStyleSheet("color: #888;")
        self._privkey_data: Optional[bytes] = None
        load_privkey_btn = QPushButton("Загрузить приватный ключ")
        load_privkey_btn.clicked.connect(self._load_private_key)
        pk_row = QHBoxLayout()
        pk_row.addWidget(self.receive_privkey_label, stretch=1)
        pk_row.addWidget(load_privkey_btn)
        decrypt_layout.addRow("Приватный ключ:", pk_row)

        layout.addWidget(decrypt_group)

        # Просмотр расшифрованной записи
        preview_group = QGroupBox("Расшифрованная запись")
        preview_layout = QVBoxLayout(preview_group)
        self.received_preview = QTextEdit()
        self.received_preview.setReadOnly(True)
        self.received_preview.setFont(QFont("Courier", 10))
        self.received_preview.setMaximumHeight(150)
        preview_layout.addWidget(self.received_preview)
        layout.addWidget(preview_group)

        # Кнопки
        btn_layout = QHBoxLayout()
        decrypt_btn = QPushButton("🔓 Расшифровать")
        decrypt_btn.clicked.connect(self._do_receive)
        self.save_received_btn = QPushButton("💾 Сохранить в хранилище")
        self.save_received_btn.clicked.connect(self._save_received)
        self.save_received_btn.setEnabled(False)
        self._received_entry: Optional[Dict] = None

        btn_layout.addStretch()
        btn_layout.addWidget(decrypt_btn)
        btn_layout.addWidget(self.save_received_btn)
        layout.addLayout(btn_layout)

        layout.addStretch()
        return tab

    # ------------------------------------------------------------------ #
    # Логика — вкладка Поделиться
    # ------------------------------------------------------------------ #

    def _on_method_changed(self, checked: bool):
        is_password = self.password_radio.isChecked()
        self.password_fields.setVisible(is_password)
        self.pubkey_widget.setVisible(not is_password)

    def _on_contact_selected(self, index: int):
        # Заполняет поле получателя из выбранного контакта
        contact = self.contacts_combo.itemData(index)
        if not contact:
            return
        self.recipient_input.setText(
            contact.get("name", "") + " " + contact.get("identifier", "")
        )
        # Если у контакта есть публичный ключ — переключаемся на pubkey метод
        if contact.get("public_key_pem"):
            self.pubkey_radio.setChecked(True)
            self._pubkey_data = contact["public_key_pem"].encode("utf-8")
            self.pubkey_path_label.setText(
                f"Ключ контакта: {contact.get('name', '')}"
            )
            self.pubkey_path_label.setStyleSheet("color: green;")

    def _load_public_key(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Загрузить публичный ключ", "",
            "PEM Files (*.pem);;All Files (*)"
        )
        if not path:
            return
        try:
            with open(path, "rb") as f:
                self._pubkey_data = f.read()
            from pathlib import Path
            self.pubkey_path_label.setText(Path(path).name)
            self.pubkey_path_label.setStyleSheet("color: green;")
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Не удалось загрузить ключ: {e}")

    def _do_share(self):
        if not self.entry_id:
            QMessageBox.warning(self, "Ошибка", "Запись не выбрана.")
            return

        method    = "password" if self.password_radio.isChecked() else "public_key"
        recipient = self.recipient_input.text().strip()
        expires   = self.expires_spin.value()
        permissions = {
            "read": True,
            "edit": self.allow_edit_check.isChecked(),
        }

        password       = None
        public_key_pem = None

        if method == "password":
            password = self.share_password_input.text()
            confirm  = self.share_password_confirm.text()
            if not password:
                QMessageBox.warning(self, "Ошибка", "Введите пароль для пакета.")
                return
            if password != confirm:
                QMessageBox.warning(self, "Ошибка", "Пароли не совпадают.")
                return
        else:
            if not self._pubkey_data:
                QMessageBox.warning(
                    self, "Ошибка", "Загрузите публичный ключ получателя."
                )
                return
            public_key_pem = self._pubkey_data

        self.share_btn.setEnabled(False)

        self._thread = _ShareThread(
            service=self.service,
            entry_id=self.entry_id,
            method=method,
            recipient=recipient,
            permissions=permissions,
            expires_days=expires,
            password=password,
            public_key_pem=public_key_pem,
        )
        self._thread.finished.connect(self._on_share_done)
        self._thread.error.connect(self._on_share_error)
        self._thread.start()

    def _on_share_done(self, result: Dict[str, Any]):
        self.share_btn.setEnabled(True)
        self._last_result = result

        # Предлагаем сохранить пакет в файл
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Сохранить пакет шаринга",
            f"share_{result['share_id'][:8]}.json",
            "JSON Files (*.json)"
        )
        if save_path:
            try:
                self.service.export_share_package(result, save_path)
                QMessageBox.information(
                    self, "Готово",
                    f"Пакет шаринга сохранён:\n{save_path}\n\n"
                    f"Share ID: {result['share_id']}\n"
                    f"Истекает: {result['expires_at']}"
                )
            except Exception as e:
                QMessageBox.warning(self, "Ошибка сохранения", str(e))

        self._load_history()

    def _on_share_error(self, message: str):
        self.share_btn.setEnabled(True)
        QMessageBox.critical(self, "Ошибка шаринга", message)

    # ------------------------------------------------------------------ #
    # Логика — вкладка История
    # ------------------------------------------------------------------ #

    def _load_history(self):
        try:
            shares = self.service.get_active_shares()
            self.history_table.setRowCount(len(shares))
            now = datetime.utcnow()

            for row, share in enumerate(shares):
                expires_str = share.get("expires_at", "")
                is_expired  = False
                if expires_str:
                    try:
                        expires_dt = datetime.fromisoformat(
                            expires_str.replace("Z", "")
                        )
                        is_expired = now > expires_dt
                    except Exception:
                        pass

                status = "✅ Активен" if not is_expired else "❌ Истёк"
                values = [
                    share.get("share_id", "")[:12] + "...",
                    share.get("recipient_info", "—"),
                    share.get("encryption_method", ""),
                    expires_str[:10] if expires_str else "—",
                    status,
                ]
                for col, val in enumerate(values):
                    item = QTableWidgetItem(val)
                    item.setData(Qt.ItemDataRole.UserRole,
                                 share.get("share_id"))
                    self.history_table.setItem(row, col, item)
        except Exception:
            pass

    def _revoke_selected(self):
        selected = self.history_table.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Ошибка", "Выберите шаринг для отзыва.")
            return
        share_id = selected[0].data(Qt.ItemDataRole.UserRole)
        if not share_id:
            return

        msg = QMessageBox(self)
        msg.setWindowTitle("Подтверждение")
        msg.setText(f"Отозвать шаринг {share_id[:12]}...?")
        yes_btn = msg.addButton("Отозвать", QMessageBox.ButtonRole.YesRole)
        msg.addButton("Отмена", QMessageBox.ButtonRole.NoRole)
        msg.exec()
        if msg.clickedButton() != yes_btn:
            return

        try:
            self.service.revoke_share(share_id)
            self._load_history()
            QMessageBox.information(self, "Готово", "Шаринг отозван.")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))

    # ------------------------------------------------------------------ #
    # Логика — вкладка Получить
    # ------------------------------------------------------------------ #

    def _load_package(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Загрузить пакет шаринга", "",
            "JSON Files (*.json);;All Files (*)"
        )
        if not path:
            return
        self._package_path = path
        from pathlib import Path
        self.receive_path_label.setText(Path(path).name)
        self.receive_path_label.setStyleSheet("color: #000;")

    def _load_private_key(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Загрузить приватный ключ", "",
            "PEM Files (*.pem);;All Files (*)"
        )
        if not path:
            return
        try:
            with open(path, "rb") as f:
                self._privkey_data = f.read()
            from pathlib import Path
            self.receive_privkey_label.setText(Path(path).name)
            self.receive_privkey_label.setStyleSheet("color: green;")
        except Exception as e:
            QMessageBox.warning(self, "Ошибка", f"Не удалось загрузить ключ: {e}")

    def _do_receive(self):
        package_path = getattr(self, "_package_path", None)
        if not package_path:
            QMessageBox.warning(self, "Ошибка", "Загрузите файл пакета.")
            return

        import json
        try:
            with open(package_path, "r", encoding="utf-8") as f:
                package = json.load(f)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось прочитать файл: {e}")
            return

        password   = self.receive_password_input.text() or None
        privkey    = self._privkey_data

        try:
            entry = self.service.receive_entry(
                package=package,
                password=password,
                private_key_pem=privkey,
            )
            self._received_entry = entry

            # Показываем превью (без пароля)
            preview = {
                k: v for k, v in entry.items()
                if k != "password"
            }
            preview["password"] = "••••••••"
            self.received_preview.setPlainText(
                json.dumps(preview, ensure_ascii=False, indent=2)
            )
            self.save_received_btn.setEnabled(True)

        except ValueError as e:
            QMessageBox.warning(self, "Ошибка расшифровки", str(e))
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))

    def _save_received(self):
        if not self._received_entry:
            return
        try:
            entry_id = self.service.save_received_entry(self._received_entry)
            QMessageBox.information(
                self, "Сохранено",
                f"Запись сохранена в хранилище.\nID: {entry_id}"
            )
            self.save_received_btn.setEnabled(False)
            self._received_entry = None
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))

    # ------------------------------------------------------------------ #
    # Вспомогательные
    # ------------------------------------------------------------------ #

    def _load_contacts(self):
        try:
            contacts = self.service.get_contacts()
            for contact in contacts:
                self.contacts_combo.addItem(
                    f"{contact['name']} ({contact.get('identifier', '')})",
                    contact,
                )
        except Exception:
            pass