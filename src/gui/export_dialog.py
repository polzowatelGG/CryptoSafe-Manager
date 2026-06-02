# src/gui/export_dialog.py
# Изменения:
#  1. Добавлен формат bitwarden_encrypted (зашифрованный Bitwarden JSON)
#  2. Поле пароля показывается для encrypted_json и bitwarden_encrypted
#  3. Обновлены описания форматов
#  4. Предупреждения безопасности только для открытых форматов (csv, bitwarden)
#  5. Расширения файлов: для bitwarden_encrypted также .json

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLabel, QLineEdit, QPushButton, QComboBox, QCheckBox,
    QListWidget, QListWidgetItem, QFileDialog, QMessageBox,
    QGroupBox, QProgressBar, QTextEdit, QSplitter, QWidget,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont
from pathlib import Path
from typing import Optional, List


class _ExportThread(QThread):
    finished = pyqtSignal(int)
    error    = pyqtSignal(str)

    def __init__(self, exporter, filepath, password, format,
                 entry_ids, exclude_fields, compress):
        super().__init__()
        self.exporter       = exporter
        self.filepath       = filepath
        self.password       = password
        self.format         = format
        self.entry_ids      = entry_ids
        self.exclude_fields = exclude_fields
        self.compress       = compress

    def run(self):
        try:
            count = self.exporter.export(
                filepath=self.filepath,
                password=self.password,
                format=self.format,
                entry_ids=self.entry_ids if self.entry_ids else None,
                exclude_fields=self.exclude_fields if self.exclude_fields else None,
                compress=self.compress,
            )
            self.finished.emit(count)
        except Exception as e:
            self.error.emit(str(e))


class ExportDialog(QDialog):

    # Форматы: ключ совпадает с тем что передаётся в VaultExporter.export()
    FORMATS = ["encrypted_json", "csv", "bitwarden", "bitwarden_encrypted"]

    FORMAT_LABELS = {
        "encrypted_json":      "🔒 CryptoSafe Encrypted JSON",
        "csv":                 "📄 CSV",
        "bitwarden":           "🔓 Bitwarden JSON (unencrypted)",
        "bitwarden_encrypted": "🔐 Bitwarden Encrypted JSON (password protected)",
    }

    FORMAT_DESCRIPTIONS = {
        "encrypted_json": (
            "🔒 Нативный зашифрованный формат CryptoSafe\n"
            "AES-256-GCM + PBKDF2. Рекомендуется для резервных копий."
        ),
        "csv": (
            "📄 CSV (таблица)\n"
            "Открытый формат без шифрования. ⚠️ Пароли в открытом виде!"
        ),
        "bitwarden": (
            "🔓 Bitwarden JSON (незашифрованный)\n"
            "Стандартный формат для импорта в Bitwarden.\n"
            "⚠️ Файл содержит пароли в открытом виде — удалите после импорта."
        ),
        "bitwarden_encrypted": (
            "🔐 Bitwarden Password Protected Export\n"
            "Зашифрованный формат, совместимый с Bitwarden.\n"
            "Импортируется напрямую, требуется пароль при импорте."
        ),
    }

    def __init__(self, exporter, entry_manager, parent=None):
        super().__init__(parent)
        self.exporter      = exporter
        self.entry_manager = entry_manager
        self._thread       = None
        self._all_entries  = []

        self.setWindowTitle("Экспорт хранилища")
        self.setModal(True)
        self.resize(700, 580)

        self._init_ui()
        self._load_entries()
        self._on_format_changed(0)

    # -----------------------------------------------------------------------
    # Построение UI
    # -----------------------------------------------------------------------

    def _init_ui(self):
        layout = QVBoxLayout(self)
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # ── Левая панель — настройки ────────────────────────────────────────
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 4, 0)

        # Формат
        fmt_group = QGroupBox("Формат экспорта")
        fmt_layout = QVBoxLayout(fmt_group)

        self.format_combo = QComboBox()
        for fmt in self.FORMATS:
            self.format_combo.addItem(self.FORMAT_LABELS[fmt], fmt)
        self.format_combo.currentIndexChanged.connect(self._on_format_changed)
        fmt_layout.addWidget(self.format_combo)

        self.format_desc = QLabel()
        self.format_desc.setWordWrap(True)
        self.format_desc.setStyleSheet("color: #555; font-size: 11px;")
        fmt_layout.addWidget(self.format_desc)
        left_layout.addWidget(fmt_group)

        # Шифрование (только для encrypted_json и bitwarden_encrypted)
        self.enc_group = QGroupBox("Шифрование")
        enc_layout = QFormLayout(self.enc_group)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Пароль для экспорта")

        self.password_confirm = QLineEdit()
        self.password_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_confirm.setPlaceholderText("Подтверждение пароля")

        enc_layout.addRow("Пароль:", self.password_input)
        enc_layout.addRow("Подтверждение:", self.password_confirm)
        left_layout.addWidget(self.enc_group)

        # Опции
        opt_group = QGroupBox("Опции")
        opt_layout = QVBoxLayout(opt_group)

        self.compress_check = QCheckBox("Сжатие GZIP")
        self.compress_check.setToolTip(
            "Уменьшает размер файла (~50-70%). Только для зашифрованного JSON (CryptoSafe)."
        )
        self.exclude_notes_check = QCheckBox("Исключить заметки")
        self.exclude_tags_check  = QCheckBox("Исключить теги")

        opt_layout.addWidget(self.compress_check)
        opt_layout.addWidget(self.exclude_notes_check)
        opt_layout.addWidget(self.exclude_tags_check)
        left_layout.addWidget(opt_group)

        # Файл
        file_group = QGroupBox("Файл сохранения")
        file_layout = QHBoxLayout(file_group)

        self.filepath_input = QLineEdit()
        self.filepath_input.setPlaceholderText("Выберите путь...")
        self.filepath_input.setReadOnly(True)

        browse_btn = QPushButton("Обзор...")
        browse_btn.clicked.connect(self._browse_file)
        file_layout.addWidget(self.filepath_input)
        file_layout.addWidget(browse_btn)
        left_layout.addWidget(file_group)

        left_layout.addStretch()
        splitter.addWidget(left)

        # ── Правая панель — выбор записей ───────────────────────────────────
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(4, 0, 0, 0)

        entries_group = QGroupBox("Записи для экспорта")
        entries_layout = QVBoxLayout(entries_group)

        sel_layout = QHBoxLayout()
        select_all_btn   = QPushButton("Выбрать все")
        deselect_all_btn = QPushButton("Снять все")
        select_all_btn.clicked.connect(self._select_all)
        deselect_all_btn.clicked.connect(self._deselect_all)
        sel_layout.addWidget(select_all_btn)
        sel_layout.addWidget(deselect_all_btn)
        entries_layout.addLayout(sel_layout)

        self.entries_list = QListWidget()
        self.entries_list.setSelectionMode(
            QListWidget.SelectionMode.MultiSelection
        )
        self.entries_list.itemSelectionChanged.connect(self._update_preview)
        entries_layout.addWidget(self.entries_list)

        self.selected_label = QLabel("Выбрано: 0")
        self.selected_label.setFont(QFont("", 10))
        entries_layout.addWidget(self.selected_label)

        right_layout.addWidget(entries_group)

        # Превью
        preview_group = QGroupBox("Превью")
        preview_layout = QVBoxLayout(preview_group)
        self.preview_text = QTextEdit()
        self.preview_text.setReadOnly(True)
        self.preview_text.setMaximumHeight(120)
        self.preview_text.setFont(QFont("Courier", 9))
        preview_layout.addWidget(self.preview_text)
        right_layout.addWidget(preview_group)

        splitter.addWidget(right)
        splitter.setSizes([340, 340])
        layout.addWidget(splitter)

        # Прогресс
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.hide()
        layout.addWidget(self.progress)

        # Кнопки
        btn_layout = QHBoxLayout()
        self.export_btn = QPushButton("💾 Экспортировать")
        self.export_btn.setDefault(True)
        self.export_btn.clicked.connect(self._do_export)
        cancel_btn = QPushButton("Отмена")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addStretch()
        btn_layout.addWidget(self.export_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)

    # -----------------------------------------------------------------------
    # Логика
    # -----------------------------------------------------------------------

    def _load_entries(self):
        try:
            entries = self.entry_manager.get_all_entries()
            self._all_entries = entries
            for entry in entries:
                item = QListWidgetItem(
                    f"{entry.get('title', '?')}  —  {entry.get('username', '')}"
                )
                item.setData(Qt.ItemDataRole.UserRole, entry.get("id"))
                item.setSelected(True)
                self.entries_list.addItem(item)
            self._update_selected_label()
        except Exception as e:
            QMessageBox.warning(
                self, "Ошибка", f"Не удалось загрузить записи: {e}"
            )

    def _current_format(self) -> str:
        """Возвращает ключ текущего выбранного формата."""
        idx = self.format_combo.currentIndex()
        return self.format_combo.itemData(idx) or "encrypted_json"

    def _on_format_changed(self, _index: int):
        fmt = self._current_format()
        self.format_desc.setText(self.FORMAT_DESCRIPTIONS.get(fmt, ""))

        # Поле пароля — только для зашифрованных форматов
        show_enc = (fmt == "encrypted_json" or fmt == "bitwarden_encrypted")
        self.enc_group.setVisible(show_enc)

        # GZIP-сжатие — только для cryptosafe encrypted_json
        self.compress_check.setEnabled(fmt == "encrypted_json")

        self._update_preview()

    def _browse_file(self):
        fmt = self._current_format()

        filters = {
            "encrypted_json":      "CryptoSafe Export (*.json);;All Files (*)",
            "csv":                 "CSV Files (*.csv);;All Files (*)",
            "bitwarden":           "Bitwarden JSON (*.json);;All Files (*)",
            "bitwarden_encrypted": "Bitwarden Encrypted JSON (*.json);;All Files (*)",
        }
        default_names = {
            "encrypted_json":      "vault_export.json",
            "csv":                 "vault_export.csv",
            "bitwarden":           "bitwarden_export.json",
            "bitwarden_encrypted": "bitwarden_encrypted.json",
        }

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Сохранить экспорт",
            default_names.get(fmt, "export.json"),
            filters.get(fmt, "All Files (*)"),
        )
        if path:
            self.filepath_input.setText(path)
            self._update_preview()

    def _select_all(self):
        for i in range(self.entries_list.count()):
            self.entries_list.item(i).setSelected(True)
        self._update_selected_label()

    def _deselect_all(self):
        for i in range(self.entries_list.count()):
            self.entries_list.item(i).setSelected(False)
        self._update_selected_label()

    def _update_selected_label(self):
        count = len(self.entries_list.selectedItems())
        self.selected_label.setText(f"Выбрано: {count}")

    def _update_preview(self):
        self._update_selected_label()
        fmt      = self._current_format()
        count    = len(self.entries_list.selectedItems())
        filepath = self.filepath_input.text()

        lines = [
            f"Формат:   {fmt}",
            f"Записей:  {count}",
            f"Файл:     {filepath or '(не выбран)'}",
        ]
        if fmt == "encrypted_json":
            lines.append(f"Сжатие:   {'да' if self.compress_check.isChecked() else 'нет'}")
            if self.password_input.text():
                lines.append("Шифрование: ✅ пароль задан")
            else:
                lines.append("Шифрование: ⚠️ пароль не задан")
        elif fmt == "bitwarden_encrypted":
            # Зашифрованный Bitwarden – пароль обязателен
            if self.password_input.text():
                lines.append("Шифрование: ✅ пароль задан (AES-256-CBC + HMAC)")
            else:
                lines.append("Шифрование: ⚠️ пароль не задан – экспорт будет зашифрован, но нужен пароль")
        elif fmt in ("csv", "bitwarden"):
            lines.append("Шифрование: ❌ открытый формат")

        if self.exclude_notes_check.isChecked():
            lines.append("Исключено: notes")
        if self.exclude_tags_check.isChecked():
            lines.append("Исключено: tags")

        self.preview_text.setPlainText("\n".join(lines))

    def _get_selected_entry_ids(self) -> Optional[List[str]]:
        selected = self.entries_list.selectedItems()
        total    = self.entries_list.count()
        if len(selected) == total:
            return None
        return [
            item.data(Qt.ItemDataRole.UserRole)
            for item in selected
            if item.data(Qt.ItemDataRole.UserRole)
        ]

    def _get_exclude_fields(self) -> List[str]:
        fields = []
        if self.exclude_notes_check.isChecked():
            fields.append("notes")
        if self.exclude_tags_check.isChecked():
            fields.append("tags")
        return fields

    def _do_export(self):
        fmt      = self._current_format()
        filepath = self.filepath_input.text().strip()

        if not filepath:
            QMessageBox.warning(self, "Ошибка", "Выберите файл для сохранения.")
            return

        # ── Зашифрованные форматы: encrypted_json и bitwarden_encrypted ──────
        if fmt in ("encrypted_json", "bitwarden_encrypted"):
            password = self.password_input.text()
            confirm  = self.password_confirm.text()
            if not password:
                QMessageBox.warning(self, "Ошибка", "Введите пароль для экспорта.")
                return
            if password != confirm:
                QMessageBox.warning(self, "Ошибка", "Пароли не совпадают.")
                return

        # ── Открытый Bitwarden JSON (unencrypted) ────────────────────────────
        elif fmt == "bitwarden":
            msg = QMessageBox(self)
            msg.setWindowTitle("⚠️ Предупреждение безопасности")
            msg.setText(
                "Bitwarden JSON (незашифрованный) сохраняет пароли в открытом виде.\n\n"
                "Файл предназначен только для одноразового импорта в Bitwarden.\n"
                "Удалите файл сразу после импорта!\n\n"
                "Продолжить?"
            )
            msg.setIcon(QMessageBox.Icon.Warning)
            yes_btn = msg.addButton("Продолжить", QMessageBox.ButtonRole.YesRole)
            msg.addButton("Отмена", QMessageBox.ButtonRole.NoRole)
            msg.exec()
            if msg.clickedButton() != yes_btn:
                return
            password = ""

        # ── CSV ───────────────────────────────────────────────────────────
        elif fmt == "csv":
            msg = QMessageBox(self)
            msg.setWindowTitle("⚠️ Предупреждение безопасности")
            msg.setText(
                "CSV сохраняет пароли в открытом виде!\n\n"
                "Используйте только для миграции. Продолжить?"
            )
            msg.setIcon(QMessageBox.Icon.Warning)
            yes_btn = msg.addButton("Продолжить", QMessageBox.ButtonRole.YesRole)
            msg.addButton("Отмена", QMessageBox.ButtonRole.NoRole)
            msg.exec()
            if msg.clickedButton() != yes_btn:
                return
            password = ""

        else:
            password = ""

        selected_ids = self._get_selected_entry_ids()
        exclude      = self._get_exclude_fields()

        self.export_btn.setEnabled(False)
        self.progress.show()

        self._thread = _ExportThread(
            exporter=self.exporter,
            filepath=filepath,
            password=password,
            format=fmt,
            entry_ids=selected_ids,
            exclude_fields=exclude,
            compress=self.compress_check.isChecked() if fmt == "encrypted_json" else False,
        )
        self._thread.finished.connect(self._on_export_done)
        self._thread.error.connect(self._on_export_error)
        self._thread.start()

    def _on_export_done(self, count: int):
        self.progress.hide()
        self.export_btn.setEnabled(True)

        fmt = self._current_format()
        extra = ""
        if fmt == "bitwarden":
            extra = "\n\n💡 Совет: удалите этот файл сразу после импорта в Bitwarden."
        elif fmt == "bitwarden_encrypted":
            extra = "\n\n💡 При импорте в Bitwarden введите тот же пароль."

        QMessageBox.information(
            self, "Готово",
            f"Экспортировано {count} записей.\n\n"
            f"Файл: {self.filepath_input.text()}{extra}"
        )
        self.accept()

    def _on_export_error(self, message: str):
        self.progress.hide()
        self.export_btn.setEnabled(True)
        QMessageBox.critical(self, "Ошибка экспорта", message)