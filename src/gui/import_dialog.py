# Диалог импорта записей из файлов различных форматов.
# авто-определение формата, опции конфликтов, превью, итог.

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLabel, QLineEdit, QPushButton, QComboBox,
    QDialogButtonBox, QFileDialog, QMessageBox,
    QGroupBox, QProgressBar, QTextEdit, QRadioButton,
    QButtonGroup, QTableWidget, QTableWidgetItem,
    QHeaderView, QWidget, QSplitter,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QBrush
from pathlib import Path
from typing import Optional


class _ImportThread(QThread):
    finished = pyqtSignal(object)   # ImportResult
    error    = pyqtSignal(str)

    def __init__(self, importer, filepath, password, format, mode):
        super().__init__()
        self.importer  = importer
        self.filepath  = filepath
        self.password  = password
        self.format    = format
        self.mode      = mode

    def run(self):
        try:
            result = self.importer.import_file(
                filepath=self.filepath,
                password=self.password or None,
                format=self.format or None,
                mode=self.mode,
            )
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class ImportDialog(QDialog):
    # Диалог импорта записей.

    # Функции:
    # - Авто-определение формата файла
    # - Ввод пароля для зашифрованных файлов
    # - Выбор режима: merge / replace / dry_run (превью)
    # - Таблица с превью импортируемых записей
    # - Итоговая статистика после импорта
    # - Обработка ошибок с подробным отчётом
    FORMAT_LABELS = {
        "auto":           "Авто-определение",
        "encrypted_json": "🔒 CryptoSafe JSON",
        "csv":            "📄 CSV",
        "bitwarden":      "🔑 Bitwarden JSON",
        "lastpass_csv":   "🔑 LastPass CSV",
    }

    def __init__(self, importer, parent=None):
        super().__init__(parent)
        self.importer  = importer
        self._thread   = None
        self._filepath = ""

        self.setWindowTitle("Импорт записей")
        self.setModal(True)
        self.resize(750, 600)

        self._init_ui()

    # ------------------------------------------------------------------ #
    # Построение UI
    # ------------------------------------------------------------------ #

    def _init_ui(self):
        layout = QVBoxLayout(self)

        # Верхняя панель — файл и настройки
        top_group = QGroupBox("Файл и настройки")
        top_layout = QVBoxLayout(top_group)

        # Выбор файла
        file_layout = QHBoxLayout()
        self.filepath_label = QLabel("Файл не выбран")
        self.filepath_label.setStyleSheet("color: #888;")
        browse_btn = QPushButton("📂 Выбрать файл...")
        browse_btn.clicked.connect(self._browse_file)
        file_layout.addWidget(self.filepath_label, stretch=1)
        file_layout.addWidget(browse_btn)
        top_layout.addLayout(file_layout)

        # Формат и пароль
        settings_layout = QFormLayout()

        self.format_combo = QComboBox()
        for key, label in self.FORMAT_LABELS.items():
            self.format_combo.addItem(label, key)
        settings_layout.addRow("Формат:", self.format_combo)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText(
            "Только для зашифрованных файлов CryptoSafe"
        )
        settings_layout.addRow("Пароль:", self.password_input)

        top_layout.addLayout(settings_layout)

        # Режим импорта
        mode_layout = QHBoxLayout()
        mode_layout.addWidget(QLabel("Режим:"))

        self.mode_group = QButtonGroup(self)

        self.merge_radio   = QRadioButton("Объединить (merge)")
        self.replace_radio = QRadioButton("Заменить (replace)")
        self.dryrun_radio  = QRadioButton("Превью (dry run)")

        self.merge_radio.setChecked(True)
        self.merge_radio.setToolTip(
            "Добавить новые записи, обновить существующие по совпадению title+username+url"
        )
        self.replace_radio.setToolTip(
            "Очистить всё хранилище и импортировать заново. ВНИМАНИЕ: все текущие записи будут удалены!"
        )
        self.dryrun_radio.setToolTip(
            "Только показать что будет импортировано, без сохранения"
        )

        self.mode_group.addButton(self.merge_radio)
        self.mode_group.addButton(self.replace_radio)
        self.mode_group.addButton(self.dryrun_radio)

        mode_layout.addWidget(self.merge_radio)
        mode_layout.addWidget(self.replace_radio)
        mode_layout.addWidget(self.dryrun_radio)
        mode_layout.addStretch()
        top_layout.addLayout(mode_layout)

        layout.addWidget(top_group)

        # Кнопка Анализ (dry run)
        analyze_layout = QHBoxLayout()
        self.analyze_btn = QPushButton("🔍 Анализировать файл")
        self.analyze_btn.clicked.connect(self._do_dry_run)
        self.analyze_btn.setEnabled(False)
        analyze_layout.addStretch()
        analyze_layout.addWidget(self.analyze_btn)
        layout.addLayout(analyze_layout)

        # Таблица превью
        preview_group = QGroupBox("Превью записей")
        preview_layout = QVBoxLayout(preview_group)

        self.preview_table = QTableWidget()
        self.preview_table.setColumnCount(4)
        self.preview_table.setHorizontalHeaderLabels(
            ["Название", "Логин", "URL", "Статус"]
        )
        self.preview_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.preview_table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.preview_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.preview_table.verticalHeader().setVisible(False)
        preview_layout.addWidget(self.preview_table)

        # Статистика
        self.stats_label = QLabel("Выберите файл для анализа")
        self.stats_label.setFont(QFont("", 10))
        self.stats_label.setStyleSheet("color: #555;")
        preview_layout.addWidget(self.stats_label)

        layout.addWidget(preview_group)

        # Ошибки
        self.errors_group = QGroupBox("Ошибки и предупреждения")
        errors_layout = QVBoxLayout(self.errors_group)
        self.errors_text = QTextEdit()
        self.errors_text.setReadOnly(True)
        self.errors_text.setMaximumHeight(80)
        self.errors_text.setFont(QFont("Courier", 9))
        errors_layout.addWidget(self.errors_text)
        self.errors_group.hide()
        layout.addWidget(self.errors_group)

        # Прогресс
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.hide()
        layout.addWidget(self.progress)

        # Кнопки
        btn_layout = QHBoxLayout()
        self.import_btn = QPushButton("📥 Импортировать")
        self.import_btn.setDefault(True)
        self.import_btn.setEnabled(False)
        self.import_btn.clicked.connect(self._do_import)

        cancel_btn = QPushButton("Отмена")
        cancel_btn.clicked.connect(self.reject)

        btn_layout.addStretch()
        btn_layout.addWidget(self.import_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)

    # ------------------------------------------------------------------ #
    # Логика
    # ------------------------------------------------------------------ #

    def _browse_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Выбрать файл для импорта",
            "",
            "Все поддерживаемые (*.json *.csv);;"
            "CryptoSafe JSON (*.json);;"
            "CSV Files (*.csv);;"
            "All Files (*)",
        )
        if not path:
            return

        self._filepath = path
        self.filepath_label.setText(Path(path).name)
        self.filepath_label.setStyleSheet("color: #000;")
        self.filepath_label.setToolTip(path)

        # Авто-определение формата
        self._auto_detect_format(path)

        self.analyze_btn.setEnabled(True)
        self.import_btn.setEnabled(True)

        # Показываем поле пароля если это encrypted_json
        self._update_password_visibility()

    def _auto_detect_format(self, path: str):
        # Пытается определить формат и выставляет в комбо
        try:
            from core.import_export.importer import _detect_format
            detected = _detect_format(path)
            # Ищем в комбо
            for i in range(self.format_combo.count()):
                if self.format_combo.itemData(i) == detected:
                    self.format_combo.setCurrentIndex(i)
                    return
        except Exception:
            pass
        # Оставляем "авто"
        self.format_combo.setCurrentIndex(0)

    def _update_password_visibility(self):
        fmt = self.format_combo.currentData()
        # Поле пароля нужно только для encrypted_json
        # Для авто — показываем на всякий случай
        show = fmt in ("encrypted_json", "auto")
        self.password_input.setVisible(show)

    def _get_mode(self) -> str:
        if self.replace_radio.isChecked():
            return "replace"
        if self.dryrun_radio.isChecked():
            return "dry_run"
        return "merge"

    def _do_dry_run(self):
        # Запускает анализ файла без сохранения
        if not self._filepath:
            return
        self._run(mode="dry_run")

    def _do_import(self):
        # Запускает реальный импорт
        if not self._filepath:
            return

        mode = self._get_mode()

        # Предупреждение для replace
        if mode == "replace":
            msg = QMessageBox(self)
            msg.setWindowTitle("Подтверждение")
            msg.setText(
                "Режим ЗАМЕНА удалит ВСЕ текущие записи хранилища!\n\n"
                "Это действие необратимо. Продолжить?"
            )
            msg.setIcon(QMessageBox.Icon.Warning)
            yes_btn = msg.addButton("Удалить и импортировать",
                                     QMessageBox.ButtonRole.YesRole)
            msg.addButton("Отмена", QMessageBox.ButtonRole.NoRole)
            msg.exec()
            if msg.clickedButton() != yes_btn:
                return

        self._run(mode=mode)

    def _run(self, mode: str):
        # Запускает импорт/анализ в фоновом потоке
        fmt = self.format_combo.currentData()
        if fmt == "auto":
            fmt = None

        password = self.password_input.text() or None

        # Блокируем UI
        self.analyze_btn.setEnabled(False)
        self.import_btn.setEnabled(False)
        self.progress.show()
        self.errors_group.hide()

        self._thread = _ImportThread(
            importer=self.importer,
            filepath=self._filepath,
            password=password,
            format=fmt,
            mode=mode,
        )
        self._thread.finished.connect(lambda r: self._on_done(r, mode))
        self._thread.error.connect(self._on_error)
        self._thread.start()

    def _on_done(self, result, mode: str):
        #Обрабатывает результат импорта
        self.progress.hide()
        self.analyze_btn.setEnabled(True)
        self.import_btn.setEnabled(True)

        # Заполняем таблицу превью
        self._fill_preview_table(result, mode)

        # Статистика
        if mode == "dry_run":
            self.stats_label.setText(
                f"Будет импортировано: {result.total_parsed} записей  "
                f"(пропущено: {result.skipped})"
            )
        else:
            self.stats_label.setText(
                f"✅ Импортировано: {result.imported}  "
                f"Обновлено: {result.updated}  "
                f"Пропущено: {result.skipped}"
            )

        # Ошибки
        if result.errors:
            self.errors_group.show()
            self.errors_text.setPlainText("\n".join(result.errors))

        # Финальное сообщение для реального импорта
        if mode != "dry_run":
            QMessageBox.information(
                self, "Импорт завершён",
                f"Импортировано: {result.imported}\n"
                f"Обновлено: {result.updated}\n"
                f"Пропущено: {result.skipped}\n"
                f"Ошибок: {len(result.errors)}"
            )
            self.accept()

    def _fill_preview_table(self, result, mode: str):
        # Заполняет таблицу превью записями
        entries = result.dry_run_entries if mode == "dry_run" else []

        # Для не-dry_run показываем только статистику через stats_label
        if not entries:
            self.preview_table.setRowCount(0)
            return

        self.preview_table.setRowCount(len(entries))
        green  = QBrush(QColor(220, 255, 220))
        normal = QBrush(QColor(255, 255, 255))

        for row, entry in enumerate(entries):
            title    = entry.get("title",    "")
            username = entry.get("username", "")
            url      = entry.get("url",      "")
            status   = "Новая"
            color    = green

            for col, val in enumerate([title, username, url, status]):
                item = QTableWidgetItem(val)
                item.setBackground(color)
                self.preview_table.setItem(row, col, item)

    def _on_error(self, message: str):
        # Обрабатывает ошибку импорта
        self.progress.hide()
        self.analyze_btn.setEnabled(True)
        self.import_btn.setEnabled(True)
        QMessageBox.critical(self, "Ошибка импорта", message)