# Виджет просмотра журнала аудита 
# Таблица с сортировкой, фильтрацией, поиском, пагинацией и панелью деталей

import json
from datetime import datetime
from typing import Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget,
    QTableWidgetItem, QLabel, QLineEdit, QComboBox,
    QPushButton, QHeaderView, QSplitter, QTextEdit,
    QDateEdit, QFormLayout, QFrame, QMessageBox,
    QFileDialog, QInputDialog
)
from PyQt6.QtCore import Qt, QDate, pyqtSignal
from PyQt6.QtGui import QColor, QBrush, QFont


class AuditLogViewer(QWidget):
    # сигнал: пользователь кликнул на запись vault-операции
    # передаём entry_id для подсветки в SecureTable (GUI-4)
    vault_entry_selected = pyqtSignal(str)

    PAGE_SIZE = 50  # записей на странице по умолчанию

    def __init__(self, db=None, parent=None):
        super().__init__(parent)
        self.db = db

        # состояние пагинации и фильтрации
        self._current_page = 0
        self._total_entries = 0
        self._all_entries = []     # все записи после фильтрации
        self._filtered_entries = []

        self._init_ui()

        # загружаем данные если БД передана
        if self.db:
            self._load_entries()

    # ------------------------------------------------------------------ #
    # Построение интерфейса
    # ------------------------------------------------------------------ #

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        # панель фильтров
        layout.addWidget(self._build_filter_panel())

        # разделитель: таблица слева, детали справа (GUI-2)
        splitter = QSplitter(Qt.Orientation.Horizontal)

        self.table = self._build_table()
        splitter.addWidget(self.table)

        self.details_panel = self._build_details_panel()
        splitter.addWidget(self.details_panel)

        splitter.setSizes([680, 320])
        layout.addWidget(splitter)

        # панель пагинации
        layout.addWidget(self._build_pagination_panel())

    def _build_filter_panel(self) -> QWidget:
        panel = QFrame()
        panel.setFrameShape(QFrame.Shape.StyledPanel)
        layout = QHBoxLayout(panel)
        layout.setContentsMargins(4, 4, 4, 4)

        # полнотекстовый поиск
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Поиск по деталям...")
        self.search_input.setMinimumWidth(180)
        self.search_input.textChanged.connect(self._apply_filters)
        layout.addWidget(QLabel("Поиск:"))
        layout.addWidget(self.search_input)

        # фильтр по типу события
        self.type_filter = QComboBox()
        self.type_filter.addItems([
            "Все типы",
            "SYSTEM_GENESIS", "USER_LOGIN", "USER_LOGOUT",
            "LOGIN_FAILED", "ENTRY_CREATED", "ENTRY_UPDATED",
            "ENTRY_DELETED", "CLIPBOARD_COPIED", "CLIPBOARD_CLEARED",
            "PASSWORD_CHANGED", "SETTINGS_CHANGED",
            "CLIPBOARD_ERROR", "SUSPICIOUS_ACCESS",
        ])
        self.type_filter.currentTextChanged.connect(self._apply_filters)
        layout.addWidget(QLabel("Тип:"))
        layout.addWidget(self.type_filter)

        # фильтр по severity
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(
            ["Все", "INFO", "WARN", "ERROR", "CRITICAL"]
        )
        self.severity_filter.currentTextChanged.connect(self._apply_filters)
        layout.addWidget(QLabel("Severity:"))
        layout.addWidget(self.severity_filter)

        # фильтр по дате от/до
        self.date_from = QDateEdit()
        self.date_from.setDate(QDate.currentDate().addDays(-30))
        self.date_from.setCalendarPopup(True)
        self.date_from.dateChanged.connect(self._apply_filters)

        self.date_to = QDateEdit()
        self.date_to.setDate(QDate.currentDate())
        self.date_to.setCalendarPopup(True)
        self.date_to.dateChanged.connect(self._apply_filters)

        layout.addWidget(QLabel("От:"))
        layout.addWidget(self.date_from)
        layout.addWidget(QLabel("До:"))
        layout.addWidget(self.date_to)

        # кнопка сброса фильтров
        reset_btn = QPushButton("Сбросить")
        reset_btn.clicked.connect(self._reset_filters)
        layout.addWidget(reset_btn)

        # кнопка обновления
        refresh_btn = QPushButton("🔄")
        refresh_btn.setToolTip("Обновить")
        refresh_btn.setFixedWidth(32)
        refresh_btn.clicked.connect(self._load_entries)
        layout.addWidget(refresh_btn)

        layout.addStretch()
        return panel

    def _build_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(6)
        table.setHorizontalHeaderLabels([
            "#", "Время", "Тип события", "Severity", "Источник", "Пользователь"
        ])

        # колонка # — узкая, остальные — растягиваются
        table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        for col in range(1, 6):
            table.horizontalHeader().setSectionResizeMode(
                col, QHeaderView.ResizeMode.Stretch
            )

        table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        table.setSortingEnabled(True)
        table.verticalHeader().setVisible(False)

        # клик на строку — показываем детали 
        table.itemSelectionChanged.connect(self._on_row_selected)

        # контекстное меню 
        table.setContextMenuPolicy(
            Qt.ContextMenuPolicy.CustomContextMenu
        )
        table.customContextMenuRequested.connect(
            self._show_context_menu
        )

        return table

    def _build_details_panel(self) -> QWidget:
        panel = QFrame()
        panel.setFrameShape(QFrame.Shape.StyledPanel)
        panel.setMinimumWidth(280)
        layout = QVBoxLayout(panel)

        layout.addWidget(QLabel("Детали записи:"))

        # JSON деталей в читаемом формате (GUI-2)
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setFont(QFont("Courier", 10))
        layout.addWidget(self.details_text)

        # статус верификации подписи (GUI-2)
        self.sig_status_label = QLabel("Подпись: —")
        self.sig_status_label.setWordWrap(True)
        layout.addWidget(self.sig_status_label)

        # hash chain (GUI-2)
        layout.addWidget(QLabel("Hash chain:"))
        self.hash_label = QLabel("—")
        self.hash_label.setFont(QFont("Courier", 9))
        self.hash_label.setWordWrap(True)
        self.hash_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        layout.addWidget(self.hash_label)

        return panel

    def _build_pagination_panel(self) -> QWidget:
        panel = QWidget()
        layout = QHBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)

        self.prev_btn = QPushButton("◀ Назад")
        self.prev_btn.clicked.connect(self._prev_page)
        self.prev_btn.setEnabled(False)

        self.page_label = QLabel("Стр. 1 из 1")

        self.next_btn = QPushButton("Вперёд ▶")
        self.next_btn.clicked.connect(self._next_page)
        self.next_btn.setEnabled(False)

        self.entries_label = QLabel("Записей: 0")

        layout.addWidget(self.prev_btn)
        layout.addWidget(self.page_label)
        layout.addWidget(self.next_btn)
        layout.addStretch()
        layout.addWidget(self.entries_label)

        return panel

    # ------------------------------------------------------------------ #
    # Загрузка и фильтрация данных
    # ------------------------------------------------------------------ #

    def _load_entries(self):
        # загружаем все записи из БД
        if not self.db:
            return
        try:
            rows = self.db.execute(
                "SELECT sequence_number, timestamp, entry_data, "
                "entry_hash, signature, previous_hash "
                "FROM audit_log ORDER BY sequence_number DESC"
            ).fetchall()

            self._all_entries = [dict(r) for r in rows]
            self._apply_filters()

        except Exception as e:
            self.details_text.setPlainText(f"Ошибка загрузки: {e}")

    def _apply_filters(self):
        # применяем все активные фильтры к _all_entries
        search = self.search_input.text().lower().strip()
        type_f = self.type_filter.currentText()
        sev_f  = self.severity_filter.currentText()
        date_f = self.date_from.date().toPyDate()
        date_t = self.date_to.date().toPyDate()

        filtered = []
        for row in self._all_entries:
            try:
                data = json.loads(row.get('entry_data', '{}'))
            except Exception:
                data = {}

            # фильтр по типу события
            if type_f != "Все типы" and data.get('event_type') != type_f:
                continue

            # фильтр по severity
            if sev_f != "Все" and data.get('severity') != sev_f:
                continue

            # фильтр по дате
            ts_str = row.get('timestamp', '')
            if ts_str:
                try:
                    ts_date = datetime.fromisoformat(
                        ts_str.replace('Z', '+00:00')
                    ).date()
                    if not (date_f <= ts_date <= date_t):
                        continue
                except Exception:
                    pass

            # полнотекстовый поиск по деталям
            if search:
                details_str = json.dumps(
                    data.get('details', {}), ensure_ascii=False
                ).lower()
                if search not in details_str and search not in str(
                    data.get('event_type', '')
                ).lower():
                    continue

            filtered.append(row)

        self._filtered_entries = filtered
        self._current_page = 0
        self._render_page()

    def _reset_filters(self):
        self.search_input.clear()
        self.type_filter.setCurrentIndex(0)
        self.severity_filter.setCurrentIndex(0)
        self.date_from.setDate(QDate.currentDate().addDays(-30))
        self.date_to.setDate(QDate.currentDate())

    # ------------------------------------------------------------------ #
    # Рендеринг страницы
    # ------------------------------------------------------------------ #

    def _render_page(self):
        # рендерим текущую страницу из _filtered_entries
        total = len(self._filtered_entries)
        total_pages = max(1, (total + self.PAGE_SIZE - 1) // self.PAGE_SIZE)
        start = self._current_page * self.PAGE_SIZE
        end   = min(start + self.PAGE_SIZE, total)
        page_entries = self._filtered_entries[start:end]

        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(page_entries))

        # цвета severity
        sev_colors = {
            'INFO':     QColor(255, 255, 255, 0),
            'WARN':     QColor(255, 255, 200),
            'ERROR':    QColor(255, 220, 220),
            'CRITICAL': QColor(255, 180, 180),
        }

        for row_idx, row in enumerate(page_entries):
            try:
                data = json.loads(row.get('entry_data', '{}'))
            except Exception:
                data = {}

            severity = data.get('severity', 'INFO')
            color = sev_colors.get(severity, sev_colors['INFO'])
            brush = QBrush(color)

            values = [
                str(row.get('sequence_number', '')),
                row.get('timestamp', ''),
                data.get('event_type', ''),
                severity,
                data.get('source', ''),
                data.get('user_id', ''),
            ]

            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                item.setBackground(brush)
                # сохраняем полную строку в UserRole для деталей
                if col == 0:
                    item.setData(Qt.ItemDataRole.UserRole, row)
                self.table.setItem(row_idx, col, item)

        self.table.setSortingEnabled(True)

        # обновляем навигацию
        self.page_label.setText(
            f"Стр. {self._current_page + 1} из {total_pages}"
        )
        self.prev_btn.setEnabled(self._current_page > 0)
        self.next_btn.setEnabled(
            self._current_page < total_pages - 1
        )
        self.entries_label.setText(f"Записей: {total}")

    # ------------------------------------------------------------------ #
    # Пагинация
    # ------------------------------------------------------------------ #

    def _prev_page(self):
        if self._current_page > 0:
            self._current_page -= 1
            self._render_page()

    def _next_page(self):
        total = len(self._filtered_entries)
        total_pages = max(
            1, (total + self.PAGE_SIZE - 1) // self.PAGE_SIZE
        )
        if self._current_page < total_pages - 1:
            self._current_page += 1
            self._render_page()

    # ------------------------------------------------------------------ #
    # Детали и верификация (GUI-2)
    # ------------------------------------------------------------------ #

    def _on_row_selected(self):
        selected = self.table.selectedItems()
        if not selected:
            return

        row_idx = self.table.currentRow()
        item = self.table.item(row_idx, 0)
        if not item:
            return

        row = item.data(Qt.ItemDataRole.UserRole)
        if not row:
            return

        self._show_entry_details(row)

    def _show_entry_details(self, row: dict):
        # показываем JSON деталей в читаемом виде (GUI-2)
        try:
            data = json.loads(row.get('entry_data', '{}'))
            pretty = json.dumps(
                data, indent=2, ensure_ascii=False
            )
        except Exception:
            pretty = row.get('entry_data', '')

        self.details_text.setPlainText(pretty)

        # показываем hash chain (GUI-2)
        entry_hash = row.get('entry_hash', '—')
        prev_hash  = row.get('previous_hash', '—')
        self.hash_label.setText(
            f"prev: {prev_hash[:16]}…\n"
            f"this: {entry_hash[:16]}…"
        )

        # показываем статус подписи (GUI-2)
        sig = row.get('signature', '')
        if sig:
            self.sig_status_label.setText("🔐 Подпись: присутствует")
            self.sig_status_label.setStyleSheet("color: green;")
        else:
            self.sig_status_label.setText("⚠️ Подпись: отсутствует")
            self.sig_status_label.setStyleSheet("color: red;")

    # ------------------------------------------------------------------ #
    # Контекстное меню 
    # ------------------------------------------------------------------ #

    def _show_context_menu(self, pos):
        from PyQt6.QtWidgets import QMenu
        from PyQt6.QtGui import QAction

        row_idx = self.table.rowAt(pos.y())
        if row_idx < 0:
            return

        item = self.table.item(row_idx, 0)
        if not item:
            return

        row = item.data(Qt.ItemDataRole.UserRole)
        if not row:
            return

        try:
            data = json.loads(row.get('entry_data', '{}'))
        except Exception:
            data = {}

        menu = QMenu(self)
        event_type = data.get('event_type', '')

        # если vault-операция — предлагаем перейти к записи (GUI-4)
        if event_type in (
            'ENTRY_CREATED', 'ENTRY_UPDATED', 'ENTRY_DELETED'
        ):
            entry_id = data.get('details', {}).get('entry_id', '')
            if entry_id:
                goto_action = QAction(
                    "🔍 Перейти к записи в хранилище", self
                )
                goto_action.triggered.connect(
                    lambda: self.vault_entry_selected.emit(entry_id)
                )
                menu.addAction(goto_action)

        # показываем детали в панели
        detail_action = QAction("📋 Показать детали", self)
        detail_action.triggered.connect(
            lambda: self._show_entry_details(row)
        )
        menu.addAction(detail_action)

        menu.exec(self.table.viewport().mapToGlobal(pos))

    # ------------------------------------------------------------------ #
    # Публичный API для внешнего обновления
    # ------------------------------------------------------------------ #

    def refresh(self):
        # вызывается из MainWindow после новых событий
        self._load_entries()

    def set_db(self, db):
        # устанавливаем БД после инициализации (для случаев
        # когда AuditLogViewer создаётся до подключения к БД)
        self.db = db
        self._load_entries()
        
    def _on_export(self, format_name: str):

        # запрашиваем мастер-пароль перед экспортом 
        password, ok = QInputDialog.getText(
            self,
            "Подтверждение экспорта",
            "Введите мастер-пароль для подтверждения экспорта:",
            QLineEdit.EchoMode.Password
        )
        if not ok or not password:
            return

        # запрашиваем путь к файлу
        extensions = {
            "json": "JSON (*.json)",
            "csv":  "CSV (*.csv)",
            "pdf":  "PDF (*.pdf)",
        }
        path, _ = QFileDialog.getSaveFileName(
            self,
            f"Экспорт в {format_name.upper()}",
            f"audit_log.{format_name}",
            extensions.get(format_name, "*.*")
        )
        if not path:
            return

        try:
            export_method = getattr(self.formatter, f"export_{format_name}")
            count = export_method(path, password=password)
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.information(
                self, "Готово",
                f"Экспортировано {count} записей в {path}"
            )
        except PermissionError as e:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.warning(self, "Отказано", str(e))
        except Exception as e:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.critical(self, "Ошибка экспорта", str(e))