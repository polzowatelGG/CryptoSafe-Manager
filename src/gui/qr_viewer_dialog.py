# Диалог просмотра и сканирования QR-кодов.
# большой QR, информация о payload, copy/share, auto-refresh, сканирование.

import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFileDialog, QMessageBox,
    QGroupBox, QTextEdit, QTabWidget, QWidget,
    QProgressBar, QSizePolicy,
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtSvgWidgets import QSvgWidget


class _ScanThread(QThread):
    finished = pyqtSignal(object)   # dict или None
    error    = pyqtSignal(str)

    def __init__(self, qr_service, image_path: str):
        super().__init__()
        self.qr_service = qr_service
        self.image_path = image_path

    def run(self):
        try:
            result = self.qr_service.scan_qr_from_file(self.image_path)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class QRViewerDialog(QDialog):
    # Диалог для отображения и сканирования QR-кодов 

    # Вкладки:
    # - Показать QR — отображает сгенерированный QR-код крупно
    # - Сканировать — загружает изображение и декодирует QR

    # Функции:
    # - Большой SVG QR-код
    # - Информация о payload (тип, время создания, срок действия)
    # - Кнопки: Копировать SVG, Сохранить как PNG/SVG
    # - Auto-refresh каждые 60 секунд (обновляет TTL-индикатор)
    # - Сканирование QR из файла изображения
    def __init__(self, qr_service, qr_results: Optional[List[Dict]] = None,
                 parent=None):
        super().__init__(parent)
        self.qr_service  = qr_service
        self.qr_results  = qr_results or []
        self._current_chunk = 0
        self._thread     = None

        self.setWindowTitle("QR-код")
        self.setModal(True)
        self.resize(520, 620)

        self._init_ui()

        if self.qr_results:
            self._display_chunk(0)

        # Таймер обновления TTL-индикатора (auto-refresh UI-4)
        self._ttl_timer = QTimer(self)
        self._ttl_timer.setInterval(1000)
        self._ttl_timer.timeout.connect(self._update_ttl)
        self._ttl_timer.start()

    # ------------------------------------------------------------------ #
    # Построение UI
    # ------------------------------------------------------------------ #

    def _init_ui(self):
        layout = QVBoxLayout(self)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_view_tab(),   "📷 QR-код")
        self.tabs.addTab(self._build_scan_tab(),   "🔍 Сканировать")
        layout.addWidget(self.tabs)

        close_btn = QPushButton("Закрыть")
        close_btn.clicked.connect(self.accept)
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)

    def _build_view_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # SVG виджет для QR
        self.svg_widget = QSvgWidget()
        self.svg_widget.setMinimumSize(380, 380)
        self.svg_widget.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )
        layout.addWidget(self.svg_widget, alignment=Qt.AlignmentFlag.AlignCenter)

        # Навигация по чанкам
        self.chunk_nav = QWidget()
        nav_layout = QHBoxLayout(self.chunk_nav)

        self.prev_chunk_btn = QPushButton("◀")
        self.prev_chunk_btn.setFixedWidth(36)
        self.prev_chunk_btn.clicked.connect(self._prev_chunk)

        self.chunk_label = QLabel("1 / 1")
        self.chunk_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.chunk_label.setFont(QFont("", 11))

        self.next_chunk_btn = QPushButton("▶")
        self.next_chunk_btn.setFixedWidth(36)
        self.next_chunk_btn.clicked.connect(self._next_chunk)

        nav_layout.addStretch()
        nav_layout.addWidget(self.prev_chunk_btn)
        nav_layout.addWidget(self.chunk_label)
        nav_layout.addWidget(self.next_chunk_btn)
        nav_layout.addStretch()
        self.chunk_nav.hide()
        layout.addWidget(self.chunk_nav)

        # Информация о payload
        info_group = QGroupBox("Информация")
        info_layout = QVBoxLayout(info_group)

        self.payload_type_label = QLabel("Тип: —")
        self.created_at_label   = QLabel("Создан: —")
        self.ttl_label          = QLabel("Действителен: —")
        self.ttl_label.setStyleSheet("font-weight: bold;")
        self.session_label      = QLabel("Session: —")
        self.session_label.setFont(QFont("Courier", 9))

        info_layout.addWidget(self.payload_type_label)
        info_layout.addWidget(self.created_at_label)
        info_layout.addWidget(self.ttl_label)
        info_layout.addWidget(self.session_label)
        layout.addWidget(info_group)

        # Кнопки
        btn_layout = QHBoxLayout()

        copy_svg_btn = QPushButton("📋 Копировать SVG")
        copy_svg_btn.clicked.connect(self._copy_svg)

        save_svg_btn = QPushButton("💾 Сохранить SVG")
        save_svg_btn.clicked.connect(self._save_svg)

        save_png_btn = QPushButton("💾 Сохранить PNG")
        save_png_btn.clicked.connect(self._save_png)

        btn_layout.addWidget(copy_svg_btn)
        btn_layout.addWidget(save_svg_btn)
        btn_layout.addWidget(save_png_btn)
        layout.addLayout(btn_layout)

        return tab

    def _build_scan_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Инструкция
        hint = QLabel(
            "Загрузите изображение с QR-кодом для сканирования.\n"
            "Поддерживаются форматы: PNG, JPG, BMP."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #555;")
        layout.addWidget(hint)

        # Загрузка файла
        file_layout = QHBoxLayout()
        self.scan_file_label = QLabel("Файл не выбран")
        self.scan_file_label.setStyleSheet("color: #888;")
        load_btn = QPushButton("📂 Выбрать изображение")
        load_btn.clicked.connect(self._load_scan_file)
        file_layout.addWidget(self.scan_file_label, stretch=1)
        file_layout.addWidget(load_btn)
        layout.addLayout(file_layout)

        # Кнопка сканирования
        scan_btn_layout = QHBoxLayout()
        self.scan_btn = QPushButton("🔍 Сканировать")
        self.scan_btn.setEnabled(False)
        self.scan_btn.clicked.connect(self._do_scan)
        scan_btn_layout.addStretch()
        scan_btn_layout.addWidget(self.scan_btn)
        layout.addLayout(scan_btn_layout)

        # Прогресс
        self.scan_progress = QProgressBar()
        self.scan_progress.setRange(0, 0)
        self.scan_progress.hide()
        layout.addWidget(self.scan_progress)

        # Результат
        result_group = QGroupBox("Результат сканирования")
        result_layout = QVBoxLayout(result_group)

        self.scan_result_text = QTextEdit()
        self.scan_result_text.setReadOnly(True)
        self.scan_result_text.setFont(QFont("Courier", 10))
        self.scan_result_text.setPlaceholderText(
            "Результат появится здесь после сканирования..."
        )
        result_layout.addWidget(self.scan_result_text)

        self.use_scanned_btn = QPushButton("✅ Использовать данные")
        self.use_scanned_btn.setEnabled(False)
        self.use_scanned_btn.clicked.connect(self._use_scanned)
        self._scanned_payload: Optional[Dict] = None
        result_layout.addWidget(
            self.use_scanned_btn,
            alignment=Qt.AlignmentFlag.AlignRight,
        )

        layout.addWidget(result_group)
        layout.addStretch()

        return tab

    # ------------------------------------------------------------------ #
    # Логика — вкладка Показать QR
    # ------------------------------------------------------------------ #

    def _display_chunk(self, index: int):
        # Отображает чанк QR по индексу
        if not self.qr_results or index >= len(self.qr_results):
            return

        chunk = self.qr_results[index]
        self._current_chunk = index

        # Отображаем SVG
        image = chunk.get("image", "")
        if image and chunk.get("format", "svg") == "svg":
            self.svg_widget.load(image.encode("utf-8"))

        # Навигация по чанкам
        total = chunk.get("total", 1)
        if total > 1:
            self.chunk_nav.show()
            self.chunk_label.setText(f"{index + 1} / {total}")
            self.prev_chunk_btn.setEnabled(index > 0)
            self.next_chunk_btn.setEnabled(index < total - 1)

        # Информация
        self.payload_type_label.setText(
            f"Тип: {self._format_payload_type(chunk)}"
        )
        self.created_at_label.setText(
            f"Создан: {self._format_datetime(chunk.get('session_id', ''))}"
        )
        self.session_label.setText(
            f"Session: {chunk.get('session_id', '—')}"
        )
        self._expires_at_str = chunk.get("expires_at", "")
        self._update_ttl()

    def _prev_chunk(self):
        if self._current_chunk > 0:
            self._display_chunk(self._current_chunk - 1)

    def _next_chunk(self):
        if self._current_chunk < len(self.qr_results) - 1:
            self._display_chunk(self._current_chunk + 1)

    def _update_ttl(self):
        # Обновляет индикатор времени жизни QR 
        expires_at_str = getattr(self, "_expires_at_str", "")
        if not expires_at_str:
            self.ttl_label.setText("Действителен: —")
            return

        try:
            expires_at = datetime.fromisoformat(
                expires_at_str.replace("Z", "+00:00")
            ).replace(tzinfo=None)
            remaining  = (expires_at - datetime.utcnow()).total_seconds()

            if remaining <= 0:
                self.ttl_label.setText("⛔ QR-код истёк")
                self.ttl_label.setStyleSheet("color: red; font-weight: bold;")
            elif remaining < 60:
                self.ttl_label.setText(
                    f"⚠️ Истекает через {int(remaining)} сек"
                )
                self.ttl_label.setStyleSheet("color: orange; font-weight: bold;")
            else:
                minutes = int(remaining // 60)
                seconds = int(remaining % 60)
                self.ttl_label.setText(
                    f"✅ Действителен ещё {minutes}м {seconds}с"
                )
                self.ttl_label.setStyleSheet("color: green; font-weight: bold;")
        except Exception:
            self.ttl_label.setText("Действителен: неизвестно")

    def _copy_svg(self):
        # Копирует SVG в буфер обмена
        if not self.qr_results:
            return
        chunk = self.qr_results[self._current_chunk]
        svg   = chunk.get("image", "")
        if svg:
            from PyQt6.QtWidgets import QApplication
            QApplication.clipboard().setText(svg)
            QMessageBox.information(self, "Скопировано", "SVG скопирован в буфер обмена.")

    def _save_svg(self):
        # Сохраняет SVG в файл
        if not self.qr_results:
            return
        chunk = self.qr_results[self._current_chunk]
        svg   = chunk.get("image", "")
        if not svg:
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Сохранить QR как SVG", "qrcode.svg", "SVG Files (*.svg)"
        )
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(svg)
                QMessageBox.information(self, "Сохранено", f"QR сохранён: {path}")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", str(e))

    def _save_png(self):
        # Генерирует и сохраняет PNG версию QR
        if not self.qr_results or not self.qr_service.is_qr_available():
            QMessageBox.warning(self, "Недоступно", "Библиотека qrcode не установлена.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Сохранить QR как PNG", "qrcode.png", "PNG Files (*.png)"
        )
        if not path:
            return

        try:
            chunk = self.qr_results[self._current_chunk]
            # Перегенерируем как PNG
            image = chunk.get("image", "")
            if isinstance(image, bytes):
                with open(path, "wb") as f:
                    f.write(image)
            else:
                QMessageBox.warning(
                    self, "Недоступно",
                    "PNG недоступен. Используйте Сохранить SVG."
                )
                return
            QMessageBox.information(self, "Сохранено", f"QR сохранён: {path}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))

    # ------------------------------------------------------------------ #
    # Логика — вкладка Сканировать
    # ------------------------------------------------------------------ #

    def _load_scan_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Выбрать изображение с QR",
            "", "Images (*.png *.jpg *.jpeg *.bmp);;All Files (*)"
        )
        if not path:
            return
        self._scan_file_path = path
        from pathlib import Path
        self.scan_file_label.setText(Path(path).name)
        self.scan_file_label.setStyleSheet("color: #000;")
        self.scan_btn.setEnabled(True)

    def _do_scan(self):
        path = getattr(self, "_scan_file_path", None)
        if not path:
            return

        self.scan_btn.setEnabled(False)
        self.scan_progress.show()
        self.scan_result_text.clear()

        self._thread = _ScanThread(self.qr_service, path)
        self._thread.finished.connect(self._on_scan_done)
        self._thread.error.connect(self._on_scan_error)
        self._thread.start()

    def _on_scan_done(self, result: Optional[Dict]):
        self.scan_progress.hide()
        self.scan_btn.setEnabled(True)

        if not result:
            self.scan_result_text.setPlainText(
                "QR-код не найден или данные повреждены."
            )
            return

        self._scanned_payload = result

        # Показываем результат
        payload_type = result.get("payload_type", "unknown")
        expires_at   = result.get("expires_at", "")
        data         = result.get("data", {})

        display = {
            "payload_type": payload_type,
            "expires_at":   expires_at,
            "data_preview": str(data)[:200] + ("..." if len(str(data)) > 200 else ""),
        }

        self.scan_result_text.setPlainText(
            json.dumps(display, ensure_ascii=False, indent=2)
        )
        self.use_scanned_btn.setEnabled(True)

    def _on_scan_error(self, message: str):
        self.scan_progress.hide()
        self.scan_btn.setEnabled(True)
        self.scan_result_text.setPlainText(f"Ошибка сканирования:\n{message}")

    def _use_scanned(self):
        # Принимает отсканированный payload и закрывает диалог
        if self._scanned_payload:
            self._result_payload = self._scanned_payload
            self.accept()

    def get_scanned_payload(self) -> Optional[Dict]:
        # Возвращает отсканированный payload после закрытия диалога
        return getattr(self, "_result_payload", None)

    # ------------------------------------------------------------------ #
    # Вспомогательные
    # ------------------------------------------------------------------ #

    def _format_payload_type(self, chunk: Dict) -> str:
        types = {
            "public_key":    "Публичный ключ",
            "share_package": "Пакет шаринга",
            "share_link":    "Ссылка на шаринг",
        }
        # Тип хранится в конверте — попробуем достать из session_id
        return types.get(chunk.get("payload_type", ""), "Данные")

    def _format_datetime(self, session_id: str) -> str:
        return datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    def closeEvent(self, event):
        self._ttl_timer.stop()
        super().closeEvent(event)