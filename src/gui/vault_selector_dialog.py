from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QListWidget, QListWidgetItem,
    QFileDialog, QMessageBox, QWidget,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from pathlib import Path
import json


class VaultSelectorDialog(QDialog):
    """
    Стартовый экран: выбор существующей БД или создание новой.
    Возвращает self.selected_db_path после accept().
    """

    RECENT_KEY = "recent_vaults"

    def __init__(self, config, parent=None):
        super().__init__(parent)
        self.config = config
        self.selected_db_path: str | None = None

        self.setWindowTitle("CryptoSafe Manager — Выбор хранилища")
        self.setModal(True)
        self.setMinimumWidth(480)
        self.resize(520, 400)

        self._init_ui()
        self._load_recent()

    # ------------------------------------------------------------------ #
    # UI
    # ------------------------------------------------------------------ #

    def _init_ui(self):
        layout = QVBoxLayout(self)

        title = QLabel("Выберите хранилище паролей")
        title.setFont(QFont("", 14, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        subtitle = QLabel("Откройте существующую базу данных или создайте новую")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet("color: #666;")
        layout.addWidget(subtitle)

        layout.addSpacing(12)

        # Список недавних БД
        recent_label = QLabel("Недавние хранилища:")
        recent_label.setFont(QFont("", 10, QFont.Weight.Bold))
        layout.addWidget(recent_label)

        self.recent_list = QListWidget()
        self.recent_list.setAlternatingRowColors(True)
        self.recent_list.itemDoubleClicked.connect(self._on_recent_double_click)
        self.recent_list.setMinimumHeight(160)
        layout.addWidget(self.recent_list)

        # Кнопки управления списком
        list_btn_layout = QHBoxLayout()
        self.open_selected_btn = QPushButton("🔓 Открыть выбранное")
        self.open_selected_btn.clicked.connect(self._open_selected)
        remove_btn = QPushButton("✕ Убрать из списка")
        remove_btn.clicked.connect(self._remove_selected)
        list_btn_layout.addWidget(self.open_selected_btn)
        list_btn_layout.addWidget(remove_btn)
        list_btn_layout.addStretch()
        layout.addLayout(list_btn_layout)

        layout.addSpacing(8)

        # Разделитель
        sep = QLabel("─" * 60)
        sep.setStyleSheet("color: #ccc;")
        layout.addWidget(sep)

        layout.addSpacing(4)

        # Кнопки действий
        action_layout = QHBoxLayout()

        browse_btn = QPushButton("📂 Открыть файл БД...")
        browse_btn.setMinimumHeight(36)
        browse_btn.clicked.connect(self._browse_existing)

        new_btn = QPushButton("➕ Создать новое хранилище")
        new_btn.setMinimumHeight(36)
        new_btn.setDefault(True)
        new_btn.setStyleSheet(
            "QPushButton { background-color: #2a7ae2; color: white; "
            "border-radius: 4px; padding: 4px 12px; }"
            "QPushButton:hover { background-color: #1a5bb5; }"
        )
        new_btn.clicked.connect(self._create_new)

        action_layout.addWidget(browse_btn)
        action_layout.addWidget(new_btn)
        layout.addLayout(action_layout)

        layout.addSpacing(8)

        # Выход
        quit_layout = QHBoxLayout()
        quit_layout.addStretch()
        quit_btn = QPushButton("Выход")
        quit_btn.clicked.connect(self.reject)
        quit_layout.addWidget(quit_btn)
        layout.addLayout(quit_layout)

    # ------------------------------------------------------------------ #
    # Логика
    # ------------------------------------------------------------------ #

    def _load_recent(self):
        """Загружает список недавних БД из конфига."""
        self.recent_list.clear()
        recent = self._get_recent_list()
        for path in recent:
            p = Path(path)
            item = QListWidgetItem()
            exists = p.exists()
            if exists:
                item.setText(f"  {p.name}  —  {p.parent}")
                item.setData(Qt.ItemDataRole.UserRole, path)
            else:
                item.setText(f"  ⚠ {p.name}  [не найден]  —  {p.parent}")
                item.setData(Qt.ItemDataRole.UserRole, path)
                item.setForeground(Qt.GlobalColor.gray)
            self.recent_list.addItem(item)

        # Выбираем первый существующий
        for i in range(self.recent_list.count()):
            item = self.recent_list.item(i)
            path = item.data(Qt.ItemDataRole.UserRole)
            if path and Path(path).exists():
                self.recent_list.setCurrentRow(i)
                break

    def _get_recent_list(self) -> list:
        try:
            raw = self.config.get(self.RECENT_KEY, [])
            return raw if isinstance(raw, list) else []
        except Exception:
            return []

    def _save_recent_list(self, lst: list):
        try:
            if "preferences" not in self.config.config:
                self.config.config["preferences"] = {}
            self.config.config["preferences"][self.RECENT_KEY] = lst
            self.config.save()
        except Exception:
            pass

    def add_to_recent(self, path: str):
        """Добавляет путь в начало списка недавних (без дублей, макс 10)."""
        recent = self._get_recent_list()
        if path in recent:
            recent.remove(path)
        recent.insert(0, path)
        self._save_recent_list(recent[:10])

    def _on_recent_double_click(self, item: QListWidgetItem):
        self._open_selected()

    def _open_selected(self):
        item = self.recent_list.currentItem()
        if not item:
            QMessageBox.information(self, "Подсказка", "Выберите хранилище из списка.")
            return
        path = item.data(Qt.ItemDataRole.UserRole)
        if not path or not Path(path).exists():
            QMessageBox.warning(
                self, "Файл не найден",
                f"Файл не найден:\n{path}\n\nУберите его из списка или выберите другой."
            )
            return
        self.selected_db_path = path
        self.accept()

    def _remove_selected(self):
        item = self.recent_list.currentItem()
        if not item:
            return
        path = item.data(Qt.ItemDataRole.UserRole)
        recent = self._get_recent_list()
        if path in recent:
            recent.remove(path)
            self._save_recent_list(recent)
        self._load_recent()

    def _browse_existing(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Открыть хранилище", "",
            "Database Files (*.db);;All Files (*)"
        )
        if not path:
            return
        if not Path(path).exists():
            QMessageBox.warning(self, "Ошибка", "Выбранный файл не существует.")
            return
        self.add_to_recent(path)
        self.selected_db_path = path
        self.accept()

    def _create_new(self):
        """Запускает SetupWizard и при успехе возвращает путь к новой БД."""
        from gui.setup_wizard import SetupWizard
        wizard = SetupWizard()
        if wizard.exec() != QDialog.DialogCode.Accepted:
            return
        db_path = wizard.db_path
        if not db_path:
            return
        self.add_to_recent(db_path)
        self.selected_db_path = db_path
        # Передаём пароль чтобы app.py мог сразу инициализировать KeyManager
        self._new_vault_password = wizard.password_entry.text()
        self.accept()

    def get_new_vault_password(self) -> str | None:
        """Возвращает пароль если только что создано новое хранилище."""
        return getattr(self, "_new_vault_password", None)