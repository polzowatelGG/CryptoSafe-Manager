from PyQt6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QTabWidget,
    QWidget,
    QFormLayout,
    QSpinBox,
    QCheckBox,
    QComboBox,
    QPushButton,
    QHBoxLayout,
    QLabel,
)


class SettingsDialog(QDialog):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Настройки")
        self.resize(500, 400)

        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout()

        self.tabs = QTabWidget()
        self.tabs.addTab(self._create_security_tab(), "Безопасность")
        self.tabs.addTab(self._create_appearance_tab(), "Внешний вид")
        self.tabs.addTab(self._create_advanced_tab(), "Дополнительно")

        layout.addWidget(self.tabs)

        # Кнопки
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        self.save_btn = QPushButton("Сохранить")
        self.save_btn.clicked.connect(self.accept)

        self.cancel_btn = QPushButton("Отмена")
        self.cancel_btn.clicked.connect(self.reject)

        btn_layout.addWidget(self.save_btn)
        btn_layout.addWidget(self.cancel_btn)

        layout.addLayout(btn_layout)

        self.setLayout(layout)

    # ------------------------
    # Вкладка Безопасность
    # ------------------------
    def _create_security_tab(self):
        tab = QWidget()
        layout = QFormLayout()

        self.clipboard_timeout = QSpinBox()
        self.clipboard_timeout.setRange(5, 300)
        self.clipboard_timeout.setValue(30)
        self.clipboard_timeout.setSuffix(" сек")

        self.auto_lock_checkbox = QCheckBox("Включить авто-блокировку")

        layout.addRow("Таймаут буфера обмена:", self.clipboard_timeout)
        layout.addRow("", self.auto_lock_checkbox)

        tab.setLayout(layout)
        return tab

    # ------------------------
    # Вкладка Внешний вид
    # ------------------------
    def _create_appearance_tab(self):
        tab = QWidget()
        layout = QFormLayout()

        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Светлая", "Тёмная", "Системная"])

        self.language_combo = QComboBox()
        self.language_combo.addItems(["Русский", "English"])

        layout.addRow("Тема:", self.theme_combo)
        layout.addRow("Язык:", self.language_combo)

        tab.setLayout(layout)
        return tab

    # ------------------------
    # Вкладка Дополнительно
    # ------------------------
    def _create_advanced_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.backup_btn = QPushButton("Создать резервную копию")
        self.export_btn = QPushButton("Экспорт данных")

        layout.addWidget(QLabel("Резервное копирование и экспорт:"))
        layout.addWidget(self.backup_btn)
        layout.addWidget(self.export_btn)
        layout.addStretch()

        tab.setLayout(layout)
        return tab

