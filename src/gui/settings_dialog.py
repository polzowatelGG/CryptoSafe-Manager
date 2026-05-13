from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QTabWidget, QWidget, QFormLayout,
    QSpinBox, QCheckBox, QComboBox, QPushButton, QHBoxLayout, QLabel,QMessageBox,
)
from database.models import Settings
from core.crypto.placeholder import AES256Placeholder


class SettingsDialog(QDialog):
    def __init__(self, config=None, pool=None):
        super().__init__()
        self.config = config  
        self.pool = pool
        self.setWindowTitle("Настройки")
        self.resize(500, 400)
        self.profile_combo = QComboBox()
        self.profile_combo.addItems(["Стандарт (30с)", "Безопасный (15с)", "Публичный ПК (5с)"])
        self.profile_combo.currentIndexChanged.connect(self._apply_profile)
        self._init_ui()
        self._load_settings()  # загружаем текущие значения из config
        self._setting_model = None  # модель для связи с базой данных, если нужно будет сохранять настройки там
        if self.pool:
            self._setting_model = Settings(self.pool, AES256Placeholder)  # модель для сохранения настроек в базе данных, если pool доступен

    def _apply_profile(self, index):
        timeouts = [30, 15, 5]
        self.clipboard_timeout.setValue(timeouts[index])

    def _init_ui(self):
        layout = QVBoxLayout()
        
        self.tabs = QTabWidget()
        self.tabs.addTab(self._create_security_tab(), "Безопасность")
        self.tabs.addTab(self._create_appearance_tab(), "Внешний вид")
        self.tabs.addTab(self._create_advanced_tab(), "Дополнительно")

        layout.addWidget(self.tabs)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        self.save_btn = QPushButton("Сохранить")
        self.save_btn.clicked.connect(self._save_and_accept) 

        self.cancel_btn = QPushButton("Отмена")
        self.cancel_btn.clicked.connect(self.reject)

        btn_layout.addWidget(self.save_btn)
        btn_layout.addWidget(self.cancel_btn)

        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def _create_security_tab(self):
        tab = QWidget()
        layout = QFormLayout()
        layout.addRow("Профиль:", self.profile_combo)

        self.clipboard_timeout = QSpinBox()
        self.clipboard_timeout.setRange(5, 300)
        self.clipboard_timeout.setValue(30)
        self.clipboard_timeout.setSuffix(" сек")

        self.auto_lock_checkbox = QCheckBox("Включить авто-блокировку")

        layout.addRow("Таймаут буфера обмена:", self.clipboard_timeout)
        layout.addRow("", self.auto_lock_checkbox)

        tab.setLayout(layout)
        return tab

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

    def _load_settings(self):
        # пытаемся загрузить из зашифрованной таблицы settings 
        if self._settings_model:
            try:
                timeout = self._settings_model.get('clipboard_timeout')
                if timeout:
                    self.clipboard_timeout.setValue(int(timeout))
                else:
                    # fallback на config если в БД ещё нет значения
                    self._load_from_config()
                return
            except Exception:
                pass

        self._load_from_config()
        
    def _load_from_config(self):
    # резервная загрузка из ConfigManager
        if not self.config:
            return
        timeout = self.config.get_preference('clipboard_timeout') or 30
        self.clipboard_timeout.setValue(int(timeout))
        auto_lock = self.config.get_preference('auto_lock')
        if auto_lock is not None:
            self.auto_lock_checkbox.setChecked(bool(auto_lock))
        
    def _save_and_accept(self):
        timeout = self.clipboard_timeout.value()
        auto_lock = self.auto_lock_checkbox.isChecked()

        # сохраняем в зашифрованную таблицу settings 
        if self._settings_model:
            try:
                # clipboard_timeout шифруем — это чувствительная настройка
                self._settings_model.set(
                    'clipboard_timeout', str(timeout), encrypted=True
                )
                # auto_lock не шифруем — это не секрет
                self._settings_model.set(
                    'auto_lock', str(auto_lock), encrypted=False
                )
            except Exception as e:
                QMessageBox.warning(
                    self, "Предупреждение",
                    f"Не удалось сохранить в БД:\n{e}\nНастройки сохранены в файл."
                )

        # всегда дублируем в ConfigManager для быстрого доступа при старте
        if self.config:
            self.config.set_preference('clipboard_timeout', timeout)
            self.config.set_preference('auto_lock', auto_lock)
            try:
                self.config.save()
            except Exception:
                pass

        self.accept()