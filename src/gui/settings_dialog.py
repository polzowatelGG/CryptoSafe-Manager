from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QTabWidget, QWidget, QFormLayout,
    QSpinBox, QCheckBox, QComboBox, QPushButton, QHBoxLayout,
    QLabel, QMessageBox, QGroupBox,
)
from database.models import Settings
from core.crypto.placeholder import AES256Placeholder


# Профили безопасности (Sprint 7 — CFG-1, CFG-2, CFG-3)
SECURITY_PROFILES = {
    "Стандартный": {
        "clipboard_timeout":   30,
        "inactivity_timeout":  300,   # 5 минут
        "description": "Стандартная защита: буфер 30с, блокировка 5 мин",
    },
    "Усиленный": {
        "clipboard_timeout":   15,
        "inactivity_timeout":  120,   # 2 минуты
        "description": "Усиленная защита: буфер 15с, блокировка 2 мин",
    },
    "Параноидальный": {
        "clipboard_timeout":   5,
        "inactivity_timeout":  60,    # 1 минута
        "description": "Максимальная защита: буфер 5с, блокировка 1 мин",
    },
}

# Минимальные значения (CFG-3 валидация)
MIN_CLIPBOARD_TIMEOUT = 5      # секунды
MIN_INACTIVITY_TIMEOUT = 60    # секунды (1 минута) для обычных профилей


class SettingsDialog(QDialog):
    def __init__(self, config=None, pool=None, activity_monitor=None, clipboard_service=None):
        super().__init__()
        self.config = config
        self.pool = pool
        self.activity_monitor = activity_monitor
        self.clipboard_service = clipboard_service

        self.setWindowTitle("Настройки")
        self.resize(520, 480)

        self._settings_model = None
        if self.pool:
            try:
                self._settings_model = Settings(self.pool, AES256Placeholder)
            except Exception:
                self._settings_model = None

        self._init_ui()
        self._load_settings()

    # ========================
    # UI
    # ========================
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

    def _create_security_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Sprint 7: Профили безопасности (CFG-1)
        profile_group = QGroupBox("Профиль безопасности")
        profile_layout = QVBoxLayout(profile_group)

        self.profile_combo = QComboBox()
        self.profile_combo.addItems(list(SECURITY_PROFILES.keys()))
        self.profile_combo.addItem("Пользовательский")
        self.profile_combo.currentTextChanged.connect(self._apply_profile)
        profile_layout.addWidget(self.profile_combo)

        self.profile_desc_label = QLabel("")
        self.profile_desc_label.setStyleSheet("color: #555; font-size: 11px;")
        self.profile_desc_label.setWordWrap(True)
        profile_layout.addWidget(self.profile_desc_label)

        layout.addWidget(profile_group)

        # Таймауты
        timeouts_group = QGroupBox("Таймауты")
        form = QFormLayout(timeouts_group)

        self.clipboard_timeout = QSpinBox()
        self.clipboard_timeout.setRange(5, 300)
        self.clipboard_timeout.setValue(30)
        self.clipboard_timeout.setSuffix(" сек")
        self.clipboard_timeout.valueChanged.connect(self._on_value_changed)
        form.addRow("Таймаут буфера обмена:", self.clipboard_timeout)

        self.inactivity_timeout = QSpinBox()
        self.inactivity_timeout.setRange(60, 28800)   # 1 мин – 8 часов
        self.inactivity_timeout.setValue(300)
        self.inactivity_timeout.setSuffix(" сек")
        self.inactivity_timeout.setToolTip("Время бездействия до авто-блокировки")
        self.inactivity_timeout.valueChanged.connect(self._on_value_changed)
        form.addRow("Авто-блокировка (бездействие):", self.inactivity_timeout)

        layout.addWidget(timeouts_group)

        # Прочие настройки безопасности
        misc_group = QGroupBox("Дополнительно")
        misc_layout = QVBoxLayout(misc_group)

        self.auto_lock_checkbox = QCheckBox("Включить авто-блокировку")
        self.auto_lock_checkbox.setChecked(True)
        misc_layout.addWidget(self.auto_lock_checkbox)

        layout.addWidget(misc_group)
        layout.addStretch()

        return tab

    def _create_appearance_tab(self) -> QWidget:
        tab = QWidget()
        layout = QFormLayout()

        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Светлая", "Тёмная", "Системная"])

        self.language_combo = QComboBox()
        self.language_combo.addItems(["Русский", "English"])

        # Sprint 7: опция сворачивания в трей (TRAY-4)
        self.minimize_to_tray_check = QCheckBox("Сворачивать в системный трей при закрытии")
        self.minimize_to_tray_check.setChecked(True)

        self.start_minimized_check = QCheckBox("Запускать свёрнутым в трей")
        self.start_minimized_check.setChecked(False)

        layout.addRow("Тема:", self.theme_combo)
        layout.addRow("Язык:", self.language_combo)
        layout.addRow("", self.minimize_to_tray_check)
        layout.addRow("", self.start_minimized_check)

        tab.setLayout(layout)
        return tab

    def _create_advanced_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout()

        self.backup_btn = QPushButton("Создать резервную копию")
        self.export_btn = QPushButton("Экспорт данных")
        self.backup_btn.clicked.connect(self._on_backup)
        self.export_btn.clicked.connect(self._on_export)

        layout.addWidget(QLabel("Резервное копирование и экспорт:"))
        layout.addWidget(self.backup_btn)
        layout.addWidget(self.export_btn)
        layout.addStretch()

        tab.setLayout(layout)
        return tab

    # ========================
    # Профили безопасности (CFG-2)
    # ========================
    def _apply_profile(self, profile_name: str):
        profile = SECURITY_PROFILES.get(profile_name)
        if not profile:
            self.profile_desc_label.setText("Настройте параметры вручную")
            return

        # Устанавливаем значения без рекурсии (блокируем сигналы)
        self.clipboard_timeout.blockSignals(True)
        self.inactivity_timeout.blockSignals(True)

        self.clipboard_timeout.setValue(profile["clipboard_timeout"])
        self.inactivity_timeout.setValue(profile["inactivity_timeout"])

        self.clipboard_timeout.blockSignals(False)
        self.inactivity_timeout.blockSignals(False)

        self.profile_desc_label.setText(profile.get("description", ""))

    def _on_value_changed(self):
        """При ручном изменении значений — переключаемся на 'Пользовательский'."""
        idx = self.profile_combo.findText("Пользовательский")
        if idx >= 0:
            self.profile_combo.blockSignals(True)
            self.profile_combo.setCurrentIndex(idx)
            self.profile_combo.blockSignals(False)
        self.profile_desc_label.setText("")

    # ========================
    # Загрузка и сохранение
    # ========================
    def _load_settings(self):
        if self._settings_model:
            try:
                timeout = self._settings_model.get('clipboard_timeout')
                if timeout:
                    self.clipboard_timeout.setValue(int(timeout))
                inactivity = self._settings_model.get('inactivity_timeout')
                if inactivity:
                    self.inactivity_timeout.setValue(int(inactivity))
                return
            except Exception:
                pass
        self._load_from_config()

    def _load_from_config(self):
        if not self.config:
            return
        timeout = self.config.get_preference('clipboard_timeout') or 30
        self.clipboard_timeout.setValue(int(timeout))
        inactivity = self.config.get_preference('inactivity_timeout') or 300
        self.inactivity_timeout.setValue(int(inactivity))
        auto_lock = self.config.get_preference('auto_lock')
        if auto_lock is not None:
            self.auto_lock_checkbox.setChecked(bool(auto_lock))
        minimize_to_tray = self.config.get_preference('minimize_to_tray')
        if minimize_to_tray is not None:
            self.minimize_to_tray_check.setChecked(bool(minimize_to_tray))
        start_minimized = self.config.get_preference('start_minimized')
        if start_minimized is not None:
            self.start_minimized_check.setChecked(bool(start_minimized))

    def _save_and_accept(self):
        clip_timeout = self.clipboard_timeout.value()
        inact_timeout = self.inactivity_timeout.value()
        auto_lock = self.auto_lock_checkbox.isChecked()
        minimize_to_tray = self.minimize_to_tray_check.isChecked()
        start_minimized = self.start_minimized_check.isChecked()

        # CFG-3: Валидация
        if clip_timeout < MIN_CLIPBOARD_TIMEOUT:
            QMessageBox.warning(
                self, "Небезопасное значение",
                f"Таймаут буфера обмена не может быть меньше {MIN_CLIPBOARD_TIMEOUT} секунд.")
            return

        if auto_lock and inact_timeout < MIN_INACTIVITY_TIMEOUT:
            current_profile = self.profile_combo.currentText()
            if current_profile != "Параноидальный":
                QMessageBox.warning(
                    self, "Небезопасное значение",
                    f"Таймаут авто-блокировки не может быть меньше {MIN_INACTIVITY_TIMEOUT} секунд.")
                return

        # Сохраняем в модель БД
        if self._settings_model:
            try:
                self._settings_model.set('clipboard_timeout', str(clip_timeout), encrypted=False)
                self._settings_model.set('inactivity_timeout', str(inact_timeout), encrypted=False)
                self._settings_model.set('auto_lock', str(auto_lock), encrypted=False)
            except Exception as e:
                QMessageBox.warning(
                    self, "Предупреждение",
                    f"Не удалось сохранить в БД:\n{e}\nНастройки сохранены в файл.")

        # Сохраняем в ConfigManager
        if self.config:
            self.config.set_preference('clipboard_timeout', clip_timeout)
            self.config.set_preference('inactivity_timeout', inact_timeout)
            self.config.set_preference('auto_lock', auto_lock)
            self.config.set_preference('minimize_to_tray', minimize_to_tray)
            self.config.set_preference('start_minimized', start_minimized)
            try:
                self.config.save()
            except Exception:
                pass

        # Sprint 7: применяем изменения к живым компонентам (CFG-2)
        if self.activity_monitor and auto_lock:
            self.activity_monitor.update_config({'inactivity_timeout': inact_timeout})

        if self.clipboard_service:
            # clipboard_service читает таймаут из config при каждом копировании,
            # поэтому достаточно уже сохранить в config выше.
            pass

        self.accept()

    # ========================
    # Резервная копия / Экспорт
    # ========================
    def _on_backup(self):
        if not self.pool:
            QMessageBox.warning(self, "Ошибка", "База данных недоступна")
            return
        from PyQt6.QtWidgets import QFileDialog
        from pathlib import Path
        import shutil

        db_path = getattr(self.pool, 'db_path', None)
        if not db_path:
            QMessageBox.warning(self, "Ошибка", "Не удалось определить путь к базе данных")
            return

        default_name = f"backup_{Path(db_path).stem}.db"
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Сохранить резервную копию", default_name,
            "Database Files (*.db);;All Files (*)")
        if not save_path:
            return
        try:
            shutil.copy2(db_path, save_path)
            QMessageBox.information(self, "Готово", f"Резервная копия сохранена:\n{save_path}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось создать резервную копию:\n{e}")

    def _on_export(self):
        if not self.pool:
            QMessageBox.warning(self, "Ошибка", "База данных недоступна")
            return
        from PyQt6.QtWidgets import QFileDialog
        import json, datetime

        save_path, _ = QFileDialog.getSaveFileName(
            self, "Экспорт данных", "export.json",
            "JSON Files (*.json);;CSV Files (*.csv);;All Files (*)")
        if not save_path:
            return
        try:
            with self.pool.connection() as conn:
                rows = conn.execute(
                    "SELECT id, title, username, url, notes, created_at, updated_at "
                    "FROM vault_entries ORDER BY title").fetchall()
            entries = [dict(row) for row in rows]

            if save_path.endswith('.csv'):
                import csv
                with open(save_path, 'w', newline='', encoding='utf-8') as f:
                    if entries:
                        writer = csv.DictWriter(f, fieldnames=entries[0].keys())
                        writer.writeheader()
                        writer.writerows(entries)
            else:
                export_data = {
                    "exported_at": datetime.datetime.utcnow().isoformat(),
                    "entries_count": len(entries),
                    "entries": entries,
                }
                with open(save_path, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, ensure_ascii=False, indent=2, default=str)

            msg = (f"Экспортировано записей: {len(entries)}\nФайл: {save_path}\n\n"
                   "⚠️ Внимание: файл содержит данные без шифрования.")
            QMessageBox.information(self, "Готово", msg)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось экспортировать данные:\n{e}")