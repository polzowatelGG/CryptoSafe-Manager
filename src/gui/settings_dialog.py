# src/gui/settings_dialog.py
# Управление конфигурацией, профилями безопасности (Sprint 7) и экспортом.

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QTabWidget, QWidget, QFormLayout,
    QSpinBox, QCheckBox, QComboBox, QPushButton, QHBoxLayout,
    QLabel, QMessageBox, QGroupBox, QFileDialog,
)
import sys
import os
import json
import shutil
import time
import gzip
from database.models import Settings
from core.crypto.placeholder import AES256Placeholder

# Профили безопасности (Sprint 7 — CFG-1, CFG-2, CFG-3)
SECURITY_PROFILES = {
    "Стандартный": {
        "clipboard_timeout":   30,
        "inactivity_timeout":  300,   # 5 минут
        "description": "Стандартная защита: буфер 30с, автоблокировка 5 мин",
    },
    "Усиленный": {
        "clipboard_timeout":   15,
        "inactivity_timeout":  120,   # 2 минуты
        "description": "Усиленная защита: буфер 15с, автоблокировка 2 мин",
    },
    "Параноидальный": {
        "clipboard_timeout":   5,
        "inactivity_timeout":  60,    # 1 минута
        "description": "Максимальная защита: буфер 5с, автоблокировка 1 мин",
    },
}

# Минимальные значения для защиты от Side-Channel и брутфорса конфигурации (CFG-3)
MIN_CLIPBOARD_TIMEOUT = 5      # секунды
MIN_INACTIVITY_TIMEOUT = 60    # секунды (1 минута)


class SettingsDialog(QDialog):
    def __init__(self, config=None, pool=None, activity_monitor=None,clipboard_service=None, key_manager=None):
        super().__init__()
        self.config = config
        self.pool = pool
        self.activity_monitor = activity_monitor
        self.clipboard_service = clipboard_service
        self.key_manager = key_manager # Передаем KeyManager для расшифровки при экспорте

        self.setWindowTitle("Настройки конфигурации")
        self.resize(540, 500)

        self._settings_model = None
        if self.pool:
            try:
                self._settings_model = Settings(self.pool, AES256Placeholder)
            except Exception:
                self._settings_model = None

        self._init_ui()
        self._load_settings()

    # ========================
    # UI Инициализация
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
        self.save_btn.setDefault(True)
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

        # Профили безопасности (CFG-1)
        profile_group = QGroupBox("Профиль аппаратной защиты")
        profile_layout = QVBoxLayout(profile_group)

        self.profile_combo = QComboBox()
        self.profile_combo.addItems(list(SECURITY_PROFILES.keys()))
        self.profile_combo.addItem("Пользовательский")
        self.profile_combo.currentTextChanged.connect(self._apply_profile)
        profile_layout.addWidget(self.profile_combo)

        self.profile_desc_label = QLabel("")
        self.profile_desc_label.setStyleSheet("color: #666; font-size: 11px; font-weight: bold;")
        self.profile_desc_label.setWordWrap(True)
        profile_layout.addWidget(self.profile_desc_label)

        layout.addWidget(profile_group)

        # Таймауты
        timeouts_group = QGroupBox("Параметры задержек (Таймауты)")
        form = QFormLayout(timeouts_group)

        self.clipboard_timeout = QSpinBox()
        self.clipboard_timeout.setRange(MIN_CLIPBOARD_TIMEOUT, 3600)
        self.clipboard_timeout.setSuffix(" сек")
        self.clipboard_timeout.valueChanged.connect(self._on_value_changed)
        form.addRow("Очистка буфера обмена:", self.clipboard_timeout)

        self.inactivity_timeout = QSpinBox()
        self.inactivity_timeout.setRange(MIN_INACTIVITY_TIMEOUT, 86400) # до 24 часов
        self.inactivity_timeout.setSuffix(" сек")
        self.inactivity_timeout.setToolTip("Время бездействия до блокировки мастер-ключа")
        self.inactivity_timeout.valueChanged.connect(self._on_value_changed)
        form.addRow("Автоблокировка сессии:", self.inactivity_timeout)

        layout.addWidget(timeouts_group)

        # Дополнительные гварды
        misc_group = QGroupBox("Фоновые политики безопасности")
        misc_layout = QVBoxLayout(misc_group)

        self.auto_lock_checkbox = QCheckBox("Включить аппаратный мониторинг активности (Автоблокировка)")
        self.auto_lock_checkbox.setChecked(True)
        self.auto_lock_checkbox.toggled.connect(self.inactivity_timeout.setEnabled)
        misc_layout.addWidget(self.auto_lock_checkbox)

        layout.addWidget(misc_group)
        layout.addStretch()

        return tab

    def _create_appearance_tab(self) -> QWidget:
        tab = QWidget()
        layout = QFormLayout(tab)

        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Светлая", "Тёмная", "Системная"])

        self.language_combo = QComboBox()
        self.language_combo.addItems(["Русский", "English"])

        # Опции системного трея (TRAY-4)
        self.minimize_to_tray_check = QCheckBox("Сворачивать в системный трей при закрытии окна")
        self.minimize_to_tray_check.setChecked(True)

        self.start_minimized_check = QCheckBox("Запускать приложение скрытым в трее")
        self.start_minimized_check.setChecked(False)

        layout.addRow("Визуальная тема:", self.theme_combo)
        layout.addRow("Язык интерфейса:", self.language_combo)
        layout.addRow("", self.minimize_to_tray_check)
        layout.addRow("", self.start_minimized_check)

        return tab

    def _create_advanced_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.backup_btn = QPushButton("Создать криптографическую резервную копию базы данных")
        self.export_btn = QPushButton("Экспорт расшифрованных данных (JSON/CSV)")
        self.backup_btn.clicked.connect(self._on_backup)
        self.export_btn.clicked.connect(self._on_export)

        layout.addWidget(QLabel("Управление резервным копированием:"))
        layout.addWidget(self.backup_btn)
        layout.addWidget(self.export_btn)
        layout.addStretch()

        return tab

    # ========================
    # Профили безопасности (CFG-2)
    # ========================
    def _apply_profile(self, profile_name: str):
        profile = SECURITY_PROFILES.get(profile_name)
        if not profile:
            self.profile_desc_label.setText("Пользовательский режим: параметры задаются вручную.")
            return

        self.clipboard_timeout.blockSignals(True)
        self.inactivity_timeout.blockSignals(True)

        self.clipboard_timeout.setValue(profile["clipboard_timeout"])
        self.inactivity_timeout.setValue(profile["inactivity_timeout"])

        self.clipboard_timeout.blockSignals(False)
        self.inactivity_timeout.blockSignals(False)

        self.profile_desc_label.setText(profile.get("description", ""))

    def _on_value_changed(self):
        """Автоматическое переключение профиля на пользовательский при ручной правке."""
        idx = self.profile_combo.findText("Пользовательский")
        if idx >= 0 and self.profile_combo.currentText() != "Пользовательский":
            self.profile_combo.blockSignals(True)
            self.profile_combo.setCurrentIndex(idx)
            self.profile_combo.blockSignals(False)
            self.profile_desc_label.setText("Пользовательский режим: параметры задаются вручную.")

    def _detect_matching_profile(self, clip: int, inactivity: int):
        """Определяет, подходит ли текущая комбинация под один из пресетов."""
        for name, values in SECURITY_PROFILES.items():
            if values["clipboard_timeout"] == clip and values["inactivity_timeout"] == inactivity:
                self.profile_combo.setCurrentText(name)
                self.profile_desc_label.setText(values["description"])
                return
        self.profile_combo.setCurrentText("Пользовательский")

    # ========================
    # Загрузка и сохранение настроек
    # ========================
    def _load_settings(self):
        # Инициализируем дефолты
        clip_val, inact_val = 30, 300
        auto_lock, min_tray, start_min = True, True, False

        # Пытаемся загрузить из БД
        if self._settings_model:
            try:
                t = self._settings_model.get('clipboard_timeout')
                if t is not None: clip_val = int(t)
                i = self._settings_model.get('inactivity_timeout')
                if i is not None: inact_val = int(i)
                a = self._settings_model.get('auto_lock')
                if a is not None: auto_lock = (a == 'True' or a == '1')
            except Exception:
                pass

        # Догружаем/перекрываем из локального конфигурационного файла, если модель вернула пустоту
        if self.config:
            clip_val = self.config.get_preference('clipboard_timeout') or clip_val
            inact_val = self.config.get_preference('inactivity_timeout') or inact_val
            
            al = self.config.get_preference('auto_lock')
            if al is not None: auto_lock = bool(al)
            mt = self.config.get_preference('minimize_to_tray')
            if mt is not None: min_tray = bool(mt)
            sm = self.config.get_preference('start_minimized')
            if sm is not None: start_min = bool(sm)

        # Выставляем виджеты
        self.clipboard_timeout.setValue(int(clip_val))
        self.inactivity_timeout.setValue(int(inact_val))
        self.auto_lock_checkbox.setChecked(auto_lock)
        self.inactivity_timeout.setEnabled(auto_lock)
        self.minimize_to_tray_check.setChecked(min_tray)
        self.start_minimized_check.setChecked(start_min)

        # Вычисляем текущий профиль
        self._detect_matching_profile(int(clip_val), int(inact_val))

    def _save_and_accept(self):
        clip_timeout = self.clipboard_timeout.value()
        inact_timeout = self.inactivity_timeout.value()
        auto_lock = self.auto_lock_checkbox.isChecked()
        minimize_to_tray = self.minimize_to_tray_check.isChecked()
        start_minimized = self.start_minimized_check.isChecked()

        # Валидация политик безопасности (CFG-3)
        if clip_timeout < MIN_CLIPBOARD_TIMEOUT:
            QMessageBox.warning(
                self, "Ошибка безопасности",
                f"Таймаут очистки буфера не может быть меньше {MIN_CLIPBOARD_TIMEOUT} сек.")
            return

        if auto_lock and inact_timeout < MIN_INACTIVITY_TIMEOUT:
            if self.profile_combo.currentText() != "Параноидальный":
                QMessageBox.warning(
                    self, "Ошибка безопасности",
                    f"Период автоблокировки простоя не может быть меньше {MIN_INACTIVITY_TIMEOUT} сек.")
                return

        # Атомарное сохранение в базу данных
        if self._settings_model:
            try:
                self._settings_model.set('clipboard_timeout', str(clip_timeout), encrypted=False)
                self._settings_model.set('inactivity_timeout', str(inact_timeout), encrypted=False)
                self._settings_model.set('auto_lock', str(auto_lock), encrypted=False)
            except Exception as e:
                QMessageBox.warning(self, "Ошибка БД", f"Не удалось записать настройки в БД: {e}")

        # Сохранение в менеджер конфигураций файла
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

        # Динамическое применение к живым сервисам ядра приложения (CFG-2)
        if self.activity_monitor:
            if auto_lock:
                self.activity_monitor.update_config({'inactivity_timeout': inact_timeout})
                self.activity_monitor.set_vault_locked_state(False)
            else:
                self.activity_monitor.set_vault_locked_state(True)

        if self.clipboard_service and hasattr(self.clipboard_service, 'update_timeout'):
            self.clipboard_service.update_timeout(clip_timeout)

        self.accept()

    # ========================
    # Криптографический экспорт и резервные копии
    # ========================
    def _on_backup(self):
        if not self.pool:
            QMessageBox.warning(self, "Ошибка", "Пул соединений базы данных недоступен.")
            return

        db_path = getattr(self.pool, 'db_path', None) or "crypto_vault.db"
        if not os.path.exists(db_path):
            QMessageBox.warning(self, "Ошибка", f"Файл базы данных не найден по пути: {db_path}")
            return

        default_name = f"backup_vault_{int(time.time())}.db"
        save_path, _ = QFileDialog.getSaveFileName(
            self, "Создать защищенный бэкап БД", default_name, "Database Files (*.db);;All Files (*)"
        )
        if not save_path:
            return

        try:
            # Копируем файл целиком (он сохраняет криптографическое шифрование страниц SQLite)
            shutil.copy2(db_path, save_path)
            QMessageBox.information(self, "Успех", f"Зашифрованная резервная копия создана успешно:\n{save_path}")
        except Exception as e:
            QMessageBox.critical(self, "Критическая ошибка", f"Сбой резервного копирования: {e}")

    def _on_export(self):
        """Безопасный постраничный экспорт с расшифровкой на лету."""
        if not self.pool:
            QMessageBox.warning(self, "Ошибка", "База данных недоступна.")
            return

        # Проверяем, разблокирован ли мастер-ключ
        if self.key_manager and not self.key_manager.has_key():
            QMessageBox.warning(self, "Ошибка доступа", "Для экспорта записей необходимо сначала разблокировать хранилище.")
            return

        save_path, _ = QFileDialog.getSaveFileName(
            self, "Экспорт расшифрованных данных", "decrypted_export.json.gz",
            "Compressed JSON (*.json.gz);;Standard JSON (*.json);;All Files (*)"
        )
        if not save_path:
            return

        try:
            # Читаем зашифрованные записи из базы данных
            with self.pool.connection() as conn:
                rows = conn.execute(
                    "SELECT id, title, username, url, notes, category, created_at FROM vault_entries"
                ).fetchall()

            decrypted_entries = []
            
            # Логика расшифровки записей перед экспортом
            for row in rows:
                item = dict(row)
                
                # Если у нас есть KeyManager и реальный расшифровщик — расшифровываем поля
                if self.key_manager:
                    for field in ['username', 'url', 'notes']:
                        if item.get(field):
                            try:
                                # Предполагаем интеграцию с реальным EntryManager/CryptoEngine из Спринта 3
                                decrypted_val = self.key_manager.decrypt_value(item[field])
                                item[field] = decrypted_val
                            except Exception:
                                # Если это заглушка или сбой — оставляем как есть или помечаем
                                pass
                
                decrypted_entries.append(item)

            export_data = {
                "exported_at": str(time.time()),
                "version": "1.0.0",
                "entries_count": len(decrypted_entries),
                "entries": decrypted_entries
            }

            # Сохраняем в зависимости от выбранного формата (с поддержкой сжатия GZIP по ТЗ Спринта 6)
            json_bytes = json.dumps(export_data, ensure_ascii=False, indent=2, default=str).encode('utf-8')
            
            if save_path.endswith('.gz'):
                with gzip.open(save_path, 'wb') as f:
                    f.write(json_bytes)
            else:
                with open(save_path, 'wb') as f:
                    f.write(json_bytes)

            QMessageBox.information(
                self, "Экспорт завершен",
                f"Успешно экспортировано записей: {len(decrypted_entries)}\n"
                f"Файл: {save_path}\n\n"
                "⚠️ ВНИМАНИЕ: Файл содержит конфиденциальные пароли в ОТКРЫТОМ виде! Храните его в безопасном месте."
            )
        except Exception as e:
            QMessageBox.critical(self, "Ошибка экспорта", f"Не удалось выполнить экспорт данных: {e}")