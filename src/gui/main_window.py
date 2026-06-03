# src/gui/main_window.py
import platform
import time
import re
import functools

from PyQt6.QtWidgets import (
    QFileDialog, QMainWindow, QStatusBar, QMessageBox,
    QDialog, QVBoxLayout, QFormLayout, QLineEdit, QTextEdit,
    QDialogButtonBox, QApplication, QPushButton, QHBoxLayout,
    QLabel, QWidget, QSystemTrayIcon, QMenu, QInputDialog, QToolBar,
)
from PyQt6.QtGui import (
    QAction, QFont, QIcon, QPixmap, QColor, QShortcut, QKeySequence,
)
from PyQt6.QtCore import QEvent, Qt, QTimer, QThread, pyqtSignal as Signal

from core.crypto.key_derivation import PasswordValidator
from core.vault.password_generator import PasswordGenerator
from gui.widgets.audit_log_viewer import AuditLogViewer
from gui.widgets.secure_table import SecureTable
from gui.settings_dialog import SettingsDialog
from core import events

try:
    from core.security.side_channel_protection import secure_wipe_str, secure_wipe_bytes
except ImportError:
    def secure_wipe_str(s): pass
    def secure_wipe_bytes(b): pass


# ─────────────────────────────────────────────────────────────────────────────
# Вспомогательные компоненты
# ─────────────────────────────────────────────────────────────────────────────

class PasswordStrengthIndicator(QLabel):
    """Отображает текстовый индикатор сложности пароля."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(20)
        self.update_strength("")

    def update_strength(self, password: str):
        """Вычисляет сложность и обновляет текст/цвет виджета."""
        if not password:
            self.setText("⚪ Не введён")
            self.setStyleSheet("color: gray;")
            return

        score = 0
        if len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        if any(c.islower() for c in password) and any(c.isupper() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(c in "!@#$%^&*()_+-=[]{};:,.<>?/|" for c in password):
            score += 1

        if score <= 1:
            self.setText("🔴 Слабый пароль")
            self.setStyleSheet("color: red;")
        elif score == 2:
            self.setText("🟠 Средний пароль")
            self.setStyleSheet("color: orange;")
        elif score in (3, 4):
            self.setText("🟡 Хороший пароль")
            self.setStyleSheet("color: goldenrod;")
        else:
            self.setText("🟢 Надёжный пароль")
            self.setStyleSheet("color: green; font-weight: bold;")


def _make_colored_icon(color_hex: str) -> QIcon:
    pixmap = QPixmap(16, 16)
    pixmap.fill(QColor(color_hex))
    return QIcon(pixmap)


def profile_performance(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = func(*args, **kwargs)
        elapsed = time.perf_counter() - start
        if elapsed > 0.001:
            print(f"[PERF] {func.__name__} — {elapsed * 1000:.3f} мс")
        return result
    return wrapper


# ─────────────────────────────────────────────────────────────────────────────
# Главное окно
# ─────────────────────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(
        self,
        entry_manager=None,
        key_manager=None,
        authenticator=None,
        state_manager=None,
        clipboard_service=None,
        log_verifier=None,
        parent=None,
        # Спринт 6
        exporter=None,
        importer=None,
        sharing_service=None,
        qr_service=None,
        # Спринт 7
        activity_monitor=None,
        panic_mode=None,
        # Конфиг и аудит
        config=None,
        audit_logger=None,
        db_pool=None,
    ):
        super().__init__(parent)
        self.entry_manager    = entry_manager
        self.key_manager      = key_manager
        self.authenticator    = authenticator
        self.state_manager    = state_manager
        self.clipboard_service = clipboard_service
        self.log_verifier     = log_verifier
        self.exporter         = exporter
        self.importer         = importer
        self.sharing_service  = sharing_service
        self.qr_service       = qr_service
        self.activity_monitor = activity_monitor
        self.panic_mode       = panic_mode
        self.config           = config        
        self.audit_logger     = audit_logger  
        self.db_pool          = db_pool

        self._minimize_to_tray  = True
        self._quit_confirmed    = False
        self._unlock_dialog_open = False

        self.installEventFilter(self)
        self._create_tray_icon()

        self.setWindowTitle("Secure Vault")
        self.resize(960, 620)

        self._create_menu()
        self._create_toolbar()
        self._create_central_table()
        self._create_status_bar()
        self._start_clipboard_timer()

        # Хоткей паники
        self._panic_shortcut = QShortcut(QKeySequence("Ctrl+Shift+1"), self)
        self._panic_shortcut.activated.connect(self._on_panic_activate)

        events.subscribe("UserLoggedIn",       self._on_user_logged_in)
        events.subscribe("UserLoggedOut",      self._on_vault_locked)
        events.subscribe("VaultLocked",        self._on_vault_locked)
        events.subscribe("VaultUnlocked",      self._on_vault_unlocked)
        events.subscribe("ClipboardUnblocked", self._on_clipboard_unblocked)

        if self.clipboard_service:
            self.clipboard_service.subscribe(self._on_clipboard_notification)

        if self.log_verifier:
            self.log_verifier.start_periodic_verification(
                interval_hours=24,
                on_result=self._on_verification_result,
            )

        self._mouse_positions   = []
        self._last_activity_time = time.time()
        self._idle_timeout      = 300
        self._activity_timer    = QTimer(self)
        self._activity_timer.timeout.connect(self._check_idle_timeout)
        self._activity_timer.start(1000)

        self.os_type = platform.system()
        self._setup_platform_hooks()

    # =========================================================================
    # Вспомогательные
    # =========================================================================

    @staticmethod
    def sanitize_text(text: str, max_len: int = 500) -> str:
        if not isinstance(text, str):
            return ""
        return re.sub(r'[\x00-\x1f\x7f]', '', text)[:max_len]

    def _bring_to_front(self):
        self.show()
        self.raise_()
        self.activateWindow()

    # =========================================================================
    # Диалог повторного входа
    # =========================================================================

    def _show_relock_dialog(self):
        if getattr(self, "_unlock_dialog_open", False):
            return

        if not self.authenticator:
            return

        self._unlock_dialog_open = True

        try:
            self._bring_to_front()

            from gui.login_dialog import LoginDialog

            dlg = LoginDialog(self.authenticator, self)
            dlg.setWindowTitle("Хранилище заблокировано")

            result = dlg.exec()

            if result == QDialog.DialogCode.Accepted:

                # снимаем блокировку приложения
                if self.state_manager:
                    self.state_manager.unlock()

                if result == QDialog.DialogCode.Accepted:
                    if self.state_manager:
                        self.state_manager.unlock()
                    # key_manager.unlock() БЕЗ ПАРОЛЯ — УБРАТЬ этот блок:
                    # if self.key_manager and hasattr(self.key_manager, "unlock"):
                    #     try:
                    #         self.key_manager.unlock()   # <-- падает, пароль не передан
                    #     except Exception:
                    #         pass
                    self._last_activity_time = time.time()
                    self._rebuild_tray_menu()
                    self._update_tray_icon_state()
                    self._load_entries()
                    self.show_toast("🔓 Хранилище разблокировано")

                # сбрасываем состояние ActivityMonitor
                if self.activity_monitor:

                    if hasattr(self.activity_monitor, "set_vault_locked_state"):
                        try:
                            self.activity_monitor.set_vault_locked_state(False)
                        except Exception:
                            pass

                    if hasattr(self.activity_monitor, "reset_activity"):
                        try:
                            self.activity_monitor.reset_activity()
                        except Exception:
                            pass

                    try:
                        self._record_activity_monitor()
                    except Exception:
                        pass

                # если есть panic_mode — снимаем флаг паники
                if getattr(self, "panic_mode", None):

                    if hasattr(self.panic_mode, "active"):
                        self.panic_mode.active = False

                    if hasattr(self.panic_mode, "_active"):
                        self.panic_mode._active = False

                    if hasattr(self.panic_mode, "is_active"):
                        try:
                            self.panic_mode.is_active = False
                        except Exception:
                            pass

                self._load_entries()

                self._rebuild_tray_menu()
                self._update_tray_icon_state()

                self.show()
                self.raise_()
                self.activateWindow()

                self.show_toast(
                    "🔓 Хранилище разблокировано"
                )

        finally:
            self._unlock_dialog_open = False

    def _record_activity_monitor(self):
        """Безопасный вызов методов ActivityMonitor — разные версии имеют разные имена."""
        if not self.activity_monitor:
            return
    
        for method_name in ("record_activity", "reset_activity", "update_activity"):
            method = getattr(self.activity_monitor, method_name, None)
            if callable(method):
                try:
                    method()
                except Exception:
                    pass
                return
        # Крайний случай: просто обновляем last_activity напрямую
        if hasattr(self.activity_monitor, "last_activity"):
            from datetime import datetime
            self.activity_monitor.last_activity = datetime.utcnow()

    # =========================================================================
    # Перехват событий активности
    # =========================================================================

    @profile_performance
    def eventFilter(self, obj, event):
        if event.type() in (
            QEvent.Type.MouseMove,
            QEvent.Type.MouseButtonPress,
            QEvent.Type.KeyPress,
            QEvent.Type.FocusIn,
        ):
            self._last_activity_time = time.time()
        if event.type() == QEvent.Type.WindowDeactivate:
            remaining = time.time() - self._last_activity_time
            if remaining < (self._idle_timeout - 30):
                self._last_activity_time = time.time() - (self._idle_timeout - 30)
        return super().eventFilter(obj, event)

    @profile_performance  
    def _check_idle_timeout(self):
        if not self.state_manager:
            return
        if self.state_manager.is_locked():
            self._last_activity_time = time.time()  # не накапливать idle пока заблокировано
            return
        if getattr(self, "_unlock_dialog_open", False):
            return
        if QApplication.activeModalWidget() is not None:
            return
        for widget in QApplication.topLevelWidgets():
            if isinstance(widget, QFileDialog) and widget.isVisible():
                return
        if time.time() - self._last_activity_time > self._idle_timeout:
            self.lock_application()

    @profile_performance
    def lock_application(self):
        if self.clipboard_service:
            self.clipboard_service._clear_clipboard()
        if self.state_manager:
            self.state_manager.lock()
        if self.key_manager:
            self.key_manager.lock()
        # УБРАТЬ весь блок try/except с os-специфичной блокировкой
        self._last_activity_time = time.time()  # сбрасываем таймер
        self.show_toast("🔒 Безопасная блокировка выполнена", duration=3000)

    def _check_mouse_shake(self, current_pos):
        self._mouse_positions.append((time.time(), current_pos))
        self._mouse_positions = [
            p for p in self._mouse_positions if time.time() - p[0] < 0.5
        ]
        if len(self._mouse_positions) < 4:
            return
        velocities = []
        for i in range(1, len(self._mouse_positions)):
            dt = self._mouse_positions[i][0] - self._mouse_positions[i - 1][0]
            if dt > 0:
                dx = self._mouse_positions[i][1].x() - self._mouse_positions[i - 1][1].x()
                dy = self._mouse_positions[i][1].y() - self._mouse_positions[i - 1][1].y()
                velocities.append((dx * dx + dy * dy) ** 0.5 / dt)
        if len(velocities) >= 3:
            changes = sum(
                1 for i in range(1, len(velocities))
                if (velocities[i] - velocities[i - 1]) > 500
            )
            if changes >= 2:
                self._on_panic_activate()

    # =========================================================================
    # Меню
    # =========================================================================

    def _create_menu(self):
        mb = self.menuBar()

        # Файл
        file_menu = mb.addMenu("Файл")
        new_action    = QAction("Создать",         self)
        open_action   = QAction("Открыть",         self)
        backup_action = QAction("Резервная копия", self)
        exit_action   = QAction("Выход",           self)
        new_action.triggered.connect(self._on_new_vault)
        open_action.triggered.connect(self._on_open_vault)
        backup_action.triggered.connect(self._on_backup_vault)
        exit_action.triggered.connect(self._quit_app)
        file_menu.addActions([new_action, open_action, backup_action])
        file_menu.addSeparator()
        file_menu.addAction(exit_action)

        # Правка
        edit_menu = mb.addMenu("Правка")
        self.add_action    = QAction("Добавить", self)
        self.edit_action   = QAction("Изменить", self)
        self.delete_action = QAction("Удалить",  self)
        self.add_action.triggered.connect(self._on_add_entry)
        self.edit_action.triggered.connect(self._on_edit_entry)
        self.delete_action.triggered.connect(self._on_delete_entry)
        edit_menu.addActions([self.add_action, self.edit_action, self.delete_action])

        # Данные
        ie_menu = mb.addMenu("Данные")
        export_action = QAction("Экспорт...",           self)
        import_action = QAction("Импорт...",             self)
        share_action  = QAction("Поделиться записью...", self)
        export_action.triggered.connect(self._on_export)
        import_action.triggered.connect(self._on_import)
        share_action.triggered.connect(self._on_share_entry)
        ie_menu.addActions([export_action, import_action, share_action])

        # Вид
        view_menu = mb.addMenu("Вид")
        logs_action     = QAction("Логи",      self)
        settings_action = QAction("Настройки", self)
        logs_action.triggered.connect(self._show_audit_log)
        settings_action.triggered.connect(self._show_settings)
        view_menu.addActions([logs_action, settings_action])

        self.toggle_pass_action = QAction("Показать пароли", self)
        self.toggle_pass_action.setCheckable(True)
        self.toggle_pass_action.setShortcut("Ctrl+Shift+P")
        self.toggle_pass_action.triggered.connect(self._toggle_passwords)
        view_menu.addSeparator()
        view_menu.addAction(self.toggle_pass_action)

        verify_action = QAction("Проверить целостность логов", self)
        verify_action.triggered.connect(self._on_verify_integrity)
        view_menu.addAction(verify_action)

        # Безопасность
        security_menu = mb.addMenu("Безопасность")
        change_pw_action = QAction("Сменить мастер-пароль", self)
        change_pw_action.triggered.connect(self._on_change_password)
        security_menu.addAction(change_pw_action)

        self.unblock_clipboard_action = QAction("Разблокировать буфер обмена", self)
        self.unblock_clipboard_action.triggered.connect(self._on_unblock_clipboard)
        self.unblock_clipboard_action.setVisible(False)
        security_menu.addAction(self.unblock_clipboard_action)

        preview_action = QAction("Предпросмотр буфера обмена", self)
        preview_action.triggered.connect(self._on_clipboard_preview)
        security_menu.addAction(preview_action)

        security_menu.addSeparator()
        panic_action = QAction("🚨 Активировать панику (Ctrl+Shift+1)", self)
        panic_action.triggered.connect(self._on_panic_activate)
        security_menu.addAction(panic_action)

        # Справка
        help_menu = mb.addMenu("Справка")
        about_action = QAction("О программе", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    # =========================================================================
    # Панель инструментов
    # =========================================================================

    def _create_toolbar(self):
        tb = QToolBar("Основная панель", self)
        tb.setMovable(False)
        self.addToolBar(Qt.ToolBarArea.TopToolBarArea, tb)

        add_tb = QAction("➕ Добавить", self)
        add_tb.triggered.connect(self._on_add_entry)
        tb.addAction(add_tb)

        del_tb = QAction("🗑 Удалить", self)
        del_tb.triggered.connect(self._on_delete_entry)
        tb.addAction(del_tb)

        tb.addSeparator()

        self.tb_toggle_pass = QAction("👁 Пароли", self)
        self.tb_toggle_pass.setCheckable(True)
        self.tb_toggle_pass.setToolTip("Показать/скрыть пароли (Ctrl+Shift+P)")
        self.tb_toggle_pass.triggered.connect(self._on_toolbar_toggle_pass)
        tb.addAction(self.tb_toggle_pass)

        tb.addSeparator()

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Поиск...")
        self.search_input.setMaximumWidth(260)
        self.search_input.textChanged.connect(self._on_search)
        tb.addWidget(self.search_input)

    def _on_toolbar_toggle_pass(self, checked: bool):
        self.toggle_pass_action.setChecked(checked)
        self._toggle_passwords(checked)

    # =========================================================================
    # Системный трей
    # =========================================================================

    def _create_tray_icon(self):
        self._tray = QSystemTrayIcon(self)
        self._tray_icon_locked   = _make_colored_icon("#c0392b")
        self._tray_icon_unlocked = _make_colored_icon("#27ae60")
        self._tray.setIcon(self._tray_icon_unlocked)
        self._tray.setToolTip("CryptoSafe Manager")
        self._rebuild_tray_menu()
        self._tray.activated.connect(self._on_tray_activated)
        self._tray.show()

    def _rebuild_tray_menu(self):
        tray_menu = QMenu()

        show_action = QAction("Открыть", self)
        show_action.triggered.connect(self._bring_to_front)
        tray_menu.addAction(show_action)

        tray_menu.addSeparator()

        locked = self.state_manager.is_locked() if self.state_manager else False
        if locked:
            lock_action = QAction("🔓 Разблокировать", self)
            lock_action.triggered.connect(self._on_tray_unlock)
        else:
            lock_action = QAction("🔒 Заблокировать", self)
            lock_action.triggered.connect(self._on_tray_lock)
        tray_menu.addAction(lock_action)

        clear_clip = QAction("🗑 Очистить буфер обмена", self)
        clear_clip.triggered.connect(self._on_tray_clear_clipboard)
        tray_menu.addAction(clear_clip)

          #9: быстрый поиск теперь вызывает _on_search вместо _on_search_changed
        search_action = QAction("🔍 Быстрый поиск", self)
        search_action.triggered.connect(self._on_tray_quick_search)
        tray_menu.addAction(search_action)

        tray_menu.addSeparator()

        panic_tray = QAction("🚨 Активировать панику", self)
        panic_tray.triggered.connect(self._on_panic_activate)
        tray_menu.addAction(panic_tray)

        settings_tray = QAction("⚙️ Настройки", self)
        settings_tray.triggered.connect(self._show_settings)
        tray_menu.addAction(settings_tray)

        tray_menu.addSeparator()

        quit_action = QAction("Выход", self)
        quit_action.triggered.connect(self._quit_app)
        tray_menu.addAction(quit_action)

        self._tray.setContextMenu(tray_menu)

    def _on_tray_quick_search(self):
        """FIX #9: диалог быстрого поиска — вызывает _on_search, а не _on_search_changed."""
        text, ok = QInputDialog.getText(
            self, "Поиск записей", "Введите название или username:"
        )
        if ok and text:
            self.search_input.setText(text)
            self._bring_to_front()
            self._on_search(text)    

    def _on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self._bring_to_front()

    def _on_tray_lock(self):
        if self.state_manager:
            self.state_manager.lock()
        if self.key_manager:
            self.key_manager.lock()

    def _on_tray_unlock(self):
        self._bring_to_front()
        if self.authenticator:
            from gui.login_dialog import LoginDialog
            dlg = LoginDialog(self.authenticator, self)
            if dlg.exec() == QDialog.DialogCode.Accepted:
                # LoginDialog вызывает authenticator.login() который делает
                # key_manager.unlock() и публикует UserLoggedIn —
                # но state_manager нужно разблокировать явно
                if self.state_manager:
                    self.state_manager.unlock()
                self._last_activity_time = time.time()
                self._load_entries()
                self._rebuild_tray_menu()
                self._update_tray_icon_state()   
                QTimer.singleShot(50, self._bring_to_front)

    def _on_tray_clear_clipboard(self):
        if self.clipboard_service:
            self.clipboard_service._clear_clipboard()

    def _quit_app(self):
        self._quit_confirmed = True
        self.close()

    def _update_tray_icon_state(self):
        if not hasattr(self, "_tray"):
            return
        locked = self.state_manager.is_locked() if self.state_manager else False
        if locked:
            self._tray.setIcon(self._tray_icon_locked)
            self._tray.setToolTip("CryptoSafe Manager 🔒 Заблокировано")
        else:
            self._tray.setIcon(self._tray_icon_unlocked)
            self._tray.setToolTip("CryptoSafe Manager 🔓 Разблокировано")
        self._rebuild_tray_menu()

    # =========================================================================
    # Паника (Спринт 7)
    # =========================================================================

    def _on_panic_activate(self):
        try:
            if self.panic_mode:
                self.panic_mode.activate(method="ui_button")
            else:
                if self.clipboard_service:
                    self.clipboard_service._clear_clipboard()
                if self.state_manager:
                    self.state_manager.lock()
                if self.key_manager:
                    self.key_manager.lock()
                self.hide()

            if self.activity_monitor:
                  #10: используем безопасный враппер
                self._record_activity_monitor()

            self._rebuild_tray_menu()
            self._update_tray_icon_state()

            QMessageBox.critical(
                None,
                "🚨 Паника",
                "Критический режим! Сессия уничтожена, оперативная память аппаратно зачищена.",
            )
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось активировать режим паники: {e}")

    def _setup_platform_hooks(self):
        pass  # расширяется под каждую ОС при необходимости

    # =========================================================================
    # Импорт / Экспорт / Шаринг
    # =========================================================================

    def _check_unlocked(self) -> bool:
        if self.key_manager and not self.key_manager.is_unlocked():
            QMessageBox.warning(
                self,
                "Хранилище заблокировано",
                "Разблокируйте хранилище перед выполнением этой операции.",
            )
            return False
        return True

    def _on_export(self):
        if not self._check_unlocked():
            return
        if not self.exporter:
            QMessageBox.warning(self, "Недоступно", "Сервис экспорта не инициализирован.")
            return
        from gui.export_dialog import ExportDialog
        ExportDialog(exporter=self.exporter, entry_manager=self.entry_manager, parent=self).exec()

    def _on_import(self):
        if not self._check_unlocked():
            return
        if not self.importer:
            QMessageBox.warning(self, "Недоступно", "Сервис импорта не инициализирован.")
            return
        from gui.import_dialog import ImportDialog
        dlg = ImportDialog(importer=self.importer, parent=self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self._load_entries()

    def _on_share_entry(self):
        if not self._check_unlocked():
            return
        if not self.sharing_service:
            QMessageBox.warning(self, "Недоступно", "Сервис шаринга не инициализирован.")
            return
        entry_id = self.table.get_selected_entry_id()
        entry_title = ""
        if entry_id:
            for e in self.table.entries:
                if e.get("id") == entry_id:
                    entry_title = e.get("title", "")
                    break
        from gui.sharing_dialog import SharingDialog
        SharingDialog(
            sharing_service=self.sharing_service,
            entry_id=entry_id,
            entry_title=entry_title,
            qr_service=self.qr_service,
            parent=self,
        ).exec()
        self._load_entries()

    # =========================================================================
    # Буфер обмена
    # =========================================================================

    def _on_unblock_clipboard(self):
        if self.clipboard_service:
            self.clipboard_service.unblock_copies()
            self.unblock_clipboard_action.setVisible(False)

    def _on_clipboard_preview(self):
        if not self.clipboard_service:
            QMessageBox.information(self, "Информация", "Сервис буфера обмена недоступен")
            return
        status = self.clipboard_service.get_clipboard_status()
        dialog = QDialog(self)
        dialog.setWindowTitle("Предпросмотр буфера обмена")
        dialog.setModal(True)
        dialog.resize(420, 220)
        layout = QVBoxLayout(dialog)
        form = QFormLayout()

        data_type = status.get("data_type", "—")
        source_id = status.get("source_entry_id", "неизвестно")
        remaining = int(status.get("remaining_seconds", 0))

        _type_text = data_type if status.get("active") else "Буфер пуст"
        form.addRow("Тип данных:", QLabel(_type_text))
        form.addRow("Источник:",   QLabel(str(source_id) if source_id else "неизвестно"))
        form.addRow("Очистка через:", QLabel(f"{remaining} сек" if status.get("active") else "—"))

        masks = {"password": "pas••••••••", "username": "usr••••••••", "notes": "note•••••••"}
        content_label = QLabel(masks.get(data_type, "•••••••••••") if status.get("active") else "—")
        content_label.setFont(QFont("Courier", 11))
        content_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        form.addRow("Содержимое:", content_label)
        layout.addLayout(form)

        btn_layout = QHBoxLayout()
        reveal_btn = QPushButton("👁 Показать")

        def on_reveal():
            password, ok = QInputDialog.getText(
                dialog, "Подтверждение", "Введите мастер-пароль:", QLineEdit.EchoMode.Password
            )
            if not ok or not password:
                return
            if not self.key_manager or not self.key_manager.is_unlocked():
                QMessageBox.warning(dialog, "Ошибка", "Хранилище заблокировано")
                return
            with self.clipboard_service._lock:
                item = self.clipboard_service._current_content
                if item and item.data:
                    content_label.setText(item.data)
                    reveal_btn.setEnabled(False)
                else:
                    QMessageBox.information(dialog, "Информация", "Буфер обмена пуст")

        reveal_btn.clicked.connect(on_reveal)
        reveal_btn.setEnabled(status.get("active", False))

        clear_btn = QPushButton("🗑 Очистить")
        clear_btn.setStyleSheet("color: red;")

        def on_clear():
            self.clipboard_service._clear_clipboard()
            self.clipboard_service.events.publish("ClipboardCleared", reason="manual")
            dialog.accept()

        clear_btn.clicked.connect(on_clear)
        clear_btn.setEnabled(status.get("active", False))

        close_btn = QPushButton("Закрыть")
        close_btn.clicked.connect(dialog.accept)
        btn_layout.addWidget(reveal_btn)
        btn_layout.addWidget(clear_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)
        dialog.exec()

    def _on_clipboard_notification(self, message: str):
        self.show_toast(message)
        if self.clipboard_service and self.clipboard_service.is_blocked():
            self.unblock_clipboard_action.setVisible(True)

    def _on_clipboard_unblocked(self, data=None):
        self.unblock_clipboard_action.setVisible(False)
        self.show_toast("Буфер обмена разблокирован", duration=2000)
        if hasattr(self, "table") and self.table:
            self.table.highlight_clipboard_entry(None)

    def show_toast(self, message: str, duration: int = 3000):
        if hasattr(self, "status_bar"):
            self.status_bar.showMessage(message)
            QTimer.singleShot(
                duration,
                lambda: self.status_bar.showMessage(
                    f"{self.login_status} | {self.clipboard_status}"
                ),
            )

    # =========================================================================
    # Центральная таблица
    # =========================================================================

    def _create_central_table(self):
        self.table       = SecureTable(clipboard_service=self.clipboard_service)
        self.secure_table = self.table
        self._load_entries()
        self.table.entry_edit_requested.connect(self._on_edit_entry_by_id)
        self.table.entry_delete_requested.connect(self._on_delete_entry_by_id)
        container = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(4, 4, 4, 4)
        layout.addWidget(self.table)
        container.setLayout(layout)
        self.setCentralWidget(container)

    def _load_entries(self):
        if not self.entry_manager or (self.state_manager and self.state_manager.is_locked()):
            return
        self.table.clear_entries()
        entries = self.entry_manager.get_all_entries()
        try:
            for entry in entries:
                self.table.add_entry(
                    entry_id=entry.get("id", ""),
                    title=entry.get("title", ""),
                    username=entry.get("username", ""),
                    url=entry.get("url", ""),
                    updated_at=entry.get("updated_at", ""),
                    password=entry.get("password", ""),
                    notes=entry.get("notes", ""),
                )
        finally:
            self.entry_manager.secure_wipe_list(entries)

    # =========================================================================
    # События хранилища
    # =========================================================================

    def _on_user_logged_in(self, **kwargs):
        self.login_status = "Вход выполнен"
        self.status_bar.showMessage(f"{self.login_status} | {self.clipboard_status}")
        self._update_tray_icon_state()
        self._load_entries()
        QTimer.singleShot(50, self._bring_to_front)
        if self.activity_monitor:
            self.activity_monitor.start(on_timeout_callback=self._on_activity_timeout)

    def _on_activity_timeout(self):
            # защита от повторного открытия окна
        import traceback
        
        if self.state_manager and self.state_manager.is_locked():
            return
        if self.state_manager:
            self.state_manager.lock()
        if self.key_manager:
            self.key_manager.lock()
        if self.clipboard_service:
            self.clipboard_service._clear_clipboard()
        self.show_toast("🔒 Автоблокировка по причине неактивности", duration=4000)
        self._show_relock_dialog()

    def _on_vault_locked(self, **kwargs):
        self.table.clear_entries()
        self.login_status = "Не выполнен вход"
        self.status_bar.showMessage(f"{self.login_status} | {self.clipboard_status}")
        self._update_tray_icon_state()
        reason = kwargs.get("reason", "")
        # Добавить "timeout" и пустой reason в список исключений
        # key_manager.lock() публикует UserLoggedOut без reason — это дубль
        if reason in ("manual", "panic", ""):
            return
        if self.authenticator:
            QTimer.singleShot(200, self._show_relock_dialog)

    def _on_vault_unlocked(self, **kwargs):
        self.login_status = "Вход выполнен"
        self.status_bar.showMessage(f"{self.login_status} | {self.clipboard_status}")
        self._update_tray_icon_state()
        self._load_entries()
        QTimer.singleShot(50, self._bring_to_front)

    def _on_search(self, text: str):
        """FIX #9: единый метод поиска, вызывается и из toolbar, и из трея."""
        self.table.filter_entries(text)

    # =========================================================================
    # Статус-бар
    # =========================================================================

    def _create_status_bar(self):
        self.status_bar      = QStatusBar()
        self.login_status    = "Не выполнен вход"
        self.clipboard_status = "Буфер: ---"
        self.status_bar.showMessage(f"{self.login_status} | {self.clipboard_status}")
        self.setStatusBar(self.status_bar)

    def _start_clipboard_timer(self):
        self._status_timer = QTimer(self)
        self._status_timer.setInterval(1000)
        self._status_timer.timeout.connect(self._update_clipboard_status)
        self._status_timer.start()

    @profile_performance
    def _update_clipboard_status(self):
        if not self.clipboard_service:
            return
        status = self.clipboard_service.get_clipboard_status()
        if status.get("active"):
            remaining = int(status.get("remaining_seconds", 0))
            data_type = status.get("data_type", "")
            if 0 < remaining <= 5:
                self.clipboard_status = f"⚠️ Буфер очистится через {remaining}с"
            elif remaining > 0:
                self.clipboard_status = f"📋 Буфер [{data_type}]: {remaining}с"
            else:
                self.clipboard_status = "Буфер: ---"
        else:
            self.clipboard_status = "Буфер: ---"
        if hasattr(self, "status_bar"):
            self.status_bar.showMessage(f"{self.login_status} | {self.clipboard_status}")
        if not status.get("active") and hasattr(self, "table"):
            self.table.highlight_clipboard_entry(None)

    def _toggle_passwords(self, checked: bool):
        self.table.update_password_visibility(checked)
        self.toggle_pass_action.setText("Скрыть пароли" if checked else "Показать пароли")
        if hasattr(self, "tb_toggle_pass"):
            self.tb_toggle_pass.setChecked(checked)

    # =========================================================================
    # CRUD
    # =========================================================================

    def _on_add_entry(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Добавить запись")
        dialog.resize(460, 520)
        layout      = QVBoxLayout(dialog)
        form_layout = QFormLayout()

        title_edit    = QLineEdit()
        username_edit = QLineEdit()
        url_edit      = QLineEdit()
        category_edit = QLineEdit()
        category_edit.setPlaceholderText("Например: Работа, Личное")
        tags_edit = QLineEdit()
        tags_edit.setPlaceholderText("Теги через запятую: email,bank")
        password_edit = QLineEdit()
        password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        notes_edit = QTextEdit()
        notes_edit.setMaximumHeight(80)

          #1: strength_indicator.update_strength обновляет виджет (не возвращает tuple)
        strength_indicator = PasswordStrengthIndicator()
        show_pass_btn = QPushButton("👁")
        show_pass_btn.setCheckable(True)
        show_pass_btn.setFixedWidth(32)
        gen_btn = QPushButton("🔄 Сгенерировать")

        def toggle_visibility(checked):
            password_edit.setEchoMode(
                QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
            )

        show_pass_btn.toggled.connect(toggle_visibility)

        def generate_password():
            pw = PasswordGenerator().generate_password(length=16)
            password_edit.setText(pw)
            strength_indicator.update_strength(pw)

        gen_btn.clicked.connect(generate_password)
        password_edit.textChanged.connect(strength_indicator.update_strength)

        pass_layout = QHBoxLayout()
        pass_layout.addWidget(password_edit)
        pass_layout.addWidget(show_pass_btn)
        pass_layout.addWidget(gen_btn)

        form_layout.addRow("Название *:",  title_edit)
        form_layout.addRow("Логин:",        username_edit)
        form_layout.addRow("Пароль *:",     pass_layout)
        form_layout.addRow("",              strength_indicator)
        form_layout.addRow("URL:",          url_edit)
        form_layout.addRow("Категория:",    category_edit)
        form_layout.addRow("Теги:",         tags_edit)
        form_layout.addRow("Заметки:",      notes_edit)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addLayout(form_layout)
        layout.addWidget(buttons)

        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        raw_title    = title_edit.text().strip()
        raw_username = username_edit.text()
        raw_url      = url_edit.text()
        raw_password = password_edit.text()
        raw_notes    = notes_edit.toPlainText()
        raw_category = category_edit.text()
        raw_tags     = tags_edit.text()

        title    = self.sanitize_text(raw_title,    100)
        username = self.sanitize_text(raw_username, 255)
        url      = self.sanitize_text(raw_url,      500)
        password = raw_password
        notes    = self.sanitize_text(raw_notes,   2000)
        category = self.sanitize_text(raw_category, 100)
        tags     = self.sanitize_text(raw_tags,     500)

        if not title:
            QMessageBox.warning(self, "Ошибка", "Название не может быть пустым")
            return
        if not password:
            QMessageBox.warning(self, "Ошибка", "Пароль обязателен")
            return

        if not PasswordValidator.validate_password_strength(password):
            msg = QMessageBox(self)
            msg.setWindowTitle("Слабый пароль")
            msg.setText("Пароль не соответствует требованиям безопасности.\nВсё равно использовать?")
            msg.setIcon(QMessageBox.Icon.Warning)
            yes_btn = msg.addButton("Да", QMessageBox.ButtonRole.YesRole)
            msg.addButton("Нет", QMessageBox.ButtonRole.NoRole)
            msg.exec()
            if msg.clickedButton() != yes_btn:
                return

        if self.entry_manager:
            try:
                self.entry_manager.create_entry({
                    "title": title, "username": username,
                    "password": password, "url": url,
                    "notes": notes, "category": category, "tags": tags,
                })
                self._load_entries()
                self.show_toast("✅ Запись успешно добавлена")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка сохранения", f"Не удалось сохранить запись: {e}")
            finally:
                for s in (raw_title, raw_username, raw_url, raw_password,
                          raw_notes, raw_category, raw_tags,
                          title, username, url, password, notes, category, tags):
                    secure_wipe_str(s)

    def _on_edit_entry(self):
        selected = self.table.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Редактирование", "Выберите запись для редактирования.")
            return
        row  = selected[0].row()
        item = self.table.item(row, 0)
        if not item:
            return
        entry_id = item.data(Qt.ItemDataRole.UserRole) or item.text()
        self._on_edit_entry_by_id(entry_id)

    def _on_delete_entry(self):
        selected = self.table.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Удаление", "Выберите запись для удаления.")
            return
        row  = selected[0].row()
        item = self.table.item(row, 0)
        if not item:
            return
        entry_id = item.data(Qt.ItemDataRole.UserRole) or item.text()
        answer = QMessageBox.question(
            self, "Удаление", "Удалить выбранную запись?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            self.entry_manager.delete_entry(entry_id)
            self._load_entries()
            self.show_toast("🗑 Запись удалена")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось удалить запись: {e}")

    def _on_edit_entry_by_id(self, eid: str):
        try:
            entry = self.entry_manager.get_entry(eid)
            dialog = QDialog(self)
            dialog.setWindowTitle("Редактировать запись")
            dialog.resize(460, 520)
            layout = QVBoxLayout(dialog)
            form   = QFormLayout()

            title_edit    = QLineEdit(entry.get("title", ""))
            username_edit = QLineEdit(entry.get("username", ""))
            url_edit      = QLineEdit(entry.get("url", ""))
            category_edit = QLineEdit(entry.get("category", ""))
            tags_edit     = QLineEdit(str(entry.get("tags", "")))
            password_edit = QLineEdit(entry.get("password", ""))
            password_edit.setEchoMode(QLineEdit.EchoMode.Password)
            notes_edit = QTextEdit()
            notes_edit.setPlainText(entry.get("notes", ""))

            form.addRow("Название:",   title_edit)
            form.addRow("Логин:",       username_edit)
            form.addRow("Пароль:",      password_edit)
            form.addRow("URL:",         url_edit)
            form.addRow("Категория:",   category_edit)
            form.addRow("Теги:",        tags_edit)
            form.addRow("Заметки:",     notes_edit)
            layout.addLayout(form)

            buttons = QDialogButtonBox(
                QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
            )
            buttons.accepted.connect(dialog.accept)
            buttons.rejected.connect(dialog.reject)
            layout.addWidget(buttons)

            if dialog.exec() != QDialog.DialogCode.Accepted:
                return

            self.entry_manager.update_entry(eid, {
                "title":    title_edit.text().strip(),
                "username": username_edit.text().strip(),
                "password": password_edit.text(),
                "url":      url_edit.text().strip(),
                "category": category_edit.text().strip(),
                "tags":     tags_edit.text().strip(),
                "notes":    notes_edit.toPlainText().strip(),
            })
            self._load_entries()
            self.show_toast("✏️ Запись успешно обновлена")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось обновить запись:\n{e}")

    def _on_delete_entry_by_id(self, eid: str):
        answer = QMessageBox.question(
            self, "Удаление записи", "Удалить выбранную запись?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            self.entry_manager.delete_entry(eid)
            self._load_entries()
            self.show_toast("🗑 Запись удалена")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка удаления", str(e))

    # =========================================================================
    # Файл — Создать / Открыть / Резервная копия
    # =========================================================================

    def _on_new_vault(self):
        """Создаёт новое хранилище и перезапускает приложение с ним."""
        msg = QMessageBox(self)
        msg.setWindowTitle("Создать хранилище")
        msg.setText(
            "Создать новое хранилище?\n\n"
            "Вы будете перенаправлены на экран выбора хранилища."
        )
        msg.setIcon(QMessageBox.Icon.Question)
        yes_btn = msg.addButton("Продолжить", QMessageBox.ButtonRole.YesRole)
        msg.addButton("Отмена", QMessageBox.ButtonRole.NoRole)
        msg.exec()
        if msg.clickedButton() != yes_btn:
            return

        from gui.vault_selector_dialog import VaultSelectorDialog
        config = getattr(self, "_config", None)
        if config is None:
            from core.config import ConfigManager
            config = ConfigManager()

        selector = VaultSelectorDialog(config, parent=self)
        # Показываем сразу диалог создания
        selector._create_new()

        if selector.result() != QDialog.DialogCode.Accepted:
            return

        db_path = selector.selected_db_path
        new_password = selector.get_new_vault_password()

        if not db_path or not new_password:
            return

        # Инициализируем новую БД
        from database.db import DatabasePool
        from core.crypto.key_storage import KeyStorage
        from core.key_manager import KeyManager

        try:
            pool = DatabasePool(db_path)
            pool.migrate()
            key_storage = KeyStorage(pool)
            key_manager = KeyManager(key_storage, config={
                "argon2_time":        3,
                "argon2_memory":      65536,
                "argon2_parallelism": 4,
                "pbkdf2_iterations":  100000,
            })
            key_manager.initialize(new_password)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось создать хранилище:\n{e}")
            return

        selector.add_to_recent(db_path)
        config.set_database_path(db_path)
        config.save()

        QMessageBox.information(
            self, "Готово",
            f"Хранилище создано:\n{db_path}\n\n"
            "Перезапустите приложение для входа в новое хранилище."
        )

    def _on_open_vault(self):
          #3: self.config теперь существует
        path, _ = QFileDialog.getOpenFileName(
            self, "Открыть хранилище", "",
            "Database Files (*.db);;All Files (*)",
        )
        if not path:
            return
        try:
            if self.config:
                self.config.set_preference("database_path", path)
                self.config.save()
            QMessageBox.information(
                self, "Готово",
                "Хранилище выбрано. Перезапустите приложение для применения.",
            )
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось открыть хранилище: {e}")

    def _on_backup_vault(self):
          #4: self.config теперь существует
        try:
            from pathlib import Path
            import shutil

            db_path = None
            if self.config:
                db_path = self.config.get_preference("database_path") or \
                          self.config.get_database_path()
            # Запасной вариант — достать путь из entry_manager
            if not db_path and self.entry_manager:
                db_obj = getattr(self.entry_manager, "db", None)
                db_path = str(getattr(db_obj, "db_path", "") or "")

            if not db_path or not Path(db_path).exists():
                QMessageBox.warning(self, "Ошибка", "Файл базы данных не найден.")
                return

            backup_path, _ = QFileDialog.getSaveFileName(
                self, "Создать резервную копию",
                f"backup_{int(time.time())}.db",
                "Database Files (*.db);;All Files (*)",
            )
            if not backup_path:
                return
            shutil.copy2(db_path, backup_path)
            QMessageBox.information(self, "Готово", f"Резервная копия создана:\n{backup_path}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось создать резервную копию: {e}")

    # =========================================================================
    # Логи, настройки, смена пароля
    # =========================================================================

    def _show_audit_log(self):
          #5: используем self.db_pool (не self.audit_logger) для AuditLogViewer
        try:
            pool = self.db_pool or (
                getattr(self.entry_manager, "db", None) if self.entry_manager else None
            )
            dlg = QDialog(self)
            dlg.setWindowTitle("Журнал аудита")
            dlg.resize(960, 600)
            layout = QVBoxLayout(dlg)
            layout.addWidget(AuditLogViewer(db=pool, parent=dlg))
            dlg.exec()
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось открыть журнал аудита: {e}")

    def _on_verify_integrity(self):
          #7: используем self.log_verifier, а не self.audit_logger
        try:
            verifier = self.log_verifier
            if not verifier:
                QMessageBox.warning(self, "Аудит", "LogVerifier недоступен.")
                return
            result = verifier.verify_log(start_seq=0)
            if result.get("verified"):
                QMessageBox.information(
                    self, "Проверка логов",
                    f"Целостность логов подтверждена.\n"
                    f"Проверено записей: {result.get('total_entries', 0)}",
                )
            else:
                QMessageBox.critical(
                    self, "Проверка логов",
                    "Обнаружено нарушение целостности журнала аудита."
                )
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось проверить целостность логов: {e}")

    def _on_change_password(self):
          #8: ChangePasswordDialog принимает key_manager и entry_manager, не authenticator
        try:
            from gui.change_password_dialog import ChangePasswordDialog
            dlg = ChangePasswordDialog(
                key_manager=self.key_manager,
                entry_manager=self.entry_manager,
                parent=self,
            )
            if dlg.exec() == QDialog.DialogCode.Accepted:
                QMessageBox.information(self, "Готово", "Мастер-пароль успешно изменён.")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сменить мастер-пароль: {e}")

    def _show_settings(self):
        config = self.config or getattr(self, "_config", None)
        pool = self.db_pool or (
            getattr(self.entry_manager, "db", None) if self.entry_manager else None
        )
        dialog = SettingsDialog(
            config=config,
            pool=pool,
            clipboard_service=self.clipboard_service,
            activity_monitor=self.activity_monitor,
        )
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._apply_settings_from_config()  
            
    def _apply_settings_from_config(self):
        config = self.config or getattr(self, "_config", None)
        if not config:
            return

        # Принудительно перечитываем настройки из конфига (который уже обновлён)
        new_timeout = config.get_preference("inactivity_timeout") or 300
        self._idle_timeout = int(new_timeout)

        # Сбрасываем локальный счётчик активности
        self._last_activity_time = time.time()

        # Если используется ActivityMonitor – сбрасываем и его счётчик
        if self.activity_monitor:
            auto_lock = config.get_preference("auto_lock")
            if auto_lock is False:
                self._idle_timeout = 999999
            self.activity_monitor.update_config({
                "inactivity_timeout": new_timeout
            })
            # Вызываем record_activity() чтобы сбросить внутренний last_activity
            # Используем безопасный вызов, так как метод может называться по-разному
            self._record_activity_monitor()
            print(f"[DEBUG] inactivity_timeout обновлён: {self._idle_timeout}, last_activity сброшен")

    def _apply_settings(self):
        """Применяет сохранённые настройки к живым сервисам."""
        config = getattr(self, "_config", None)
        if not config:
            return

        # Обновляем таймаут буфера обмена
        if self.clipboard_service:
            new_timeout = config.get_preference("clipboard_timeout") or 30
            # config уже обновлён — clipboard_service читает его при следующем copy
            # но если буфер сейчас активен — перезапускаем таймер
            with self.clipboard_service._lock:
                if self.clipboard_service._current_content:
                    # отменяем старый таймер
                    if self.clipboard_service._timer:
                        self.clipboard_service._timer.cancel()
                    if self.clipboard_service._warning_timer:
                        self.clipboard_service._warning_timer.cancel()

                    # запускаем новый с актуальным таймаутом
                    import threading
                    from datetime import datetime
                    copied_at = self.clipboard_service._current_content.copied_at
                    elapsed = (datetime.utcnow() - copied_at).total_seconds()
                    remaining = max(1, new_timeout - elapsed)

                    op_id = self.clipboard_service._operation_id

                    self.clipboard_service._timer = threading.Timer(
                        remaining,
                        self.clipboard_service._on_timeout,
                        args=(op_id,)
                    )
                    self.clipboard_service._timer.daemon = True
                    self.clipboard_service._timer.start()

                    if remaining > 5:
                        self.clipboard_service._warning_timer = threading.Timer(
                            remaining - 5,
                            self.clipboard_service._on_warning,
                            args=(op_id,)
                        )
                        self.clipboard_service._warning_timer.daemon = True
                        self.clipboard_service._warning_timer.start()

        # Применяем авто-блокировку
        if self.state_manager:
            auto_lock = config.get_preference("auto_lock")
            if auto_lock is not None:
                self.state_manager.inactivity_timeout = (
                    config.get_preference("inactivity_timeout") or 300
                ) if auto_lock else None

        self.show_toast("✅ Настройки применены", duration=2000)

    def _show_about(self):
        QMessageBox.about(
            self, "О программе",
            "<h3>CryptoSafe Manager</h3>"
            "<p>Криптостойкий менеджер паролей.</p>"
            "<p>Версия: 1.0 &nbsp;|&nbsp; © 2026</p>"
            "<ul>"
            "<li>Шифрование AES-256-GCM</li>"
            "<li>Генератор паролей</li>"
            "<li>Аудит безопасности</li>"
            "<li>Импорт / Экспорт</li>"
            "<li>Режим паники</li>"
            "</ul>",
        )

    def _on_verification_result(self, res: dict):
        try:
            def _show():
                if res.get("verified"):
                    QMessageBox.information(
                        self, "Проверка завершена",
                        f"Целостность подтверждена.\n"
                        f"Проверено записей: {res.get('total_entries', 0)}",
                    )
                else:
                    QMessageBox.critical(
                        self, "Нарушение целостности",
                        res.get("error", "Обнаружено нарушение журнала аудита."),
                    )
            QTimer.singleShot(0, _show)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Ошибка обработки результата:\n{e}")

    # =========================================================================
    # Закрытие
    # =========================================================================

    def closeEvent(self, event):
        if not self._quit_confirmed and self._minimize_to_tray and self._tray.isVisible():
            self.hide()
            event.ignore()
            return
        if self.log_verifier:
            self.log_verifier.stop_periodic_verification()
        if hasattr(self, "_status_timer"):
            self._status_timer.stop()
        if hasattr(self, "_activity_timer"):
            self._activity_timer.stop()
        if hasattr(self, "_tray"):
            self._tray.hide()
        super().closeEvent(event)
        from PyQt6.QtWidgets import QApplication
        QApplication.instance().quit()