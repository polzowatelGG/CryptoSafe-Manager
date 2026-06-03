# src/core/security/panic_mode.py
# Аварийная блокировка приложения.
# При активации: очищает буфер обмена, блокирует хранилище, скрывает окна, затирает память.

import threading
import os
import sys
import subprocess
import gc
import ctypes
from typing import List, Callable, Optional

class PanicMode:
    """Emergency response system — activated by hotkey, tray, or menu."""

    def __init__(self, config: dict,
                 key_manager=None,
                 state_manager=None,
                 clipboard_service=None,
                 audit_logger=None,
                 main_window=None):
        self.config = config
        self.key_manager = key_manager
        self.state_manager = state_manager
        self.clipboard_service = clipboard_service
        self.audit_logger = audit_logger
        self.main_window = main_window

        self.activated = False
        self.response_handlers: List[Callable] = []
        self._lock = threading.Lock()

        # Register default handlers in strict order: clear -> lock -> wipe -> hide/decoy
        self._register_default_handlers()

    def _register_default_handlers(self):
        """Register default panic response handlers in order of priority."""
        self.register_handler(self._clear_clipboard)
        self.register_handler(self._lock_vault)
        self.register_handler(self._wipe_memory)
        self.register_handler(self._close_windows)

    def register_handler(self, handler: Callable):
        """Register a panic response handler."""
        self.response_handlers.append(handler)

    def activate(self, method: str = "hotkey"):
        import traceback
        print("[DEBUG] Panic activate started")
        with self._lock:
            if self.activated:
                print("[DEBUG] Already activated, exit")
                return
            self.activated = True
        print("[DEBUG] Logging panic event")
        self._log_panic_event(method)
        print("[DEBUG] Executing handlers")
        for i, handler in enumerate(self.response_handlers):
            print(f"[DEBUG] Running handler {i}: {handler.__name__}")
            try:
                handler()
                print(f"[DEBUG] Handler {handler.__name__} OK")
            except Exception as e:
                traceback.print_exc()
                sys.stderr.write(f"[PanicMode] Handler {handler.__name__} failed: {e}\n")
        if self.config.get('stealth_mode', False):
            self._execute_stealth_actions()
        with self._lock:
            self.activated = False
        print("[DEBUG] Panic activate finished")

    def _clear_clipboard(self):
        """Clear clipboard contents completely using service or native fallback."""
        if self.clipboard_service:
            try:
                # Вызываем публичный или внутренний метод очистки сервиса
                if hasattr(self.clipboard_service, 'clear'):
                    self.clipboard_service.clear()
                else:
                    self.clipboard_service._clear_clipboard()
                return
            except Exception:
                pass
        
        # Fallback: Ручная очистка в зависимости от ОС, если сервис недоступен
        try:
            import pyperclip
            pyperclip.copy('')
        except Exception:
            try:
                if sys.platform == 'win32':
                    os.system('echo off | clip')
                elif sys.platform == 'darwin':
                    subprocess.run(['pbcopy'], input=b'', check=False)
                else:
                    subprocess.run(['xclip', '-selection', 'clipboard', '/dev/null'], check=False)
            except Exception:
                pass

    def _lock_vault(self):
        """Lock the vault, clear keys from KeyManager and reset StateManager."""
        if self.key_manager:
            try:
                self.key_manager.lock()
            except Exception:
                pass
        if self.state_manager:
            try:
                self.state_manager.lock()
            except Exception:
                pass

    def _close_windows(self):
        if self.main_window:
            try:
                # Просто скрываем окно, не вызывая несуществующих методов
                self.main_window.hide()
            except Exception:
                pass

    def _wipe_memory(self):
        """Securely overwrite internal state variables and trigger garbage collection."""
        with self._lock:
            # Безопасное затирание словаря конфигурации в памяти приложения
            if isinstance(self.config, dict):
                for key in list(self.config.keys()):
                    # Затираем только чувствительные строки (пароли, пути, токены), если они там есть
                    if isinstance(self.config[key], str):
                        self.config[key] = "0" * len(self.config[key])
                self.config.clear()

        # Принудительный запуск сборщика мусора во всех поколениях
        try:
            gc.collect()
            gc.garbage.clear()
        except Exception:
            pass

    def _execute_stealth_actions(self):
        """Execute stealth actions to obscure panic activation."""
        stealth_config = self.config.get('stealth_actions', {})

        if stealth_config.get('show_fake_error', False):
            self._show_fake_error()

        if stealth_config.get('launch_decoy', False):
            self._launch_decoy_app()

    def _show_fake_error(self):
        """Show fake crash error message."""
        try:
            from PyQt6.QtWidgets import QMessageBox
            from PyQt6.QtCore import QTimer
    
            def _do_show():
                msg = QMessageBox()
                msg.setIcon(QMessageBox.Icon.Critical)
                msg.setText("Application Error")
                msg.setInformativeText(
                    "The application has encountered an unhandled exception "
                    "(0xc0000005) and must close."
                )
                msg.setWindowTitle("Runtime Error")
                msg.exec()
    
            QTimer.singleShot(0, _do_show)
        except Exception:
            pass


    def _launch_decoy_app(self):
        """Launch a harmless decoy application depending on the operating system."""
        try:
            if sys.platform == "win32":
                # Запуск встроенного Блокнота или Калькулятора Windows
                subprocess.Popen(["notepad.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif sys.platform == "darwin":
                # Запуск Текстового редактора на macOS
                subprocess.Popen(["open", "-a", "TextEdit"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                # Универсальный запуск браузера или редактора на Linux
                subprocess.Popen(["xdg-open", "https://www.google.com"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    def _log_panic_event(self, method: str):
        """Log panic activation to audit logger."""
        if self.audit_logger:
            try:
                self.audit_logger.log_event(
                    event_type="PANIC_MODE_ACTIVATED",
                    severity="CRITICAL",
                    source="panic_mode",
                    details={"activation_method": method}
                )
            except Exception:
                pass