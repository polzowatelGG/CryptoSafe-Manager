# src/core/security/panic_mode.py
# Аварийная блокировка приложения.
# При активации: очищает буфер обмена, блокирует хранилище, скрывает окна.

import threading
from typing import List, Callable, Optional


class PanicMode:
    """Emergency response system — activated by hotkey or menu."""

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

        # Register default handlers in order: clear → lock → hide
        self._register_default_handlers()

    def _register_default_handlers(self):
        """Register default panic response handlers."""
        self.register_handler(self._clear_clipboard)
        self.register_handler(self._lock_vault)
        self.register_handler(self._close_windows)
        self.register_handler(self._wipe_memory)

    def register_handler(self, handler: Callable):
        """Register a panic response handler."""
        self.response_handlers.append(handler)

    def activate(self, method: str = "hotkey"):
        """Activate panic mode — idempotent, logs to audit."""
        with self._lock:
            if self.activated:
                return
            self.activated = True

        # Execute all response handlers regardless of errors
        for handler in self.response_handlers:
            try:
                handler()
            except Exception as e:
                print(f"[PanicMode] Handler {handler.__name__} failed: {e}")

        # Execute stealth actions if configured
        if self.config.get('stealth_mode', False):
            self._execute_stealth_actions()

        # Log panic activation to audit
        self._log_panic_event(method)

        # Reset so panic can be re-activated after re-unlock
        with self._lock:
            self.activated = False

    def _clear_clipboard(self):
        """Clear clipboard contents."""
        if self.clipboard_service:
            try:
                self.clipboard_service._clear_clipboard()
            except Exception:
                pass
        else:
            # Fallback: pyperclip
            try:
                import pyperclip
                pyperclip.copy('')
            except Exception:
                pass

    def _lock_vault(self):
        """Lock the vault and session."""
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
        """Hide main application windows."""
        if self.main_window:
            try:
                # Use invokeMethod-safe approach from non-GUI thread
                from PyQt6.QtCore import QMetaObject, Qt
                QMetaObject.invokeMethod(
                    self.main_window, "hide",
                    Qt.ConnectionType.QueuedConnection
                )
            except Exception:
                pass

    def _wipe_memory(self):
        """Best-effort wipe of sensitive in-memory data."""
        # The clipboard_service already wipes its SecureBuffer on clear.
        # Additional wipe hooks can be registered via register_handler().
        pass

    def _execute_stealth_actions(self):
        """Execute stealth actions to obscure panic activation."""
        stealth_config = self.config.get('stealth_actions', {})

        if stealth_config.get('show_fake_error', False):
            self._show_fake_error()

        if stealth_config.get('launch_decoy', False):
            self._launch_decoy_app()

    def _show_fake_error(self):
        """Show fake error message to deceive observer."""
        try:
            import tkinter.messagebox as mb
            mb.showerror(
                "Application Error",
                "The application has encountered an unexpected error and must close."
            )
        except Exception:
            pass

    def _launch_decoy_app(self):
        """Launch decoy application — platform-specific."""
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