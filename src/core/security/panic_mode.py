# src/core/security/panic_mode.py
import sys
import threading
from typing import List, Callable

class PanicMode:
    """Emergency response system."""

    def __init__(self, config: dict):
        self.config = config
        self.activated = False
        self.response_handlers: List[Callable] = []
        self.lock = threading.Lock()

        # Register default handlers
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
        """Activate panic mode."""
        with self.lock:
            if self.activated:
                return

            self.activated = True

            # Execute all response handlers
            for handler in self.response_handlers:
                try:
                    handler()
                except Exception as e:
                    # Log but continue with other handlers
                    print(f"Panic handler failed: {e}")

            # Execute stealth actions if configured
            if self.config.get('stealth_mode', False):
                self._execute_stealth_actions()

            # Log panic activation
            self._log_panic_event(method)

    def _clear_clipboard(self):
        """Clear clipboard."""
        try:
            import pyperclip
            pyperclip.copy('')
        except:
            pass

    def _lock_vault(self):
        """Lock the vault."""
        # This would call into the vault locking mechanism
        from src.core.vault.vault_manager import VaultManager #type: ignore
        vault = VaultManager.get_instance()
        vault.lock()

    def _close_windows(self):
        """Close all application windows."""
        # Platform-specific window closing
        pass

    def _wipe_memory(self):
        """Wipe sensitive memory."""
        from src.core.security.memory_guard import SecureMemory
        memory = SecureMemory()
        # Implementation depends on memory tracking system

    def _execute_stealth_actions(self):
        """Execute stealth actions to hide panic."""
        stealth_config = self.config.get('stealth_actions', {})

        if stealth_config.get('show_fake_error', False):
            self._show_fake_error()

        if stealth_config.get('launch_decoy', False):
            self._launch_decoy_app()

    def _show_fake_error(self):
        """Show fake error message."""
        import tkinter.messagebox as mb
        mb.showerror(
            "Application Error",
            "The application has encountered an unexpected error and must close."
        )

    def _launch_decoy_app(self):
        """Launch decoy application."""
        # Platform-specific decoy launching
        pass

    def _log_panic_event(self, method: str):
        """Log panic activation event."""
        from src.core.audit.audit_logger import AuditLogger
        logger = AuditLogger.get_instance()
        logger.log_event(
            event_type="PANIC_MODE_ACTIVATED",
            severity="CRITICAL",
            source="panic_mode",
            details={"activation_method": method}
        )