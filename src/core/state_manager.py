# state_manager.py - управление состоянием приложения.
# Спринт 7: добавлен activity_monitor_ref для сигнала активности из eventFilter.

import threading


class StateManager:
    def __init__(self, config, key_manager=None, event_bus=None):
        self.config = config
        self._event_bus = event_bus
        self.key_manager = key_manager
        self.session_locked = False
        self.inactivity_timer = None
        self.inactivity_timeout = config.get_preference('inactivity_timeout') or 300
        self._clipboard_value = None
        self._clipboard_timer = None

        self.activity_monitor = None

    def lock(self):
        self.session_locked = True
        if self.key_manager:
            self.key_manager.lock()
        if self._event_bus:
            self._event_bus.publish("VaultLocked", reason="manual")

    def unlock(self):
        self.session_locked = False
        if self._event_bus:
            self._event_bus.publish("VaultUnlocked")

    def is_locked(self) -> bool:
        return self.session_locked

    def reset_inactivity_timer(self):
        """Сброс таймера неактивности (legacy — используйте activity_monitor.record_activity)."""
        if self.activity_monitor:
            self.activity_monitor.record_activity()
            return

        if self.inactivity_timer:
            self.inactivity_timer.cancel()
        if self.inactivity_timeout:
            self.inactivity_timer = threading.Timer(self.inactivity_timeout, self.lock)
            self.inactivity_timer.daemon = True
            self.inactivity_timer.start()

    def set_clipboard(self, value: str):
        if self._clipboard_timer:
            self._clipboard_timer.cancel()
            self._clipboard_timer = None
        self._clipboard_value = value
        timeout = self.config.get_preference('clipboard_timeout') or 30
        self._clipboard_timer = threading.Timer(timeout, self._clear_clipboard)
        self._clipboard_timer.daemon = True
        self._clipboard_timer.start()

    def get_clipboard(self):
        return self._clipboard_value

    def _clear_clipboard(self):
        self._clipboard_value = None
        self._clipboard_timer = None