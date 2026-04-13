import threading

class StateManager:
    def __init__(self, config, key_manager=None):
        self.config = config
        self.key_manager = key_manager
        self.session_locked = False
        self.clipboard = None
        self.clipboard_timer = None
        self.inactivity_timer = None

        self.clipboard_timeout = self.config.get_preference("clipboard_timeout")
        auto_lock = self.config.get_preference("auto_lock")
        self.inactivity_timeout = self.clipboard_timeout * 5 if auto_lock else None

    def lock(self):
        self.session_locked = True
        if self.key_manager:
            self.key_manager.lock()   # блокируем доступ к ключам

    def unlock(self):
        self.session_locked = False

    def is_locked(self):
        return self.session_locked

    def set_clipboard(self, data):
        self.clipboard = data
        self.start_clipboard_timer()

    def get_clipboard(self):
        return self.clipboard

    def clear_clipboard(self):
        self.clipboard = None

    def start_clipboard_timer(self):
        if self.clipboard_timer:
            self.clipboard_timer.cancel()
        self.clipboard_timer = threading.Timer(self.clipboard_timeout, self.clear_clipboard)
        self.clipboard_timer.start()

    def reset_inactivity_timer(self):
        if self.inactivity_timer:
            self.inactivity_timer.cancel()
        if self.inactivity_timeout:
            self.inactivity_timer = threading.Timer(self.inactivity_timeout, self.lock)
            self.inactivity_timer.start()