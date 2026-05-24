# state_manager.py - модуль для управления состоянием приложения, включая блокировку сессии, таймеры неактивности и буфер обмена. он взаимодействует с key_manager 
# для блокировки доступа к ключам при блокировке сессии и может использоваться для автоматической блокировки после определенного времени неактивности. 
import threading

class StateManager:
    def __init__(self, config, key_manager=None, event_bus = None):
        self.config = config
        self._event_bus = event_bus
        self.key_manager = key_manager
        self.session_locked = False 
        self.inactivity_timer = None
        self.inactivity_timeout = config.get_preference('inactivity_timeout') or 300
        self._clipboard_value = None
        self._clipboard_timer = None
    
    def lock(self):
        self.session_locked = True
        if self._event_bus:
            self._event_bus.publish("VaultLocked", reason="manual")

    def unlock(self):
        self.session_locked = False
        if self._event_bus:
            self._event_bus.publish("VaultUnlocked")

    def is_locked(self) -> bool: #метод для проверки, заблокирована ли сессия. он возвращает True, если сессия заблокирована, и False в противном случае. он может использоваться в других частях приложения для проверки состояния блокировки перед выполнением действий, требующих доступа к ключам или другим защищенным ресурсам.
        return self.session_locked

    def reset_inactivity_timer(self): #метод для сброса таймера неактивности. он останавливает существующий таймер, если он запущен, и запускает новый таймер с заданным временем, после которого будет вызван метод lock для блокировки сессии из-за неактивности. этот метод должен быть вызван при каждом взаимодействии пользователя с приложением, чтобы предотвратить автоматическую блокировку во время активного использования.
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