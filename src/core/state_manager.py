import threading

class StateManager: 
    def __init__(self, config):
        self.config = config
        self.session_locked = False
        self.clipboard = None
        self.clipboard_timer = None
        self.inactivity_timer = None

        # берём настройки из config
        self.clipboard_timeout = self.config.get_preference("clipboard_timeout")
        auto_lock = self.config.get_preference("auto_lock")
        self.inactivity_timeout = self.clipboard_timeout * 5 if auto_lock else None

    def lock(self):
        self.session_locked = True  # блокируем сессию
        
    def unlock(self):
        self.session_locked = False # разблокируем сессию
        
    def is_locked(self):
        return self.session_locked # возвращаем статус блокировки сессии
    
    def set_clipboard(self, data):
        self.clipboard = data  # обновляем буфер обмена
        self.start_clipboard_timer()  # запускаем таймер очистки буфера
        
    def get_clipboard(self):
        return self.clipboard  # возвращаем содержимое буфера
    
    def clear_clipboard(self):
        self.clipboard = None  # очищаем буфер обмена
        
    def start_clipboard_timer(self):
        if self.clipboard_timer:
            self.clipboard_timer.cancel()  # если таймер уже запущен — отменяем его
            
        self.clipboard_timer = threading.Timer(self.clipboard_timeout, self.clear_clipboard)
        self.clipboard_timer.start()  # создаём и запускаем новый таймер для очистки
        
    def reset_inactivity_timer(self):
        if self.inactivity_timer:
            self.inactivity_timer.cancel()  # отменяем старый таймер
        
        self.inactivity_timer = threading.Timer(self.inactivity_timeout, self.lock)  # создаём таймер авто-блокировки
        self.inactivity_timer.start()  # запускаем таймер
