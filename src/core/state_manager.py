import threading

class StateManager:
    def __init__(self):
        self.session_locked = False  # при создании новой сессии она будет разблокирована 
        
        self.clipboard = None  # содержимое буфера обмена
        self.clipboard_timer = None  # объект таймера очистки буфера
        self.clipboard_timeout = 67  # хранение данных в буфере 67 сек
        
        self.inactivity_timer = None  # таймер неактивности пользователя
        self.inactivity_timeout = self.clipboard_timeout * 5  # через 335 сек включается авто-блокировка
        
    def lock(self):
        self.session_locked = True
        print('Сессия заблокирована')  # блокировка сессии
        
    def unlock(self):
        self.session_locked = False
        print('Сессия разблокирована')  # разблокировка сессии
        
    def is_locked(self):
        return self.session_locked
    
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
