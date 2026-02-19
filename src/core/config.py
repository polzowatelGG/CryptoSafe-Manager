import threading

class StateManager:
    def __init__(self):
        self.session_locked = False # при создании новой сессии она будет разблокирована 
        
        self.clipboard = None # содержимое буффера обмена 
        self.clipboard_timer = None # таймер очистки буффера по умолчанию 
        self.clipboard_timeout = 67 # хранение данных в буффере 67 сек. 
        
        self.inactivity_timer = None # таймер неактивности 
        self.inactivity_timeout = self.clipboard_timeout*5 # через 335 сек вкл 
        
    def lock(self):
        self.session_locked = True 
        print('Сессия заблокирована') # блокировка сессии
        
    def unlock(self):
        self.session_locked = False 
        print('Сессия разблокирована') # разблокировка сессии
        
    def is_locked(self):
        return self.session_locked
    
    def set_clipboard(self, data):
        self.clipboard = data # обновляем буффер обмена  
        self.clipboard_timer() # вкл таймер
        
    def get_clipboard(self, data):
        return self.clipboard 
    
    def clear_clipboard(self):
        self.clipboard = None # очищаем буффер обмена 
        
    def start_clipboard_timer(self):
        if self.clipboard_timer:
            self.clipboard_timer.cancel() # если таймер уже запущен - отменяем 
            
        self.clipboard_timer = threading.Timer(self.clipboard_timeout, self.clear_clipboard)
        self.clipboard_timer.start() # создаём новый таймер для очистки
        
    def reset_inactivity_timer(self):
        if self.inactivity_timer:
            self.inactivity_timer.cancel()
        self.inactivity_timer = threading.Timer(self.inactivity_timeout, self.lock) # автоблокировка от бездействия пользователя 
        
