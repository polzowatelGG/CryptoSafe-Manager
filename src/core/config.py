

class StateManager:
    def __init__(self):
        self.session_locked = False # при создании новой сессии она будет разблокирована 
        
    def lock(self):
        self.session_locked = True 
        print('Сессия заблокирована') # блокировка сессии
        
    def unlock(self):
        self.session_locked = False 
        print('Сессия разблокирована') # разблокировка сессии
        
    def is_locked(self):
        return self.session_locked
    
    #first try