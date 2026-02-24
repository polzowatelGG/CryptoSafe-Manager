class Events:
    #хз че тут делать спрошу у ребят
    def EntryAdded(entry_id: str): # событие при добавлении новой записи в хранилище / доделать
        pass
    
    def EntryUpdated(entry_id: str): # событие при обновлении записи в хранилище / доделать
        pass
    
    def EntryDeleted(entry_id: str): # событие при удалении записи из хранилища / доделать
        pass
    
    def userLoggedIn(user_id: str): # событие при входе пользователя в систему / доделать
        pass
    
    def userLoggedOut(user_id: str): # событие при выходе пользователя из системы / доделать
        pass
    
    def ClipboardCopied(entry_id: str):     # Cобытие при копировании данных в буфер обмена / зашлушка
        pass
    
    def ClipboardCleared():     # Событие при очистке буфера обмена / зашлушка
        pass