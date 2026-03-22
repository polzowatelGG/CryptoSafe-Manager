import time
from typing import Optional

class KeyCache:
    def __init__(self, ttl_seconds: int =  3600 ):
        self._key: Optional[bytearray] = None
        self._created_at: Optional[float] = None 
        self._last_access: Optional[float] = None
        self._ttl = ttl_seconds
    
    def store_key(self, key:bytes):
        self.clear_key() #очищаем если есть старый ключ
        
        self._key = bytearray(key) #сохраняем в bytearray для очистки если что
        self._created_at = time.time()
        self._last_access = time.time()
    
    def get_key(self, key: bytes):
        if self._key is None:
            return None 
        
        if self._is_expired():
            self.clear_key()
            return None 
        
        self._last_access = time.time()        
        return bytes(self._key)

    def clear_key(self, key: bytes):
        if self._key() is not None:
            for i in range (len(self._key)):
                self._key[i] = 0
                
        self._key = None 
        self._created_at = None 
        self._last_access = None 
        return
    
    def _is_expired(self):
        if self._created_at is None:
            return True 
        
        return (time.time() - self._created_at) > self._ttl
        