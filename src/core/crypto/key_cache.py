import time
from typing import Optional
import threading

class KeyCache:
    def __init__(self, ttl_seconds: int =  3600 ):
        self._key: Optional[bytearray] = None
        self._created_at: Optional[float] = None
        self._last_access: Optional[float] = None
        self._ttl = ttl_seconds

        self._lock = threading.Lock()
    
    def store_key(self, key:bytes):
        with self._lock:
            self.clear_key() #очищаем если есть старый ключ
            
            self._key = bytearray(key) #сохраняем в bytearray для очистки если что
        self._created_at = time.time()
        self._last_access = time.time()
    
    def get_key(self, key: bytes):
        with self._lock:
            if self._key is None:  
                return None 
        
        if self._is_expired():
            self.clear_key()
            return None 
        
        self._last_access = time.time()        
        return bytes(self._key)

     # TTL проверка
    def _is_expired(self) -> bool:
        if self._created_at is None:
            return True

        now = time.time()

        # устаревание по времени жизни
        if (now - self._created_at) > self._ttl:
            return True

        return False