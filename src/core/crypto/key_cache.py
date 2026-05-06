# этот файл определяет класс KeyCache, который отвечает за безопасное хранение ключа в памяти с поддержкой TTL (времени жизни) и автоматической очисткой при истечении срока действия. он также обеспечивает потокобезопасность при доступе к ключу.

import time
from typing import Optional
import threading

class KeyCache: # класс KeyCache, который отвечает за безопасное хранение ключа в памяти с поддержкой TTL (времени жизни) и автоматической очисткой при истечении срока действия. он также обеспечивает потокобезопасность при доступе к ключу.
    def __init__(self, ttl_seconds: int = 3600):
        self._key: Optional[bytearray] = None
        self._created_at: Optional[float] = None
        self._last_access: Optional[float] = None
        self._ttl = ttl_seconds

        self._lock = threading.RLock()

    def store_key(self, key: bytes): 
        with self._lock:
            self._secure_clear()

            self._key = bytearray(key)
            now = time.time()

            self._created_at = now
            self._last_access = now

    def get_key(self) -> Optional[bytes]: # метод для получения ключа из кэша. он возвращает ключ, если он еще не истек, и None в противном случае. он также обновляет время последнего доступа при каждом вызове.
        with self._lock:
            if self._key is None:
                return None

            if self._is_expired():                                                                             
                self._secure_clear()
                return None

            self._last_access = time.time()
            return bytes(self._key)

    def clear_key(self): # метод для очистки ключа из кэша. он безопасно очищает память, удаляя содержимое ключа и сбрасывая все связанные метаданные.
        with self._lock:
            self._secure_clear()

    def _is_expired(self) -> bool: # метод для проверки, истек ли срок действия ключа. он возвращает True, если ключ истек, и False в противном случае. если ключ еще не был создан, он также считается истекшим.
        if self._created_at is None:
            return True

        return (time.time() - self._created_at) > self._ttl

    def _secure_clear(self): # метод для безопасной очистки ключа из памяти. он перезаписывает содержимое ключа нулями перед удалением ссылки на него, чтобы предотвратить возможность восстановления ключа из памяти.
        if self._key is not None:
            for i in range(len(self._key)):
                self._key[i] = 0

        self._key = None
        self._created_at = None
        self._last_access = None