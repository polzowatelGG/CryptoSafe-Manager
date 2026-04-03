import time
from typing import Optional
import threading

class KeyCache:
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

    def get_key(self) -> Optional[bytes]:
        with self._lock:
            if self._key is None:
                return None

            if self._is_expired():
                self._secure_clear()
                return None

            self._last_access = time.time()
            return bytes(self._key)

    def clear_key(self):
        with self._lock:
            self._secure_clear()

    def _is_expired(self) -> bool:
        if self._created_at is None:
            return True

        return (time.time() - self._created_at) > self._ttl

    def _secure_clear(self):
        if self._key is not None:
            for i in range(len(self._key)):
                self._key[i] = 0

        self._key = None
        self._created_at = None
        self._last_access = None