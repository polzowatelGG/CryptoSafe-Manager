from abc import ABC, abstractmethod
from typing import Optional
from core.crypto.key_derivation import KeyDerivation
from core.crypto.key_cache import KeyCache

class EncryptionService(ABC):
    def __init__(
        self,
        key_manager: Optional[KeyDerivation] = None,
        cache: Optional[KeyCache] = None,
    ):
        self.key_manager = key_manager
        self.cache = cache

    @abstractmethod
    def encrypt(self, data: bytes, key: Optional[bytes] = None) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, ciphertext: bytes, key: Optional[bytes] = None) -> bytes:
        pass