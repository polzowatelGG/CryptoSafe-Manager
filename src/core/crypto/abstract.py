from abc import ABC, abstractmethod
from core.crypto.key_derivation import KeyDerivation
from core.crypto.key_cache import KeyCache

class EncryptionService(ABC):
    def __init__(self, key_manager: KeyDerivation, cache: KeyCache):
        self.key_manager = key_manager
        self.cache = cache

    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, ciphertext: bytes) -> bytes:
        pass