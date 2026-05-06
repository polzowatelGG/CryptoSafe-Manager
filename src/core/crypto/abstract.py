# этот файл определяет абстрактный класс для шифрования и дешифрования данных, который может быть реализован различными алгоритмами шифрования. 
# он также поддерживает использование менеджера ключей и кеша для оптимизации работы с ключами.

from abc import ABC, abstractmethod
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from core.crypto.key_cache import KeyCache

class EncryptionService(ABC): # абстрактный класс для шифрования и дешифрования данных
    def __init__(self, key_manager=None):
        self.key_manager = key_manager
        
    def _get_key(self, key: Optional[bytes] = None) -> bytes: # метод для получения ключа шифрования из менеджера ключей. он пытается получить ключ из кеша, и если он недоступен, он вызывает исключение. этот метод используется в реализациях шифрования для получения ключа при необходимости.
        if key is not None:
            return key
        if self.key_manager is None:
            raise ValueError("KeyManager не установлен и ключ не передан")
        return self.key_manager.get_active_key()

    @abstractmethod
    def encrypt(self, data: bytes, key: Optional[bytes] = None) -> bytes: # абстрактный метод для шифрования данных, который должен быть реализован в подклассах
        pass

    @abstractmethod
    def decrypt(self, ciphertext: bytes, key: Optional[bytes] = None) -> bytes: # абстрактный метод для дешифрования данных, который должен быть реализован в подклассах
        pass