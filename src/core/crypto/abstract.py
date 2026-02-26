from abc import ABC, abstractmethod # абстрактный класс для криптографических сервисов

class EncryptionService(ABC): 
    @abstractmethod # абстрактный метод для шифрования данных в дочернем классе
    def encrypt(self, data: bytes, key: bytes) -> bytes: #зашифровать данные с помощью ключа в дочернем классе
        pass #реализование в placeholder 

    @abstractmethod
    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes: #расшифровать данные с помощью ключа в дочернем классе
        pass #реализование в placeholder