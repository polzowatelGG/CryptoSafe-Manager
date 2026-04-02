from core.crypto.abstract import EncryptionService

class AES256Placeholder(EncryptionService):
    def encrypt(self, data: bytes) -> bytes:
        key = self.cache.get_key()  # берём ключ из кэша
        if key is None:
            raise ValueError("Encryption key not available in cache")
        return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

    def decrypt(self, ciphertext: bytes) -> bytes:
        key = self.cache.get_key()
        if key is None:
            raise ValueError("Encryption key not available in cache")
        return bytes([b ^ key[i % len(key)] for i, b in enumerate(ciphertext)])