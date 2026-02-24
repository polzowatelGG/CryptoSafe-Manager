from core.crypto.abstract import EncryptionService

class AES256Placeholder(EncryptionService):
    """Placeholder service; encrypt/decrypt with simple XOR."""

    def encrypt(self, data: bytes, key: bytes) -> bytes:  # зашифровать данные с помощью ключа
        if not key:
            raise ValueError("key must not be empty")
        # XOR each byte of data with corresponding byte of key (cycled)
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:  # расшифровать данные с помощью ключа
        if not key:
            raise ValueError("key must not be empty")
        # XOR is its own inverse
        return bytes(c ^ key[i % len(key)] for i, c in enumerate(ciphertext))