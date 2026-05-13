from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import json

NONCE_SIZE = 12   # байт, os.urandom(12)
TAG_SIZE   = 16   # байт, GCM authentication tag (добавляется библиотекой автоматически)
class AES256EncryptionService:
    def __init__(self, key_manager):
        self.key_manager = key_manager

    def encrypt(self, data: dict) -> bytes:
        key = self.key_manager.get_active_key()
        aesgcm = AESGCM(key)

        nonce = os.urandom(12)
        plaintext = json.dumps(data).encode()

        ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, None)

        # итоговый blob: nonce + ciphertext + tag
        return nonce + ciphertext_and_tag

    def decrypt(self, blob: bytes) -> dict:
        if len(blob) < NONCE_SIZE + TAG_SIZE:
            raise ValueError("Blob too short to be valid ciphertext")
        
        key = self.key_manager.get_active_key()
        aesgcm = AESGCM(key)

        nonce          = blob[:NONCE_SIZE]
        ciphertext_and_tag = blob[NONCE_SIZE:]

        # decrypt() проверяет GCM-тег автоматически —
        # при подмене данных бросает InvalidTag
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext_and_tag, None)
        except Exception:
            raise ValueError("Decryption failed: data corrupted or tag invalid")

        return json.loads(plaintext.decode("utf-8"))
