from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import json

class AES256EncryptionService:
    def __init__(self, key_manager):
        self.key_manager = key_manager

    def encrypt(self, data: dict) -> bytes:
        key = self.key_manager.get_active_key()
        aesgcm = AESGCM(key)

        nonce = os.urandom(12)
        plaintext = json.dumps(data).encode()

        ciphertext = aesgcm.encrypt(nonce, plaintext, None) 
        return nonce + ciphertext

    def decrypt(self, blob: bytes) -> dict:
        key = self.key_manager.get_active_key()
        aesgcm = AESGCM(key)

        nonce = blob[:12]
        ciphertext = blob[12:]

        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode())