# Рализация класса LogSigner для создания и проверки цифровых подписей с использованием Ed25519
# и HKDF для получения ключа из мастер-ключа, предоставляемого менеджером ключей.

import cryptography.hazmat.primitives.asymmetric.ed25519 as ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

class LogSigner:
    def __init__(self, key_manager):
        # выводим приватный ключ из менеджера ключей и создаем объект для подписи
        self._private_key : ed25519.Ed25519PrivateKey = self._derive_signing_key(key_manager)
        self._public_key = self._private_key.public_key()

    def _derive_signing_key(self, key_manager) -> ed25519.Ed25519PrivateKey:
        # получаем мастер-ключ из менеджера ключей
        master_key = key_manager.get_active_key()# предполагается, что мастер-ключ возвращается в виде байтов
        
        # используем HKDF для получения ключа для подписи
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt= None,
            info=b'audit-signing',
        )
        signing_key_material = hkdf.derive(master_key)
        
        # создаем объект Ed25519PrivateKey из полученного материала
        return ed25519.Ed25519PrivateKey.from_private_bytes(signing_key_material)

    def sign(self, data: bytes) -> bytes:
        try:
            signature = self._private_key.sign(data)
            # если подпись успешно создана, возвращаем ее
            return signature
        except Exception as e:            # обработка ошибок при подписании
            raise Exception(f"Error signing data: {str(e)}")
        pass
    
    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            self._public_key.verify(signature, data)
            # если верификация прошла успешно, возвращаем True
            return True
        except InvalidSignature:
            return False
        except Exception as e:            # обработка других ошибок при верификации
            raise Exception(f"Error verifying signature: {str(e)}")
        pass    
    
    def get_public_key_bytes(self) -> bytes:
        # возвращаем публичный ключ в виде байтов для хранения или передачи
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )