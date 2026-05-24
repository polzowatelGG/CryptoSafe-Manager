# Рализация класса LogSigner для создания и проверки цифровых подписей с использованием Ed25519
# и HKDF для получения ключа из мастер-ключа, предоставляемого менеджером ключей.
from typing import Optional
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
    def save_public_key_to_db(self, db) -> None:
        # сохраняем публичный ключ в таблицу audit_signing_keys
        # вызывается один раз при инициализации AuditLogger
        public_key_hex = self.get_public_key_bytes().hex()

        # проверяем — не сохранён ли уже этот ключ
        row = db.execute(
            "SELECT id FROM audit_signing_keys WHERE public_key = ?",
            (public_key_hex,)
        ).fetchone()

        if not row:
            db.execute(
                """
                INSERT INTO audit_signing_keys (public_key, algorithm, is_active)
                VALUES (?, 'Ed25519', 1)
                """,
                (public_key_hex,),
                commit=True
            )

    @classmethod
    def load_from_db(cls, db) -> Optional["LogSigner"]:
        # загружаем активный публичный ключ из БД для верификации
        # используется LogVerifier при проверке подписей
        row = db.execute(
            "SELECT public_key FROM audit_signing_keys WHERE is_active = 1 "
            "ORDER BY created_at DESC LIMIT 1"
        ).fetchone()

        if not row:
            return None

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        public_key_bytes = bytes.fromhex(row["public_key"])
        publik_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        # возвращаем только публичный ключ — для верификации приватный не нужен
        instance = object.__new__(cls)
        instance.key_manager = None
        instance._private_key = None
        instance._public_key = publik_key
        return instance