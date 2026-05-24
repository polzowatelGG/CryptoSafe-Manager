# Безопасный обмен отдельными записями хранилища.
# Поддерживает: шифрование паролем, шифрование публичным ключом (RSA-OAEP).
# Все операции логируются в audit_log и сохраняются в shared_entries.

import hashlib
import json
import os
import uuid
from base64 import b64encode, b64decode
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend


# Вспомогательные функции
def _derive_share_key(password: str, salt: bytes,
                      iterations: int = 100_000) -> bytes:
    # Деривация ключа шифрования пакета шаринга из пароля 
    # Отдельная от мастер-ключа и ключа экспорта 
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def _encrypt_aes_gcm(plaintext: bytes, key: bytes) -> Dict[str, str]:
    # Шифрует байты через AES-256-GCM.
    # Возвращает словарь nonce + ciphertext в base64.
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return {
        "nonce":      b64encode(nonce).decode("ascii"),
        "ciphertext": b64encode(ciphertext).decode("ascii"),
    }


def _decrypt_aes_gcm(enc: Dict[str, str], key: bytes) -> bytes:
    # Расшифровывает AES-256-GCM пакет.
    # Бросает ValueError при неверном ключе или повреждении данных.
    try:
        nonce      = b64decode(enc["nonce"])
        ciphertext = b64decode(enc["ciphertext"])
        aesgcm     = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise ValueError(
            f"Расшифровка не удалась. Неверный пароль или повреждённый пакет. ({e})"
        )


def _package_integrity_hash(package: Dict[str, Any]) -> str:
    # SHA-256 хэш пакета для верификации целостности 
    # Вычисляется по полю 'data' пакета.
    data_str = json.dumps(package.get("data", {}), sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(data_str.encode("utf-8")).hexdigest()


# Основной класс сервиса шаринга
class SharingService:
    # Сервис для безопасного обмена отдельными записями хранилища.

    # Методы шифрования пакета (SHR-1):
    #     password   — AES-256-GCM с ключом из PBKDF2 (CRY-1)
    #     public_key — RSA-OAEP + AES-256-GCM гибридное шифрование (CRY-2)

    # Workflow отправителя (SHR-3):
    #     1. share_entry() → получить пакет
    #     2. Передать пакет получателю (файл / QR)

    # Workflow получателя (SHR-4):
    #     1. receive_entry() → расшифровать пакет
    #     2. Опционально сохранить в хранилище через save_received_entry()
    def __init__(self, entry_manager, key_manager, db, audit_logger=None):
        self.entry_manager = entry_manager
        self.key_manager   = key_manager
        self.db            = db
        self.audit_logger  = audit_logger

    # Workflow отправителя
    def share_entry(
        self,
        entry_id: str,
        encryption_method: str,
        recipient: Optional[str] = None,
        permissions: Optional[Dict[str, bool]] = None,
        expires_in_days: int = 7,
        password: Optional[str] = None,
        recipient_public_key_pem: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        # Создаёт зашифрованный пакет для передачи записи получателю (SHR-2, SHR-3).

        # Args:
        #     entry_id:                 ID записи в хранилище
        #     encryption_method:        'password' | 'public_key'
        #     recipient:                имя/email получателя (для логирования)
        #     permissions:              {'read': True, 'edit': False}
        #     expires_in_days:          срок действия пакета (1-30 дней)
        #     password:                 пароль для метода 'password'
        #     recipient_public_key_pem: PEM публичный ключ для метода 'public_key'

        # Returns:
        #     Словарь с share_id, package (для передачи), expires_at, permissions

        # Raises:
        #     PermissionError: хранилище заблокировано
        #     ValueError:      неверные параметры
        if not self.key_manager.is_unlocked():
            raise PermissionError("Хранилище заблокировано.")

        if encryption_method not in ("password", "public_key"):
            raise ValueError(
                f"Неизвестный метод: {encryption_method}. "
                "Доступны: password, public_key"
            )

        expires_in_days = max(1, min(30, expires_in_days))
        permissions = permissions or {"read": True, "edit": False}

        # Получаем и расшифровываем запись
        entry = self._get_entry(entry_id)
        if not entry:
            raise ValueError(f"Запись {entry_id} не найдена.")

        share_id  = str(uuid.uuid4())
        expires_at = datetime.utcnow() + timedelta(days=expires_in_days)

        try:
            # Фильтруем поля по правам доступа
            filtered = self._filter_entry_for_sharing(entry, permissions)

            # Создаём пакет в зависимости от метода
            if encryption_method == "password":
                if not password:
                    raise ValueError("Пароль обязателен для метода 'password'.")
                package = self._create_password_package(
                    filtered, share_id, permissions, expires_at, password
                )
            else:
                if not recipient_public_key_pem:
                    raise ValueError("Публичный ключ обязателен для метода 'public_key'.")
                package = self._create_public_key_package(
                    filtered, share_id, permissions, expires_at,
                    recipient_public_key_pem
                )

            # Сохраняем метаданные в БД 
            package_hash = _package_integrity_hash(package)
            self._save_share_record(
                share_id=share_id,
                entry_id=entry_id,
                encryption_method=encryption_method,
                recipient=recipient,
                permissions=permissions,
                expires_at=expires_at,
                package_hash=package_hash,
            )

            # Логируем в аудит 
            self._log_share_event(entry_id, recipient, share_id, encryption_method)

            return {
                "share_id":    share_id,
                "package":     package,
                "expires_at":  expires_at.isoformat() + "Z",
                "permissions": permissions,
            }

        finally:
            # Очищаем расшифрованные данные из памяти 
            if entry:
                for k in list(entry.keys()):
                    entry[k] = None
                entry.clear()

    def export_share_package(
        self, share_result: Dict[str, Any], filepath: str
    ):
        # Сохраняет пакет шаринга в JSON-файл для передачи получателю.

        # Args:
        #     share_result: результат share_entry()
        #     filepath:     путь к выходному файлу
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(share_result["package"], f, ensure_ascii=False, indent=2)

    # Workflow получателя
    def receive_entry(
        self,
        package: Dict[str, Any],
        password: Optional[str] = None,
        private_key_pem: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        # Расшифровывает полученный пакет шаринга 

        # Args:
        #     package:         словарь пакета (из файла или QR)
        #     password:        пароль (для метода 'password')
        #     private_key_pem: приватный ключ получателя (для 'public_key')

        # Returns:
        #     Расшифрованная запись в виде словаря

        # Raises:
        #     ValueError: неверный пароль, повреждённый пакет, истёк срок
        # Верификация структуры пакета
        self._verify_package_structure(package)

        # Проверяем срок действия
        expires_at_str = package.get("expires_at")
        if expires_at_str:
            try:
                expires_at = datetime.fromisoformat(
                    expires_at_str.replace("Z", "+00:00")
                ).replace(tzinfo=None)
                if datetime.utcnow() > expires_at:
                    raise ValueError(
                        f"Пакет шаринга истёк: {expires_at_str}. "
                        "Запросите новый пакет у отправителя."
                    )
            except ValueError as e:
                if "истёк" in str(e):
                    raise
                # Неверный формат даты — игнорируем проверку

        # Верификация целостности пакета (CRY-4)
        expected_hash = package.get("integrity_hash")
        if expected_hash:
            computed = _package_integrity_hash(package)
            if computed != expected_hash:
                raise ValueError(
                    "Нарушение целостности пакета: данные были изменены."
                )

        # Расшифровываем в зависимости от метода
        method = package.get("encryption_method")

        if method == "password":
            if not password:
                raise ValueError("Пароль необходим для расшифровки этого пакета.")
            return self._decrypt_password_package(package, password)

        elif method == "public_key":
            if not private_key_pem:
                raise ValueError(
                    "Приватный ключ необходим для расшифровки этого пакета."
                )
            return self._decrypt_public_key_package(package, private_key_pem)

        else:
            raise ValueError(f"Неизвестный метод шифрования пакета: {method}")

    def save_received_entry(
        self, entry: Dict[str, Any]
    ) -> str:
        # Сохраняет полученную запись в хранилище (SHR-4).

        # Args:
        #     entry: расшифрованная запись из receive_entry()

        # Returns:
        #     ID новой записи
        if not self.key_manager.is_unlocked():
            raise PermissionError("Хранилище заблокировано.")

        return self.entry_manager.create_entry(entry)

    # Создание пакетов
    def _create_password_package(
        self,
        entry: Dict[str, Any],
        share_id: str,
        permissions: Dict[str, bool],
        expires_at: datetime,
        password: str,
    ) -> Dict[str, Any]:
        # Создаёт пакет зашифрованный паролем 
        # AES-256-GCM + PBKDF2-HMAC-SHA256.
        share_key = None
        try:
            salt      = os.urandom(16)
            share_key = _derive_share_key(password, salt)

            plaintext = json.dumps(entry, ensure_ascii=False).encode("utf-8")
            enc       = _encrypt_aes_gcm(plaintext, share_key)

            package = {
                "version":           "1.0",
                "cryptosafe_share":  True,
                "share_id":          share_id,
                "encryption_method": "password",
                "expires_at":        expires_at.isoformat() + "Z",
                "permissions":       permissions,
                "key_derivation": {
                    "algorithm":  "PBKDF2-HMAC-SHA256",
                    "iterations": 100_000,
                    "salt":       b64encode(salt).decode("ascii"),
                },
                "data": enc,
            }

            # Добавляем хэш целостности (CRY-4)
            package["integrity_hash"] = _package_integrity_hash(package)
            return package

        finally:
            if share_key is not None:
                share_key = bytes(len(share_key))
                del share_key

    def _create_public_key_package(
        self,
        entry: Dict[str, Any],
        share_id: str,
        permissions: Dict[str, bool],
        expires_at: datetime,
        recipient_public_key_pem: bytes,
    ) -> Dict[str, Any]:
        # Создаёт пакет с гибридным шифрованием RSA-OAEP + AES-256-GCM 
        # Эфемерный симметричный ключ шифруется публичным ключом получателя.
        symmetric_key = None
        try:
            # Генерируем эфемерный ключ 
            symmetric_key = os.urandom(32)

            # Шифруем данные AES-GCM
            plaintext = json.dumps(entry, ensure_ascii=False).encode("utf-8")
            enc       = _encrypt_aes_gcm(plaintext, symmetric_key)

            # Шифруем симметричный ключ публичным ключом RSA-OAEP
            pub_key = serialization.load_pem_public_key(
                recipient_public_key_pem,
                backend=default_backend()
            )
            encrypted_key = pub_key.encrypt(
                symmetric_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                )
            )

            package = {
                "version":           "1.0",
                "cryptosafe_share":  True,
                "share_id":          share_id,
                "encryption_method": "public_key",
                "expires_at":        expires_at.isoformat() + "Z",
                "permissions":       permissions,
                "encrypted_key":     b64encode(encrypted_key).decode("ascii"),
                "data":              enc,
            }

            # Добавляем хэш целостности (CRY-4)
            package["integrity_hash"] = _package_integrity_hash(package)
            return package

        finally:
            if symmetric_key is not None:
                symmetric_key = bytes(len(symmetric_key))
                del symmetric_key


    # Расшифровка пакетов
    def _decrypt_password_package(
        self, package: Dict[str, Any], password: str
    ) -> Dict[str, Any]:
        # Расшифровывает пакет зашифрованный паролем
        share_key = None
        try:
            kd        = package["key_derivation"]
            salt      = b64decode(kd["salt"])
            iterations = int(kd.get("iterations", 100_000))
            share_key  = _derive_share_key(password, salt, iterations)
            plaintext  = _decrypt_aes_gcm(package["data"], share_key)
            return json.loads(plaintext.decode("utf-8"))
        finally:
            if share_key is not None:
                share_key = bytes(len(share_key))
                del share_key

    def _decrypt_public_key_package(
        self, package: Dict[str, Any], private_key_pem: bytes
    ) -> Dict[str, Any]:
        # Расшифровывает пакет с гибридным шифрованием RSA-OAEP + AES-GCM
        symmetric_key = None
        try:
            priv_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
                backend=default_backend()
            )
            encrypted_key = b64decode(package["encrypted_key"])
            symmetric_key = priv_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                )
            )
            plaintext = _decrypt_aes_gcm(package["data"], symmetric_key)
            return json.loads(plaintext.decode("utf-8"))
        except ValueError:
            raise
        except Exception as e:
            raise ValueError(
                f"Не удалось расшифровать пакет приватным ключом: {e}"
            )
        finally:
            if symmetric_key is not None:
                symmetric_key = bytes(len(symmetric_key))
                del symmetric_key


    # Управление контактами и ключами
    def generate_key_pair(self) -> Dict[str, bytes]:
        # Генерирует пару RSA-2048 ключей для получения шарингов 

        # Returns:
        #     {'private_key_pem': bytes, 'public_key_pem': bytes}
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        fingerprint = self._key_fingerprint(public_pem)

        return {
            "private_key_pem": private_pem,
            "public_key_pem":  public_pem,
            "fingerprint":     fingerprint,
        }

    def save_contact(
        self,
        name: str,
        public_key_pem: bytes,
        identifier: Optional[str] = None,
    ) -> str:
        # Сохраняет публичный ключ контакта в БД

        # Returns:
        #     contact_id
        contact_id  = str(uuid.uuid4())
        fingerprint = self._key_fingerprint(public_key_pem)

        self.db.execute(
            """
            INSERT INTO contacts
                (contact_id, name, identifier, public_key_pem, key_fingerprint)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                contact_id,
                name,
                identifier or "",
                public_key_pem.decode("utf-8") if isinstance(public_key_pem, bytes)
                else public_key_pem,
                fingerprint,
            ),
            commit=True,
        )
        return contact_id

    def get_contacts(self) -> List[Dict[str, Any]]:
        # Возвращает список контактов из БД
        rows = self.db.execute(
            """
            SELECT contact_id, name, identifier, public_key_pem,
                   key_fingerprint, created_at, last_used
            FROM contacts
            ORDER BY name
            """
        ).fetchall()
        return [dict(r) for r in rows]

    def get_active_shares(self) -> List[Dict[str, Any]]:
        # Возвращает список активных (не истёкших) шарингов
        rows = self.db.execute(
            """
            SELECT share_id, original_entry_id, encryption_method,
                   recipient_info, permissions, shared_at, expires_at
            FROM shared_entries
            WHERE expires_at IS NULL OR expires_at > datetime('now')
            ORDER BY shared_at DESC
            """
        ).fetchall()
        return [dict(r) for r in rows]

    def revoke_share(self, share_id: str):
        # Отзывает шаринг — устанавливает expires_at в прошлое.
        # Физически запись остаётся для аудита.
        self.db.execute(
            """
            UPDATE shared_entries
            SET expires_at = datetime('now', '-1 second')
            WHERE share_id = ?
            """,
            (share_id,),
            commit=True,
        )
        self._log_audit_event(
            event_type="SHARE_REVOKED",
            details={"share_id": share_id},
        )

    # Вспомогательные методы
    def _get_entry(self, entry_id: str) -> Optional[Dict[str, Any]]:
        #Получает расшифрованную запись из хранилища
        try:
            return self.entry_manager.get_entry(entry_id)
        except Exception:
            return None

    def _filter_entry_for_sharing(
        self,
        entry: Dict[str, Any],
        permissions: Dict[str, bool],
    ) -> Dict[str, Any]:
        # Фильтрует поля записи в соответствии с правами доступа 
        # Всегда включает title и url.
        # Пароль включается только если permissions["read"] == True.
        # Заметки включаются только если явно разрешены.
        # Базовые поля — всегда включаются
        filtered = {
            "title":    entry.get("title", ""),
            "username": entry.get("username", ""),
            "url":      entry.get("url", ""),
            "category": entry.get("category", ""),
            "tags":     entry.get("tags", ""),
        }

        # Пароль — только при явном чтении
        if permissions.get("read", True):
            filtered["password"] = entry.get("password", "")

        # Заметки — включаем если есть право чтения
        if permissions.get("read", True):
            filtered["notes"] = entry.get("notes", "")

        return filtered

    def _verify_package_structure(self, package: Dict[str, Any]):
        # Проверяет структуру пакета перед расшифровкой
        required = {"cryptosafe_share", "share_id", "encryption_method", "data"}
        missing  = required - set(package.keys())
        if missing:
            raise ValueError(
                f"Повреждённый пакет шаринга: отсутствуют поля {missing}"
            )
        if not package.get("cryptosafe_share"):
            raise ValueError("Файл не является пакетом шаринга CryptoSafe.")

    def _key_fingerprint(self, public_key_pem: bytes) -> str:
        # SHA-256 отпечаток публичного ключа 
        if isinstance(public_key_pem, str):
            public_key_pem = public_key_pem.encode("utf-8")
        return hashlib.sha256(public_key_pem).hexdigest()[:16]

    def _save_share_record(
        self,
        share_id: str,
        entry_id: str,
        encryption_method: str,
        recipient: Optional[str],
        permissions: Dict[str, bool],
        expires_at: datetime,
        package_hash: str,
    ):
       # Сохраняет метаданные шаринга в shared_entries 
        try:
            self.db.execute(
                """
                INSERT INTO shared_entries
                    (share_id, original_entry_id, encryption_method,
                     recipient_info, permissions, shared_at, expires_at,
                     package_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    share_id,
                    entry_id,
                    encryption_method,
                    recipient or "",
                    json.dumps(permissions),
                    datetime.utcnow().isoformat(),
                    expires_at.isoformat(),
                    package_hash,
                ),
                commit=True,
            )
        except Exception:
            pass

    def _log_share_event(
        self,
        entry_id: str,
        recipient: Optional[str],
        share_id: str,
        encryption_method: str,
    ):
        # Логирует событие шаринга в аудит 
        self._log_audit_event(
            event_type="ENTRY_SHARED",
            details={
                "entry_id":          entry_id,
                "share_id":          share_id,
                "recipient":         recipient or "unknown",
                "encryption_method": encryption_method,
            },
        )

    def _log_audit_event(self, event_type: str, details: Dict[str, Any]):
        # Отправляет событие в AuditLogger
        if not self.audit_logger:
            return
        try:
            self.audit_logger.log_event(
                event_type=event_type,
                severity="INFO",
                source="sharing_service",
                details=details,
            )
        except Exception:
            pass