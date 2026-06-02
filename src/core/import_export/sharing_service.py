
# src/core/import_export/sharing_service.py
import base64
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend

from ..security.side_channel_protection import constant_time_compare
from .crypto import (
    checksum,
    decrypt_aes_gcm,
    decrypt_with_private_key,
    derive_password_key,
    encrypt_aes_gcm,
    encrypt_with_public_key,
    new_salt_and_nonce,
    public_key_fingerprint,
    random_bytes,
    wipe_bytes,
)
from .exceptions import ImportValidationError
from .models import SharePermissions


class SharingService:
    PACKAGE_VERSION = "1.0"
    ALLOWED_ENTRY_FIELDS = ("title", "username", "password", "url", "notes", "category", "tags")

    def __init__(self, entry_manager, key_manager, db, audit_logger=None):
        self.entry_manager = entry_manager
        self.key_manager = key_manager
        self.db = db
        self.audit_logger = audit_logger

    # ------------------------------------------------------------------------
    # Публичные методы (API совместим с вашим кодом)
    # ------------------------------------------------------------------------

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
        if not self.key_manager.is_unlocked():
            raise PermissionError("Хранилище заблокировано.")

        if encryption_method not in ("password", "public_key"):
            raise ValueError(f"Неизвестный метод: {encryption_method}. Доступны: password, public_key")

        expires_in_days = max(1, min(30, expires_in_days))
        perms = SharePermissions(
            read=permissions.get("read", True) if permissions else True,
            edit=permissions.get("edit", False) if permissions else False,
            expires_in_days=expires_in_days,
        )

        entry = self._get_entry(entry_id)
        if not entry:
            raise ValueError(f"Запись {entry_id} не найдена.")

        share_id = str(uuid.uuid4())
        expires_at = datetime.now(timezone.utc) + timedelta(days=expires_in_days)

        try:
            filtered = self._filter_entry_for_sharing(entry, perms.as_dict())

            if encryption_method == "password":
                if not password:
                    raise ValueError("Пароль обязателен для метода 'password'.")
                package = self._create_password_package(filtered, share_id, perms, expires_at, password)
            else:  # public_key
                if not recipient_public_key_pem:
                    raise ValueError("Публичный ключ обязателен для метода 'public_key'.")
                package = self._create_public_key_package(
                    filtered, share_id, perms, expires_at, recipient_public_key_pem
                )

            # Сохраняем метаданные
            self._save_share_record(
                share_id=share_id,
                entry_id=entry_id,
                encryption_method=encryption_method,
                recipient=recipient,
                permissions=perms.as_dict(),
                expires_at=expires_at,
                package_checksum=package["integrity"]["checksum"],
            )

            self._log_share_event(entry_id, recipient, share_id, encryption_method)

            return {
                "share_id": share_id,
                "package": package,
                "expires_at": expires_at.isoformat(),
                "permissions": perms.as_dict(),
            }
        finally:
            if entry:
                for k in list(entry.keys()):
                    entry[k] = None
                entry.clear()

    def export_share_package(self, share_result: Dict[str, Any], filepath: str):
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(share_result["package"], f, ensure_ascii=False, indent=2)

    def receive_entry(
        self,
        package: Dict[str, Any],
        password: Optional[str] = None,
        private_key_pem: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        self._verify_package_structure(package)
        self._ensure_not_expired(package)
        self._verify_package_integrity(package)

        method = package["encryption"]["method"]
        if method == "password":
            if not password:
                raise ValueError("Пароль необходим для расшифровки этого пакета.")
            return self._decrypt_password_package(package, password)
        elif method == "public_key":
            if not private_key_pem:
                raise ValueError("Приватный ключ необходим для расшифровки этого пакета.")
            return self._decrypt_public_key_package(package, private_key_pem)
        else:
            raise ValueError(f"Неизвестный метод шифрования: {method}")

    def save_received_entry(self, entry: Dict[str, Any]) -> str:
        if not self.key_manager.is_unlocked():
            raise PermissionError("Хранилище заблокировано.")
        return self.entry_manager.create_entry(entry)

    def get_or_create_public_key(self) -> bytes:
        # Пробуем загрузить из key_store
        try:
            row = self.db.execute(
                "SELECT key_data FROM key_store WHERE key_type = 'rsa_public' LIMIT 1"
            ).fetchone()
            if row:
                key_data = row["key_data"] if hasattr(row, "keys") else row[0]
                if isinstance(key_data, str):
                    return key_data.encode("utf-8")
                return key_data
        except Exception:
            pass

        # Ключа нет — генерируем новую пару
        key_pair = self.generate_key_pair()
        import uuid as _uuid
        for key_type, key_data in (
            ("rsa_private", key_pair["private_key_pem"]),
            ("rsa_public", key_pair["public_key_pem"]),
        ):
            self.db.execute(
                """
                INSERT OR REPLACE INTO key_store (id, key_type, key_data, version, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    str(_uuid.uuid4()),
                    key_type,
                    key_data.decode("utf-8") if isinstance(key_data, bytes) else key_data,
                    1,
                    datetime.now(timezone.utc).isoformat(),
                ),
                commit=True,
            )
        return key_pair["public_key_pem"]

    def get_share_package(self, share_id: str) -> dict:
        if not self.key_manager.is_unlocked():
            raise PermissionError("Хранилище заблокировано.")

        row = self.db.execute(
            """
            SELECT share_id, original_entry_id, encryption_method,
                   recipient_info, permissions, expires_at
            FROM shared_entries
            WHERE share_id = ?
            """,
            (share_id,),
        ).fetchone()
        if not row:
            raise ValueError(f"Шаринг {share_id[:12]}... не найден.")

        if hasattr(row, "keys"):
            share = dict(row)
        else:
            share = {
                "share_id": row[0],
                "original_entry_id": row[1],
                "encryption_method": row[2],
                "recipient_info": row[3],
                "permissions": row[4],
                "expires_at": row[5],
            }

        # Проверяем срок действия
        expires_str = share.get("expires_at", "")
        if expires_str:
            try:
                expires_dt = datetime.fromisoformat(expires_str.replace("Z", ""))
                if datetime.now(timezone.utc) > expires_dt:
                    raise ValueError(f"Шаринг истёк {expires_str[:10]}. Создайте новый.")
            except ValueError as e:
                if "истёк" in str(e):
                    raise

        # Парсим permissions
        import json as _json
        permissions = share.get("permissions", '{"read": true, "edit": false}')
        if isinstance(permissions, str):
            try:
                permissions = _json.loads(permissions)
            except Exception:
                permissions = {"read": True, "edit": False}

        return {
            "version": self.PACKAGE_VERSION,
            "cryptosafe_share": True,
            "share_id": share_id,
            "encryption_method": share["encryption_method"],
            "expires_at": expires_str,
            "permissions": permissions,
            "recipient_info": share.get("recipient_info", ""),
            "type": "share_link",
        }

    def add_contact(self, name: str, public_key_pem: bytes, identifier: str = None) -> str:
        return self.save_contact(name, public_key_pem, identifier)

    def generate_key_pair(self) -> Dict[str, bytes]:
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
        return {
            "private_key_pem": private_pem,
            "public_key_pem": public_pem,
            "fingerprint": self._key_fingerprint(public_pem),
        }

    def save_contact(self, name: str, public_key_pem: bytes, identifier: Optional[str] = None) -> str:
        contact_id = str(uuid.uuid4())
        fingerprint = self._key_fingerprint(public_key_pem)
        self.db.execute(
            """
            INSERT INTO contacts (contact_id, name, identifier, public_key_pem, key_fingerprint)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                contact_id,
                name,
                identifier or "",
                public_key_pem.decode("utf-8") if isinstance(public_key_pem, bytes) else public_key_pem,
                fingerprint,
            ),
            commit=True,
        )
        return contact_id

    def get_contacts(self) -> List[Dict[str, Any]]:
        rows = self.db.execute(
            """
            SELECT contact_id, name, identifier, public_key_pem,
                   key_fingerprint, created_at, last_used
            FROM contacts ORDER BY name
            """
        ).fetchall()
        return [dict(r) for r in rows]

    def get_active_shares(self) -> List[Dict[str, Any]]:
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
        self.db.execute(
            "UPDATE shared_entries SET expires_at = datetime('now', '-1 second') WHERE share_id = ?",
            (share_id,),
            commit=True,
        )
        self._log_audit_event("SHARE_REVOKED", {"share_id": share_id})

    # ------------------------------------------------------------------------
    # Приватные методы создания пакетов
    # ------------------------------------------------------------------------

    def _create_password_package(
        self,
        entry: Dict[str, Any],
        share_id: str,
        permissions: SharePermissions,
        expires_at: datetime,
        password: str,
    ) -> Dict[str, Any]:
        payload = {
            "entry": entry,
            "permissions": permissions.as_dict(),
            "share_id": share_id,
        }
        plaintext = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        salt, _ = new_salt_and_nonce()
        key = derive_password_key(password, salt, bits=256, iterations=100000)
        keybuf = bytearray(key)
        associated_data = share_id.encode("utf-8")
        try:
            nonce, ciphertext = encrypt_aes_gcm(plaintext, keybuf, associated_data=associated_data)
            pkg_hmac = hmac.new(bytes(keybuf), ciphertext, "sha256").hexdigest()
        finally:
            wipe_bytes(keybuf)

        return {
            "cryptosafe_share": True,
            "version": self.PACKAGE_VERSION,
            "metadata": {
                "share_id": share_id,
                "permissions": permissions.as_dict(),
                "shared_at": datetime.now(timezone.utc).isoformat(),
                "expires_at": expires_at.isoformat(),
                "package_checksum": checksum(ciphertext),
            },
            "encryption": {
                "method": "password",
                "algorithm": "AES-256-GCM",
                "kdf": "PBKDF2-HMAC-SHA256",
                "iterations": 100000,
                "salt": base64.b64encode(salt).decode("ascii"),
                "nonce": base64.b64encode(nonce).decode("ascii"),
            },
            "data": {
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            },
            "integrity": {
                "checksum": checksum(ciphertext),
                "payload_checksum": checksum(plaintext),
                "hmac": pkg_hmac,
                "signature": pkg_hmac,
            },
        }

    def _create_public_key_package(
        self,
        entry: Dict[str, Any],
        share_id: str,
        permissions: SharePermissions,
        expires_at: datetime,
        recipient_public_key_pem: bytes,
    ) -> Dict[str, Any]:
        payload = {
            "entry": entry,
            "permissions": permissions.as_dict(),
            "share_id": share_id,
        }
        plaintext = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        associated_data = share_id.encode("utf-8")
        encrypted = encrypt_with_public_key(plaintext, recipient_public_key_pem.decode("ascii"), associated_data=associated_data)

        encryption = {
            "method": encrypted["method"],
            "algorithm": encrypted["algorithm"],
            "key_fingerprint": encrypted["key_fingerprint"],
            "nonce": encrypted["nonce"],
        }
        if "key_size" in encrypted:
            encryption["key_size"] = encrypted["key_size"]

        package = {
            "cryptosafe_share": True,
            "version": self.PACKAGE_VERSION,
            "metadata": {
                "share_id": share_id,
                "permissions": permissions.as_dict(),
                "shared_at": datetime.now(timezone.utc).isoformat(),
                "expires_at": expires_at.isoformat(),
                "package_checksum": encrypted["checksum"],
            },
            "encryption": encryption,
            "data": {
                "ciphertext": encrypted["ciphertext"],
                "encrypted_key": encrypted["encrypted_key"],
            },
            "integrity": {
                "checksum": encrypted["checksum"],
                "payload_checksum": checksum(plaintext),
                "signature": encrypted["checksum"],
            },
        }
        return package

    # ------------------------------------------------------------------------
    # Приватные методы расшифровки
    # ------------------------------------------------------------------------

    def _decrypt_password_package(self, package: Dict[str, Any], password: str) -> Dict[str, Any]:
        enc = package["encryption"]
        salt = base64.b64decode(enc["salt"])
        nonce = base64.b64decode(enc["nonce"])
        ciphertext = base64.b64decode(package["data"]["ciphertext"])
        key = derive_password_key(password, salt, bits=256, iterations=int(enc.get("iterations", 100000)))
        keybuf = bytearray(key)
        associated_data = package["metadata"]["share_id"].encode("utf-8")
        try:
            expected_hmac = package["integrity"].get("hmac", "")
            if expected_hmac:
                computed = hmac.new(bytes(keybuf), ciphertext, "sha256").hexdigest()
                if not constant_time_compare(computed, expected_hmac):
                    raise ImportValidationError("Share package HMAC mismatch")
            plaintext = decrypt_aes_gcm(ciphertext, keybuf, nonce, associated_data=associated_data)
        finally:
            wipe_bytes(keybuf)

        if checksum(plaintext) != package["integrity"].get("payload_checksum", ""):
            raise ImportValidationError("Share package plaintext checksum mismatch")
        decoded = json.loads(plaintext.decode("utf-8"))
        return self._validate_share_payload(decoded)

    def _decrypt_public_key_package(self, package: Dict[str, Any], private_key_pem: bytes) -> Dict[str, Any]:
        encrypted_payload = {
            "encrypted_key": package["data"].get("encrypted_key", ""),
            "nonce": package["encryption"].get("nonce", ""),
            "ciphertext": package["data"]["ciphertext"],
            "checksum": package["integrity"]["checksum"],
        }
        associated_data = package["metadata"]["share_id"].encode("utf-8")
        plaintext = decrypt_with_private_key(encrypted_payload, private_key_pem.decode("ascii"), associated_data=associated_data)

        if checksum(plaintext) != package["integrity"].get("payload_checksum", ""):
            raise ImportValidationError("Share package plaintext checksum mismatch")
        decoded = json.loads(plaintext.decode("utf-8"))
        return self._validate_share_payload(decoded)

    # ------------------------------------------------------------------------
    # Вспомогательные и служебные методы
    # ------------------------------------------------------------------------

    def _get_entry(self, entry_id: str) -> Optional[Dict[str, Any]]:
        try:
            return self.entry_manager.get_entry(entry_id)
        except Exception:
            return None

    def _filter_entry_for_sharing(self, entry: Dict[str, Any], permissions: Dict[str, bool]) -> Dict[str, Any]:
        filtered = {
            field: str(entry.get(field, "") or "")
            for field in self.ALLOWED_ENTRY_FIELDS
        }
        if not permissions.get("read", True):
            filtered.pop("password", None)
            filtered.pop("notes", None)
        return filtered

    def _verify_package_structure(self, package: Dict[str, Any]):
        if not package.get("cryptosafe_share"):
            raise ImportValidationError("File is not a CryptoSafe share package")
        for field in ("metadata", "encryption", "data", "integrity"):
            if not isinstance(package.get(field), dict):
                raise ImportValidationError(f"Share package missing {field}")

    def _ensure_not_expired(self, package: Dict[str, Any]):
        expires_at = package["metadata"].get("expires_at")
        if not expires_at:
            return
        try:
            parsed = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError:
            raise ImportValidationError("Share package expiration invalid")
        if parsed < datetime.now(timezone.utc):
            raise ImportValidationError("Share package has expired")

    def _verify_package_integrity(self, package: Dict[str, Any]):
        ciphertext = base64.b64decode(package["data"]["ciphertext"])
        if checksum(ciphertext) != package["integrity"].get("checksum", ""):
            raise ImportValidationError("Share package checksum mismatch")
        integrity_hash = package.get("integrity_hash")
        if integrity_hash and integrity_hash != package["integrity"].get("checksum", ""):
            raise ImportValidationError("Share package integrity mismatch")

    def _validate_share_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        entry = payload.get("entry")
        permissions = payload.get("permissions")
        if not isinstance(entry, dict) or not isinstance(permissions, dict):
            raise ImportValidationError("Share package payload incomplete")
        if not entry.get("title") or not entry.get("password"):
            raise ImportValidationError("Share package entry missing required fields")
        return {k: str(v) for k, v in entry.items() if k in self.ALLOWED_ENTRY_FIELDS}

    def _key_fingerprint(self, public_key_pem: bytes) -> str:
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
        package_checksum: str,
    ):
        try:
            self.db.execute(
                """
                INSERT INTO shared_entries
                    (share_id, original_entry_id, encryption_method,
                     recipient_info, permissions, shared_at, expires_at, package_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    share_id,
                    entry_id,
                    encryption_method,
                    recipient or "",
                    json.dumps(permissions),
                    datetime.now(timezone.utc).isoformat(),
                    expires_at.isoformat(),
                    package_checksum,
                ),
                commit=True,
            )
        except Exception:
            pass

    def _log_share_event(self, entry_id: str, recipient: Optional[str], share_id: str, encryption_method: str):
        self._log_audit_event(
            "ENTRY_SHARED",
            {
                "entry_id": entry_id,
                "share_id": share_id,
                "recipient": recipient or "unknown",
                "encryption_method": encryption_method,
            },
        )

    def _log_audit_event(self, event_type: str, details: Dict[str, Any]):
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
