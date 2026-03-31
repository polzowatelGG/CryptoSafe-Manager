import json
import uuid
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class EntryManager:
    def __init__(self, db_connection, key_manager):
        self.db = db_connection
        self.key_manager = key_manager

    # получение AESGCM
    def _get_crypto(self) -> AESGCM:
        key = self.key_manager.get_active_key()

        if not key:
            raise ValueError("Encryption key not available")

        return AESGCM(key)

    # шифрование
    def _encrypt(self, data: dict) -> bytes:
        aesgcm = self._get_crypto()

        nonce = os.urandom(12)
        plaintext = json.dumps(data).encode("utf-8")

        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        return nonce + ciphertext

    # дешифрование
    def _decrypt(self, encrypted_blob: bytes) -> dict:
        aesgcm = self._get_crypto()

        nonce = encrypted_blob[:12]
        ciphertext = encrypted_blob[12:]

        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception:
            raise ValueError("Decryption failed (corrupted data or wrong key)")

        return json.loads(plaintext.decode("utf-8"))

    # создание новой записи
    def create_entry(self, data: dict) -> str:
        entry_id = str(uuid.uuid4())

        payload = {
            **data,
            "id": entry_id,
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "version": 1,
        }

        encrypted_blob = self._encrypt(payload)

        self.db.execute(
            """
            INSERT INTO vault_entries (id, encrypted_data, created_at, updated_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                entry_id,
                encrypted_blob,
                datetime.utcnow(),
                datetime.utcnow(),
            ),
            commit=True,
        )

        return entry_id

    # чтение одной записи по id
    def get_entry(self, entry_id: str) -> dict:
        row = self.db.execute(
            "SELECT encrypted_data FROM vault_entries WHERE id = ?",
            (entry_id,),
        ).fetchone()

        if not row:
            raise ValueError("Entry not found")

        return self._decrypt(row["encrypted_data"])

    # чтение всех записей 
    def get_all_entries(self) -> list[dict]:
        rows = self.db.execute(
            "SELECT encrypted_data FROM vault_entries"
        ).fetchall()

        result = []

        for row in rows:
            try:
                result.append(self._decrypt(row["encrypted_data"]))
            except Exception:
                # не упадет из-за одной битой записи 
                continue

        return result

    # обновление 
    def update_entry(self, entry_id: str, new_data: dict):
        existing = self.get_entry(entry_id)

        updated_payload = {
            **existing,
            **new_data,
            "updated_at": datetime.utcnow().isoformat(),
            "version": existing.get("version", 1) + 1,
        }

        encrypted_blob = self._encrypt(updated_payload)

        self.db.execute(
            """
            UPDATE vault_entries
            SET encrypted_data = ?, updated_at = ?
            WHERE id = ?
            """,
            (encrypted_blob, datetime.utcnow(), entry_id),
            commit=True,
        )

    # удаление 
    def delete_entry(self, entry_id: str, soft_delete: bool = True):
        if soft_delete:
            self.db.execute(
                """
                INSERT INTO deleted_enties (id, deleted_at, expires_at)
                VALUES (?, ?, ?)
                """,
                (
                    entry_id,
                    datetime.utcnow(),
                    datetime.utcnow(),
                ),
                commit=True,
            )

        self.db.execute(
            "DELETE FROM vault_entries WHERE id = ?",
            (entry_id,),
            commit=True,
        )