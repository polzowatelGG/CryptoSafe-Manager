import json
import os
from pathlib import Path
from typing import Optional



try:
    import keyring
except ImportError:
    keyring = None

from database.db import DatabasePool

class KeyStorage:
    def __init__(self, pool: DatabasePool):
        self.pool = pool
        self._service = "CryptoSafeManager"
        self._username = "master"
        self._fallback_path = Path.home() / ".cryptosafe_manager_key"

    # ---------------- AUTH HASH ----------------

    def save_auth_hash(self, auth_hash: str):
        with self.pool.connection() as conn:
            conn.execute(
                """
                INSERT INTO key_store (key_type, key_data)
                VALUES (?, ?)
                """,
                ("auth_hash", auth_hash.encode())
            )
            conn.commit()

    def get_auth_hash(self) -> Optional[str]:
        with self.pool.connection() as conn:
            row = conn.execute(
                """
                SELECT key_data FROM key_store
                WHERE key_type = 'auth_hash'
                ORDER BY id DESC
                LIMIT 1
                """
            ).fetchone()

            if not row:
                return None

            return row["key_data"].decode()

    # ---------------- PBKDF2 PARAMS ----------------

    def save_pbkdf2_params(self, salt: bytes, iterations: int):
        params = {
            "iterations": iterations
        }

        with self.pool.connection() as conn:
            conn.execute(
                """
                INSERT INTO key_store (key_type, key_data, params)
                VALUES (?, ?, ?)
                """,
                ("enc_params", salt, json.dumps(params))
            )
            conn.commit()

    def get_pbkdf2_params(self) -> Optional[dict]:
        with self.pool.connection() as conn:
            row = conn.execute(
                """
                SELECT key_data, params FROM key_store
                WHERE key_type = 'enc_params'
                ORDER BY id DESC
                LIMIT 1
                """
            ).fetchone()

            if not row:
                return None

            return {
                "salt": row["key_data"],
                **json.loads(row["params"])
            }

    # ---------------- KEYCHAIN / FALLBACK ----------------

    def _keychain_available(self) -> bool:
        return keyring is not None

    def store_encryption_key(self, key: bytes) -> None:
        hex_key = key.hex()

        if self._keychain_available():
            try:
                keyring.set_password(self._service, self._username, hex_key)
                return
            except Exception:
                # попытка через keychain не удалась — переключаемся на fallback
                pass

        self._save_key_fallback(hex_key)

    def load_encryption_key(self) -> Optional[bytes]:
        if self._keychain_available():
            try:
                stored = keyring.get_password(self._service, self._username)
                if stored:
                    return bytes.fromhex(stored)
            except Exception:
                pass

        return self._load_key_fallback()

    def delete_encryption_key(self) -> None:
        if self._keychain_available():
            try:
                keyring.delete_password(self._service, self._username)
            except Exception:
                pass

        if self._fallback_path.exists():
            try:
                self._fallback_path.unlink()
            except Exception:
                pass

    def _save_key_fallback(self, hex_key: str) -> None:
        self._fallback_path.write_text(hex_key, encoding="utf-8")
        try:
            os.chmod(self._fallback_path, 0o600)
        except Exception:
            pass

    def _load_key_fallback(self) -> Optional[bytes]:
        if not self._fallback_path.exists():
            return None

        try:
            hex_key = self._fallback_path.read_text(encoding="utf-8").strip()
            if not hex_key:
                return None
            return bytes.fromhex(hex_key)
        except Exception:
            return None

    # ---------------- KEYSTORE helpers for transaction ----------------

    def save_auth_hash_on_conn(self, conn, auth_hash: str):
        conn.execute(
            """
            INSERT INTO key_store (key_type, key_data)
            VALUES (?, ?)
            """,
            ("auth_hash", auth_hash.encode())
        )

    def save_pbkdf2_params_on_conn(self, conn, salt: bytes, iterations: int):
        params = {"iterations": iterations}
        conn.execute(
            """
            INSERT INTO key_store (key_type, key_data, params)
            VALUES (?, ?, ?)
            """,
            ("enc_params", salt, json.dumps(params))
        )
