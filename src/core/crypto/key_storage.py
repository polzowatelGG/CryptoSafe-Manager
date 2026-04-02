import json
from typing import Optional
from database.db import DatabasePool


class KeyStorage:
    def __init__(self, pool: DatabasePool):
        self.pool = pool

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