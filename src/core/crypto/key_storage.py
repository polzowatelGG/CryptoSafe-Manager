from typing import Optional, Dict
from database.db import DatabasePool


class KeyType:
    AUTH_HASH = "auth_hash"
    ENC_SALT = "enc_salt"


class KeyStorage:
    def __init__(self, pool: DatabasePool):
        self.pool = pool
        self._create_table()

    def _create_table(self):
        with self.pool.connection() as conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS key_store (
                id INTEGER PRIMARY KEY,
                key_type TEXT NOT NULL,
                key_data BLOB NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,

                -- PBKDF2 params
                pbkdf2_iterations INTEGER,
                pbkdf2_salt BLOB,
                pbkdf2_key_len INTEGER,

                -- Argon2 params
                argon2_time INTEGER,
                argon2_memory INTEGER,
                argon2_parallelism INTEGER,
                argon2_hash_len INTEGER,

                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """)
            conn.commit()

    def _next_version(self, key_type: str) -> int:
        with self.pool.connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT MAX(version) FROM key_store WHERE key_type = ?",
                (key_type,)
            )
            row = cur.fetchone()
            return (row[0] or 0) + 1

    def add_auth_hash(
        self,
        hash_str: str,
        time_cost: int,
        memory_cost: int,
        parallelism: int,
        hash_len: int
    ) -> int:
        version = self._next_version(KeyType.AUTH_HASH)

        with self.pool.connection() as conn:
            cur = conn.cursor()
            cur.execute("""
            INSERT INTO key_store
            (key_type, key_data, version,
             argon2_time, argon2_memory, argon2_parallelism, argon2_hash_len)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                KeyType.AUTH_HASH,
                hash_str.encode("utf-8"),
                version,
                time_cost,
                memory_cost,
                parallelism,
                hash_len
            ))

            conn.commit()
            return cur.lastrowid

    def get_auth_hash(self) -> Optional[str]:
        row = self.get_latest_key(KeyType.AUTH_HASH)
        if not row:
            return None
        return row["key_data"].decode("utf-8")

    def add_pbkdf2_params(
        self,
        salt: bytes,
        iterations: int,
        key_len: int
    ) -> int:

        if len(salt) != 16:
            raise ValueError("Salt must be 16 bytes")

        version = self._next_version(KeyType.ENC_SALT)

        with self.pool.connection() as conn:
            cur = conn.cursor()
            cur.execute("""
            INSERT INTO key_store
            (key_type, key_data, version,
             pbkdf2_iterations, pbkdf2_salt, pbkdf2_key_len)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (
                KeyType.ENC_SALT,
                b"",  # ключ не храним
                version,
                iterations,
                salt,
                key_len
            ))

            conn.commit()
            return cur.lastrowid

    def get_pbkdf2_params(self) -> Optional[Dict]:
        row = self.get_latest_key(KeyType.ENC_SALT)
        if not row:
            return None

        return {
            "salt": row["pbkdf2_salt"],
            "iterations": row["pbkdf2_iterations"],
            "key_len": row["pbkdf2_key_len"]
        }

    def get_latest_key(self, key_type: str) -> Optional[Dict]:
        with self.pool.connection() as conn:
            cur = conn.cursor()
            cur.execute("""
            SELECT * FROM key_store
            WHERE key_type = ?
            ORDER BY version DESC
            LIMIT 1
            """, (key_type,))
            row = cur.fetchone()
            return dict(row) if row else None

    def clear_keys(self):
      with self.pool.connection() as conn:
            conn.execute("DELETE FROM key_store")
            conn.commit()