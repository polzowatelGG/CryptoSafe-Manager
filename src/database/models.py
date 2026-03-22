import sqlite3
from datetime import datetime
import base64
from typing import Optional, List, Dict, Any
from core.crypto.placeholder import AES256Placeholder
from core.crypto.abstract import EncryptionService
from database.db import DatabasePool

def _serialize_tags(tags: Optional[List[str]]) -> Optional[str]:
    # Сериализует список тегов в строку, или возвращает None
    if tags is None:
        return None
    return ",".join(tags)

def _deserialize_tags(s: Optional[str]) -> List[str]:
    # Десериализует строку тегов в список
    if not s:
        return []
    return [t for t in s.split(",") if t]

class VaultEntries:

    def __init__(self, pool: DatabasePool, encryptor: Optional[EncryptionService] = None):
        # Пул соединений и сервис шифрования (заглушка по умолчанию)
        self.pool = pool
        self.encryptor = encryptor or AES256Placeholder()

    def add_entry(
        self,
        title: str,
        username: Optional[str],
        password: str,
        url: Optional[str] = None,
        notes: Optional[str] = None,
        tags: Optional[List[str]] = None,
        key: bytes = None,
    ) -> int:
        # Требуем ключ для шифрования пароля
        if not key:
            raise ValueError("enc_key is required to store password")

        enc = self.encryptor.encrypt(password.encode("utf-8"), key)
        tags_s = _serialize_tags(tags)

        # Вставляем запись в БД
        with self.pool.connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO vault_entries (title, username, encrypted_password, url, notes, tags)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (title, username, sqlite3.Binary(enc), url, notes, tags_s),
            )
            conn.commit()
            return cur.lastrowid

    def get_entry(self, entry_id: int, key: bytes) -> Optional[Dict[str, Any]]:
        # Возвращает запись с расшифрованным паролем (если ключ корректен)
        with self.pool.connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM vault_entries WHERE id = ?", (entry_id,))
            row = cur.fetchone()
            if not row:
                return None

            enc = row["encrypted_password"]
            try:
                pwd = self.encryptor.decrypt(bytes(enc), key).decode("utf-8")
            except Exception:
                pwd = None

            return {
                "id": row["id"],
                "title": row["title"],
                "username": row["username"],
                "password": pwd,
                "url": row["url"],
                "notes": row["notes"],
                "tags": _deserialize_tags(row["tags"]),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }

    def list_entries(self, limit: int = 100) -> List[Dict[str, Any]]:
        # Возвращает список записей (без паролей) для списка/таблицы
        with self.pool.connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, title, username, url, tags, created_at, updated_at FROM vault_entries ORDER BY created_at DESC LIMIT ?", (limit,))
            rows = cur.fetchall()
            return [
                {
                    "id": r["id"],
                    "title": r["title"],
                    "username": r["username"],
                    "url": r["url"],
                    "tags": _deserialize_tags(r["tags"]),
                    "created_at": r["created_at"],
                    "updated_at": r["updated_at"],
                }
                for r in rows
            ]

class AuditLog:
    # Репозиторий для записи событий аудита в таблицу `audit_log`
    def __init__(self, pool: DatabasePool):
        self.pool = pool

    def add(self, action: str, entry_id: Optional[int] = None, details: Optional[str] = None, signature: Optional[str] = None) -> int:
        # Добавляет запись в журнал аудита
        with self.pool.connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO audit_log (action, entry_id, details, signature) VALUES (?, ?, ?, ?)",
                (action, str(entry_id) if entry_id is not None else None, details, signature),
            )
            conn.commit()
            return cur.lastrowid

class Settings:
    # Репозиторий для настроек приложения (таблица `settings`)
    def __init__(self, pool: DatabasePool, encryptor: Optional[EncryptionService] = None):
        self.pool = pool
        self.encryptor = encryptor or AES256Placeholder()

    def set(self, key: str, value: str, encrypted: bool = False, enc_key: Optional[bytes] = None) -> None:
        # Сохраняет настройку; при encrypted=True шифрует значение и сохраняет в base64
        if encrypted:
            if not enc_key:
                raise ValueError("enc_key required for encrypted setting")
            blob = self.encryptor.encrypt(value.encode("utf-8"), enc_key)
            value_stored = base64.b64encode(blob).decode("ascii")
            enc_flag = 1
        else:
            value_stored = value
            enc_flag = 0

        with self.pool.connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO settings (setting_key, setting_value, encrypted) VALUES (?, ?, ?) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value, encrypted=excluded.encrypted",
                (key, value_stored, enc_flag),
            )
            conn.commit()

    def get(self, key: str, enc_key: Optional[bytes] = None) -> Optional[str]:
        # Получает настройку; расшифровывает при необходимости
        with self.pool.connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT setting_value, encrypted FROM settings WHERE setting_key = ?", (key,))
            row = cur.fetchone()
            if not row:
                return None

            value, encrypted = row[0], row[1]
            if encrypted:
                if not enc_key:
                    raise ValueError("enc_key required to read encrypted setting")
                blob = base64.b64decode(value)
                return self.encryptor.decrypt(blob, enc_key).decode("utf-8")

            return value

class KeyStore:
    # Репозиторий для метаданных ключей (таблица `key_store`)
    def __init__(self, pool: DatabasePool):
        self.pool = pool
        
    def create_table(self):
        with self.pool.connection() as conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS key_store (
                id INTEGER PRIMARY KEY,
                key_type TEXT NOT NULL,
                key_data BLOB NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """)
            conn.commit()

    def add_key(self, key_type: str, key_data: bytes, version: int = 1) -> int:
        # Добавляет запись о ключе
        with self.pool.connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO key_store (key_type, key_data, version, created_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
                (key_type, key_data, version),
            )
            conn.commit()
            return cur.lastrowid

    def list_keys(self) -> List[Dict[str, Any]]:
        # Возвращает список хранимых ключевых записей
        with self.pool.connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, key_type, key_data, version, created_at FROM key_store")
            rows = cur.fetchall()
            return [dict(r) for r in rows]

    def list_keys(self) -> List[Dict[str, Any]]:
        with self.pool.connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, key_type, key_data, version, created_at FROM key_store")
            rows = cur.fetchall()
            return [dict(r) for r in rows]

    def get_latest_key(self, key_type: str):
        with self.pool.connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT key_data, version, created_at FROM key_store WHERE key_type = ? ORDER BY version DESC LIMIT 1",
                (key_type,)
            )
            row = cur.fetchone()
            return row if row else None