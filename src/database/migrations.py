import sqlite3
from database.db import DatabasePool

def migrate_key_store(pool: DatabasePool):
    with pool.connection() as conn:
        cur = conn.cursor()
        # проверяем наличие таблицы
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='key_store'")
        if not cur.fetchone():
            # создаем базовую таблицу
            cur.execute("""
            CREATE TABLE key_store (
                id INTEGER PRIMARY KEY,
                key_type TEXT NOT NULL,
                key_data BLOB NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                pbkdf2_iterations INTEGER,
                pbkdf2_salt BLOB,
                pbkdf2_key_len INTEGER,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """)
            conn.commit()
            return

        # добавляем недостающие колонки
        cur.execute("PRAGMA table_info(key_store)")
        columns = {row[1]: row for row in cur.fetchall()}

        if 'pbkdf2_iterations' not in columns:
            cur.execute("ALTER TABLE key_store ADD COLUMN pbkdf2_iterations INTEGER")
        if 'pbkdf2_salt' not in columns:
            cur.execute("ALTER TABLE key_store ADD COLUMN pbkdf2_salt BLOB")
        if 'pbkdf2_key_len' not in columns:
            cur.execute("ALTER TABLE key_store ADD COLUMN pbkdf2_key_len INTEGER")

        conn.commit()