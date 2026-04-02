import sqlite3
from pathlib import Path
from queue import Queue, Empty
from contextlib import contextmanager
from typing import Callable, List


class DatabasePool:
    def __init__(self, db_path: str, size: int = 4):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.size = max(1, size)
        self._pool: Queue[sqlite3.Connection] = Queue(maxsize=self.size)
        self._fill_pool()

        self._migrations: List[Callable[[sqlite3.Connection], None]] = [
            self._migration_1,
        ]

    # ---------------- pool ----------------
    def new_connection(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _fill_pool(self):
        for _ in range(self.size):
            self._pool.put(self.new_connection())

    @contextmanager
    def connection(self):
        try:
            conn = self._pool.get_nowait()
            temp = False
        except Empty:
            conn = self.new_connection()
            temp = True

        try:
            yield conn
        finally:
            if temp:
                conn.close()
            else:
                self._pool.put(conn)

    def execute(self, sql: str, params: tuple = (), commit: bool = False):
        with self.connection() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)
            if commit:
                conn.commit()
            return cur

    # ---------------- migrations ----------------
    def migrate(self):
        with self.connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS schema_meta (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version INTEGER NOT NULL,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cur = conn.cursor()
            cur.execute("SELECT MAX(version) FROM schema_meta")
            current = cur.fetchone()[0] or 0

            for i in range(current, len(self._migrations)):
                self._migrations[i](conn)
                conn.execute(
                    "INSERT INTO schema_meta (version) VALUES (?)",
                    (i + 1,)
                )
                conn.commit()

    # ---------------- migration v1 ----------------
    def _migration_1(self, conn: sqlite3.Connection):
        cur = conn.cursor()

        # vault
        cur.execute("""
        CREATE TABLE IF NOT EXISTS vault_entries (
            id TEXT PRIMARY KEY,
            encrypted_data BLOB NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            tags TEXT
        )
        """)

        # audit
        cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            entry_id TEXT,
            details TEXT,
            signature TEXT
        )
        """)

        # settings
        cur.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            setting_key TEXT UNIQUE,
            setting_value TEXT,
            encrypted INTEGER DEFAULT 0
        )
        """)

        # ---------------- KEY STORAGE (CLEAN) ----------------
        cur.execute("""
        CREATE TABLE IF NOT EXISTS key_store (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_type TEXT NOT NULL,      
            key_data BLOB NOT NULL,      
            params TEXT,                 
            version INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        conn.commit()
        
__all__ = ["DatabasePool"]