import sqlite3
from pathlib import Path
from queue import Queue, Empty
from contextlib import contextmanager
from typing import Callable, List
from database.migrations import ensure_key_store_schema, ensure_audit_log_schema
import json
import logging

log = logging.getLogger(__name__)


class DatabasePool:
    def __init__(self, db_path: str, size: int = 4):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.size = max(1, size)
        self._pool: Queue[sqlite3.Connection] = Queue(maxsize=self.size)
        self._fill_pool()

        self._migrations: List[Callable[[sqlite3.Connection], None]] = [
            self._migration_1,
            self._migration_2,
            self._migration_3,
        ]

    def new_connection(self):
        conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False,
            timeout=30,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _fill_pool(self):
        for _ in range(self.size):
            self._pool.put(self.new_connection())

    def check_integrity(self) -> bool:
        try:
            with self.connection() as conn:
                row = conn.execute("PRAGMA integrity_check").fetchone()
                ok = row and str(row[0]).lower() == "ok"
                if not ok:
                    log.error("Database integrity check failed: %s", row[0] if row else "no result")
                return ok
        except Exception as e:
            log.error("Database integrity check error: %s", e)
            return False

    def try_recover(self) -> bool:
        backup_path = self.db_path.with_suffix(".recovered.db")
        try:
            with self.connection() as conn:
                conn.execute(f"VACUUM INTO '{backup_path}'")
            log.warning("Database recovered to: %s", backup_path)
            return True
        except Exception as e:
            log.error("Database recovery failed: %s", e)
            return False

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
        except sqlite3.DatabaseError as e:
            if "malformed" in str(e).lower() or "corrupt" in str(e).lower():
                log.error("Detected corrupted DB connection, replacing: %s", e)
                try:
                    conn.close()
                except Exception:
                    pass
                if not temp:
                    try:
                        self._pool.put(self.new_connection())
                    except Exception:
                        pass
                raise
            raise
        finally:
            try:
                if temp:
                    conn.close()
                else:
                    self._pool.put(conn)
            except Exception:
                pass

    def execute(self, sql: str, params: tuple = (), commit: bool = False):
        with self.connection() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)
            if commit:
                conn.commit()
            return cur

    def close(self):
        while not self._pool.empty():
            try:
                conn = self._pool.get_nowait()
                conn.close()
            except Exception:
                pass

    def migrate(self):
        conn = self.new_connection()
        try:
            current = conn.execute("PRAGMA user_version").fetchone()[0]

            for i in range(current, len(self._migrations)):
                self._migrations[i](conn)
                conn.execute(f"PRAGMA user_version = {i + 1}")

            self._ensure_indexes(conn)
            conn.commit()
        finally:
            conn.close()
            
    def _ensure_indexes(self, conn: sqlite3.Connection):
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_vault_entries_created_at "
            "ON vault_entries(created_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_vault_entries_updated_at "
            "ON vault_entries(updated_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_vault_entries_tags "
            "ON vault_entries(tags)"
        )

    def _migration_1(self, conn: sqlite3.Connection):
        cur = conn.cursor()
        cur.execute("DROP TABLE IF EXISTS schema_meta")

        cur.execute("""
        CREATE TABLE IF NOT EXISTS vault_entries (
            id TEXT PRIMARY KEY,
            encrypted_data BLOB NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            tags TEXT
        )
        """)

        existing = {row[1] for row in cur.execute("PRAGMA table_info(vault_entries)")}
        if "totp_secret" not in existing:
            cur.execute("ALTER TABLE vault_entries ADD COLUMN totp_secret TEXT")
        if "shared_metadata" not in existing:
            cur.execute("ALTER TABLE vault_entries ADD COLUMN shared_metadata TEXT")

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

        cur.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            setting_key TEXT UNIQUE,
            setting_value TEXT,
            encrypted INTEGER DEFAULT 0
        )
        """)

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

        cur.execute("""
        CREATE TABLE IF NOT EXISTS deleted_entries (
            id TEXT PRIMARY KEY,
            deleted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP
        );
        """)

        conn.commit()

    def _migration_2(self, conn: sqlite3.Connection):
        cur = conn.cursor()

        cur.execute("DROP TABLE IF EXISTS audit_log_old")
        cur.execute("ALTER TABLE audit_log RENAME TO audit_log_old")
        cur.execute("""
        CREATE TABLE audit_log (
            sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
            previous_hash TEXT NOT NULL,
            entry_data TEXT NOT NULL,
            entry_hash TEXT NOT NULL,
            signature TEXT NOT NULL,
            timestamp DATETIME NOT NULL
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_signing_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            public_key TEXT NOT NULL,
            algorithm TEXT NOT NULL DEFAULT 'Ed25519',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1
        )
        """)

        cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_sequence ON audit_log (sequence_number)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log (timestamp)")
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_log_event_type
            ON audit_log ((json_extract(entry_data, '$.event_type')))
        """)

        cur.execute("DROP TABLE audit_log_old")

        ensure_key_store_schema(conn)
        ensure_audit_log_schema(conn)

        conn.commit()

        cur.execute("DROP TABLE IF EXISTS audit_log_old")
        conn.commit()

    def _migration_3(self, conn: sqlite3.Connection):
        cur = conn.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS shared_entries (
            share_id          TEXT PRIMARY KEY,
            original_entry_id TEXT NOT NULL,
            encryption_method TEXT NOT NULL,
            recipient_info    TEXT,
            permissions       TEXT NOT NULL DEFAULT '{"read": true, "edit": false}',
            shared_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at        TIMESTAMP,
            package_hash      TEXT
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS import_export_history (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            operation_type TEXT NOT NULL,
            format         TEXT NOT NULL,
            encryption_used INTEGER NOT NULL DEFAULT 1,
            entry_count    INTEGER NOT NULL DEFAULT 0,
            file_size      INTEGER NOT NULL DEFAULT 0,
            file_path      TEXT,
            checksum       TEXT,
            verified       INTEGER NOT NULL DEFAULT 0,
            created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS contacts (
            contact_id      TEXT PRIMARY KEY,
            name            TEXT NOT NULL,
            identifier      TEXT,
            public_key_pem  TEXT,
            key_fingerprint TEXT,
            created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_used       TIMESTAMP
        )
        """)

        cur.execute("CREATE INDEX IF NOT EXISTS idx_shared_entries_original ON shared_entries (original_entry_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_shared_entries_expires ON shared_entries (expires_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_import_export_history_type ON import_export_history (operation_type)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_import_export_history_created ON import_export_history (created_at)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_contacts_identifier ON contacts (identifier)")

        conn.commit()

    @staticmethod
    def add_column_if_missing(conn, table: str, column: str, definition: str):
        cur = conn.cursor()
        cur.execute(f"PRAGMA table_info({table})")
        existing_columns = {row[1] for row in cur.fetchall()}
        if column not in existing_columns:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    @contextmanager
    def transaction(self):
        with self.connection() as conn:
            try:
                yield conn
                conn.commit()
            except:
                conn.rollback()
                raise

    def add_import_export_history(self, *, operation_type: str, format: str, encryption_used,
                                  entry_count: int = 0, file_size: int = 0, checksum: str = None,
                                  verification_status=None, details=None, file_path: str = None):
        try:
            if isinstance(encryption_used, str):
                enc_flag = 0 if encryption_used.lower() in ("none", "0", "false", "no", "") else 1
            else:
                enc_flag = 1 if bool(encryption_used) else 0
        except Exception:
            enc_flag = 1

        verified = 1 if str(verification_status).lower() in ("1", "true", "verified", "ok", "success") else 0

        details_json = None
        if details is not None:
            try:
                details_json = json.dumps(details, ensure_ascii=False)
            except Exception:
                details_json = str(details)

        store_path = file_path if file_path else details_json

        sql = (
            "INSERT INTO import_export_history"
            " (operation_type, format, encryption_used, entry_count, file_size, file_path, checksum, verified)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        )
        params = (operation_type, format, enc_flag, entry_count, file_size, store_path, checksum, verified)
        with self.transaction() as conn:
            conn.cursor().execute(sql, params)


__all__ = ["DatabasePool"]