import sqlite3
from pathlib import Path
from queue import Queue, Empty
from contextlib import contextmanager
from typing import Callable, List
from migrations import migrate_key_store

class DatabasePool:
    def __init__(self, db_path: str, size: int = 4):
        # путь к файлу БД; создаём директорию при необходимости
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # размер пула и очередь соединений
        self.size = max(1, size)
        self._pool: "Queue[sqlite3.Connection]" = Queue(maxsize=self.size)
        self._fill_pool()

        # список функций-миграций (каждая принимает sqlite3.Connection)
        self._migrations: List[Callable[[sqlite3.Connection], None]] = [
            self._migration_1_initial_schema,
            lambda conn: migrate_key_store(self),  # наша новая миграция
        ]

    def new_connection(self) -> sqlite3.Connection:
        # Создаёт новое sqlite3-соединение (без проверки потока)
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _fill_pool(self) -> None:
        # Наполняем пул стартовыми соединениями
        for _ in range(self.size):
            self._pool.put(self.new_connection())

    @contextmanager
    def connection(self) -> sqlite3.Connection: 
        try:
            conn = self._pool.get_nowait()
            temporary = False
        except Empty:
            conn = self.new_connection()
            temporary = True

        try:
            yield conn
        finally:
            # Возвращаем соединение в пул или закрываем временное
            if temporary:
                try:
                    conn.close()
                except Exception:
                    pass
            else:
                try:
                    self._pool.put_nowait(conn)
                except Exception:
                    try:
                        conn.close()
                    except Exception:
                        pass

    def close(self) -> None:
        # Закрывает все соединения в пуле (использовать при завершении работы)
        while True:
            try:
                conn = self._pool.get_nowait()
            except Empty:
                break
            try:
                conn.close()
            except Exception:
                pass

    def execute(self, sql: str, params: tuple = (), commit: bool = False) -> sqlite3.Cursor:
        # Выполняет SQL-запрос и возвращает курсор. При need commit — фиксируем изменения.
        with self.connection() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)
            if commit:
                conn.commit()
            return cur

    def query(self, sql: str, params: tuple = ()) -> list:
        # Удобный wrapper: выполнить запрос и вернуть все строки
        cur = self.execute(sql, params)
        return cur.fetchall()

    def get_user_version(self) -> int:
        # Возвращает текущую версию схемы (PRAGMA user_version)
        with self.connection() as conn:
            cur = conn.cursor()
            cur.execute('PRAGMA user_version')
            row = cur.fetchone()
            return int(row[0]) if row is not None else 0

    def _set_user_version(self, v: int) -> None:
        # Устанавливает версию схемы (PRAGMA user_version = v)
        with self.connection() as conn:
            cur = conn.cursor()
            cur.execute(f'PRAGMA user_version = {int(v)}')
            conn.commit()

    def migrate(self) -> None:
        # Применяет последовательные миграции до актуальной версии
        current = self.get_user_version()
        target = len(self._migrations)
        if current >= target:
            return

        for idx in range(current, target):
            migration = self._migrations[idx]
            with self.connection() as conn:
                migration(conn)
                self._set_user_version(idx + 1)

    def _migration_1_initial_schema(self, conn: sqlite3.Connection) -> None:
        # Первая миграция: создаём базовые таблицы и индексы
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE vault_entries (
                id TEXT PRIMARY KEY,
                encrypted_data BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                tags TEXT
            );
            """
        )

        # Таблица аудита
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                entry_id TEXT,
                details TEXT,
                signature TEXT
            );
            """
        )

        # Таблица настроек
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                setting_key TEXT UNIQUE,
                setting_value TEXT,
                encrypted INTEGER NOT NULL DEFAULT 0
            );
            """
        )

        # Таблица для хранения ключевых метаданных
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS key_store (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_type TEXT,
                salt TEXT,
                hash TEXT,
                params TEXT
            );
            """
        )
        
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS deleted_enties(
                id TEXT,
                deleted_at TIMESTAMP,
                expires_at TIMESTAMP
            )
            """
        )

        # Индексы для быстрого поиска
        cur.execute("CREATE INDEX IF NOT EXISTS idx_vault_entries_title ON vault_entries(title)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_vault_entries_username ON vault_entries(username)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_vault_entries_tags ON vault_entries(tags)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_entry_id ON audit_log(entry_id)")
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_settings_key ON settings(setting_key)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_key_store_type ON key_store(key_type)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_vault_created_at ON vault_entries(created_at);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_vault_updated_at ON vault_entries(updated_at);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_vault_tags ON vault_entries(tags);")
        conn.commit()

__all__ = ["DatabasePool"]