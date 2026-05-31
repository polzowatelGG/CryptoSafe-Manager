# database.py - модуль для управления базой данных SQLite, включая пул соединений и миграции схемы. он обеспечивает безопасный и эффективный доступ к базе данных для хранения зашифрованных данных, аудита и настроек приложения. 
# он также включает механизмы для управления транзакциями и обеспечения целостности данных при выполнении операций с базой данных.
# он использует стандартную библиотеку sqlite3 для взаимодействия с базой данных и может
# быть расширен для поддержки дополнительных функций, таких как резервное копирование, восстановление и оптимизация производительности.

import sqlite3
from pathlib import Path
from queue import Queue, Empty
from contextlib import contextmanager
from typing import Callable, List
from database.migrations import ensure_key_store_schema, ensure_audit_log_schema
import json


class DatabasePool: # класс для управления пулом соединений с базой данных SQLite и миграциями схемы. он обеспечивает безопасный и эффективный доступ к базе данных для хранения зашифрованных данных, аудита и настроек приложения.
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

    # пул соединений: методы для получения и возврата соединений с базой данных
    def new_connection(self): # метод для создания нового соединения с базой данных. он устанавливает параметр check_same_thread в False, чтобы разрешить использование соединений в разных потоках, и устанавливает row_factory для удобного доступа к данным по именам столбцов.
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _fill_pool(self): # метод для заполнения пула соединений при инициализации. он создает указанное количество соединений и помещает их в очередь пула.
        for _ in range(self.size):
            self._pool.put(self.new_connection())

    @contextmanager
    def connection(self): # контекстный менеджер для получения соединения из пула. он пытается получить соединение из пула без блокировки, и если пул пуст, он создает новое соединение. после использования соединения он возвращает его в пул, если оно было взято из пула, или закрывает его, если оно было создано временно.
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

    def execute(self, sql: str, params: tuple = (), commit: bool = False): # метод для выполнения SQL-запросов с использованием соединения из пула. он принимает SQL-запрос, параметры для запроса и флаг commit для указания, нужно ли коммитить транзакцию после выполнения запроса. он возвращает курсор с результатами запроса.
        with self.connection() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)
            if commit:
                conn.commit()
            return cur

    def close(self): # метод для закрытия всех соединений в пуле. он извлекает все соединения из пула и закрывает их, чтобы освободить ресурсы при завершении работы приложения.
        while not self._pool.empty():
            conn = self._pool.get_nowait()
            try:
                conn.close()
            except Exception:
                pass

    # схемы миграции
    def migrate(self):
        with self.connection() as conn:
            cur = conn.cursor()

            # читаем текущую версию схемы из заголовка файла БД
            cur.execute("PRAGMA user_version")
            current = cur.fetchone()[0]  # 0 если БД новая

        # применяем только те миграции, которые ещё не были применены
            for i in range(current, len(self._migrations)):
                self._migrations[i](conn)
            # записываем новую версию прямо в заголовок БД
                conn.execute(f"PRAGMA user_version = {i + 1}")
                conn.commit()

    # миграция весии 1: создание таблиц для хранения зашифрованных данных, аудита и настроек приложения, а также таблицы для хранения ключей и удаленных записей. она также добавляет индексы для ускорения поиска по датам и тегам.
    def _migration_1(self, conn: sqlite3.Connection):
        cur = conn.cursor()
        cur.execute("DROP TABLE IF EXISTS schema_meta") # удаляем старую таблицу, если она существует

        # основная таблица хранения зашифрованных данных
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

        # таблица аудита для хранения логов действий пользователя и изменений данных. 
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

        # таблица для хранения настроек приложения и параметров шифрования 
        cur.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            setting_key TEXT UNIQUE,
            setting_value TEXT,
            encrypted INTEGER DEFAULT 0
        )
        """)

        # таблица для хранения ключей шифрования и связанных параметров. 
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

        # таблица для хранения удаленных записей с информацией о времени удаления и сроке хранения, чтобы поддерживать функцию "корзины" для восстановления удаленных данных в течение определенного времени.
        cur.execute("""
        CREATE TABLE IF NOT EXISTS deleted_entries (
            id TEXT PRIMARY KEY,
            deleted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP
        );
        """)

        # индексы для ускорения поиска по датам и тегам 
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_vault_entries_created_at ON vault_entries (created_at);
        """)
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_vault_entries_updated_at ON vault_entries (updated_at);
        """)
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_vault_entries_tags ON vault_entries (tags);
        """)

        conn.commit()
        
        
    # миграция версии 2: улучшение таблицы аудита для обеспечения целостности и неизменности логов. она добавляет поля для хранения хэшей записей и цифровых подписей, а также индексы для оптимизации запросов по последовательному номеру и времени.
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
        
        #таблица дял хранения публичных ключей для проверки подписей в аудите. она позволяет управлять ключами и алгоритмами, используемыми для обеспечения целостности логов аудита.
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

    # добавляем недостающие колонки если их нет
        ensure_key_store_schema(conn)
        ensure_audit_log_schema(conn)

        conn.commit()
        
        cur.execute("DROP TABLE IF EXISTS audit_log_old")
        conn.commit
        
    # миграция версия 3: import/export и sharing 
    def _migration_3(self, conn: sqlite3.Connection):
        cur = conn.cursor()
 
        # таблица для хранения метаданных общих записей
        # shared_id       — уникальный идентификатор шаринга
        # original_entry_id — ссылка на vault_entries.id (логическая)
        # encryption_method — "password" | "public_key"
        # recipient_info  — идентификатор/контакт получателя
        # permissions     — JSON: {"read": true, "edit": false}
        # shared_at       — время создания шаринга
        # expires_at      — время истечения (NULL = бессрочно)
        # package_hash    — SHA-256 зашифрованного пакета для верификации
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
 
        # таблица истории импорта/экспорта
        # operation_type  — "import" | "export"
        # format          — "encrypted_json" | "csv" | "bitwarden" | "lastpass"
        # encryption_used — boolean (0/1)
        # entry_count     — количество записей в операции
        # file_size       — размер файла в байтах
        # file_path       — путь к файлу (только имя, не полный путь)
        # checksum        — SHA-256 файла для верификации
        # verified        — результат верификации (0/1)
        # created_at      — время операции
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
 
        # таблица контактов для хранения публичных ключей
        # contact_id      — уникальный идентификатор
        # name            — отображаемое имя контакта
        # identifier      — email / username / другой идентификатор
        # public_key_pem  — публичный ключ RSA/ECC в PEM формате
        # key_fingerprint — отпечаток ключа для верификации
        # last_used       — время последнего использования
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
 
        # индексы для производительности
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_shared_entries_original
        ON shared_entries (original_entry_id)
        """)
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_shared_entries_expires
        ON shared_entries (expires_at)
        """)
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_import_export_history_type
        ON import_export_history (operation_type)
        """)
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_import_export_history_created
        ON import_export_history (created_at)
        """)
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_contacts_identifier
        ON contacts (identifier)
        """)
 
        conn.commit()

    
    @staticmethod
    def add_column_if_missing(conn, table: str, column: str, definition: str):
        # получаем список существующих колонок через PRAGMA
        cur = conn.cursor()
        cur.execute(f"PRAGMA table_info({table})")
        existing_columns = {row[1] for row in cur.fetchall()}

        # добавляем колонку только если её ещё нет
        if column not in existing_columns:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        
    @contextmanager
    def transaction(self): # контекстный менеджер для управления транзакциями с базой данных. он обеспечивает автоматическое 
        #начало транзакции при входе в блок и коммит или откат транзакции при выходе из блока в зависимости от наличия исключений. этот метод позволяет
        #гарантировать целостность данных при выполнении нескольких связанных операций с базой данных, обеспечивая атомарность и согласованность.
        with self.connection() as conn:
            try:
                yield conn
                conn.commit()
            except:
                conn.rollback()
                raise

    def add_import_export_history(self, *, operation_type: str, format: str, encryption_used, entry_count: int = 0,
                                  file_size: int = 0, checksum: str = None, verification_status=None, details=None,
                                  file_path: str = None):
        """Insert a row into import_export_history.

        Normalizes some incoming values (encryption_used -> int flag, verification_status -> verified int)
        and stores optional details as JSON into the `file_path` column when no explicit path is given.
        """
        # normalize encryption_used to integer flag (1 = used, 0 = not used)
        try:
            if isinstance(encryption_used, (str,)):
                enc_flag = 0 if encryption_used.lower() in ("none", "0", "false", "no", "") else 1
            else:
                enc_flag = 1 if bool(encryption_used) else 0
        except Exception:
            enc_flag = 1

        # normalize verification_status to integer (1 = verified/success, 0 = not)
        verified = 1 if str(verification_status).lower() in ("1", "true", "verified", "ok", "success") else 0

        details_json = None
        if details is not None:
            try:
                details_json = json.dumps(details, ensure_ascii=False)
            except Exception:
                details_json = str(details)

        # if caller provided explicit file_path, use it; else store details JSON in file_path column
        store_path = file_path if file_path else details_json

        sql = (
            "INSERT INTO import_export_history"
            " (operation_type, format, encryption_used, entry_count, file_size, file_path, checksum, verified)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        )
        params = (operation_type, format, enc_flag, entry_count, file_size, store_path, checksum, verified)
        with self.transaction() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)
            # do not return id to keep API simple; caller can query if needed
        
__all__ = ["DatabasePool"]