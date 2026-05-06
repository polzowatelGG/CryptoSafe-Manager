# src/database/migrations.py
# Централизованное управление миграциями схемы базы данных.
# Каждая функция migration_N отвечает за одну версию схемы.
# Добавление новых колонок делается через _add_column_if_missing
# чтобы не потерять данные в уже существующих базах.

from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from database.db import DatabasePool


def migrate(pool: "DatabasePool"):
    # точка входа — вызывается из db.py при pool.migrate()
    # здесь ничего не делаем: вся логика живёт в db.py через _migration_N
    # этот файл теперь содержит только вспомогательные функции миграций
    pass


def ensure_key_store_schema(conn):
    # проверяем и при необходимости обновляем схему таблицы key_store
    # используется при добавлении новых полей в будущих спринтах
    # без пересоздания таблицы и без потери существующих данных

    from database.db import DatabasePool

    # колонки которые должны быть в key_store по ТЗ Спринта 2:
    # id, key_type, key_data, version, created_at
    # если в будущем добавятся новые — добавляем их здесь через _add_column_if_missing

    DatabasePool._add_column_if_missing(
        conn, "key_store", "version", "INTEGER DEFAULT 1"
    )
    DatabasePool._add_column_if_missing(
        conn, "key_store", "params", "TEXT"
    )


def ensure_audit_log_schema(conn):
    # проверяем и при необходимости обновляем схему таблицы audit_log
    # используется при переходе от заглушки Спринта 1
    # к полноценной реализации Спринта 5

    from database.db import DatabasePool

    DatabasePool._add_column_if_missing(
        conn, "audit_log", "sequence_number", "INTEGER"
    )
    DatabasePool._add_column_if_missing(
        conn, "audit_log", "previous_hash", "TEXT"
    )
    DatabasePool._add_column_if_missing(
        conn, "audit_log", "entry_data", "BLOB"
    )
    DatabasePool._add_column_if_missing(
        conn, "audit_log", "entry_hash", "TEXT"
    )