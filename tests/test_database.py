import sqlite3
from database.db import DatabasePool

def test_migrate_creates_tables(tmp_path):
    db_file = tmp_path / "test.db"
    pool = DatabasePool(str(db_file))
    pool.migrate()

    # проверяем, что таблица vault_entries создана
    with pool.connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vault_entries'")
        assert cur.fetchone() is not None

    pool.close()
