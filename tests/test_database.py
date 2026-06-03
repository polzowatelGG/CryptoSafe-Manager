import sqlite3
from database.db import DatabasePool

def test_new_connection_basic(tmp_path): 
    db_file = tmp_path / "test.db"
    pool = DatabasePool(str(db_file))

    # new_connection должен возвращать sqlite3.Connection с row_factory sqlite3.Row
    conn = pool.new_connection()
    assert conn is not None
    assert conn.row_factory is sqlite3.Row

    cur = conn.cursor()
    cur.execute("SELECT 1")
    row = cur.fetchone()
    assert row is not None
    assert row[0] == 1

    conn.close()
    pool.close()
    
def test_migrate_creates_all_tables(tmp_path):
    db_file = tmp_path / "test.db"
    pool = DatabasePool(str(db_file))
    pool.migrate()
    with pool.connection() as conn:
        tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        table_names = {row[0] for row in tables}
    expected = {"vault_entries", "audit_log", "settings", "key_store", "deleted_entries",
                "shared_entries", "import_export_history", "contacts", "audit_signing_keys"}
    assert expected.issubset(table_names)

def test_check_integrity_ok(tmp_path):
    pool = DatabasePool(str(tmp_path / "test.db"))
    pool.migrate()
    assert pool.check_integrity() is True

def test_add_import_export_history(tmp_path):
    pool = DatabasePool(str(tmp_path / "test.db"))
    pool.migrate()
    pool.add_import_export_history(
        operation_type="export", format="json", encryption_used=True,
        entry_count=5, file_size=1024, checksum="abc", verification_status="verified"
    )
    row = pool.execute("SELECT * FROM import_export_history").fetchone()
    assert row["operation_type"] == "export"
    assert row["entry_count"] == 5
