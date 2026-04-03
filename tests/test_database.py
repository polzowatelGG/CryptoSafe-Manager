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
