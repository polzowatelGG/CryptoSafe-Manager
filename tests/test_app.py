from pathlib import Path
from src.app import _init_new_vault, _open_existing_vault

def test_init_new_vault(tmp_path):
    db_path = str(tmp_path / "new.db")
    pool, km = _init_new_vault(db_path, "TestPass123!")
    assert pool is not None
    assert km.is_unlocked()
    assert Path(db_path).exists()

def test_open_existing_vault(tmp_path):
    db_path = str(tmp_path / "exist.db")
    pool, km = _init_new_vault(db_path, "TestPass123!")
    km.lock()
    pool2, km2 = _open_existing_vault(db_path)
    assert km2.is_unlocked() is False