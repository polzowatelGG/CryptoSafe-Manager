import time
import psutil  # нужно установить: pip install psutil
import os
from database.db import DatabasePool
from core.crypto.key_storage import KeyStorage
from core.key_manager import KeyManager
from core.vault.entry_manager import EntryManager

def test_performance_1000_entries(tmp_path):
    db_file = tmp_path / "perf.db"
    pool = DatabasePool(str(db_file))
    pool.migrate()
    key_storage = KeyStorage(pool)
    key_manager = KeyManager(key_storage, {...})
    key_manager.initialize("StrongPass123!")
    key_manager.unlock("StrongPass123!")
    entry_manager = EntryManager(pool, key_manager)

    # создаём 1000 записей
    start = time.time()
    ids = []
    for i in range(1000):
        eid = entry_manager.create_entry({"title": f"Perf{i}", "password": "p"})
        ids.append(eid)
    create_time = time.time() - start
    assert create_time < 2.0, f"Creation of 1000 entries took {create_time:.2f}s"

    # замеряем память после создания (приблизительно)
    process = psutil.Process(os.getpid())
    mem_mb = process.memory_info().rss / 1024 / 1024
    assert mem_mb < 50, f"Memory usage {mem_mb:.1f} MB exceeds 50 MB"

    # поиск
    start = time.time()
    results = [entry_manager.get_entry(eid) for eid in ids[:100]]  # первые 100
    search_time = time.time() - start
    assert search_time < 0.2, f"100 random searches took {search_time:.2f}s"