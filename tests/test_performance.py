import time
import psutil
import os
import gc
from database.db import DatabasePool
from core.crypto.key_storage import KeyStorage
from core.key_manager import KeyManager
from core.vault.entry_manager import EntryManager

def test_performance_1000_entries(tmp_path):
    db_file = tmp_path / "perf.db"
    pool = DatabasePool(str(db_file))
    pool.migrate()
    key_storage = KeyStorage(pool)
    key_manager = KeyManager(key_storage, {
        "argon2_time": 3,
        "argon2_memory": 65536,
        "argon2_parallelism": 4,
        "pbkdf2_iterations": 100000,
    })
    key_manager.initialize("StrongPass123!")
    key_manager.unlock("StrongPass123!")
    entry_manager = EntryManager(pool, key_manager)

    # Память до создания записей
    gc.collect()
    process = psutil.Process(os.getpid())
    mem_before = process.memory_info().rss / 1024 / 1024

    # Создаём 1000 записей
    start = time.time()
    ids = []
    for i in range(1000):
        eid = entry_manager.create_entry({"title": f"Perf{i}", "password": "p"})
        ids.append(eid)
    create_time = time.time() - start
    assert create_time < 2.0, f"Creation of 1000 entries took {create_time:.2f}s"

    # Память после создания
    gc.collect()
    mem_after = process.memory_info().rss / 1024 / 1024
    mem_diff = mem_after - mem_before
    # Прирост памяти не должен превышать 50 МБ (только данные записей)
    assert mem_diff < 50, f"Memory increase {mem_diff:.1f} MB exceeds 50 MB"

    # Поиск (первые 100 записей)
    start = time.time()
    for eid in ids[:100]:
        entry_manager.get_entry(eid)
    search_time = time.time() - start
    assert search_time < 0.2, f"100 searches took {search_time:.2f}s"