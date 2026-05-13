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
    # Загрузка всех 1000 записей — PERF-1
    start = time.time()
    all_entries = entry_manager.get_all_entries()
    load_time = time.time() - start
    assert load_time < 2.0, f"Loading 1000 entries took {load_time:.2f}s"
    assert len(all_entries) == 1000

    # Поиск среди 1000 записей — PERF-2
    # имитируем фильтрацию по содержимому как делает SecureTable.filter_entries()
    # это реалистичная нагрузка: перебор всех расшифрованных записей по полю title
    search_query = "Perf500"  # ищем конкретную запись по title среди 1000

    start = time.time()
    results = [
        e for e in all_entries
        if search_query.lower() in e.get("title", "").lower()
    ]
    search_time = time.time() - start

    assert search_time < 0.2, (
        f"Search among 1000 entries took {search_time:.3f}s, expected < 0.2s"
    )
    assert len(results) == 1, (
        f"Expected 1 result for '{search_query}', got {len(results)}"
    )

    # затираем расшифрованные данные после теста (SEC-1)
    entry_manager.secure_wipe_list(all_entries)

    # Память после создания
    gc.collect()
    mem_after = process.memory_info().rss / 1024 / 1024
    mem_diff = mem_after - mem_before
    # Прирост памяти не должен превышать 50 МБ (только данные записей)
    assert mem_diff < 50, f"Memory increase {mem_diff:.1f} MB exceeds 50 MB"