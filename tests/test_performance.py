import time
import psutil
import os
import gc
from database.db import DatabasePool
from core.crypto.key_storage import KeyStorage
from core.key_manager import KeyManager
from core.vault.entry_manager import EntryManager


def test_performance_1000_entries(tmp_path):
    #Комплексный тест производительности на 1000 записей.

    #Проверяемые требования ТЗ:
    #- Загрузка 1000 записей < 2 с
    #- Поиск среди 1000 записей < 200 мс
    #- Прирост памяти после операций < 50 МБ

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

    # Снимаем baseline памяти до создания записей
    gc.collect()
    process = psutil.Process(os.getpid())
    mem_before = process.memory_info().rss / 1024 / 1024

    # Создаём 1000 записей — это не измеряется по времени,
    # нас интересует только скорость чтения (загрузка из БД)
    for i in range(1000):
        entry_manager.create_entry({
            "title":    f"Entry {i}",
            "username": f"user{i}",
            "password": f"Pass{i}!Xy",
            "url":      f"https://site{i}.com",
            "notes":    f"note {i}",
        })

    # Измеряем время загрузки всех 1000 записей с расшифровкой
    start = time.time()
    all_entries = entry_manager.get_all_entries()
    load_time = time.time() - start
    assert load_time < 2.0, f"Loading 1000 entries took {load_time:.2f}s"
    assert len(all_entries) == 1000

    # Имитируем фильтрацию как в UI: линейный перебор с поиском подстроки.
    # Это реалистичная нагрузка — именно так работает поиск в таблице паролей.
    search_query = "Entry 500"

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

    # Явно затираем расшифрованные данные после использования —
    # не оставляем пароли в памяти дольше необходимого
    entry_manager.secure_wipe_list(all_entries)

    # Проверяем прирост памяти: не должен превысить 50 МБ
    # (только сами данные записей, без оверхеда интерпретатора)
    gc.collect()
    mem_after = process.memory_info().rss / 1024 / 1024
    mem_diff = mem_after - mem_before
    assert mem_diff < 50, f"Memory increase {mem_diff:.1f} MB exceeds 50 MB"