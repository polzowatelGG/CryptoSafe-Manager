from pathlib import Path
import time, os
from pytest import MonkeyPatch
from core.crypto.key_derivation import KeyDerivation
from core.crypto.key_cache import KeyCache
from core.events import EventBus
from core.crypto.key_storage import KeyStorage
from core.key_manager import KeyManager
from database.db import DatabasePool
import statistics


def test_change_password_with_reencrypt(tmp_path: Path):
    #Проверяет смену мастер-пароля с перешифрованием всех записей.

    from core.vault.entry_manager import EntryManager

    db_file = tmp_path / "test.db"
    pool = DatabasePool(str(db_file))
    pool.migrate()

    key_storage = KeyStorage(pool)
    key_manager = KeyManager(key_storage, {
        "argon2_time": 3,
        "argon2_memory": 65536,
        "argon2_parallelism": 4,
        "pbkdf2_iterations": 100000,
    })

    key_manager.initialize("OldPassword123!")
    assert key_manager.unlock("OldPassword123!")

    entry_manager = EntryManager(pool, key_manager)

    ids = []
    for i in range(10):
        eid = entry_manager.create_entry({
            "title":    f"Entry{i}",
            "username": f"user{i}",
            "password": f"pass{i}",
            "url":      f"https://site{i}.com",
            "notes":    f"Note {i}",
            "category": "Test",
        })
        ids.append(eid)

    assert len(ids) == 10

    # Меняем пароль: старый ключ расшифровывает все записи,
    # новый ключ шифрует их заново и сохраняет в БД
    key_manager.change_password("OldPassword123!", "NewPassword456!", entry_manager)

    key_manager.lock()
    assert key_manager.unlock("NewPassword456!"), "Новый пароль не работает"

    # Все 10 записей должны быть доступны и содержать оригинальные данные
    for i, eid in enumerate(ids):
        entry = entry_manager.get_entry(eid)
        assert entry["title"]    == f"Entry{i}",    f"title повреждён у записи {i}"
        assert entry["username"] == f"user{i}",     f"username повреждён у записи {i}"
        assert entry["password"] == f"pass{i}",     f"password повреждён у записи {i}"
        assert entry["url"]      == f"https://site{i}.com", f"url повреждён у записи {i}"

    key_manager.lock()
    # Старый пароль после смены должен быть недействителен
    assert not key_manager.unlock("OldPassword123!"), "Старый пароль не должен работать"


def test_keychain_fallback_store_load(tmp_path: Path, monkeypatch: MonkeyPatch):
    #Проверяет fallback на хранение ключа в БД когда системный keychain недоступен.
    pool = DatabasePool(str(tmp_path / "test.db"))
    pool.migrate()

    storage = KeyStorage(pool)
    # Симулируем недоступность системного keychain (нет macOS Keychain / SecretService)
    monkeypatch.setattr(storage, "_keychain_available", lambda: False)

    key = b"0123456789abcdef0123456789abcdef"
    storage.store_encryption_key(key)
    loaded = storage.load_encryption_key()
    assert loaded == key

    storage.delete_encryption_key()
    assert storage.load_encryption_key() is None


def test_key_derivation_consistency():
    #Проверяет детерминированность деривации ключа
    config = {"pbkdf2_iterations": 100000}
    kd = KeyDerivation(config)
    password = "test_password"
    salt = os.urandom(16)

    keys = []
    for _ in range(100):
        key = kd.derive_encryption_key(password, salt)
        keys.append(key)

    # Все 100 вызовов должны вернуть идентичный ключ
    first = keys[0]
    for key in keys[1:]:
        assert key == first

def test_timing_attack_resistance():

    #Проверяет защиту от timing attack: время проверки правильного и неправильного пароля должно быть статистически неразличимым.
    config = {
        "argon2_time":        3,
        "argon2_memory":      65536,
        "argon2_parallelism": 4,
        "pbkdf2_iterations":  100000,
    }
    kd = KeyDerivation(config)

    correct_password = "CorrectPass123!"
    wrong_password   = "WrongPass123!!"

    stored_hash = kd.create_auth_hash(correct_password)

    # Прогрев: первые вызовы argon2 медленнее из-за cold CPU cache,
    # без прогрева результаты были бы нерелевантны
    WARMUP_RUNS = 3
    for _ in range(WARMUP_RUNS):
        kd.verify_password(correct_password, stored_hash)
        kd.verify_password(wrong_password,   stored_hash)

    RUNS = 30  # 30 замеров для статистической надёжности

    correct_times = []
    for _ in range(RUNS):
        start = time.perf_counter()
        kd.verify_password(correct_password, stored_hash)
        correct_times.append(time.perf_counter() - start)

    wrong_times = []
    for _ in range(RUNS):
        start = time.perf_counter()
        kd.verify_password(wrong_password, stored_hash)
        wrong_times.append(time.perf_counter() - start)

    # Используем медиану а не среднее — устойчива к выбросам от планировщика ОС
    correct_median = statistics.median(correct_times)
    wrong_median   = statistics.median(wrong_times)

    larger = max(correct_median, wrong_median)
    diff   = abs(correct_median - wrong_median)

    THRESHOLD = 0.35  # 35% — допустимое отклонение с учётом шума системы

    assert diff / larger < THRESHOLD, (
        f"Подозрение на timing attack: "
        f"правильный={correct_median:.4f}с, "
        f"неправильный={wrong_median:.4f}с, "
        f"разница={diff / larger * 100:.1f}% "
        f"(допустимо < {THRESHOLD * 100:.0f}%)"
    )