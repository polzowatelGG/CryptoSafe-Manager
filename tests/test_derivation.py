from pathlib import Path
import time, os
from pytest import MonkeyPatch
from core.crypto.key_derivation import KeyDerivation
from core.crypto.key_cache import KeyCache
from core.events import EventBus
from core.crypto.key_storage import KeyStorage
from core.key_manager import KeyManager
from database.db import DatabasePool
import time
import statistics

class Authenticator:
    def __init__(
        self,
        key_derivation: KeyDerivation,
        cache: KeyCache,
        storage: KeyStorage,
        event_bus: EventBus
    ):
        self.kd = key_derivation
        self.cache = cache
        self.storage = storage
        self.events = event_bus

        self.failed_attempts = 0

        # session tracking
        self.login_time = None
        self.last_activity = None

    def login(self, password: str) -> bool:
        delay = self._calculate_delay()
        if delay > 0:
            time.sleep(delay)

        stored_hash = self.storage.get_auth_hash()
        pbkdf2 = self.storage.get_pbkdf2_params()

        if not pbkdf2:
            raise ValueError("Missing PBKDF2 parameters")

        try:
            if stored_hash:
                is_valid = self.kd.verify_password(password, stored_hash)
            else:
                dummy_hash = self.kd.create_auth_hash("dummy_password")
                self.kd.verify_password(password, dummy_hash)
                is_valid = False

            if is_valid:
                enc_key = self.kd.derive_encryption_key(
                    password,
                    pbkdf2["salt"]
                )

                self.cache.store_key(enc_key)

                # secure wipe
                enc_key = bytearray(enc_key)
                for i in range(len(enc_key)):
                    enc_key[i] = 0

                self.failed_attempts = 0

                now = time.time()
                self.login_time = now
                self.last_activity = now

                self.events.publish("UserLoggedIn")
                return True

            else:
                self.failed_attempts += 1
                self.events.publish("LoginFailed")
                return False

        finally:
            password = None

    def _calculate_delay(self) -> int:
        if self.failed_attempts == 0:
            return 0         
        elif 1 <= self.failed_attempts <= 2:
            return 1
        elif 3 <= self.failed_attempts <= 4:
            return 5
        else:
            return 30

    def touch(self):
        self.last_activity = time.time()

    def logout(self):
        self.cache.clear_key()
        self.login_time = None
        self.last_activity = None
        self.events.publish("UserLoggedOut")


def test_change_password_with_reencrypt(tmp_path: Path):
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
    
    key_manager.change_password("OldPassword123!", "NewPassword456!", entry_manager)

    key_manager.lock()
    assert key_manager.unlock("NewPassword456!"), "Новый пароль не работает"

    for i, eid in enumerate(ids):
        entry = entry_manager.get_entry(eid)
        assert entry["title"]    == f"Entry{i}",    f"title повреждён у записи {i}"
        assert entry["username"] == f"user{i}",     f"username повреждён у записи {i}"
        assert entry["password"] == f"pass{i}",     f"password повреждён у записи {i}"
        assert entry["url"]      == f"https://site{i}.com", f"url повреждён у записи {i}"

    key_manager.lock()
    assert not key_manager.unlock("OldPassword123!"), "Старый пароль не должен работать"


def test_keychain_fallback_store_load(tmp_path: Path, monkeypatch: MonkeyPatch):
    pool = DatabasePool(str(tmp_path / "test.db"))
    pool.migrate()

    storage = KeyStorage(pool)
    monkeypatch.setattr(storage, "_keychain_available", lambda: False)

    key = b"0123456789abcdef0123456789abcdef"
    storage.store_encryption_key(key)
    loaded = storage.load_encryption_key()
    assert loaded == key

    storage.delete_encryption_key()
    assert storage.load_encryption_key() is None

def test_key_derivation_consistency():
    from core.crypto.key_derivation import KeyDerivation
    config = {"pbkdf2_iterations": 100000}  # маленькое значение для скорости теста
    kd = KeyDerivation(config)
    password = "test_password"
    salt = os.urandom(16)
    
    keys = []
    for _ in range(100):
        key = kd.derive_encryption_key(password, salt)
        keys.append(key)
    
    # все ключи должны быть одинаковыми
    first = keys[0]
    for key in keys[1:]:
        assert key == first
        
def test_timing_attack_resistance():
    # проверяем что verify_password() выполняется
    # за статистически одинаковое время для правильного
    # и неправильного пароля — защита от timing attack
    import statistics

    config = {
        "argon2_time": 3,
        "argon2_memory": 65536,
        "argon2_parallelism": 4,
        "pbkdf2_iterations": 100000,
    }
    kd = KeyDerivation(config)

    correct_password = "CorrectPass123!"
    wrong_password   = "WrongPass123!!"

    stored_hash = kd.create_auth_hash(correct_password)

    runs = 10

    correct_times = []
    for _ in range(runs):
        start = time.perf_counter()
        kd.verify_password(correct_password, stored_hash)
        correct_times.append(time.perf_counter() - start)

    wrong_times = []
    for _ in range(runs):
        start = time.perf_counter()
        kd.verify_password(wrong_password, stored_hash)
        wrong_times.append(time.perf_counter() - start)

    correct_median = statistics.median(correct_times)
    wrong_median   = statistics.median(wrong_times)

    larger = max(correct_median, wrong_median)
    diff   = abs(correct_median - wrong_median)

    assert diff / larger < 0.20, (
        f"Подозрение на timing attack: "
        f"правильный={correct_median:.4f}с, "
        f"неправильный={wrong_median:.4f}с, "
        f"разница={diff/larger*100:.1f}%"
    )