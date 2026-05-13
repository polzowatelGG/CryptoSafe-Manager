from database.db import DatabasePool
from core.crypto.key_storage import KeyStorage
from core.key_manager import KeyManager
from core.vault.entry_manager import EntryManager
from core import events
from core.events import subscribe, unsubscribe


def test_entry_manager_crud_events(tmp_path):
    db_file = tmp_path / "test.db"
    pool = DatabasePool(str(db_file))
    pool.migrate()

    key_storage = KeyStorage(pool)
    km = KeyManager(key_storage, {
        "argon2_time": 3,
        "argon2_memory": 65536,
        "argon2_parallelism": 4,
        "pbkdf2_iterations": 100000,
    })

    km.initialize("StrongPass123!")
    assert km.unlock("StrongPass123!")

    events_received = []

    def on_created(entry_id=None):
        events_received.append(("created", entry_id))

    def on_updated(entry_id=None):
        events_received.append(("updated", entry_id))

    def on_deleted(entry_id=None):
        events_received.append(("deleted", entry_id))

    subscribe("EntryCreated", on_created)
    subscribe("EntryUpdated", on_updated)
    subscribe("EntryDeleted", on_deleted)

    em = EntryManager(pool, km, event_system=events)

    entry_id = em.create_entry({
        "title": "Site", "username": "user",
        "password": "pass", "url": "https://site",
        "notes": "note", "tags": "test"
    })
    
    entry = em.get_entry(entry_id)
    assert "category" in entry
    assert entry["category"] == ""  # дефолт если не передан
    assert entry_id

    assert em.get_entry(entry_id)["title"] == "Site"

    em.update_entry(entry_id, {"password": "newpass"})
    assert em.get_entry(entry_id)["password"] == "newpass"

    em.delete_entry(entry_id)

    assert ("created", entry_id) in events_received
    assert ("updated", entry_id) in events_received
    assert ("deleted", entry_id) in events_received

    unsubscribe("EntryCreated", on_created)
    unsubscribe("EntryUpdated", on_updated)
    unsubscribe("EntryDeleted", on_deleted)


def test_vault_entries_indices_created(tmp_path):
    db_file = tmp_path / "test.db"
    pool = DatabasePool(str(db_file))
    pool.migrate()

    with pool.connection() as conn:
        cur = conn.cursor()
        cur.execute("PRAGMA index_list('vault_entries')")
        indices = {row['name'] for row in cur.fetchall()}

    assert "idx_vault_entries_created_at" in indices
    assert "idx_vault_entries_updated_at" in indices
    assert "idx_vault_entries_tags" in indices

def test_crud_100_entries(tmp_path):
    db_file = tmp_path / "test_100.db"
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
    assert key_manager.unlock("StrongPass123!")

    entry_manager = EntryManager(pool, key_manager)

    # создаём 100 записей
    ids = []
    for i in range(100):
        eid = entry_manager.create_entry({
            "title": f"Entry {i}",
            "username": f"user{i}",
            "password": f"pass{i}",
            "url": f"https://example{i}.com",
            "notes": f"Note {i}",
            "tags": f"tag{i % 10}"
        })
        ids.append(eid)

    # проверяем, что все 100 записей читаются
    all_entries = entry_manager.get_all_entries()
    assert len(all_entries) == 100

    # обновляем каждую запись (меняем пароль)
    for i, eid in enumerate(ids):
        entry_manager.update_entry(eid, {"password": f"newpass{i}"})

    # проверяем, что пароли обновились
    for i, eid in enumerate(ids):
        entry = entry_manager.get_entry(eid)
        assert entry["password"] == f"newpass{i}"

    # удаляем каждую вторую запись (50 штук)
    for i, eid in enumerate(ids):
        if i % 2 == 0:
            entry_manager.delete_entry(eid, soft_delete=False)  # жёсткое удаление для простоты

    # проверяем, что осталось 50 записей
    remaining = entry_manager.get_all_entries()
    assert len(remaining) == 50

    # проверяем, что оставшиеся записи не повреждены
    for entry in remaining:
        assert "title" in entry
        assert "password" in entry

def test_encryption_cycle(tmp_path):
    # инициализация окружения
    db_file = tmp_path / "enc_cycle.db"
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

    # создаём запись с известными данными
    known_data = {
        "title":    "MyBank",
        "username": "john@example.com",
        "password": "SuperSecret99!",
        "url":      "https://mybank.com",
        "notes":    "Personal account",
        "category": "Finance",
    }
    entry_id = entry_manager.create_entry(known_data)
    assert entry_id

    # читаем сырой BLOB из БД и проверяем
    # что открытый текст в нём не присутствует
    with pool.connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT encrypted_data FROM vault_entries WHERE id = ?",
            (entry_id,)
        )
        row = cur.fetchone()

    assert row is not None
    raw_blob = row["encrypted_data"]

    # blob должен быть байтами, не строкой
    assert isinstance(raw_blob, bytes)

    # blob должен быть длиннее nonce(12) + tag(16) = минимум 28 байт
    assert len(raw_blob) > 28

    # ни одно из чувствительных полей не должно читаться в blob как UTF-8 текст
    # пробуем декодировать — если получится и там есть открытый текст, тест падает
    sensitive_values = [
        known_data["title"],
        known_data["username"],
        known_data["password"],
        known_data["url"],
        known_data["notes"],
        known_data["category"],
    ]
    try:
        blob_as_text = raw_blob.decode("utf-8")
        # если декодировалось — проверяем что ни одного значения там нет
        for value in sensitive_values:
            assert value not in blob_as_text, (
                f"Открытый текст '{value}' найден в зашифрованном BLOB — "
                f"шифрование не работает!"
            )
    except UnicodeDecodeError:
        # blob не декодируется как UTF-8 — это ожидаемо для зашифрованных данных
        pass

    # расшифровываем и проверяем целостность данных
    decrypted = entry_manager.get_entry(entry_id)

    assert decrypted["title"]    == known_data["title"]
    assert decrypted["username"] == known_data["username"]
    assert decrypted["password"] == known_data["password"]
    assert decrypted["url"]      == known_data["url"]
    assert decrypted["notes"]    == known_data["notes"]
    assert decrypted["category"] == known_data["category"]

    # версия и id должны быть проставлены автоматически
    assert decrypted["version"] == 1
    assert decrypted["id"]      == entry_id