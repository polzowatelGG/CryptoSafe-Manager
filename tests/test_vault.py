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

    entry_id = em.create_entry({"title": "Site", "username": "user", "password": "pass", "url": "https://site", "notes": "note", "tags": "test"})
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