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
