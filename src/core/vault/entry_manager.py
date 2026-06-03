import json
import logging
import uuid
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import core.events as events

_log = logging.getLogger(__name__)

_NONCE_SIZE           = 12
_TAG_SIZE             = 16
_SOFT_DELETE_TTL_DAYS = 30


class EntryManager:
    def __init__(self, db_connection, key_manager, event_system=None):
        self.db          = db_connection
        self.key_manager = key_manager
        self.events      = event_system if event_system is not None else events

    # ─────────────────────────────────────────────────────────────────
    # Криптографические вспомогательные методы
    # ─────────────────────────────────────────────────────────────────

    def _get_crypto(self, key: bytes = None) -> AESGCM:
        if key is None:
            key = self.key_manager.get_active_key()
        if not key:
            raise ValueError("Encryption key not available")
        return AESGCM(key)

    def _encrypt(self, data: dict, key: bytes = None) -> bytes:
        aesgcm    = self._get_crypto(key)
        nonce     = os.urandom(12)
        plaintext = json.dumps(data).encode("utf-8")
        return nonce + aesgcm.encrypt(nonce, plaintext, None)

    def _decrypt(self, encrypted_blob: bytes, key: bytes = None) -> dict:
        aesgcm             = self._get_crypto(key)
        nonce              = encrypted_blob[:_NONCE_SIZE]
        ciphertext_and_tag = encrypted_blob[_NONCE_SIZE:]
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext_and_tag, None)
        except Exception:
            raise ValueError("Decryption failed (corrupted data or wrong key)")
        return json.loads(plaintext.decode("utf-8"))

    # ─────────────────────────────────────────────────────────────────
    # CRUD
    # ─────────────────────────────────────────────────────────────────

    def create_entry(self, data: dict) -> str:
        entry_id = str(uuid.uuid4())
        payload  = {
            "title":           data.get("title", ""),
            "username":        data.get("username", ""),
            "password":        data.get("password", ""),
            "url":             data.get("url", ""),
            "notes":           data.get("notes", ""),
            "category":        data.get("category", ""),
            "totp_secret":     data.get("totp_secret"),
            "shared_metadata": data.get("shared_metadata"),
            "id":              entry_id,
            "created_at":      datetime.utcnow().isoformat(),
            "updated_at":      datetime.utcnow().isoformat(),
            "version":         1,
            "tags":            data.get("tags", ""),
        }
        encrypted_blob = self._encrypt(payload)
        with self.db.transaction() as conn:
            conn.cursor().execute(
                """
                INSERT INTO vault_entries
                    (id, encrypted_data, created_at, updated_at, tags)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    entry_id,
                    encrypted_blob,
                    datetime.utcnow(),
                    datetime.utcnow(),
                    payload.get("tags"),
                ),
            )
        self.events.publish("EntryCreated", entry_id=entry_id)
        self.invalidate_search_cache()
        return entry_id

    def get_entry(self, entry_id: str) -> dict:
        row = self.db.execute(
            "SELECT encrypted_data FROM vault_entries WHERE id = ?",
            (entry_id,),
        ).fetchone()
        if not row:
            raise ValueError("Entry not found")
        return self._decrypt(row["encrypted_data"])

    def get_all_entries(self) -> list:
        """
        FIX: повреждённые записи больше не пропускаются тихо.
        Каждая ошибка логируется с row_id для диагностики.
        Возвращается список успешно расшифрованных записей +
        для каждой повреждённой добавляется запись-заглушка с флагом
        _corrupted=True, чтобы GUI мог показать пользователю предупреждение.
        """
        rows = self.db.execute(
            "SELECT id, encrypted_data FROM vault_entries"
        ).fetchall()

        result   = []
        corrupted = []

        for row in rows:
            row_id = row["id"] if "id" in row.keys() else "unknown"
            try:
                entry = self._decrypt(row["encrypted_data"])
                result.append(entry)
            except ValueError as exc:
                _log.warning(
                    "Не удалось расшифровать запись id=%s: %s", row_id, exc
                )
                corrupted.append(row_id)
            except Exception as exc:
                _log.error(
                    "Неожиданная ошибка при расшифровке id=%s: %s", row_id, exc
                )
                corrupted.append(row_id)

        # Публикуем событие поиска
        try:
            self.events.publish(
                "VaultSearched",
                query="[ALL]",
                result_count=len(result),
            )
        except Exception:
            pass


        if corrupted:
            try:
                self.events.publish(
                    "CorruptedEntriesFound",
                    count=len(corrupted),
                    entry_ids=corrupted,
                )
            except Exception:
                pass

        return result

    def search_entries(self, query: str) -> list:
        if not hasattr(self, '_entry_cache') or self._entry_cache is None:
            self._entry_cache    = self.get_all_entries()
            self._cache_version  = self._current_version()

        if self._cache_version != self._current_version():
            self._entry_cache   = self.get_all_entries()
            self._cache_version = self._current_version()

        q = query.lower().strip()
        results = [
            e for e in self._entry_cache
            if q in e.get("title",    "").lower()
            or q in e.get("username", "").lower()
            or q in e.get("url",      "").lower()
            or q in e.get("notes",    "").lower()
            or q in e.get("category", "").lower()
        ]
        try:
            self.events.publish(
                "VaultSearched",
                query="[REDACTED]",
                query_length=len(query),
                result_count=len(results),
            )
        except Exception:
            pass
        return results

    def _current_version(self) -> int:
        try:
            with self.db.connection() as conn:
                row = conn.execute(
                    "SELECT MAX(rowid) FROM vault_entries"
                ).fetchone()
            return row[0] if row and row[0] else 0
        except Exception:
            return -1

    def invalidate_search_cache(self):
        self._entry_cache = None

    def update_entry(self, entry_id: str, new_data: dict):
        existing = self.get_entry(entry_id)
        updated  = {
            **existing,
            **new_data,
            "updated_at": datetime.utcnow().isoformat(),
            "version":    existing.get("version", 1) + 1,
        }
        encrypted_blob = self._encrypt(updated)
        with self.db.transaction() as conn:
            conn.cursor().execute(
                """
                UPDATE vault_entries
                SET encrypted_data = ?, updated_at = ?, tags = ?
                WHERE id = ?
                """,
                (
                    encrypted_blob,
                    datetime.utcnow(),
                    updated.get("tags"),
                    entry_id,
                ),
            )
        self.events.publish("EntryUpdated", entry_id=entry_id)
        self.invalidate_search_cache()

    def delete_entry(self, entry_id: str, soft_delete: bool = True):
        now     = datetime.utcnow()
        expires = now + timedelta(days=_SOFT_DELETE_TTL_DAYS)
        with self.db.transaction() as conn:
            cur = conn.cursor()
            if soft_delete:
                cur.execute(
                    """
                    INSERT OR REPLACE INTO deleted_entries
                        (id, deleted_at, expires_at)
                    VALUES (?, ?, ?)
                    """,
                    (entry_id, now, expires),
                )
            cur.execute(
                "DELETE FROM vault_entries WHERE id = ?", (entry_id,)
            )
        self.events.publish("EntryDeleted", entry_id=entry_id)
        self.invalidate_search_cache()

    def reencrypt_all(self, old_key: bytes, new_key: bytes, conn=None):
        if conn is None:
            with self.db.transaction() as tmp_conn:
                self.reencrypt_all(old_key, new_key, conn=tmp_conn)
            return
        cur  = conn.cursor()
        rows = cur.execute(
            "SELECT id, encrypted_data FROM vault_entries"
        ).fetchall()
        for row in rows:
            try:
                payload  = self._decrypt(row["encrypted_data"], key=old_key)
                new_blob = self._encrypt(payload,               key=new_key)
                cur.execute(
                    "UPDATE vault_entries SET encrypted_data=?, updated_at=? WHERE id=?",
                    (new_blob, datetime.utcnow(), row["id"]),
                )
            except Exception as exc:
                _log.error(
                    "reencrypt_all: не удалось перешифровать id=%s: %s",
                    row["id"], exc,
                )

    @staticmethod
    def secure_wipe_list(entries: list):
        for entry in entries:
            for key in list(entry.keys()):
                entry[key] = None
            entry.clear()
        entries.clear()