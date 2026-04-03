from core.crypto.key_derivation import KeyDerivation
from core.crypto.key_cache import KeyCache
from core.crypto.key_storage import KeyStorage
from core.events import publish, USER_LOGGED_IN, USER_LOGGED_OUT


class KeyManager:
    def __init__(self, storage: KeyStorage, config):
        self.storage = storage
        self.derivation = KeyDerivation(config)
        self.cache = KeyCache()
        self._unlocked = False

    # ---------------- INIT ----------------

    def initialize(self, password: str):

        salt = self.derivation.generate_salt()

        auth_hash = self.derivation.create_auth_hash(password)

        self.storage.save_auth_hash(auth_hash)
        self.storage.save_pbkdf2_params(
            salt,
            self.derivation.pbkdf2_iterations
        )

    # ---------------- UNLOCK ----------------

    def unlock(self, password: str) -> bool:
        stored_hash = self.storage.get_auth_hash()
        params = self.storage.get_pbkdf2_params()

        if not stored_hash or not params:
            return False

        if not self.derivation.verify_password(password, stored_hash):
            return False

        key = self.derivation.derive_encryption_key(
            password,
            params["salt"]
        )

        self.cache.store_key(key)
        self._unlocked = True
        publish(USER_LOGGED_IN, user_id="master")

        return True

    # ---------------- ACCESS ----------------

    def get_active_key(self) -> bytes:
        key = self.cache.get_key()

        if not key:
            raise RuntimeError("Vault is locked")

        return key

    # ---------------- LOCK ----------------

    def lock(self):
        self.cache.clear_key()
        self._unlocked = False
        publish(USER_LOGGED_OUT, user_id="master")

    # ---------------- STATE ----------------

    def is_unlocked(self) -> bool:
        return self._unlocked

    # ---------------- CHANGE PASSWORD ----------------

    def change_password(self, old_password: str, new_password: str, entry_manager):
        if not self.unlock(old_password):
            raise ValueError("Current password is invalid")

        from core.crypto.key_derivation import PasswordValidator

        if not PasswordValidator.validate_password_strength(new_password):
            raise ValueError("New password does not meet strength requirements")

        # текущий активный ключ
        old_key = self.get_active_key()

        # новый ключ и хэш
        new_salt = self.derivation.generate_salt()
        new_hash = self.derivation.create_auth_hash(new_password)
        new_key = self.derivation.derive_encryption_key(new_password, new_salt)

        try:
            with entry_manager.db.connection() as conn:
                # переупакуем все записи
                entry_manager.reencrypt_all(old_key, new_key, conn=conn)

                # записываем обновлённые параметры ключа
                self.storage.save_auth_hash_on_conn(conn, new_hash)
                self.storage.save_pbkdf2_params_on_conn(conn, new_salt, self.derivation.pbkdf2_iterations)

                conn.commit()

            # если транзакция завершена — обновляем кэш и keychain
            self.cache.store_key(new_key)
            self._unlocked = True

            try:
                self.storage.store_encryption_key(new_key)
            except Exception:
                # Keychain может быть недоступен, это необязательно
                pass

            return True

        except Exception:
            # rollback выполняется автоматически контекстом with
            # оставляем старый ключ в кэше и состояние
            self.cache.store_key(old_key)
            self._unlocked = True
            raise

    # ---------------- KEY STORAGE API  ----------------
    def derive_key(self, password: str, salt: bytes) -> bytes:
        return self.derivation.derive_encryption_key(password, salt)

    def store_key(self, key: bytes):
        self.cache.store_key(key)

    def load_key(self) -> bytes:
        return self.get_active_key()
