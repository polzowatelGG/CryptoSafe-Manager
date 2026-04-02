from core.crypto.key_derivation import KeyDerivation
from core.crypto.key_cache import KeyCache
from core.crypto.key_storage import KeyStorage


class KeyManager:
    def __init__(self, storage: KeyStorage, config):
        self.storage = storage
        self.derivation = KeyDerivation(config)
        self.cache = KeyCache()
        self._unlocked = False

    # ---------------- INIT ----------------

    def initialize(self, password: str):
        """
        Первый запуск — создаём salt + auth hash
        """
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

    # ---------------- STATE ----------------

    def is_unlocked(self) -> bool:
        return self._unlocked