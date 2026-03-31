from typing import Optional
from crypto.key_derivation import KeyDerivation
from crypto.key_cache import KeyCache
from crypto.key_storage import KeyStorage


class KeyManager:
    def __init__(self, storage: KeyStorage, config: dict):
        self.storage = storage
        self.derivation = KeyDerivation(config)
        self.cache = KeyCache()

        self._password: Optional[str] = None  # временно (до UI)

    # установка пароля (например после логина)
    def set_password(self, password: str):
        self._password = password

    # основной метод (использует EntryManager)
    def get_active_key(self) -> bytes:
        # 1. пробуем кэш
        cached = self.cache.get_key()
        if cached:
            return cached

        # 2. получаем параметры
        params = self.storage.get_pbkdf2_params()
        if not params:
            raise RuntimeError("Key not initialized")

        if not self._password:
            raise RuntimeError("Password not set")

        # 3. деривация
        key = self.derivation.derive_encryption_key(
            self._password,
            params["salt"]
        )

        # 4. кидаем в кэш
        self.cache.store_key(key)

        return key

    # первичная инициализация (регистрация)
    def initialize(self, password: str):
        salt = self.derivation.generate_salt()

        self.storage.add_pbkdf2_params(
            salt=salt,
            iterations=self.derivation.pbkdf2_iterations,
            key_len=self.derivation.pbkdf2_key_len
        )

        key = self.derivation.derive_encryption_key(password, salt)
        self.cache.store_key(key)

        self._password = password

    # логин
    def unlock(self, password: str) -> bool:
        params = self.storage.get_pbkdf2_params()
        if not params:
            return False

        key = self.derivation.derive_encryption_key(
            password,
            params["salt"]
        )

        # можно добавить проверку через тестовую запись
        self.cache.store_key(key)
        self._password = password

        return True

    # логика блокировки 
    def lock(self):
        self.cache.clear_key()
        self._password = None