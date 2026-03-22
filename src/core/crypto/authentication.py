import time
from key_derivation import KeyDerivation
from key_cache import KeyCache
from core.events import EventBus
from key_storage import KeyStorage

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
        if 1 <= self.failed_attempts <= 2:
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