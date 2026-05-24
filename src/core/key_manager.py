# key_manager.py - управление ключами шифрования, включая инициализацию, разблокировку, доступ к ключу, блокировку и смену пароля.
# он использует KeyStorage для сохранения и загрузки параметров аутентификации и PBKDF2, KeyDerivation для генерации ключей на основе пароля и соли,
# KeyCache для хранения активного ключа в памяти, и публикует события входа и выхода пользователя через шину событий.

from core.crypto.key_derivation import KeyDerivation
from core.crypto.key_cache import KeyCache
from core.crypto.key_storage import KeyStorage
from core.events import publish, USER_LOGGED_IN, USER_LOGGED_OUT
from core.crypto.key_derivation import PasswordValidator


class KeyManager: # класс для управления ключами шифрования, включая инициализацию, разблокировку, доступ к ключу, блокировку и смену пароля. он использует KeyStorage для сохранения и загрузки параметров аутентификации и PBKDF2, 
    #KeyDerivation для генерации ключей на основе пароля и соли, KeyCache для хранения активного ключа в памяти, и публикует события входа и выхода пользователя через шину событий.
    def __init__(self, storage: KeyStorage, config):
        self.storage = storage
        self.derivation = KeyDerivation(config)
        self.cache = KeyCache()
        self._unlocked = False


    def initialize(self, password: str): #метод для инициализации менеджера ключей с новым паролем. он генерирует соль, создает хэш аутентификации и сохраняет их в хранилище. этот метод должен быть вызван при первом запуске приложения или при сбросе конфигурации.

        salt = self.derivation.generate_salt()

        auth_hash = self.derivation.create_auth_hash(password)

        self.storage.save_auth_hash(auth_hash)
        self.storage.save_pbkdf2_params(
            salt,
            self.derivation.pbkdf2_iterations
        )


    def unlock(self, password: str) -> bool: #метод для разблокировки менеджера ключей с помощью пароля. он проверяет пароль и, если он верный, генерирует ключ шифрования и сохраняет его в кэше. этот метод должен быть вызван перед доступом к зашифрованным данным.
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


    def get_active_key(self) -> bytes: #метод для получения активного ключа шифрования из кэша. он возвращает ключ, если менеджер ключей разблокирован, и вызывает исключение, если он заблокирован.
        key = self.cache.get_key()

        if not key:
            raise RuntimeError("Vault is locked")

        return key


    def lock(self): #метод для блокировки менеджера ключей. он очищает кэш и устанавливает состояние как заблокированное. этот метод должен быть вызван при выходе пользователя или при блокировке приложения.
        self.cache.clear_key()
        self._unlocked = False
        publish(USER_LOGGED_OUT, user_id="master")


    def is_unlocked(self) -> bool: #метод для проверки, разблокирован ли менеджер ключей. он возвращает True, если менеджер ключей разблокирован, и False в противном случае.
        return self._unlocked


    def change_password(self, old_password: str, new_password: str, entry_manager): #метод для смены пароля. он принимает старый и новый пароли, а также менеджер записей для переупаковки всех записей с новым ключом. он проверяет старый пароль, генерирует новый ключ и хэш, и обновляет все записи в базе данных с новым ключом. если транзакция завершается успешно, он обновляет кэш и keychain новым ключом. если транзакция не удается, он откатывает изменения и сохраняет старый ключ в кэше.
        if not self.unlock(old_password):
            raise ValueError("Current password is invalid")

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

# дополнительные методы для удобства доступа к ключу и управления состоянием блокировки, которые могут быть полезны в других частях приложения.
    def derive_key(self, password: str, salt: bytes) -> bytes:#метод для генерации ключа на основе пароля и соли. 
        return self.derivation.derive_encryption_key(password, salt)

    def store_key(self, key: bytes):#метод для сохранения ключа в кэше.
        self.cache.store_key(key)

    def load_key(self) -> bytes:#метод для загрузки ключа из кэша. он возвращает ключ, если он доступен, и вызывает исключение, если его нет.
        return self.get_active_key()
