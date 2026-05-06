# модуль для управления производными ключами и хэшами паролей. он использует argon2 для хэширования паролей и PBKDF2 для 
# генерации ключей шифрования. он также включает валидатор паролей для проверки их сложности и предотвращения использования слабых паролей.
# он обеспечивает безопасное управление ключами и хэшами, а также защиту от атак перебором паролей и других распространенных уязвимостей, связанных с аутентификацией и управлением ключами.

from argon2 import PasswordHasher, Type
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import re
import secrets

class KeyDerivation: # класс для управления производными ключами и хэшами паролей. он использует argon2 для хэширования паролей и PBKDF2 для генерации ключей шифрования. он также включает валидатор паролей для проверки их сложности и предотвращения использования слабых паролей.
    def __init__(self, config: dict):
        self._validate_config(config)

        self.argon2 = PasswordHasher(
            time_cost=config.get('argon2_time', 3),
            memory_cost=config.get('argon2_memory', 65536),
            parallelism=config.get('argon2_parallelism', 4),
            hash_len=config.get('argon2_hash_len', 32),
            type=Type.ID
        )

        self.pbkdf2_iterations = config.get('pbkdf2_iterations', 100000)
        self.pbkdf2_key_len = config.get('pbkdf2_key_len', 32)

    def _validate_config(self, config): # метод для проверки конфигурации на соответствие минимальным требованиям безопасности. он проверяет, что параметры argon2 и PBKDF2 не ниже рекомендуемых значений, чтобы обеспечить достаточную защиту от атак перебором паролей.
        if config.get('argon2_memory', 65536) < 65536:
            raise ValueError("Argon2 memory too low")

        if config.get('argon2_time', 3) < 3:
            raise ValueError("Argon2 time cost too low")

        if config.get('pbkdf2_iterations', 100000) < 100000:
            raise ValueError("PBKDF2 iterations too low")

    @staticmethod
    def generate_salt(length: int = 16) -> bytes: # метод для генерации случайной соли. он возвращает соль заданной длины, которая используется для хэширования паролей.
        if length != 16:
            raise ValueError("salt must be 16 bytes (security requirement)")
        return os.urandom(length)

    def create_auth_hash(self, password: str) -> str: # метод для создания хэша пароля. он принимает пароль и возвращает его хэш, используя argon2. этот хэш может быть сохранен в базе данных для последующей проверки при аутентификации.
        return self.argon2.hash(password)

    def verify_password(self, password: str, stored_hash: str) -> bool: # метод для проверки пароля. он принимает пароль и сохраненный хэш, и возвращает True, если пароль соответствует хэшу, и False в противном случае. он также использует безопасное сравнение для предотвращения атак по времени.
        try:
            result = self.argon2.verify(stored_hash, password)
            return result
        except Exception:
            secrets.compare_digest(os.urandom(32), os.urandom(32))
            return False

    def derive_encryption_key(self, password: str, salt: bytes) -> bytes: # метод для генерации ключа шифрования. он принимает пароль и соль, и возвращает производный ключ, используя PBKDF2.
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.pbkdf2_key_len,
            salt=salt,
            iterations=self.pbkdf2_iterations
        )
        return kdf.derive(password.encode())
    
class PasswordValidator: # класс для проверки сложности паролей. он включает статический метод для проверки, соответствует ли пароль определенным требованиям безопасности, таким как минимальная длина, наличие букв верхнего и нижнего регистра, цифр и специальных символов, а также отсутствие в списке распространенных паролей.
    @staticmethod
    def validate_password_strength(password: str) -> bool: #проверка 
        common_passwords = [
            'password',
            '123456',
            '12345678',
            '1234',
            'qwerty',
            '12345',
            'dragon',
            'pussy',
            'baseball',
            'football',
            'letmein',
            'monkey',
            '696969',
            'abc123',
            'mustang',
            'michael',
            'shadow',
            'master',
            'jennifer',
            '111111',
            '2000',
            'jordan',
            'superman',
            'harley',
            '1234567',
            'fuckme',
            'fuckyou',
            'hunter',
            'trustno1',
            'ranger'
        ]
        
        if len(password) < 12:
            return False
        if not re.search(r'[a-z]', password):
            return False
        if not re.search(r'[A-Z]', password):
            return False
        if not re.search(r'\d', password):
            return False
        if not re.search(r'[^A-Za-z0-9]', password):
            return False
        
        if password.lower() in common_passwords:
            return False

        return True