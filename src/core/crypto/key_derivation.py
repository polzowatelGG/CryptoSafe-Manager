from argon2 import PasswordHasher, Type
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import re
import secrets


class KeyDerivation:
    def __init__(self, config: dict):
        # настройки Argon2
        self.argon2_hasher = PasswordHasher(
            time_cost=config.get('argon2_time', 3),
            memory_cost=config.get('argon2_memory', 65536),  # 64 MiB
            parallelism=config.get('argon2_parallelism', 4),
            hash_len=32,
            salt_len=16,
            type=Type.ID
        )
        # настройки PBKDF2
        self.pbkdf2_iterations = config.get('pbkdf2_iterations', 100000)
    
    def create_auth_hash(self, password: str) -> dict: #для argon2
        hash_str = self.argon2_hasher.hash(password) #создание хеша для проверки пароля
        params = self.argon2_hasher.params() #возвращение словаря с хешем и параметрами
        return {
            "hash" : hash_str,
            "params" : params
        }
    
    def verify_password(self, password: str, stored_hash: str) -> bool: #для argon2 
        try:
            valid = self.argon2_hasher.verify(stored_hash, password) #предупреждение о повторном хеше 
            return valid
        except:
            secrets.compare_digest(b'dummy', b'dummy') #фиктивная проверка за константное время 
    
    def derive_encryption_key(self, password: str, salt: bytes = None) -> bytes: #для pbkdf2
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA256(),
            length= 32,
            salt = salt,
            iterations = self.pbkdf2_iterations
        )
        key = kdf.derive(password.encode('utf-8'))
        return key, salt
    
    @staticmethod
    def generate_salt(length: int = 16 ) -> bytes: #для pbkdf2        
        return os.urandom(length)
    
    @classmethod
    def validate_password_strength(password: str) -> bool: #проверка 
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
            'hunter',
            'fuckyou',
            'trustno1',
            'ranger'
        ]
        
        lowered_password = password.lower()
        for i in common_passwords:
            if i in lowered_password:
                return False 
            
        return True
        