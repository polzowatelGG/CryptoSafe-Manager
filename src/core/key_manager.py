import hashlib
import ctypes
import secrets
from typing import Tuple, Optional

class KeyManager:
    def derive_key(self, password: str, salt: Optional[bytes]) -> Tuple[bytes, bytes]:

        password_bytes = password.encode('utf-8')
        used_salt = secrets.token_bytes(16) if salt is None else salt
        combo = password_bytes + used_salt
        key = hashlib.sha256(combo).digest()
        self.secure_erase(bytearray(password_bytes))
        self.secure_erase(bytearray(combo))

        return key, used_salt
    
    def secure_erase(self, data: bytearray): # Функция для безопасного удаления данных из памяти / заглушка до 4 спринта
        ptr = (ctypes.c_char * len(data)).from_buffer(data) #
        for i in range(len(data)):
            ptr[i] = 0  # Заполняем данные нулями для безопасного удаления

    def store_key(self):    # Функция для сохранения ключа в файл / заглушка
        pass
    
    def load_key(self):     # Функция для загрузки ключа из файла / заглушка
        pass