# модуль для управления безопасным хранением ключей и хэшей. он использует keyring для хранения ключей в системном хранилище, а также обеспечивает резервное сохранение в файле с ограниченными правами доступа. он также включает методы для сохранения и получения хэшей аутентификации 
# и параметров PBKDF2, которые используются для генерации ключей шифрования. этот модуль обеспечивает надежное управление ключами и защиту от несанкционированного доступа, а также обеспечивает совместимость с различными операционными системами.
# он также включает методы для сохранения и получения хэшей аутентификации и параметров PBKDF2, которые используются для генерации ключей шифрования. этот модуль обеспечивает надежное управление ключами и защиту от несанкционированного доступа, а также обеспечивает совместимость с различными операционными системами.

import json
import os
from pathlib import Path
from typing import Optional
from database.db import DatabasePool

try:
    import keyring
except ImportError:
    keyring = None

class KeyStorage: # класс для управления безопасным хранением ключей и хэшей. он использует keyring для хранения ключей в системном хранилище, а также обеспечивает резервное сохранение в файле с ограниченными правами доступа. он также включает методы для сохранения и получения хэшей аутентификации и параметров PBKDF2, которые используются для генерации ключей шифрования. 
    #этот модуль обеспечивает надежное управление ключами и защиту от несанкционированного доступа, а также обеспечивает совместимость с различными операционными системами.
    def __init__(self, pool: DatabasePool): # конструктор класса KeyStorage, который принимает пул соединений с базой данных. он сохраняет пул для использования в методах сохранения и получения данных, а также определяет имя сервиса и пользователя для хранения ключей в keyring, а также путь к файлу для резервного сохранения ключей.
        self.pool = pool
        self._service = "CryptoSafeManager"
        self._username = "master"
        self._fallback_path = Path.home() / ".cryptosafe_manager_key"

    def save_auth_hash(self, auth_hash: str): # метод для сохранения хэша аутентификации. он принимает хэш и сохраняет его в базе данных, используя пул соединений. этот хэш может быть использован для проверки пароля при аутентификации.
        with self.pool.connection() as conn:
            conn.execute(
                """
                INSERT INTO key_store (key_type, key_data)
                VALUES (?, ?)
                """,
                ("auth_hash", auth_hash.encode())
            )
            conn.commit()

    def get_auth_hash(self) -> Optional[str]:# метод для получения хэша аутентификации. он извлекает последний сохраненный хэш из базы данных и возвращает его в виде строки. если хэш не найден, он возвращает None. этот метод используется для проверки пароля при аутентификации.
        with self.pool.connection() as conn:
            row = conn.execute(
                """
                SELECT key_data FROM key_store
                WHERE key_type = 'auth_hash'
                ORDER BY id DESC
                LIMIT 1
                """
            ).fetchone()

            if not row:
                return None

            return row["key_data"].decode()


    def save_pbkdf2_params(self, salt: bytes, iterations: int): # метод для сохранения параметров PBKDF2. он принимает соль и количество итераций, и сохраняет их в базе данных в виде записи с типом "enc_params". эти параметры используются для генерации ключей шифрования и должны быть сохранены для последующего использования при аутентификации и работе с зашифрованными данными.
        params = {
            "iterations": iterations
        }

        with self.pool.connection() as conn:
            conn.execute(
                """
                INSERT INTO key_store (key_type, key_data, params)
                VALUES (?, ?, ?)
                """,
                ("enc_params", salt, json.dumps(params))
            )
            conn.commit()

    def get_pbkdf2_params(self) -> Optional[dict]:# метод для получения параметров PBKDF2. он извлекает последние сохраненные параметры из базы данных и возвращает их в виде словаря. если параметры не найдены, он возвращает None. этот метод используется для генерации ключей шифрования.
        with self.pool.connection() as conn:
            row = conn.execute(
                """
                SELECT key_data, params FROM key_store
                WHERE key_type = 'enc_params'
                ORDER BY id DESC
                LIMIT 1
                """
            ).fetchone()

            if not row:
                return None

            return {
                "salt": row["key_data"],
                **json.loads(row["params"])
            }


    def _keychain_available(self) -> bool: # метод для проверки доступности keyring. он возвращает True, если keyring доступен и может быть использован для хранения ключей, и False в противном случае. это позволяет приложению использовать системное хранилище ключей, если оно доступно, и переключаться на резервный файл, если нет.
        return keyring is not None

    def store_encryption_key(self, key: bytes) -> None: # метод для сохранения ключа шифрования. он принимает ключ в виде байтов и сохраняет его в системном хранилище с помощью keyring, если он доступен. если keyring недоступен или возникает ошибка при сохранении, он сохраняет ключ в виде шестнадцатеричной 
                                                        #строки в файле с ограниченными правами доступа. этот метод обеспечивает надежное хранение ключа шифрования и защиту от несанкционированного доступа.
        hex_key = key.hex()

        if self._keychain_available():
            try:
                keyring.set_password(self._service, self._username, hex_key)
                return
            except Exception:
                # попытка через keychain не удалась — переключаемся на fallback
                pass

        self._save_key_fallback(hex_key)

    def load_encryption_key(self) -> Optional[bytes]: # метод для загрузки ключа шифрования. он пытается загрузить ключ из системного хранилища с помощью keyring, если он доступен. если keyring недоступен или ключ не найден, он пытается загрузить ключ из резервного файла. если ключ найден в любом из источников,
        #он возвращается в виде байтов. если ключ не найден, возвращается None. этот метод обеспечивает надежное извлечение ключа шифрования для использования в процессе аутентификации и работы с зашифрованными данными.
        if self._keychain_available():
            try:
                stored = keyring.get_password(self._service, self._username)
                if stored:
                    return bytes.fromhex(stored)
            except Exception:
                pass

        return self._load_key_fallback()

    def delete_encryption_key(self) -> None: # метод для удаления ключа шифрования. он пытается удалить ключ из системного хранилища с помощью keyring, если он доступен. если keyring недоступен или возникает ошибка при удалении, он удаляет ключ из резервного файла.
        # этот метод обеспечивает надежное удаление ключа шифрования из всех возможных мест хранения, чтобы предотвратить несанкционированный доступ к ключу после его удаления.
        if self._keychain_available():
            try:
                keyring.delete_password(self._service, self._username)
            except Exception:
                pass

        if self._fallback_path.exists():
            try:
                self._fallback_path.unlink()
            except Exception:
                pass

    def _save_key_fallback(self, hex_key: str) -> None: # метод для сохранения ключа в резервном файле. он принимает ключ в виде шестнадцатеричной строки и сохраняет его в файле с ограниченными правами доступа. этот метод используется, когда keyring недоступен или возникает ошибка при сохранении в keyring, чтобы обеспечить надежное хранение ключа шифрования.
        self._fallback_path.write_text(hex_key, encoding="utf-8")
        try:
            os.chmod(self._fallback_path, 0o600)
        except Exception:
            pass

    def _load_key_fallback(self) -> Optional[bytes]: # метод для загрузки ключа из резервного файла. он проверяет наличие файла и, если он существует, читает его содержимое, ожидая шестнадцатеричную строку, которая представляет ключ. если файл не найден или возникает ошибка при чтении, он возвращает None. 
        #этот метод используется для извлечения ключа шифрования из резервного файла, если keyring недоступен или ключ не найден в keyring.
        if not self._fallback_path.exists():
            return None

        try:
            hex_key = self._fallback_path.read_text(encoding="utf-8").strip()
            if not hex_key:
                return None
            return bytes.fromhex(hex_key)
        except Exception:
            return None

    def save_auth_hash_on_conn(self, conn, auth_hash: str):
        conn.execute(
            """
            INSERT INTO key_store (key_type, key_data)
            VALUES (?, ?)
            """,
            ("auth_hash", auth_hash.encode())
        )

    def save_pbkdf2_params_on_conn(self, conn, salt: bytes, iterations: int): # метод для сохранения параметров PBKDF2 с использованием существующего соединения с базой данных. он принимает соединение, соль и количество итераций, и сохраняет их в базе данных в виде записи с типом "enc_params". эти параметры используются для генерации ключей шифрования и
        #должны быть сохранены для последующего использования при аутентификации и работе с зашифрованными данными. этот метод позволяет сохранять параметры PBKDF2 в рамках существующей транзакции или операции с базой данных, обеспечивая более гибкое управление данными.
        params = {"iterations": iterations}
        conn.execute(
            """
            INSERT INTO key_store (key_type, key_data, params)
            VALUES (?, ?, ?)
            """,
            ("enc_params", salt, json.dumps(params))
        )
