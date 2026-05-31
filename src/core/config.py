# этот файл содержит класс ConfigManager, который отвечает за управление конфигурацией приложения. он загружает и сохраняет конфигурацию в формате JSON, предоставляет методы для получения и установки различных параметров, таких как путь к базе данных, настройки шифрования и пользовательские предпочтения. 
# он также включает метод для генерации ключа на основе пароля и соли, используя KeyManager для управления процессом генерации ключей. этот класс обеспечивает централизованное управление настройками приложения и позволяет легко сохранять и загружать конфигурацию при запуске приложения.
# конфигурация включает базовые параметры, такие как путь к базе данных, настройки шифрования и пользовательские предпочтения, которые могут быть изменены пользователем и сохранены для последующего использования. ConfigManager обеспечивает удобный интерфейс для работы с этими настройками и гарантирует, что они сохраняются в надежном формате для использования при следующем запуске приложения.
import logging
import copy
import json
from pathlib import Path
from core.key_manager import KeyManager

class ConfigManager: # класс ConfigManager, который отвечает за управление конфигурацией приложения. он загружает и сохраняет конфигурацию в формате JSON, предоставляет методы для получения и установки различных параметров, таких как путь к базе данных, настройки шифрования и пользовательские предпочтения.ё

    DEFAULT_CONFIG = { # базовая конфигурация
        "database_path": "data/crypto.db",
        "encryption": {
            "method": "AES256Placeholder",
            "key_salt": None
        },
        
        "preferences": { 
            "clipboard_timeout": 30,  
            "auto_lock": True,
            "theme": "system",
            "language": "ru",
        }
    }

    def __init__(self, config_path: str = "config.json"): # инициализация менеджера конфигурации с указанием пути к файлу конфигурации
        self.config_path = Path(config_path)
        self.config = {}
        self.key_manager = None  # KeyManager создаётся позже, когда известны storage и config
        self.load()

    def load(self):
        if self.config_path.exists(): # если файл конфигурации существует загружаем его
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    self.config = json.load(f) # загружаем конфигурацию из файла
            except Exception as e:
                print(f"[ConfigManager] Ошибка загрузки: {e}")
                self.config = copy.deepcopy(self.DEFAULT_CONFIG)
        else:
            self.config = copy.deepcopy(self.DEFAULT_CONFIG)
            self.save()

    def save(self):
        # сохраняем текущую конфигурацию в JSON-файл
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logging.getLogger(__name__).warning(f"Ошибка сохранения: {e}")

    def get_database_path(self) -> str:
        return self.config.get("database_path", self.DEFAULT_CONFIG["database_path"]) # возвращаем путь к базе данных из конфигурации или из базовой конфигурации если его нет

    def get_encryption_settings(self) -> dict:
        return self.config.get("encryption", self.DEFAULT_CONFIG["encryption"]) # возвращаем настройки шифрования из конфигурации или из базовой конфигурации если их нет

    def get_preference(self, key: str):
        return self.config.get("preferences", {}).get(key, self.DEFAULT_CONFIG["preferences"].get(key)) # возвращаем предпочтение по ключу из конфигурации или из базовой конфигурации если его нет

    def set_database_path(self, path: str):
        self.config["database_path"] = path # обновляем путь к базе данных в конфигурации
        self.save()

    def set_encryption_setting(self, key: str, value):
        if "encryption" not in self.config:
            self.config["encryption"] = {} # создаём раздел шифрования если его нет
        self.config["encryption"][key] = value # обновляем настройку шифрования в конфигурации
        self.save()

    def set_preference(self, key: str, value):
        # обновляем предпочтение в памяти и сразу сохраняем на диск
        if "preferences" not in self.config:
            self.config["preferences"] = {}
        self.config["preferences"][key] = value
        self.save()
        
    def get(self, key: str, default=None):
        # FIXединый метод get() для совместимости 
        # Проверяем preferences, затем top-level ключи
        pref = self.config.get("preferences", {}).get(key)
        if pref is not None:
            return pref
        val = self.config.get(key)
        if val is not None:
            return val
        return default

    def generate_key(self, password: str) -> bytes:  # генерация ключа на основе пароля и соли с сохранением соли
        enc = self.config.setdefault("encryption", {})
        salt_hex = enc.get("key_salt")
        salt = bytes.fromhex(salt_hex) if salt_hex else None

        # если key_manager ещё не создан, инициализируем по текущим настройкам.
        # это позволяет использовать ConfigManager самостоятельно в тестах и сценариях.
        if self.key_manager is None:
            self.key_manager = KeyManager(storage=None, config={
                "argon2_time": self.config.get("argon2_time", 3),
                "argon2_memory": self.config.get("argon2_memory", 65536),
                "argon2_parallelism": self.config.get("argon2_parallelism", 4),
                "pbkdf2_iterations": self.config.get("pbkdf2_iterations", 100000),
            })

        # метод derive_key отсутствует в старой версии, используем KeyDerivation из KeyManager.
        # генерируем соль, если её ещё нет.
        if not salt:
            salt = self.key_manager.derivation.generate_salt()

        key = self.key_manager.derivation.derive_encryption_key(password, salt)

        enc["key_salt"] = salt.hex()
        self.save()
        return key