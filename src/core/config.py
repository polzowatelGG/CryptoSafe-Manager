import copy
import json
from pathlib import Path
from core.key_manager import KeyManager

class ConfigManager:

    DEFAULT_CONFIG = { # базовая конфигурация
        "database_path": "src/database/crypto.db",
        "encryption": {
            "method": "AES256Placeholder",
            "key_salt": None
        },
        
        "preferences": { 
            "clipboard_timeout": 67,  
            "auto_lock": True,
            "theme": "system",
            "language": "ru",
        }
    }

    def __init__(self, config_path: str = "config.json"): # инициализация менеджера конфигурации с указанием пути к файлу конфигурации
        self.config_path = Path(config_path)
        self.config = {}
        self.key_manager = KeyManager()
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
        try:
            if not self.config_path.parent.exists(): # если папка для конфигурации не существует создаём её
                self.config_path.parent.mkdir(parents=True) # создаём папку для конфигурации

            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(self.config, f, ensure_ascii=False, indent=4) # сохраняем конфигурацию в файл в формате json с отступами для удобства чтения
        except Exception as e:
            print(f"[ConfigManager] Ошибка сохранения: {e}")

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
        if "preferences" not in self.config:
            self.config["preferences"] = {} # создаём раздел предпочтений если его нет
        self.config["preferences"][key] = value # обновляем предпочтение в конфигурации
        self.save()

    def generate_key(self, password: str) -> bytes: #  генерации ключа на основе пароля и соли с сохранением соли в конфигурации
        enc = self.config.setdefault("encryption", {}) # получаем раздел шифрования из конфигурации или создаём его
        salt_hex = enc.get("key_salt")
        salt = bytes.fromhex(salt_hex) if salt_hex else None 
        key, used_salt = self.key_manager.derive_key(password, salt) # генерируем ключ и получаем использованную соль
        enc["key_salt"] = used_salt.hex() # сохраняем соль в конфигурации в виде hex строки
        self.save()
        return key