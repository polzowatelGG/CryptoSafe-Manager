import copy
import json
from pathlib import Path
from core.key_manager import KeyManager

class ConfigManager:

    DEFAULT_CONFIG = { # базовая конфигурация
        "database_path": "src/database/cryptos.db",
        "encryption": {
            "method": "AES256Placeholder",
            "key_salt": None
        },
        
        "preferences": { #
            "clipboard_timeout": 67,  
            "auto_lock": True,
            "theme": "system",
            "language": "ru",
        }
    }

    def __init__(self, config_path: str = "config.json"):
        self.config_path = Path(config_path)
        self.config = {}
        self.key_manager = KeyManager()
        self.load()

    def load(self):
        if self.config_path.exists():
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    self.config = json.load(f)
            except Exception as e:
                print(f"[ConfigManager] Ошибка загрузки: {e}")
                self.config = copy.deepcopy(self.DEFAULT_CONFIG)
        else:
            self.config = copy.deepcopy(self.DEFAULT_CONFIG)
            self.save()

    def save(self):
        try:
            if not self.config_path.parent.exists():
                self.config_path.parent.mkdir(parents=True)

            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(self.config, f, ensure_ascii=False, indent=4)
        except Exception as e:
            print(f"[ConfigManager] Ошибка сохранения: {e}")

    def get_database_path(self) -> str:
        return self.config.get("database_path", self.DEFAULT_CONFIG["database_path"])

    def get_encryption_settings(self) -> dict:
        return self.config.get("encryption", self.DEFAULT_CONFIG["encryption"])

    def get_preference(self, key: str):
        return self.config.get("preferences", {}).get(key, self.DEFAULT_CONFIG["preferences"].get(key))

    def set_database_path(self, path: str):
        self.config["database_path"] = path
        self.save()

    def set_encryption_setting(self, key: str, value):
        if "encryption" not in self.config:
            self.config["encryption"] = {}
        self.config["encryption"][key] = value
        self.save()

    def set_preference(self, key: str, value):
        if "preferences" not in self.config:
            self.config["preferences"] = {}
        self.config["preferences"][key] = value
        self.save()

    def generate_key(self, password: str) -> bytes:
        enc = self.config.setdefault("encryption", {})
        salt_hex = enc.get("key_salt")
        salt = bytes.fromhex(salt_hex) if salt_hex else None
        key, used_salt = self.key_manager.derive_key(password, salt)
        enc["key_salt"] = used_salt.hex()
        self.save()
        return key