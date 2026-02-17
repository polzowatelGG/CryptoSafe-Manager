import json
from pathlib import Path

class ConfigManager:
    DEFAULTS = {                                # использую словарь для хранения дефолтных настроек (ключ - название настройки, значение - её дефолтное значение)
    "db_path": "data/cryptosafe.db",            # путь к файлу базы данных
    "encryption_algorithm": "AESPlaceholder",   # заглушка для алгоритма шифрования
    "clipboard_timeout": 30,                    
    "auto_lock_timeout": 300,
    "environment": "dev",                       # текущее окружение (dev, staging, prod)
    }                                           
    
    def __init__(self, env: str = "dev"):       # при инициализации класса указываем окружение (по умолчанию - dev)
        self.env = env                          # сохранение среды внутри объекта для дальнейшего использования
        self.config_path = Path(f"config_{env}.json")  # формируем путь к файлу конфигурации на основе среды (например, config_dev.json для dev)
        self.settings = self.DEFAULTS.copy()    # создаём копию дефолтных настроек, чтобы можно было изменять их без изменения оригинала
        self.load()                             # при создании объекта сразу загружаем настройки из файла (если он существует) или используем дефолтные значения
        
    def load(self):                             
        if self.config_path.exists():           # проверяем, существует ли файл конфигурации
            with open(self.config_path, "r") as f:  # если файл есть, открываем его для чтения
                self.settings.update(json.load(f))  # загружаем настройки из файла и обновляем текущие настройки (если в файле есть какие-то значения, они перезапишут дефолтные)
                
    def save(self):
        with open(self.config_path, "w") as f:  # открываем файл конфигурации для записи (если файла нет, он будет создан)
            json.dump(self.settings, f, indent=4)  # сохраняем текущие настройки в файл в формате JSON с отступами для удобства чтения
            
    def get(self, key, default=None):
        return self.settings.get(key, default)  # метод для получения значения настройки по ключу 

    def set(self, key, value):
        self.settings[key] = value  # метод для установки значения настройки по ключy 