from core.config import ConfigManager


def test_config_defaults_and_set(tmp_path): # тестируем ConfigManager: создание с дефолтами, сохранение и загрузку настроек
    cfg_path = tmp_path / "cfg.json"
    cm = ConfigManager(str(cfg_path))

    assert cm.get_database_path() is not None # проверяем, что путь к базе данных возвращается

    cm.set_preference("theme", "dark") # устанавливаем тему в "dark" и сохраняем
    cm2 = ConfigManager(str(cfg_path))
    assert cm2.get_preference("theme") == "dark"

def test_generate_key_writes_salt(tmp_path): # тестируем генерацию ключа и сохранение соли в конфигурации
    cfg_path = tmp_path / "cfg2.json"
    cm = ConfigManager(str(cfg_path))
    key = cm.generate_key("password123")
    assert isinstance(key, bytes)
    assert cm.get_encryption_settings().get("key_salt") is not None # проверяем, что соль сохранена в конфигурации после генерации ключа
