import json
from core.config import ConfigManager

def test_config_defaults(tmp_path):
    cfg = ConfigManager(str(tmp_path / "config.json"))
    assert cfg.get_database_path() == "data/crypto.db"
    assert cfg.get_preference("clipboard_timeout") == 30

def test_config_set_and_persist(tmp_path):
    cfg = ConfigManager(str(tmp_path / "config.json"))
    cfg.set_preference("clipboard_timeout", 15)
    cfg.set_database_path("new/path.db")
    cfg2 = ConfigManager(str(tmp_path / "config.json"))
    assert cfg2.get_preference("clipboard_timeout") == 15
    assert cfg2.get_database_path() == "new/path.db"

def test_config_get_method(tmp_path):
    cfg = ConfigManager(str(tmp_path / "config.json"))
    cfg.set_preference("test", "value")
    assert cfg.get("test") == "value"
    assert cfg.get("missing", default=42) == 42