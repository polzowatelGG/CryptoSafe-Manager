# tests/test_main_window.py
from unittest.mock import Mock
from core.config import ConfigManager
from gui.main_window import MainWindow

def test_on_open_vault(qapp, monkeypatch, tmp_path):
    config = ConfigManager(str(tmp_path / "cfg.json"))
    window = MainWindow(config=config)
    monkeypatch.setattr("PyQt6.QtWidgets.QFileDialog.getOpenFileName", lambda *a, **k: (str(tmp_path / "existing.db"), None))
    mock_msg = Mock()
    monkeypatch.setattr("gui.main_window.QMessageBox", mock_msg)
    window._on_open_vault()
    assert config.get_preference("database_path") == str(tmp_path / "existing.db")