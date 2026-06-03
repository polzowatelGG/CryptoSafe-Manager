import pytest
from PyQt6.QtWidgets import QDialog, QApplication
from PyQt6.QtCore import Qt
from unittest.mock import Mock
from gui.export_dialog import ExportDialog
from gui.import_dialog import ImportDialog
from gui.settings_dialog import SettingsDialog

@pytest.fixture
def mock_services():
    return {
        "exporter": Mock(),
        "importer": Mock(),
        "entry_manager": Mock(),
        "config": Mock(),
    }

def test_settings_dialog_apply_changes(qapp, mock_services):
    config = mock_services["config"]
    config.get_preference.side_effect = lambda key: 30 if key == "clipboard_timeout" else 300
    dialog = SettingsDialog(config=config)
    dialog.clipboard_timeout.setValue(15)
    dialog.inactivity_timeout.setValue(120)
    dialog._save_and_accept()
    # Проверяем, что config.set_preference вызван с правильными значениями
    config.set_preference.assert_any_call("clipboard_timeout", 15)
    config.set_preference.assert_any_call("inactivity_timeout", 120)
    
def test_export_dialog_encrypted_json_password_mismatch(qapp, monkeypatch):
    exporter = Mock()
    dialog = ExportDialog(exporter=exporter, entry_manager=Mock())
    dialog.format_combo.setCurrentIndex(dialog.format_combo.findData("encrypted_json"))
    dialog.password_input.setText("a")
    dialog.password_confirm.setText("b")
    monkeypatch.setattr("PyQt6.QtWidgets.QMessageBox.warning", lambda *a, **k: None)
    dialog._do_export()
    exporter.export.assert_not_called()
    assert True

def test_settings_dialog_apply_security_profile(qapp):
    config = Mock()
    config.get_preference.side_effect = lambda k: 30 if k == "clipboard_timeout" else 300
    dialog = SettingsDialog(config=config)
    dialog.profile_combo.setCurrentText("Параноидальный")
    assert dialog.clipboard_timeout.value() == 5
    assert dialog.inactivity_timeout.value() == 60
    
def test_settings_dialog_load_profile(qapp):
    config = Mock()
    config.get_preference.side_effect = lambda k: 15 if k == "clipboard_timeout" else 120
    dialog = SettingsDialog(config=config)
    # Должен определиться профиль "Усиленный"
    assert dialog.profile_combo.currentText() == "Усиленный"
    
def test_export_dialog_select_entries(qapp):
    exporter = Mock()
    entry_manager = Mock()
    dialog = ExportDialog(exporter=exporter, entry_manager=entry_manager)
    # Симулируем загрузку записей
    dialog._all_entries = [{"id": "1", "title": "A"}, {"id": "2", "title": "B"}]
    dialog._load_entries = lambda: None
    dialog.entries_list.addItem("A")
    dialog.entries_list.addItem("B")
    dialog.entries_list.item(0).setSelected(True)
    dialog._update_selected_label()
    assert dialog.selected_label.text() == "Выбрано: 1"