from PyQt6.QtWidgets import QApplication
from gui.widgets.secure_table import SecureTable
from unittest.mock import Mock

def test_add_and_get_entry(qapp):
    table = SecureTable()
    table.add_entry("id1", "Title", "user", "https://example.com", "2025-01-01", "pass", "notes")
    assert table.rowCount() == 1
    assert table.item(0, 0).text() == "Title"
    assert table._get_entry_id_for_row(0) == "id1"

def test_filter_entries(qapp):
    table = SecureTable()
    table.add_entry("1", "Bank", "u1", "https://bank.com", "", "p1", "")
    table.add_entry("2", "Email", "u2", "https://mail.com", "", "p2", "")
    table.filter_entries("bank")
    assert table.isRowHidden(0) is False
    assert table.isRowHidden(1) is True
    table.filter_entries("")
    assert table.isRowHidden(0) is False
    assert table.isRowHidden(1) is False

def test_copy_password(qapp):
    clipboard = Mock()
    table = SecureTable(clipboard_service=clipboard)
    table.add_entry("id1", "Title", "user", "url", "", "secret", "")
    table._copy_password("id1")
    clipboard.copy_to_clipboard.assert_called_with(data="secret", data_type="password", source_entry_id="id1")
    
def test_clear_entries_wipe_memory(qapp):
    table = SecureTable()
    table.add_entry("id1", "Title", "user", "url", "date", "pass", "notes")
    table.clear_entries()
    assert table.rowCount() == 0
    assert len(table.entries) == 0

def test_update_password_visibility(qapp):
    table = SecureTable()
    table.add_entry("id1", "Title", "user", "url", "date", "secret", "")
    assert table.item(0, 4).text() == "••••••••"
    table.update_password_visibility(True)
    assert table.item(0, 4).text() == "secret"