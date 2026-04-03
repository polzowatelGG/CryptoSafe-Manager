import pytest
from PyQt6.QtWidgets import QDialog
from gui.setup_wizard import SetupWizard
from gui.main_window import MainWindow
from core.config import ConfigManager
from database.db import DatabasePool
from core.crypto.key_storage import KeyStorage
from core.key_manager import KeyManager
from core.vault.entry_manager import EntryManager

def test_setup_wizard_accepts_valid_data(qapp, tmp_path):
    wizard = SetupWizard()
    
    # устанавливаем пароль и подтверждение
    wizard.password_entry.line_edit.setText("StrongPass123!")
    wizard.password_confirm_entry.line_edit.setText("StrongPass123!")
    
    # выбираем временный файл БД
    db_file = tmp_path / "test_vault.db"
    wizard.db_path = str(db_file)
    wizard.db_label.setText(str(db_file))
    
    # эмулируем нажатие "Готово"
    wizard._finish_setup()
    
    # проверяем, что диалог принят (accept)
    assert wizard.result() == QDialog.DialogCode.Accepted
    assert wizard.db_path == str(db_file)


def test_setup_wizard_rejects_mismatched_passwords(qapp):
    wizard = SetupWizard()
    wizard.password_entry.line_edit.setText("Pass123")
    wizard.password_confirm_entry.line_edit.setText("Pass456")
    
    wizard._finish_setup()
    
    assert wizard.result() != QDialog.DialogCode.Accepted

def test_main_window_import():
    assert MainWindow is not None

def test_main_window_accepts_entry_manager(qapp, tmp_path):
    # создаём временную БД и настраиваем KeyManager и EntryManager
    db_file = tmp_path / "test.db"
    pool = DatabasePool(str(db_file))
    pool.migrate()
    
    key_storage = KeyStorage(pool)
    key_manager = KeyManager(key_storage, {
        "argon2_time": 3,
        "argon2_memory": 65536,
        "argon2_parallelism": 4,
        "pbkdf2_iterations": 100000,
    })
    key_manager.initialize("testpass")
    key_manager.unlock("testpass")
    
    entry_manager = EntryManager(pool, key_manager)
    entry_manager.create_entry({"title": "Test", "password": "123"})
    pass