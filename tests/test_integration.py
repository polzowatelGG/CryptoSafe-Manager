import os
from pathlib import Path

def test_initial_setup_accepts(qapp, monkeypatch, tmp_path):
    # Подменяем всплывающие сообщения, чтобы не блокировать тест
    from PyQt6.QtWidgets import QMessageBox, QDialog
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: None)
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: None)

    from gui.setup_wizard import SetupWizard

    wiz = SetupWizard()
    wiz.password_entry.line_edit.setText("strongpass")
    wiz.password_confirm_entry.line_edit.setText("strongpass")
    wiz.db_path = str(tmp_path / "app.db")

    wiz._finish_setup()

    # Поддерживаем разные версия PyQt: проверяем значение accepted гибко
    # Получаем числовое значение Accepted в разных версиях PyQt
    if hasattr(QDialog, "Accepted"):
        accepted_val = QDialog.Accepted
    elif hasattr(QDialog, "DialogCode") and hasattr(QDialog.DialogCode, "Accepted"):
        try:
            accepted_val = int(QDialog.DialogCode.Accepted)
        except Exception:
            accepted_val = 1
    else:
        accepted_val = 1

    assert wiz.result() == accepted_val


def test_main_window_creation(qapp):
    from gui.main_window import MainWindow
    from gui.widgets.secure_table import SecureTable

    win = MainWindow()

    assert "Secure Vault" in win.windowTitle()
    assert hasattr(win, "table")
    assert isinstance(win.table, SecureTable)


def test_config_load_and_save(tmp_path):
    from core.config import ConfigManager

    cfg_path = tmp_path / "cfg.json"
    cm = ConfigManager(str(cfg_path))

    # Конфиг должен существовать и иметь ключ database_path
    assert cm.get_database_path() is not None

    # Изменим и сохраним, затем загрузим заново
    cm.set_preference("theme", "dark")
    cm2 = ConfigManager(str(cfg_path))
    assert cm2.get_preference("theme") == "dark"


def test_db_fixture_allows_insert(test_db):
    """Проверяем, что фикстура тестовой БД содержит применённые миграции и позволяет операции."""
    pool, db_path = test_db

    # Вставим запись и прочитаем её
    pool.execute(
        "INSERT INTO vault_entries (title, username, encrypted_password) VALUES (?, ?, ?)",
        ("T1", "u1", b"pwd"),
        commit=True,
    )

    rows = pool.query("SELECT title, username FROM vault_entries WHERE title=?", ("T1",))
    assert len(rows) == 1
    assert rows[0]["username"] == "u1"
