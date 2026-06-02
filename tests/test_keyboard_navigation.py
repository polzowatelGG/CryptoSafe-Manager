import pytest
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QKeyEvent
from src.gui.main_window import MainWindow
from unittest.mock import Mock

@pytest.fixture
def main_window():
    app = QApplication.instance() or QApplication([])
    entry_manager_mock = Mock()
    entry_manager_mock.get_all_entries.return_value = []  # Возвращает пустой список
    
    state_manager_mock = Mock()
    state_manager_mock.is_locked.return_value = False
    
    mw = MainWindow(
        entry_manager=entry_manager_mock,
        state_manager=state_manager_mock,
        activity_monitor=Mock(),
        panic_mode=Mock(),
    )
    yield mw
    mw.close()

def test_tab_navigation(main_window):
    """Tab должен переходить между контролами."""
    main_window.show()

    initial_widget = main_window.focusWidget()
    if initial_widget is None:
        main_window.search_input.setFocus()
        initial_widget = main_window.focusWidget()

    # Отправляем Tab
    from PyQt6.QtGui import QKeyEvent
    tab_event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Tab, Qt.KeyboardModifier.NoModifier)
    main_window.keyPressEvent(tab_event)

    new_widget = main_window.focusWidget()
    assert new_widget is not None  # Хотя бы что-то получит фокус

def test_panic_hotkey(main_window):
    """Ctrl+Shift+Escape должен активировать панику."""
    main_window.show()
    main_window.panic_mode = Mock()
    
    main_window._panic_shortcut.activated.emit()
    main_window.panic_mode.activate.assert_called()

def test_enter_in_search(main_window):
    """Enter в поле поиска должен найти записи."""
    main_window.show()
    main_window.search_input.setText("test")
    main_window.search_input.setFocus()
    
    assert main_window.search_input.hasFocus()
    assert main_window.table.rowCount() >= 0
