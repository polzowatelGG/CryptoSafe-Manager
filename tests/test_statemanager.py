import threading
from core.state_manager import StateManager
from core.config import ConfigManager


class DummyTimer:
    def __init__(self, timeout, func):
        self.timeout = timeout
        self.func = func
        self.started = False

    def start(self):
        self.started = True

    def cancel(self):
        self.started = False


def test_lock_unlock(tmp_path):
    cfg = ConfigManager(str(tmp_path / "cfg.json"))
    sm = StateManager(cfg)
    assert not sm.is_locked()
    sm.lock()
    assert sm.is_locked()
    sm.unlock()
    assert not sm.is_locked()


def test_clipboard_timer_monkeypatched(tmp_path, monkeypatch):
    cfg = ConfigManager(str(tmp_path / "cfg.json"))
    cfg.set_preference("clipboard_timeout", 1)
    sm = StateManager(cfg)

    # Подменяем threading.Timer чтобы не запускать реальные потоки/задержки
    monkeypatch.setattr("threading.Timer", lambda t, f: DummyTimer(t, f))

    sm.set_clipboard("secret")
    assert sm.get_clipboard() == "secret"

    sm.clear_clipboard()
    assert sm.get_clipboard() is None
