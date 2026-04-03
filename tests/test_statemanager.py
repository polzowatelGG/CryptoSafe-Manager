import threading
from core.state_manager import StateManager
from core.config import ConfigManager


class DummyTimer:
    def __init__(self, timeout, func): # заглушка для threading.Timer, которая просто сохраняет функцию и флаг запуска
        self.timeout = timeout
        self.func = func
        self.started = False

    def start(self): # при запуске просто устанавливает флаг, не создавая реального таймера
        self.started = True

    def cancel(self): # при отмене сбрасывает флаг, не останавливая реального таймера
        self.started = False


def test_lock_unlock(tmp_path): # тестируем блокировку и разблокировку состояния
    cfg = ConfigManager(str(tmp_path / "cfg.json"))
    sm = StateManager(cfg)
    assert not sm.is_locked()
    sm.lock()
    assert sm.is_locked()
    sm.unlock()
    assert not sm.is_locked()


def test_clipboard_timer_monkeypatched(tmp_path, monkeypatch): # тестируем установку и очистку буфера обмена с подменой threading.Timer на DummyTimer
    cfg = ConfigManager(str(tmp_path / "cfg.json"))
    cfg.set_preference("clipboard_timeout", 1) 
    sm = StateManager(cfg)

    # подменяем threading.Timer чтобы не запускать реальные потоки/задержки
    monkeypatch.setattr("threading.Timer", lambda t, f: DummyTimer(t, f))

    sm.set_clipboard("secret")
    assert sm.get_clipboard() == "secret"

    sm.clear_clipboard()
    assert sm.get_clipboard() is None
