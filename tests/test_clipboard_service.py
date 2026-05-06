from datetime import datetime
import secrets
from core.clipboard.clipboard_service import ClipboardService, SecureClipboardItem

class DummyPlatform:
    def copy_to_clipboard(self, data): return True
    def clear_clipboard(self): return True
    def get_change_count(self): return 0

class DummyEvents:
    def subscribe(self, *a, **kw): pass
    def publish(self, *a, **kw): pass

class DummyConfig:
    def get_preference(self, key):
        return 30 if key == 'clipboard_timeout' else None

class DummyState:
    def is_locked(self): return False


def test_secure_wipe_via_service():
    svc = ClipboardService(DummyPlatform(), DummyEvents(), DummyConfig(), DummyState())

    svc.copy_to_clipboard("my_secret", data_type="password")
    assert svc.get_clipboard_status()['active'] is True
    assert svc.get_clipboard_status()['data_type'] == "password"

    svc._clear_clipboard()
    assert svc.get_clipboard_status()['active'] is False


def test_copy_blocked_when_locked():
    class LockedState:
        def is_locked(self): return True

    svc = ClipboardService(DummyPlatform(), DummyEvents(), DummyConfig(), LockedState())

    try:
        svc.copy_to_clipboard("secret")
        assert False
    except RuntimeError:
        pass