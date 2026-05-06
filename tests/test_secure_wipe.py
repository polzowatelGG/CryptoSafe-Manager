from datetime import datetime
import secrets
from core.clipboard.clipboard_service import SecureClipboardItem

def test_secure_wipe():
    item = SecureClipboardItem(
        data="secret_password",
        data_type="password",
        source_entry_id=None,
        copied_at=datetime.utcnow(),
        mask=secrets.token_bytes(32)
    )
    item.secure_wipe()
    assert item.data is None
    assert item.mask is None
