
import threading
import time
from datetime import datetime, timedelta
from typing import Optional
import secrets

class SecureClipboardItem:
    def __init__(self, data: str, data_type: str, source_entry_id: Optional[str],
                 copied_at: datetime, mask: bytes):
        self.data = data
        self.data_type = data_type
        self.source_entry_id = source_entry_id
        self.copied_at = copied_at
        self.mask = mask

    def secure_wipe(self):
        if self.data:

            dummy = '\0' * len(self.data)
            self.data = None
            self.mask = None


class ClipboardService:
    def __init__(self, platform_adapter, event_system, config):
        self.platform = platform_adapter
        self.events = event_system
        self.config = config
        self.current_content: Optional[SecureClipboardItem] = None
        self.timer: Optional[threading.Timer] = None
        self.lock = threading.RLock()
        self._operation_id = 0

    def copy_to_clipboard(self, data: str, data_type: str = "password",
                          source_entry_id: Optional[str] = None):
        with self.lock:

            self._clear_clipboard()


            self.current_content = SecureClipboardItem(
                data=data,
                data_type=data_type,
                source_entry_id=source_entry_id,
                copied_at=datetime.utcnow(),
                mask=secrets.token_bytes(32)  
            )


            obfuscated = self._obfuscate_data(data)


            self.platform.copy_to_clipboard(data)

            self._operation_id +=1
            op_id = self._operation_id

            timeout = self.config.get('clipboard_timeout', 30)
            self.timer = threading.Timer(timeout, self._on_timeout, args=(op_id,))
            self.timer.daemon = True
            self.timer.start()

            self.events.publish('ClipboardCopied', 
                data_type=data_type,
                source_entry_id=source_entry_id,
                timeout=timeout
            )
            
            self._show_notification(f"Copied {data_type} to clipboard")

    def _on_timeout(self, op_id):

        with self.lock:
            if op_id != self._operation_id:
                return

            self._clear_clipboard()
            self.events.publish('ClipboardCleared', reason='timeout')
            self._show_notification("Clipboard cleared automatically")

    def _clear_clipboard(self):
        assert self.lock._is_owned(), "Lock must be held to clear clipboard"

        if self.current_content:

            self.platform.clear_clipboard()
                
            self.current_content.secure_wipe()
            self.current_content = None

        if self.timer:
            self.timer.cancel()
            self.timer = None

    def _obfuscate_data(self, data: str) -> str:

        data_bytes = data.encode('utf-8')
        mask = self.current_content.mask
        obfuscated = bytes([b ^ mask[i % len(mask)] for i, b in enumerate(data_bytes)])
        return obfuscated.hex()  
    
    def _get_remaining_time(self) -> Optional[timedelta]:
        if not self.current_content:
            return None
        timeout = self.config.get('clipboard_timeout', 30)
        elapsed = datetime.utcnow() - self.current_content.copied_at
        remaining = timedelta(seconds=timeout) - elapsed
        return remaining if remaining > timedelta(0) else timedelta(0)

    def _show_notification(self, message: str):
        pass

    def get_clipboard_status(self) -> dict:

        with self.lock:
            if not self.current_content:
                return {'active': False}

            remaining = self._get_remaining_time()
            return {
                'active': True,
                'data_type': self.current_content.data_type,
                'remaining_seconds': remaining.total_seconds() if remaining else 0,
                'source_entry_id': self.current_content.source_entry_id
            }