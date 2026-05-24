# src/core/security/memory_guard.py
import ctypes
import sys
import platform
from typing import Any, Optional

class SecureMemory:
    """Secure memory allocation and wiping."""

    def __init__(self):
        self.system = platform.system()
        self._setup_platform_functions()

    def _setup_platform_functions(self):
        """Setup platform-specific memory functions."""
        if self.system == 'Windows':
            self.kernel32 = ctypes.windll.kernel32
            self._VirtualLock = self.kernel32.VirtualLock
            self._VirtualUnlock = self.kernel32.VirtualUnlock
            self._RtlSecureZeroMemory = self.kernel32.RtlSecureZeroMemory
        elif self.system in ['Linux', 'Darwin']:
            self.libc = ctypes.CDLL(None)
            self._mlock = self.libc.mlock
            self._munlock = self.libc.munlock
            self._memset = self.libc.memset

    def allocate_secure(self, size: int) -> Any:
        """Allocate memory with locking to prevent swapping."""
        # Allocate memory
        buffer = (ctypes.c_char * size)()

        # Lock memory to prevent swapping
        if self.system == 'Windows':
            self._VirtualLock(buffer, size)
        else:
            self._mlock(buffer, size)

        return buffer

    def secure_zero(self, buffer: Any, size: int) -> None:
        """Securely zero memory."""
        if self.system == 'Windows':
            self._RtlSecureZeroMemory(buffer, size)
        else:
            # Use memset_s if available, otherwise memset
            try:
                memset_s = self.libc.memset_s
                memset_s(buffer, size, 0, size)
            except:
                self._memset(buffer, 0, size)

        # Ensure compiler doesn't optimize away
        ctypes.memset(buffer, 0, size)

    def free_secure(self, buffer: Any, size: int) -> None:
        """Free securely allocated memory."""
        # Zero memory first
        self.secure_zero(buffer, size)

        # Unlock memory
        if self.system == 'Windows':
            self._VirtualUnlock(buffer, size)
        else:
            self._munlock(buffer, size)

        # Actually free (Python will handle this when buffer is GC'd)
        del buffer

class SecretHolder:
    """Holder for sensitive data with automatic wiping."""

    def __init__(self, data: bytes):
        self._memory = SecureMemory()
        self._size = len(data)
        self._buffer = self._memory.allocate_secure(self._size)

        # Copy data into secure buffer
        ctypes.memmove(self._buffer, data, self._size)

        # Wipe original
        self._memory.secure_zero(data, self._size)

    def get_data(self) -> bytes:
        """Get copy of data (caller must wipe after use)."""
        return bytes(self._buffer)

    def __del__(self):
        """Automatically wipe when destroyed."""
        if hasattr(self, '_buffer') and self._buffer:
            self._memory.free_secure(self._buffer, self._size)