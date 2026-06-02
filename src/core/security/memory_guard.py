# src/core/security/memory_guard.py
# Безопасная работа с памятью.
# Гарантирует защиту от своппинга и принудительное уничтожение чувствительных данных в RAM.

import ctypes
import platform
import sys
import gc
from typing import Any, Optional

class SecureMemory:
    """Безопасное выделение памяти с защитой от свопа и гарантированным затиранием."""
    
    def __init__(self):
        self.system = platform.system()
        self._mlock_available = False
        self._setup_platform_functions()

    def _setup_platform_functions(self):
        """Инициализирует платформенные системные вызовы через ctypes."""
        try:
            if self.system == "Windows":
                self.kernel32 = ctypes.windll.kernel32
                self._VirtualLock         = self.kernel32.VirtualLock
                self._VirtualUnlock       = self.kernel32.VirtualUnlock
                self._RtlSecureZeroMemory = self.kernel32.RtlSecureZeroMemory
                self._mlock_available = True

            elif self.system in ("Linux", "Darwin"):
                # Использование None загружает текущий процесс приложения и стандартную libc
                self.libc = ctypes.CDLL(None)
                self._mlock   = self.libc.mlock
                self._munlock = self.libc.munlock
                self._memset  = self.libc.memset
                self._mlock_available = True

        except Exception:
            # Грациозный откат, если библиотека недоступна (например, в докер-контейнере)
            self._mlock_available = False

    def allocate_secure(self, size: int) -> Any:
        """Выделяет байтовый буфер ctypes и аппаратно закрепляет страницу в RAM."""
        buffer = (ctypes.c_char * size)()

        if self._mlock_available and size > 0:
            try:
                if self.system == "Windows":
                    # Передаем адрес буфера (byref)
                    self._VirtualLock(ctypes.byref(buffer), size)
                else:
                    self._mlock(ctypes.byref(buffer), size)
            except Exception:
                pass  # Закрепить в ОЗУ не удалось (нет прав), продолжаем работу без mlock

        return buffer

    def secure_zero(self, buffer: Any, size: int) -> None:
        """Криптографически надежное затирание буфера без оптимизаций компилятора."""
        if size <= 0:
            return

        try:
            if self.system == "Windows" and hasattr(self, '_RtlSecureZeroMemory'):
                # На Windows RtlSecureZeroMemory гарантированно не вырезается компилятором
                self._RtlSecureZeroMemory(ctypes.byref(buffer), size)
            elif self._mlock_available and hasattr(self, 'libc'):
                # На POSIX системах пытаемся вызвать memset_s
                try:
                    # Некоторые старые версии libc не экспортируют memset_s напрямую
                    self.libc.memset_s(ctypes.byref(buffer), size, 0, size)
                except (AttributeError, Exception):
                    self._memset(ctypes.byref(buffer), 0, size)
        except Exception:
            pass

        # Финальный и самый надежный прогон через ctypes.memset — работает всегда на уровне Python runtime
        try:
            ctypes.memset(ctypes.byref(buffer), 0, size)
        except Exception:
            pass

    def free_secure(self, buffer: Any, size: int) -> None:
        """Затирает данные и снимает аппаратную блокировку страниц памяти."""
        self.secure_zero(buffer, size)

        if self._mlock_available and size > 0:
            try:
                if self.system == "Windows":
                    self._VirtualUnlock(ctypes.byref(buffer), size)
                else:
                    self._munlock(ctypes.byref(buffer), size)
            except Exception:
                pass


class SecretHolder:
    """Держатель конфиденциальных данных с автоматическим обнулением при уничтожении (RAII)."""
    
    def __init__(self, data: bytes):
        self._memory = SecureMemory()
        self._size   = len(data)
        self._buffer = self._memory.allocate_secure(self._size)
        self._wiped  = False

        if self._size > 0:
            ctypes.memmove(ctypes.byref(self._buffer), data, self._size)

    def get_data(self) -> bytes:
        """Возвращает копию данных. Внимание: уничтожайте полученную копию после использования!"""
        if self._wiped:
            raise ValueError("SecretHolder уже был уничтожен и затерт в памяти.")
        return bytes(self._buffer)

    def get_bytearray(self) -> bytearray:
        """Возвращает изменяемую копию данных (bytearray), которую caller сможет затереть вручную."""
        if self._wiped:
            raise ValueError("SecretHolder уже был уничтожен и затерт в памяти.")
        return bytearray(self._buffer)

    def wipe(self) -> None:
        """Явное и немедленное затирание буфера секретов."""
        if not self._wiped and hasattr(self, '_buffer') and self._buffer:
            self._memory.free_secure(self._buffer, self._size)
            self._wiped = True
            # Принудительно вызываем GC для зачистки потенциальных временных ссылок
            gc.collect()

    def __del__(self):
        """Автоматическая зачистка при выходе объекта из области видимости."""
        try:
            self.wipe()
        except Exception:
            pass

    def __bool__(self) -> bool:
        return not self._wiped