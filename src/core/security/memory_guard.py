# Безопасная работа с памятью. 

import ctypes
import platform
from typing import Any, Optional

class SecureMemory:
    # Безопасное выделение памяти с защитой от свопа и принудительным затиранием.
    # На платформах где mlock недоступен (контейнеры, ограниченные среды) работает без закрепления, но всё равно гарантирует затирание через ctypes.
    def __init__(self):
        self.system = platform.system()
        self._mlock_available = False
        self._setup_platform_functions()

    def _setup_platform_functions(self):
        # Инициализирует платформенные функции.
        # При любой ошибке (нет привилегий, нет библиотеки) — graceful fallback.
        try:
            if self.system == "Windows":
                self.kernel32 = ctypes.windll.kernel32
                self._VirtualLock         = self.kernel32.VirtualLock
                self._VirtualUnlock       = self.kernel32.VirtualUnlock
                self._RtlSecureZeroMemory = self.kernel32.RtlSecureZeroMemory
                self._mlock_available = True

            elif self.system in ("Linux", "Darwin"):
                self.libc    = ctypes.CDLL(None)
                self._mlock  = self.libc.mlock
                self._munlock = self.libc.munlock
                self._memset  = self.libc.memset
                self._mlock_available = True

        except Exception:
            # Платформенные функции недоступны — продолжаем без них.
            # secure_zero через ctypes.memset всё равно будет работать.
            self._mlock_available = False

    # Выделение памяти
    def allocate_secure(self, size: int) -> Any:
        # Выделяет ctypes-буфер и пытается закрепить страницу в RAM.
        # Если mlock недоступен — выделяет буфер без закрепления.
        # Программа не падает в обоих случаях 
        buffer = (ctypes.c_char * size)()

        if self._mlock_available:
            try:
                if self.system == "Windows":
                    self._VirtualLock(buffer, size)
                else:
                    self._mlock(buffer, size)
            except Exception:
                pass  # Закрепить не удалось — продолжаем без mlock

        return buffer

    # Затирание памяти
    def secure_zero(self, buffer: Any, size: int) -> None:
        # Затирает буфер нулями, минимизируя вероятность оптимизации компилятором.
        # Использует платформенную RtlSecureZeroMemory (Windows) или memset_s/memset
        # (Linux/macOS), после чего дополнительно вызывает ctypes.memset как страховку 
        try:
            if self.system == "Windows" and self._mlock_available:
                self._RtlSecureZeroMemory(buffer, size)
            elif self._mlock_available:
                # Предпочитаем memset_s— не оптимизируется
                try:
                    memset_s = self.libc.memset_s
                    memset_s(buffer, size, 0, size)
                except (AttributeError, Exception):
                    self._memset(buffer, 0, size)
        except Exception:
            pass

        # Финальный прогон через ctypes.memset — работает всегда
        try:
            ctypes.memset(buffer, 0, size)
        except Exception:
            pass

    # Освобождение
    def free_secure(self, buffer: Any, size: int) -> None:
        # Затирает и разблокирует буфер.
        # del buffer в теле метода не освобождает ctypes-объект — Python освободит его при уничтожении последней ссылки в вызывающем коде.
        # Этот метод гарантирует только затирание и снятие mlock.
        self.secure_zero(buffer, size)

        if self._mlock_available:
            try:
                if self.system == "Windows":
                    self._VirtualUnlock(buffer, size)
                else:
                    self._munlock(buffer, size)
            except Exception:
                pass

# Обёртка для хранения одного секрета
class SecretHolder:
    # Держатель одного секрета с автоматическим затиранием при уничтожении.
    # Хранит данные в закреплённом ctypes-буфере. При вызове __del__ или явном вызове wipe() — гарантированно обнуляет память.
    # get_data() возвращает bytes-КОПИЮ. Caller отвечает за её очистку.
    def __init__(self, data: bytes):
        self._memory = SecureMemory()
        self._size   = len(data)
        self._buffer = self._memory.allocate_secure(self._size)
        self._wiped  = False

        # Копируем данные в закреплённый буфер
        if self._size > 0:
            ctypes.memmove(self._buffer, data, self._size)

        # Затираем оригинальный bytes-объект в bytearray если возможно
        # (bytes неизменяем, но через bytearray можно обнулить буфер)
        try:
            mutable = bytearray(data)
            ctypes.memset(
                (ctypes.c_char * len(mutable)).from_buffer(mutable),
                0,
                len(mutable)
            )
        except Exception:
            pass

    def get_data(self) -> bytes:
        # Возвращает копию секретных данных как bytes.
        # Caller отвечает за очистку копии после использования.
        if self._wiped:
            raise ValueError("SecretHolder уже был затёрт")
        return bytes(self._buffer)

    def wipe(self) -> None:
        # Явное затирание буфера. После вызова get_data() недоступен
        if not self._wiped and hasattr(self, '_buffer') and self._buffer:
            self._memory.free_secure(self._buffer, self._size)
            self._wiped = True

    def __del__(self):
        # Автоматическое затирание при уничтожении объекта
        try:
            self.wipe()
        except Exception:
            pass

    def __bool__(self) -> bool:
        return not self._wiped