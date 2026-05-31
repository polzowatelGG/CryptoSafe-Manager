
# Защита от атак по сторонним каналам.
# Реализует:
# - Сравнение за константное время (constant_time_compare)
# - Безопасное затирание памяти (secure_wipe_bytes, secure_wipe_str)
# - Контекстный менеджер для секретов (SecureContext)
# - Попытку пинить страницы памяти (try_lock_memory / try_unlock_memory)

import ctypes
import secrets
import platform
from typing import Union



#Операции с константным временем

def constant_time_compare(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
    # Сравнение двух значений за гарантированно константное время.
    # Предотвращает timing-атаки через разницу в скорости ответа:
    # secrets.compare_digest использует HMAC-подход и не прерывается досрочно.
    # Оба аргумента приводятся к bytes перед сравнением, чтобы исключить
    # разницу времени при разной длине строк.
    if isinstance(a, str):
        a = a.encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")

    # secrets.compare_digest выровнен по длине через HMAC-based comparison —
    # даже при разной длине время выполнения остаётся сопоставимым.
    return secrets.compare_digest(a, b)

# Безопасное затирание памяти
def secure_wipe_bytes(data: bytearray) -> None:
    # Затирает содержимое bytearray нулями через ctypes.memset.
    # ctypes.memset не может быть оптимизирован компилятором CPython
    # Принимает ТОЛЬКО bytearray или memoryview — объекты bytes
    # в Python неизменяемы и не могут быть затёрты.
    if not isinstance(data, (bytearray, memoryview)):
        return
    size = len(data)
    if size == 0:
        return
    # from_buffer создаёт C-массив поверх того же адреса памяти,
    # что и data — без копирования
    buf = (ctypes.c_char * size).from_buffer(data)
    ctypes.memset(buf, 0, size)

def secure_wipe_str(s: str) -> None:
    # Создаёт bytearray-копию строки, затирает её и удаляет.
    # Сам объект str в CPython неизменяем и не может быть обнулён напрямую. Этот метод предотвращает утечку через
    # явно созданный bytearray-буфер.
    try:
        encoded = bytearray(s.encode("utf-8"))
        secure_wipe_bytes(encoded)
        del encoded
    except Exception:
        pass

# Контекстный менеджер для работы с секретами
class SecureContext:
    # Контекстный менеджер: гарантирует затирание bytearray при выходе из блока.
     # secret обнулён, независимо от исключений
    def __init__(self, data: bytearray):
        if not isinstance(data, bytearray):
            raise TypeError("SecureContext принимает только bytearray")
        self._data = data

    def __enter__(self) -> bytearray:
        return self._data

    def __exit__(self, exc_type, exc_val, exc_tb):
        secure_wipe_bytes(self._data)
        # Не подавляем исключения
        return False

# Попытка закрепить страницы памяти (mlock / VirtualLock)
def try_lock_memory(buffer: ctypes.Array, size: int) -> bool:
    # Пытается закрепить страницу памяти через mlock (Linux/macOS) или VirtualLock (Windows), предотвращая своп на диск.
    # Возвращает True при успехе, False если не разрешено (контейнеры, ограниченные среды, нехватка привилегий).
    # Ошибки перехватываются — отсутствие mlock не критично,программа продолжает работу.
    system = platform.system()
    try:
        if system == "Windows":
            kernel32 = ctypes.windll.kernel32
            return bool(kernel32.VirtualLock(buffer, size))
        else:  # Linux, Darwin
            libc = ctypes.CDLL(None)
            result = libc.mlock(buffer, size)
            return result == 0
    except Exception:
        return False

def try_unlock_memory(buffer: ctypes.Array, size: int) -> None:
    # Снимает блокировку страницы памяти.
    # Ошибки перехватываются — не критично для работы программы.
    system = platform.system()
    try:
        if system == "Windows":
            ctypes.windll.kernel32.VirtualUnlock(buffer, size)
        else:
            ctypes.CDLL(None).munlock(buffer, size)
    except Exception:
        pass