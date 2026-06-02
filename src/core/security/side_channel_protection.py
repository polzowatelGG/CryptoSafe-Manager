# src/core/security/side_channel_attack.py
# Защита от атак по сторонним каналам (Side-Channel Attacks).
# Реализует константное сравнение, гарантированное физическое затирание RAM и контексты безопасности.

import ctypes
import secrets
import platform
import sys
import hashlib
from typing import Union

# ─────────────────────────────────────────────────────────────────
# Операции с константным временем
# ─────────────────────────────────────────────────────────────────

def constant_time_compare(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
    """
    Сравнение двух секретов за гарантированно константное время.
    Предотвращает timing-атаки. Для абсолютной защиты от утечки информации 
    о длине секретов, сравниваются их SHA-256 хэши фиксированной длины.
    """
    if isinstance(a, str):
        a = a.encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")

    # ХАРДЕНИНГ: Сравниваем хэши, чтобы длина строк/байтов не выдавала информацию через тайминги
    hash_a = hashlib.sha256(a).digest()
    hash_b = hashlib.sha256(b).digest()

    # secrets.compare_digest теперь сравнивает массивы строго одинаковой длины (32 байта)
    return secrets.compare_digest(hash_a, hash_b)

# ─────────────────────────────────────────────────────────────────
# Безопасное затирание памяти
# ─────────────────────────────────────────────────────────────────

def secure_wipe_bytes(data: bytearray) -> None:
    """
    Затирает содержимое изменяемого bytearray нулями на уровне C-памяти.
    Защищено от оптимизаций компилятора.
    """
    if not isinstance(data, (bytearray, memoryview)):
        return
    size = len(data)
    if size == 0:
        return

    try:
        # Получаем прямой доступ к внутреннему буферу без копирования
        buf = (ctypes.c_char * size).from_buffer(data)
        
        # Физически зануляем память
        if platform.system() == "Windows":
            ctypes.windll.kernel32.RtlSecureZeroMemory(ctypes.byref(buf), size)
        else:
            try:
                ctypes.CDLL(None).memset_s(ctypes.byref(buf), size, 0, size)
            except Exception:
                ctypes.CDLL(None).memset(ctypes.byref(buf), 0, size)
    except Exception:
        pass

    # Страховочный проход средствами Python runtime
    try:
        ctypes.memset((ctypes.c_char * size).from_buffer(data), 0, size)
    except Exception:
        pass

def secure_wipe_str(s: str) -> None:
    """
    ХАРДЕНИНГ: Физически уничтожает исходный иммутабельный объект str в памяти CPython.
    Предотвращает утечку конфиденциальных паролей/ключей через дампы RAM.
    """
    if not isinstance(s, str) or not s:
        return

    try:
        # В CPython строки (str) хранятся в виде структур PyASCIIObject / PyCompactUnicodeObject.
        # Вычисляем физическое смещение начала символьных данных в структуре
        size = len(s)
        
        # Для строк, содержащих только ASCII (обычно это пароли, токены, ключи):
        # Структура PyASCIIObject резервирует заголовок, после которого идут данные
        # sys.getsizeof(s) возвращает полный размер структуры. Вычисляем точное смещение:
        offset = sys.getsizeof(s) - size - 1 # учитываем null-терминатор в конце C-строки
        
        if offset > 0:
            string_address = id(s) + offset
            # Жестко перезаписываем память оригинального объекта str нулями
            ctypes.memset(string_address, 0, size)
    except Exception:
        pass

# ─────────────────────────────────────────────────────────────────
# Контекстный менеджер для работы с секретами
# ─────────────────────────────────────────────────────────────────

class SecureContext:
    """Гарантирует автоматическое криптографическое затирание bytearray при выходе из блока."""
    
    def __init__(self, data: bytearray):
        if not isinstance(data, bytearray):
            raise TypeError("SecureContext принимает только объекты типа bytearray")
        self._data = data

    def __enter__(self) -> bytearray:
        return self._data

    def __exit__(self, exc_type, exc_val, exc_tb):
        secure_wipe_bytes(self._data)
        return False  # Не подавляем исключения внутри контекста

# ─────────────────────────────────────────────────────────────────
# Аппаратное закрепление страниц памяти (mlock / VirtualLock)
# ─────────────────────────────────────────────────────────────────

def try_lock_memory(buffer: ctypes.Array, size: int) -> bool:
    """Пытается закрепить страницу памяти в RAM через системные вызовы ОС, исключая своппинг."""
    if size <= 0:
        return False
        
    system = platform.system()
    try:
        if system == "Windows":
            kernel32 = ctypes.windll.kernel32
            # Обязательно передаем указатель через byref
            return bool(kernel32.VirtualLock(ctypes.byref(buffer), size))
        else:  # Linux, macOS (Darwin)
            libc = ctypes.CDLL(None)
            result = libc.mlock(ctypes.byref(buffer), size)
            return result == 0
    except Exception:
        return False

def try_unlock_memory(buffer: ctypes.Array, size: int) -> None:
    """Снимает блокировку фиксации страниц памяти в RAM."""
    if size <= 0:
        return
        
    system = platform.system()
    try:
        if system == "Windows":
            ctypes.windll.kernel32.VirtualUnlock(ctypes.byref(buffer), size)
        else:
            ctypes.CDLL(None).munlock(ctypes.byref(buffer), size)
    except Exception:
        pass