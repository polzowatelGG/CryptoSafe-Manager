import gc
import sys
import ctypes
import time
import threading
import platform
import subprocess
import pytest
from core.clipboard.platform_adapter import get_platform_clipboard_adapter as get_platform_adapter
from core.clipboard.clipboard_service import ClipboardService, SecureClipboardItem
import tempfile
import os
from unittest.mock import Mock
from core.clipboard.platform_adapter import PyperclipAdapter

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
        assert False, "Должен был бросить RuntimeError"
    except RuntimeError:
        pass


TIMEOUT_SECONDS = 1    # короткий таймаут для скорости теста
TOLERANCE       = 0.1  # 100 мс — ровно по ТЗ


def test_auto_clear_timing():
    class TimedConfig:
        def get_preference(self, key):
            return TIMEOUT_SECONDS if key == 'clipboard_timeout' else None

    cleared_at = []

    class TrackingPlatform:
        def copy_to_clipboard(self, data): return True
        def clear_clipboard(self):
            cleared_at.append(time.perf_counter())
            return True
        def get_change_count(self): return 0

    svc = ClipboardService(TrackingPlatform(), DummyEvents(), TimedConfig(), DummyState())

    copied_at = time.perf_counter()
    svc.copy_to_clipboard("secret_password", data_type="password")

    time.sleep(TIMEOUT_SECONDS + 0.3)

    assert len(cleared_at) > 0, (
        f"Буфер не был очищен за {TIMEOUT_SECONDS + 0.3}с"
    )

    actual_delay = cleared_at[0] - copied_at

    assert abs(actual_delay - TIMEOUT_SECONDS) <= TOLERANCE, (
        f"Таймер сработал неточно: "
        f"ожидалось {TIMEOUT_SECONDS}с ± {TOLERANCE}с, "
        f"фактически {actual_delay:.3f}с "
        f"(отклонение {abs(actual_delay - TIMEOUT_SECONDS) * 1000:.0f}мс)"
    )

    assert svc.get_clipboard_status()['active'] is False, (
        "Буфер должен быть неактивен после авто-очистки"
    )


def test_auto_clear_buffer_active_before_timeout():
    class LongConfig:
        def get_preference(self, key):
            return 60 if key == 'clipboard_timeout' else None

    svc = ClipboardService(DummyPlatform(), DummyEvents(), LongConfig(), DummyState())
    svc.copy_to_clipboard("StillAlive", data_type="password")

    time.sleep(0.2)
    assert svc.get_clipboard_status()['active'] is True, (
        "Буфер был очищен раньше таймаута"
    )
    svc._clear_clipboard()


def test_platform_adapter_fallback():
    adapter = get_platform_adapter()
    assert adapter is not None

    try:
        result = adapter.copy_to_clipboard("test_platform_check")
        assert isinstance(result, bool)
        adapter.clear_clipboard()
    except Exception as e:
        pytest.fail(f"Platform adapter упал: {e}")


def test_current_platform_is_supported():
    supported = {"win32", "darwin", "linux"}
    assert sys.platform in supported, (
        f"Неподдерживаемая платформа: {sys.platform}. "
        f"Поддерживаются: {supported}"
    )


def test_service_works_with_real_adapter():
    real_adapter = get_platform_adapter()
    svc = ClipboardService(real_adapter, DummyEvents(), DummyConfig(), DummyState())

    svc.copy_to_clipboard("real_platform_test", data_type="password")
    assert svc.get_clipboard_status()['active'] is True

    svc._clear_clipboard()
    assert svc.get_clipboard_status()['active'] is False


@pytest.mark.skipif(sys.platform != "linux", reason="Только Linux: проверка дистрибутива")
def test_linux_distro_detected():
    try:
        result = subprocess.run(
            ["cat", "/etc/os-release"],
            capture_output=True, text=True, timeout=3
        )
        distro_info = result.stdout
    except Exception:
        distro_info = platform.platform()

    known = ["ubuntu", "debian", "fedora", "centos", "arch",
             "alpine", "rhel", "opensuse", "mint", "kali"]
    assert any(d in distro_info.lower() for d in known), (
        f"Не удалось определить дистрибутив Linux:\n{distro_info[:300]}"
    )


@pytest.mark.skipif(sys.platform not in ("darwin", "linux"), reason="Только Unix")
def test_unix_mlock_available():
    lib_name = "libc.dylib" if sys.platform == "darwin" else "libc.so.6"
    try:
        libc = ctypes.CDLL(lib_name)
        assert hasattr(libc, "mlock"), "mlock не найден в libc"
    except OSError as exc:
        pytest.fail(f"Не удалось загрузить libc ({lib_name}): {exc}")


@pytest.mark.skipif(sys.platform != "win32", reason="Только Windows")
def test_windows_virtuallock_available():
    assert hasattr(ctypes, "windll"), "ctypes.windll не найден на Windows"
    assert hasattr(ctypes.windll, "kernel32")



def test_memory_security():
    secret = "SuperSecretPass99!"

    svc = ClipboardService(DummyPlatform(), DummyEvents(), DummyConfig(), DummyState())
    # шаг 1: копируем пароль
    svc.copy_to_clipboard(secret, data_type="password")
    assert svc.get_clipboard_status()['active'] is True

    item = svc._current_content
    assert item is not None

    secure_buf = item._secure_buf
    buf_address = ctypes.addressof(secure_buf._buf)
    buf_size = secure_buf._size

    # шаг 2: дампим всю память
    pid = os.getpid()
    secret_bytes = secret.encode('utf-8')
    found_in_memory = False
    
    # пытаемся сделать дамп памяти через GDB 
    if sys.platform in ('linux', 'darwin'):
        try:
            with tempfile.NamedTemporaryFile(suffix='.dump', delete=False) as tmp:
                dump_file = tmp.name
            
            gdb_commands = f"""
            set pagination off
            dump memory {dump_file} 0x0 0x7ffffffff000
            quit
            """
            
            result = subprocess.run(
                ['gdb', '-batch', '-p', str(pid)],
                input=gdb_commands,
                capture_output=True,
                timeout=10
            )
            
            if os.path.exists(dump_file):
                with open(dump_file, 'rb') as f:
                    while True:
                        chunk = f.read(1024 * 1024)
                        if not chunk:
                            break
                        if secret_bytes in chunk:
                            found_in_memory = True
                            break
                os.unlink(dump_file)
                
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
            pass

    svc._clear_clipboard()
    gc.collect()

    # шаг 3: проверки
    # п 1: если смогли сделать дамп - проверяем что секрет не найден
    if found_in_memory:
        pytest.fail(
            f"Пароль '{secret}' найден в памяти процесса после копирования!\n"
            f"Затирание не работает или данные остались в других областях памяти."
        )
    
    # п 2: буфер должен быть занулён (это всегда проверяем)
    raw_memory = (ctypes.c_char * buf_size).from_address(buf_address)
    memory_bytes = bytes(raw_memory)
    
    assert memory_bytes == b'\x00' * buf_size, (
        f"Память буфера не обнулена после wipe: {memory_bytes.hex()}"
    )
    
    # п 3: статус неактивен
    assert svc.get_clipboard_status()['active'] is False


def test_memory_secret_present_before_wipe():

    secret = "MustBeHereBeforeWipe!"

    svc = ClipboardService(DummyPlatform(), DummyEvents(), DummyConfig(), DummyState())
    svc.copy_to_clipboard(secret, data_type="password")

    item        = svc._current_content
    secure_buf  = item._secure_buf
    buf_address = ctypes.addressof(secure_buf._buf)
    buf_size    = secure_buf._size

    memory_before = bytes((ctypes.c_char * buf_size).from_address(buf_address))

    assert secret.encode() in memory_before, (
        "До wipe секрет не найден в памяти — адрес буфера некорректен"
    )
    svc._clear_clipboard()


def test_memory_no_plaintext_in_item_attributes():
    secret = "AttrLeakCheck_42!"

    svc = ClipboardService(DummyPlatform(), DummyEvents(), DummyConfig(), DummyState())
    svc.copy_to_clipboard(secret, data_type="password")

    item = svc._current_content
    for attr_name, attr_val in vars(item).items():
        if isinstance(attr_val, str):
            assert secret not in attr_val, (
                f"Секрет найден в открытом виде в атрибуте {attr_name!r}"
            )
    svc._clear_clipboard()


def test_concurrency_no_data_leakage():
    results = []
    errors  = []

    class FastConfig:
        def get_preference(self, key):
            return 60 if key == 'clipboard_timeout' else None

    svc = ClipboardService(DummyPlatform(), DummyEvents(), FastConfig(), DummyState())

    def copy_worker(thread_id: int):
        try:
            svc.copy_to_clipboard(f"secret_from_thread_{thread_id}", data_type="password")
            results.append(thread_id)
        except Exception as e:
            errors.append((thread_id, str(e)))

    threads = [threading.Thread(target=copy_worker, args=(i,)) for i in range(10)]
    for t in threads: t.start()
    for t in threads: t.join()

    assert not errors, f"Потоки завершились с ошибками: {errors}"
    assert len(results) == 10, f"Ожидалось 10 успехов, получено {len(results)}"

    assert svc.get_clipboard_status()['active'] is True, (
        "Буфер должен быть активен после последней операции копирования"
    )

    svc._clear_clipboard()
    assert svc.get_clipboard_status()['active'] is False


def test_concurrency_no_mixed_data():
    THREAD_COUNT = 20

    class FastConfig:
        def get_preference(self, key):
            return 60 if key == 'clipboard_timeout' else None

    svc     = ClipboardService(DummyPlatform(), DummyEvents(), FastConfig(), DummyState())
    barrier = threading.Barrier(THREAD_COUNT)
    errors  = []

    def worker(tid: int):
        try:
            barrier.wait()
            svc.copy_to_clipboard(f"only_thread_{tid}_DATA", data_type="password")
        except Exception as e:
            errors.append((tid, str(e)))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(THREAD_COUNT)]
    for t in threads: t.start()
    for t in threads: t.join()

    assert not errors, f"Ошибки в потоках: {errors}"

    with svc._lock:
        item = svc._current_content
        if item and item.data:
            raw     = item.data
            matches = sum(
                1 for i in range(THREAD_COUNT)
                if f"only_thread_{i}_DATA" == raw
            )
            assert matches == 1, (
                f"В буфере смешаны данные нескольких потоков: {raw!r}"
            )

    svc._clear_clipboard()


def test_concurrency_operation_id_monotonic():
    class FastConfig:
        def get_preference(self, key):
            return 60 if key == 'clipboard_timeout' else None

    svc = ClipboardService(DummyPlatform(), DummyEvents(), FastConfig(), DummyState())
    ids = []

    for i in range(10):
        svc.copy_to_clipboard(f"op_id_test_{i}", data_type="password")
        with svc._lock:
            ids.append(svc._operation_id)

    svc._clear_clipboard()

    for a, b in zip(ids, ids[1:]):
        assert b > a, (
            f"_operation_id не монотонен: {a} → {b} в последовательности {ids}"
        )


def test_concurrency_concurrent_clears_no_exception():
    svc = ClipboardService(DummyPlatform(), DummyEvents(), DummyConfig(), DummyState())
    svc.copy_to_clipboard("RaceTarget", data_type="password")

    errors = []

    def clear_worker():
        try:
            svc._clear_clipboard()
        except Exception as exc:
            errors.append(str(exc))

    threads = [threading.Thread(target=clear_worker) for _ in range(10)]
    for t in threads: t.start()
    for t in threads: t.join()

    assert not errors, f"Исключения при конкурентной очистке: {errors}"
    assert svc.get_clipboard_status()['active'] is False


def test_recovery_after_crash():
    secret          = "CrashTestSecret99!"
    crash_triggered = []

    class CrashingPlatform:
        def __init__(self):
            self.copy_count = 0

        def copy_to_clipboard(self, data):
            self.copy_count += 1
            if self.copy_count == 1:
                return True
            raise RuntimeError("Platform clipboard crash")

        def clear_clipboard(self): return True
        def get_change_count(self): return 0

    svc = ClipboardService(CrashingPlatform(), DummyEvents(), DummyConfig(), DummyState())

    svc.copy_to_clipboard(secret, data_type="password")
    assert svc.get_clipboard_status()['active'] is True

    try:
        svc.copy_to_clipboard("new_secret", data_type="password")
    except RuntimeError:
        crash_triggered.append(True)

    assert len(crash_triggered) > 0, "Сбой платформы не был вызван"

    status = svc.get_clipboard_status()

    if status.get('active'):
        with svc._lock:
            item = svc._current_content
            if item and item.data:
                assert item.data != secret, (
                    "Старый секрет остался в буфере после сбоя!"
                )

    try:
        svc._clear_clipboard()
    except Exception as e:
        assert False, f"_clear_clipboard() упал после сбоя платформы: {e}"

    assert svc.get_clipboard_status()['active'] is False


def test_recovery_platform_fails_on_clear():
    secret = "MemLeakAfterClearFail!"

    class FailingClearPlatform:
        def copy_to_clipboard(self, data): return True
        def clear_clipboard(self): raise OSError("OS clipboard API unavailable")
        def get_change_count(self): return 0

    svc = ClipboardService(FailingClearPlatform(), DummyEvents(), DummyConfig(), DummyState())
    svc.copy_to_clipboard(secret, data_type="password")

    item        = svc._current_content
    secure_buf  = item._secure_buf
    buf_address = ctypes.addressof(secure_buf._buf)
    buf_size    = secure_buf._size

    svc._clear_clipboard()
    gc.collect()

    memory = bytes((ctypes.c_char * buf_size).from_address(buf_address))
    assert secret.encode() not in memory, (
        "КРИТИЧНО: секрет в памяти после сбоя платформенной очистки!"
    )


def test_recovery_explicit_clear_always_works():
    class AlwaysCrashPlatform:
        def copy_to_clipboard(self, data): raise RuntimeError("Immediate crash")
        def clear_clipboard(self): return True
        def get_change_count(self): return 0

    svc = ClipboardService(AlwaysCrashPlatform(), DummyEvents(), DummyConfig(), DummyState())

    with pytest.raises(RuntimeError):
        svc.copy_to_clipboard("WillCrash", data_type="password")

    try:
        svc._clear_clipboard()
    except Exception as exc:
        pytest.fail(f"_clear_clipboard() упал после краша платформы: {exc}")

    assert svc.get_clipboard_status()['active'] is False


def test_recovery_timer_after_manual_clear():
    SHORT_TIMEOUT = 0.3

    class ShortConfig:
        def get_preference(self, key):
            return SHORT_TIMEOUT if key == 'clipboard_timeout' else None

    svc = ClipboardService(DummyPlatform(), DummyEvents(), ShortConfig(), DummyState())

    svc.copy_to_clipboard("TimerRaceSecret", data_type="password")
    svc._clear_clipboard()   # очищаем ДО срабатывания таймера

    time.sleep(SHORT_TIMEOUT + 0.2)

    assert svc.get_clipboard_status()['active'] is False, (
        "Буфер стал активным после ручной очистки — ошибка в логике operation_id"
    )
    
def test_clipboard_monitor_hash_fallback_detection():
    from src.core.clipboard.clipboard_monitor import ClipboardMonitor
    from src.core.clipboard.platform_adapter import PyperclipAdapter
    adapter = PyperclipAdapter()
    service = ClipboardService(adapter, DummyEvents(), DummyConfig(), DummyState())
    monitor = ClipboardMonitor(service, adapter)
    # PyperclipAdapter всегда возвращает 0, поэтому fallback должен включиться
    assert monitor._detect_hash_fallback() is True

def test_linux_adapter_change_count_always_zero():
    from src.core.clipboard.platform_adapter import LinuxPlatformClipboardAdapter
    adapter = LinuxPlatformClipboardAdapter()
    assert adapter.get_change_count() == 0
    
def test_pyperclip_adapter_copy_clear():
    from core.clipboard.platform_adapter import PyperclipAdapter
    adapter = PyperclipAdapter()
    assert adapter.copy_to_clipboard("test") is True
    assert adapter.get_clipboard_content() == "test"
    assert adapter.clear_clipboard() is True
    assert adapter.get_clipboard_content() == ""  # или None