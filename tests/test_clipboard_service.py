from datetime import datetime
import gc
import ctypes
import secrets
import time
import threading
from core.clipboard.clipboard_service import ClipboardService, SecureClipboardItem

# Общие заглушки — используются во всех тестах
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

# очистка через _clear_clipboard()
def test_secure_wipe_via_service():
    # проверяем что после _clear_clipboard() буфер становится неактивным
    # и данные затираются через secure_wipe()
    svc = ClipboardService(DummyPlatform(), DummyEvents(), DummyConfig(), DummyState())

    svc.copy_to_clipboard("my_secret", data_type="password")
    assert svc.get_clipboard_status()['active'] is True
    assert svc.get_clipboard_status()['data_type'] == "password"

    svc._clear_clipboard()
    assert svc.get_clipboard_status()['active'] is False



# блокировка копирования при заблокированном хранилище

def test_copy_blocked_when_locked():
    # копирование должно бросать RuntimeError если хранилище заблокировано
    class LockedState:
        def is_locked(self): return True

    svc = ClipboardService(DummyPlatform(), DummyEvents(), DummyConfig(), LockedState())

    try:
        svc.copy_to_clipboard("secret")
        assert False, "Должен был бросить RuntimeError"
    except RuntimeError:
        pass

# TEST-1: точность таймера авто-очистки ±100мс

def test_auto_clear_timing():
    #таймер должен очистить буфер в пределах ±100мс
    # от заданного таймаута

    TIMEOUT_SECONDS = 1  # 1 секунда для скорости теста

    class TimedConfig:
        def get_preference(self, key):
            if key == 'clipboard_timeout':
                return TIMEOUT_SECONDS
            return None

    cleared_at = []  # фиксируем момент платформенной очистки

    class TrackingPlatform:
        def copy_to_clipboard(self, data): return True
        def clear_clipboard(self):
            # фиксируем точное время вызова платформенной очистки
            cleared_at.append(time.perf_counter())
            return True
        def get_change_count(self): return 0

    svc = ClipboardService(
        TrackingPlatform(),
        DummyEvents(),
        TimedConfig(),
        DummyState()
    )

    # фиксируем момент копирования
    copied_at = time.perf_counter()
    svc.copy_to_clipboard("secret_password", data_type="password")

    # ждём чуть дольше таймаута чтобы поток таймера успел сработать
    time.sleep(TIMEOUT_SECONDS + 0.3)

    # очистка должна была произойти
    assert len(cleared_at) > 0, (
        f"Буфер не был очищен за {TIMEOUT_SECONDS + 0.3}с"
    )

    # проверяем точность: отклонение не более 100мс
    actual_delay = cleared_at[0] - copied_at
    tolerance = 0.1  # 100мс

    assert abs(actual_delay - TIMEOUT_SECONDS) <= tolerance, (
        f"Таймер сработал неточно: "
        f"ожидалось {TIMEOUT_SECONDS}с ± {tolerance}с, "
        f"фактически {actual_delay:.3f}с "
        f"(отклонение {abs(actual_delay - TIMEOUT_SECONDS) * 1000:.0f}мс)"
    )

    # буфер должен быть неактивен после авто-очистки
    assert svc.get_clipboard_status()['active'] is False, (
        "Буфер должен быть неактивен после авто-очистки"
    )

#безопасность памяти — пароль не должен оставаться после wipe

def test_memory_security():
    #после secure_wipe пароль не должен находиться
    # в памяти процесса в открытом виде

    secret = "SuperSecretPass99!"

    svc = ClipboardService(
        DummyPlatform(), DummyEvents(), DummyConfig(), DummyState()
    )

    # копируем секрет в буфер
    svc.copy_to_clipboard(secret, data_type="password")
    assert svc.get_clipboard_status()['active'] is True

    # получаем ссылку на SecureBuffer до очистки
    item = svc._current_content
    assert item is not None

    secure_buf = item._secure_buf
    buf_address = ctypes.addressof(secure_buf._buf)
    buf_size = secure_buf._size

    # очищаем буфер
    svc._clear_clipboard()

    # принудительная сборка мусора
    gc.collect()

    # читаем сырую память по адресу где были данные
    raw_memory = (ctypes.c_char * buf_size).from_address(buf_address)
    memory_bytes = bytes(raw_memory)

    secret_bytes = secret.encode('utf-8')

    # пароль не должен читаться в памяти после wipe
    assert secret_bytes not in memory_bytes, (
        f"Пароль найден в памяти после secure_wipe — затирание не работает!"
    )

    # память должна быть заполнена нулями
    assert memory_bytes == b'\x00' * buf_size, (
        f"Память не обнулена после wipe: {memory_bytes.hex()}"
    )

    # буфер должен быть неактивен
    assert svc.get_clipboard_status()['active'] is False



# конкурентность — несколько потоков копируют одновременно

def test_concurrency_no_data_leakage():
    # несколько быстрых операций копирования не должны
    # приводить к утечке данных или гонкам

    results = []       # успешные копирования
    errors = []        # ошибки потоков
    final_states = []  # состояние буфера после каждой операции

    class FastConfig:
        def get_preference(self, key):
            # большой таймаут чтобы авто-очистка не мешала тесту
            return 60 if key == 'clipboard_timeout' else None

    svc = ClipboardService(
        DummyPlatform(), DummyEvents(), FastConfig(), DummyState()
    )

    def copy_worker(thread_id: int):
        # каждый поток копирует свои уникальные данные
        try:
            data = f"secret_from_thread_{thread_id}"
            svc.copy_to_clipboard(data, data_type="password")
            results.append(thread_id)
        except Exception as e:
            errors.append((thread_id, str(e)))

    # запускаем 10 потоков одновременно
    threads = [
        threading.Thread(target=copy_worker, args=(i,))
        for i in range(10)
    ]

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # все потоки должны завершиться без необработанных исключений
    assert not errors, (
        f"Потоки завершились с ошибками: {errors}"
    )

    # все 10 потоков выполнились
    assert len(results) == 10, (
        f"Ожидалось 10 успешных операций, получено {len(results)}"
    )

    # после всех операций буфер содержит данные последнего потока
    # и активен — нет утечки состояния между потоками
    status = svc.get_clipboard_status()
    assert status['active'] is True, (
        "Буфер должен быть активен после последней операции копирования"
    )

    # явно очищаем после теста
    svc._clear_clipboard()
    assert svc.get_clipboard_status()['active'] is False

def test_recovery_after_crash():
    # имитируем аварийное завершение во время операции копирования
    # после восстановления буфер не должен содержать чувствительных данных

    secret = "CrashTestSecret99!"
    crash_triggered = []

    class CrashingPlatform:
        def __init__(self):
            self.copy_count = 0

        def copy_to_clipboard(self, data):
            self.copy_count += 1
            # первый вызов успешен
            if self.copy_count == 1:
                return True
            # второй вызов имитирует сбой платформы
            raise RuntimeError("Platform clipboard crash")

        def clear_clipboard(self):
            return True

        def get_change_count(self):
            return 0

    svc = ClipboardService(
        CrashingPlatform(), DummyEvents(), DummyConfig(), DummyState()
    )

    # первое копирование успешно
    svc.copy_to_clipboard(secret, data_type="password")
    assert svc.get_clipboard_status()['active'] is True

    # второе копирование — платформа падает во время операции
    try:
        svc.copy_to_clipboard("new_secret", data_type="password")
    except RuntimeError:
        crash_triggered.append(True)

    # сбой должен был произойти
    assert len(crash_triggered) > 0, "Сбой платформы не был вызван"

    # после сбоя буфер должен быть очищен —
    # _clear_clipboard() вызывается в начале каждого copy_to_clipboard()
    # до обращения к платформе, поэтому старые данные уже затёрты
    status = svc.get_clipboard_status()

    # либо буфер полностью неактивен
    # либо активен но не содержит старый секрет
    if status.get('active'):
        with svc._lock:
            item = svc._current_content
            if item and item.data:
                assert item.data != secret, (
                    f"Старый секрет остался в буфере после сбоя!"
                )
    # это нормально — буфер неактивен после сбоя
    else:
        pass

    # явная очистка всегда должна работать даже после сбоя
    try:
        svc._clear_clipboard()
    except Exception as e:
        assert False, f"_clear_clipboard() упал после сбоя платформы: {e}"

    assert svc.get_clipboard_status()['active'] is False