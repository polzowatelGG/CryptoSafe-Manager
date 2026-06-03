# tests/test_activity_monitor.py
# Тесты ActivityMonitor для авто-блокировки (Sprint 7 — ACT-1..ACT-4)

import time
import threading
import pytest
from core.security.activity_monitor import ActivityMonitor


# ─────────────────────────────────────────────────────────────────────────────
# Вспомогательные
# ─────────────────────────────────────────────────────────────────────────────

def _make_monitor(timeout_s: float, callback=None) -> ActivityMonitor:
    """Создаёт монитор с коротким таймаутом для тестов."""
    locked = []
    if callback is None:
        callback = lambda: locked.append(True)
    mon = ActivityMonitor(
        lock_callback=callback,
        config={
            'inactivity_timeout': timeout_s,
            'check_interval': 0.05,   # проверяем каждые 50 мс для скорости теста
        }
    )
    return mon, locked


# ─────────────────────────────────────────────────────────────────────────────
# TEST ACT-1: авто-блокировка после таймаута
# ─────────────────────────────────────────────────────────────────────────────

def test_auto_lock_after_timeout():
    """При бездействии дольше inactivity_timeout должен вызваться lock_callback."""
    TIMEOUT = 0.3   # 300 мс
    mon, locked = _make_monitor(TIMEOUT)

    mon.start_monitoring()
    # Не вызываем record_activity — ждём срабатывания
    time.sleep(TIMEOUT + 0.3)
    mon.stop_monitoring()

    assert len(locked) >= 1, (
        f"lock_callback не был вызван за {TIMEOUT + 0.3}с бездействия"
    )


# ─────────────────────────────────────────────────────────────────────────────
# TEST ACT-2: активность сбрасывает таймер
# ─────────────────────────────────────────────────────────────────────────────

def test_activity_resets_timer():
    """
    Если пользователь проявляет активность — блокировка не должна наступить
    раньше следующего периода простоя.
    """
    TIMEOUT = 0.3
    mon, locked = _make_monitor(TIMEOUT)

    mon.start_monitoring()

    # Сбрасываем таймер несколько раз в течение периода, который
    # без сброса давно бы сработал
    for _ in range(6):
        time.sleep(0.1)
        mon.record_activity()

    # После последнего сброса ждём меньше таймаута — блокировки не должно быть
    time.sleep(TIMEOUT * 0.5)
    locks_during_activity = len(locked)
    mon.stop_monitoring()

    assert locks_during_activity == 0, (
        f"lock_callback сработал {locks_during_activity} раз во время активности"
    )


# ─────────────────────────────────────────────────────────────────────────────
# TEST ACT-3: изменение конфига во время работы
# ─────────────────────────────────────────────────────────────────────────────

def test_config_update():
    """update_config должен применять новый inactivity_timeout на лету."""
    INITIAL_TIMEOUT = 10.0   # большой — не сработает само
    NEW_TIMEOUT = 0.3

    mon, locked = _make_monitor(INITIAL_TIMEOUT)
    mon.start_monitoring()

    # Убеждаемся что с большим таймаутом блокировки нет
    time.sleep(0.1)
    assert len(locked) == 0, "Блокировка не должна наступить при большом таймауте"

    # Меняем таймаут на маленький
    mon.update_config({'inactivity_timeout': NEW_TIMEOUT})

    # Ждём срабатывания
    time.sleep(NEW_TIMEOUT + 0.3)
    mon.stop_monitoring()

    assert len(locked) >= 1, (
        "lock_callback не сработал после уменьшения inactivity_timeout"
    )


# ─────────────────────────────────────────────────────────────────────────────
# TEST ACT-4: stop_monitoring прекращает мониторинг
# ─────────────────────────────────────────────────────────────────────────────

def test_stop_monitoring_prevents_lock():
    """После stop_monitoring блокировка не должна наступать."""
    TIMEOUT = 0.2
    mon, locked = _make_monitor(TIMEOUT)

    mon.start_monitoring()
    # Останавливаем ДО истечения таймаута
    mon.stop_monitoring()

    # Ждём дольше таймаута — блокировки не должно быть
    time.sleep(TIMEOUT + 0.3)

    assert len(locked) == 0, (
        f"lock_callback сработал {len(locked)} раз после stop_monitoring"
    )


# ─────────────────────────────────────────────────────────────────────────────
# TEST: повторный start_monitoring идемпотентен (нет двойного потока)
# ─────────────────────────────────────────────────────────────────────────────

def test_double_start_is_idempotent():
    """Вызов start_monitoring дважды не должен создавать второй поток."""
    mon, locked = _make_monitor(10.0)

    mon.start_monitoring()
    thread_before = mon._monitor_thread

    mon.start_monitoring()   # второй вызов — должен быть проигнорирован
    thread_after = mon._monitor_thread

    assert thread_before is thread_after, (
        "start_monitoring создал второй поток при повторном вызове"
    )
    mon.stop_monitoring()


# ─────────────────────────────────────────────────────────────────────────────
# TEST: get_idle_time возвращает актуальное время
# ─────────────────────────────────────────────────────────────────────────────

def test_get_idle_time():
    """get_idle_time должен возвращать время с момента последней активности."""
    mon, _ = _make_monitor(100.0)

    mon.record_activity()
    time.sleep(0.15)

    idle = mon.get_idle_time()
    assert idle >= 0.1, f"Ожидалось idle >= 0.1, получено {idle:.3f}"
    assert idle < 1.0, f"Слишком большое idle: {idle:.3f}"


# ─────────────────────────────────────────────────────────────────────────────
# TEST: потокобезопасность record_activity
# ─────────────────────────────────────────────────────────────────────────────

def test_concurrent_record_activity():
    """Одновременные вызовы record_activity из разных потоков не должны падать."""
    TIMEOUT = 5.0
    mon, locked = _make_monitor(TIMEOUT)
    errors = []

    def worker():
        try:
            for _ in range(50):
                mon.record_activity()
                time.sleep(0.001)
        except Exception as e:
            errors.append(str(e))

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Ошибки при конкурентном record_activity: {errors}"
    assert len(locked) == 0, "Блокировка не должна наступить при активной работе"
    
def test_auto_lock_disabled_when_timeout_zero():
    """Таймаут 0 должен отключать автоблокировку."""
    mon, locked = _make_monitor(0.0)
    mon.start_monitoring()
    time.sleep(0.5)
    mon.stop_monitoring()
    assert len(locked) == 0

def test_record_activity_ignored_when_locked():
    """record_activity не сбрасывает таймер, если vault заблокирован."""
    TIMEOUT = 0.3
    mon, locked = _make_monitor(TIMEOUT)
    mon.set_vault_locked_state(True)
    mon.start_monitoring()
    mon.record_activity()  # должен игнорироваться
    time.sleep(TIMEOUT - 0.1)
    # Блокировка всё равно должна произойти, т.к. активность не засчитана
    time.sleep(0.2)
    mon.stop_monitoring()
    assert len(locked) >= 1
    
def test_set_vault_locked_state_updates_internal_flag():
    mon, _ = _make_monitor(10.0)
    assert mon.is_vault_locked is False
    mon.set_vault_locked_state(True)
    assert mon.is_vault_locked is True
    mon.set_vault_locked_state(False)
    assert mon.is_vault_locked is False

def test_update_config_changes_timeout():
    mon, _ = _make_monitor(10.0)
    mon.update_config({'inactivity_timeout': 5.0})
    assert mon.config['inactivity_timeout'] == 5.0