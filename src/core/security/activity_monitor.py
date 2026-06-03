# src/core/security/activity_monitor.py
# Кроссплатформенный монитор активности для авто-блокировки.
# Защищен от манипуляций с системным временем ОС (использует time.monotonic).

import time
import threading
from typing import Callable, Optional


class ActivityMonitor:
    """Monitor user activity for auto-lock using secure monotonic timers."""

    def __init__(self, lock_callback: Callable, config: dict):
        self.lock_callback = lock_callback
        self.config        = dict(config)
        # Использование time.monotonic() гарантирует защиту от перевода системных часов
        self.last_activity = time.monotonic()
        self.monitoring    = False
        self.is_vault_locked = False  # Флаг для предотвращения ложных срабатываний, когда БД уже заблокирована
        
        self._monitor_thread: Optional[threading.Thread] = None
        self._lock       = threading.Lock()
        self._stop_event = threading.Event()

    # ─────────────────────────────────────────────────────────────────
    # Публичный API
    # ─────────────────────────────────────────────────────────────────

    def start_monitoring(self):
        """Запускает мониторинг в фоновом потоке."""
        with self._lock:
            if self.monitoring:
                return
            self.monitoring = True
            self.is_vault_locked = False
            self._stop_event.clear()
            self.last_activity = time.monotonic() # Сбрасываем при старте
            self._monitor_thread = threading.Thread(
                target=self._monitor_loop,
                daemon=True,
                name="ActivityMonitor",
            )
            self._monitor_thread.start()

    def stop_monitoring(self):
        """Останавливает фоновый поток мониторинга."""
        with self._lock:
            self.monitoring = False
            self._stop_event.set()
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=2.0)

    def record_activity(self):
        """Сбрасывает таймер простоя — вызывается из eventFilter главного окна."""
        with self._lock:
            # Если хранилище уже заблокировано, игнорируем фоновые события активности
            if not self.is_vault_locked:
                self.last_activity = time.monotonic()

    def set_vault_locked_state(self, locked: bool):
        """Явно переключает состояние блокировки хранилища (вызывается при входе/выходе)."""
        with self._lock:
            self.is_vault_locked = locked
            if not locked:
                self.last_activity = time.monotonic()

    def update_config(self, new_config: dict):
        """Обновляет конфигурацию на лету (например, при смене профиля безопасности)."""
        with self._lock:
            self.config.update(new_config)
            self.last_activity = time.monotonic()
            # Если в конфигурации передан профиль безопасности, можно пересчитать таймаут
            security_profile = self.config.get('security_profile', 'custom')
            if security_profile == 'paranoia':
                self.config['inactivity_timeout'] = 60  # 1 минута для Паранойи
            elif security_profile == 'high':
                self.config['inactivity_timeout'] = 180 # 3 минуты

    def get_idle_time(self) -> float:
        """Возвращает чистое время простоя в секундах."""
        with self._lock:
            return time.monotonic() - self.last_activity

    # ─────────────────────────────────────────────────────────────────
    # Внутренняя логика
    # ─────────────────────────────────────────────────────────────────

    def _monitor_loop(self):
        """
        Основной цикл проверки активности.
        Проверяет idle каждые check_interval секунд.
        Шаг сна мелкий (0.05 с) для мгновенной реакции на закрытие приложения.
        """
        while self.monitoring and not self._stop_event.is_set():
            # Читаем конфигурацию под блокировкой потока
            with self._lock:
                check_interval = float(self.config.get('check_interval', 1.0))
                lock_timeout   = float(self.config.get('inactivity_timeout', 300))
                vault_locked   = self.is_vault_locked
                idle = time.monotonic() - self.last_activity

            # Если таймаут выставлен в 0 — автоблокировка отключена
            if lock_timeout > 0 and idle >= lock_timeout and not vault_locked:
                # Переводим статус в locked ДО вызова колбэка, чтобы избежать race conditions
                with self._lock:
                    self.is_vault_locked = True
                    self.last_activity = time.monotonic()
                
                try:
                    self.lock_callback()
                except Exception:
                    pass

            # Адаптивный сон мелкими шагами с проверкой флага остановки
            step    = min(0.05, check_interval)
            elapsed = 0.0
            while elapsed < check_interval:
                if self._stop_event.is_set() or not self.monitoring:
                    return
                time.sleep(step)
                elapsed += step