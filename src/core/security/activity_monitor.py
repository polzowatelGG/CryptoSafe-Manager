# Мониторинг активности пользователя для авто-блокировки 
# используем Qt-события: MainWindow уже вызывает state_manager.record_activity() в eventFilter при каждом MouseButtonPress
# и KeyPress. ActivityMonitor получает уведомления через record_activity() и только следит за таймаутом в фоновом потоке.
import time
import threading
from datetime import datetime
from typing import Callable, Optional

class ActivityMonitor:
    # Монитор активности пользователя.
    # Получает уведомления об активности через record_activity() от Qt-eventFilter.
    # Фоновый поток проверяет время простоя каждые check_interval секунд и вызывает lock_callback при превышении inactivity_timeout.

    def __init__(self, lock_callback: Callable, config: dict):
        self.lock_callback = lock_callback
        self.config        = dict(config)  # копируем, чтобы update_config был изолирован

        self.last_activity: datetime = datetime.utcnow()
        self.monitoring: bool        = False
        self._locked_out: bool       = False  # True = уже заблокировали в этом периоде

        self._lock: threading.Lock               = threading.Lock()
        self.monitor_thread: Optional[threading.Thread] = None

    # Управление мониторингом
    def start_monitoring(self) -> None:
        # Запускает фоновый поток мониторинга.
        # Идемпотентен — повторный вызов игнорируется.
        with self._lock:
            if self.monitoring:
                return
            self.monitoring  = True
            self._locked_out = False
            self.last_activity = datetime.utcnow()

        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name="ActivityMonitor",
            daemon=True,  # завершается вместе с главным потоком
        )
        self.monitor_thread.start()

    def stop_monitoring(self) -> None:
        # Останавливает мониторинг.
        # Блокируется до завершения фонового потока (max 2 сек).
        with self._lock:
            self.monitoring = False

        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2.0)

    # Регистрация активности (вызывается из Qt)
    def record_activity(self) -> None:
        # Регистрирует активность пользователя — сбрасывает таймер.
        with self._lock:
            self.last_activity = datetime.utcnow()
            self._locked_out   = False  # активность — разрешаем следующую блокировку

    # Запросы состояния
    def get_idle_time(self) -> float:
        # Возвращает текущее время простоя в секундах
        with self._lock:
            return (datetime.utcnow() - self.last_activity).total_seconds()

    def get_timeout(self) -> int:
        # Возвращает текущий таймаут из конфига
        return int(self.config.get("inactivity_timeout", 300))

    def get_remaining(self) -> float:
        # Возвращает оставшееся время до блокировки в секундах (>= 0)
        remaining = self.get_timeout() - self.get_idle_time()
        return max(0.0, remaining)

    def is_monitoring(self) -> bool:
        # True если фоновый поток запущен
        return self.monitoring

    # Обновление конфигурации на лету
    def update_config(self, new_config: dict) -> None:
        # Обновляет конфигурацию без перезапуска потока.
        # Используется при смене профиля безопасности.
        self.config.update(new_config)

    # Внутренний цикл мониторинга
    def _monitor_loop(self) -> None:
        # Фоновый цикл. Запускается в daemon-потоке.
        # 1. Спим check_interval секунд
        # 2. Считаем idle_time
        # 3. Если idle >= timeout И ещё не блокировали → блокируем
        # 4. Повторяем
        # Потребление CPU при check_interval=1.0 сек: < 0.1%
        while self.monitoring:
            check_interval = float(self.config.get("check_interval", 1.0))
            time.sleep(check_interval)

            # Читаем состояние
            with self._lock:
                idle        = (datetime.utcnow() - self.last_activity).total_seconds()
                timeout     = int(self.config.get("inactivity_timeout", 300))
                locked_out  = self._locked_out

            if idle >= timeout and not locked_out:
                # Устанавливаем флаг ДО вызова callback — защита от race condition
                with self._lock:
                    self._locked_out = True

                try:
                    self.lock_callback()
                except Exception as e:
                    # Логируем но не падаем — мониторинг должен продолжаться
                    import logging
                    logging.getLogger(__name__).error(
                        "ActivityMonitor: lock_callback failed: %s", e
                    )