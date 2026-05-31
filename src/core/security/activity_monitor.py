# src/core/security/activity_monitor.py
# Кроссплатформенный монитор активности пользователя для авто-блокировки.
# Работает без платформенных заглушек — использует только внутренний таймер.

import time
import threading
from datetime import datetime, timedelta
from typing import Callable, Optional


class ActivityMonitor:
    """Monitor user activity for auto-lock."""

    def __init__(self, lock_callback: Callable, config: dict):
        self.lock_callback = lock_callback
        self.config = dict(config)
        self.last_activity = datetime.utcnow()
        self.monitoring = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

    def start_monitoring(self):
        """Start activity monitoring in background thread."""
        with self._lock:
            if self.monitoring:
                return
            self.monitoring = True
            self._stop_event.clear()
            self._monitor_thread = threading.Thread(
                target=self._monitor_loop,
                daemon=True,
                name="ActivityMonitor"
            )
            self._monitor_thread.start()

    def stop_monitoring(self):
        """Stop activity monitoring."""
        with self._lock:
            self.monitoring = False
            self._stop_event.set()
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=2.0)

    def record_activity(self):
        """Record user activity — resets idle timer."""
        with self._lock:
            self.last_activity = datetime.utcnow()

    def update_config(self, new_config: dict):
        """Update configuration at runtime (e.g. change inactivity_timeout)."""
        with self._lock:
            self.config.update(new_config)

    def get_idle_time(self) -> float:
        """Get current idle time in seconds."""
        with self._lock:
            return (datetime.utcnow() - self.last_activity).total_seconds()

    def _monitor_loop(self):
        """Main monitoring loop — checks idle time every check_interval seconds."""
        while self.monitoring and not self._stop_event.is_set():
            # Read check_interval and timeout under lock (supports runtime updates)
            with self._lock:
                check_interval = self.config.get('check_interval', 1.0)
                timeout_raw = self.config.get('inactivity_timeout', 300)
                lock_timeout = float(timeout_raw)
                idle = (datetime.utcnow() - self.last_activity).total_seconds()

            if lock_timeout > 0 and idle >= lock_timeout:
                # Reset activity BEFORE callback to prevent re-triggering immediately
                with self._lock:
                    self.last_activity = datetime.utcnow()
                try:
                    self.lock_callback()
                except Exception:
                    pass

            # Sleep in small increments so stop_event is checked promptly
            elapsed = 0.0
            step = min(0.05, check_interval)
            while elapsed < check_interval:
                if self._stop_event.is_set() or not self.monitoring:
                    return
                time.sleep(step)
                elapsed += step