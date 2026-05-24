# src/core/security/activity_monitor.py
import time
import threading
from datetime import datetime, timedelta
from typing import Callable, Optional

class ActivityMonitor:
    """Monitor user activity for auto-lock."""

    def __init__(self, lock_callback: Callable, config: dict):
        self.lock_callback = lock_callback
        self.config = config
        self.last_activity = datetime.utcnow()
        self.monitoring = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.lock = threading.Lock()

        # Platform-specific activity detection
        self._setup_platform_detectors()

    def _setup_platform_detectors(self):
        """Setup platform-specific activity detectors."""
        import platform
        system = platform.system()

        if system == 'Windows':
            from src.core.security.platform.windows_activity import WindowsActivityDetector # type: ignore
            self.detector = WindowsActivityDetector()
        elif system == 'Darwin':
            from src.core.security.platform.macos_activity import MacOSActivityDetector# type: ignore
            self.detector = MacOSActivityDetector()
        elif system == 'Linux':
            from src.core.security.platform.linux_activity import LinuxActivityDetector# type: ignore
            self.detector = LinuxActivityDetector()
        else:
            from src.core.security.platform.fallback_activity import FallbackActivityDetector# type: ignore
            self.detector = FallbackActivityDetector()

    def start_monitoring(self):
        """Start activity monitoring."""
        with self.lock:
            if self.monitoring:
                return

            self.monitoring = True
            self.monitor_thread = threading.Thread(
                target=self._monitor_loop,
                daemon=True
            )
            self.monitor_thread.start()

    def stop_monitoring(self):
        """Stop activity monitoring."""
        with self.lock:
            self.monitoring = False
            if self.monitor_thread:
                self.monitor_thread.join(timeout=2.0)

    def record_activity(self):
        """Record user activity."""
        with self.lock:
            self.last_activity = datetime.utcnow()

    def _monitor_loop(self):
        """Main monitoring loop."""
        check_interval = self.config.get('check_interval', 1.0)

        while self.monitoring:
            # Check for system activity
            if self.detector.has_recent_activity():
                self.record_activity()

            # Check timeout
            timeout = self.config.get('lock_timeout', 300)  # 5 minutes default
            idle_time = (datetime.utcnow() - self.last_activity).total_seconds()

            if idle_time > timeout:
                self.lock_callback()
                self.record_activity()  # Reset after lock

            time.sleep(check_interval)

    def get_idle_time(self) -> float:
        """Get current idle time in seconds."""
        with self.lock:
            return (datetime.utcnow() - self.last_activity).total_seconds()