# clipboard_monitor.py
# Мониторинг буфера обмена на изменения извне.
#
# FIX: на Linux get_change_count() всегда возвращает 0 (pyperclip не
# поддерживает счётчик). Используем резервный механизм — сравниваем
# хэш содержимого буфера, чтобы мониторинг работал на всех платформах.

import hashlib
import threading
import time
from typing import Optional


class ClipboardMonitor:
    def __init__(self, clipboard_service, platform_adapter):
        self._service  = clipboard_service
        self._platform = platform_adapter
        self._running  = False
        self._thread: Optional[threading.Thread] = None

        # Счётчик последней «своей» записи (macOS/Windows)
        self._own_change_count: Optional[int] = None

        # FIX: резервный механизм для Linux — хэш содержимого
        self._use_hash_fallback = False
        self._own_content_hash:  Optional[str] = None

    # ─────────────────────────────────────────────────────────────────
    # Публичный API
    # ─────────────────────────────────────────────────────────────────

    def start(self) -> bool:
        """Запускает мониторинг. Возвращает True если удалось."""
        # Определяем режим: счётчик или хэш-контент
        self._use_hash_fallback = self._detect_hash_fallback()

        self._running = True
        self._thread  = threading.Thread(
            target=self._loop, daemon=True, name="ClipboardMonitor"
        )
        self._thread.start()
        return True

    def stop(self):
        self._running = False

    def register_own_write(self):
        """Регистрирует, что мы сами изменили буфер — не реагировать."""
        try:
            if self._use_hash_fallback:
                content = self._platform.get_clipboard_content() or ""
                self._own_content_hash  = self._hash(content)
                self._own_change_count  = None
            else:
                self._own_change_count  = self._platform.get_change_count()
                self._own_content_hash  = None
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────
    # Внутренние методы
    # ─────────────────────────────────────────────────────────────────

    def _detect_hash_fallback(self) -> bool:
        """
        FIX: Определяет нужен ли хэш-фоллбэк.
        Если платформа возвращает 0 дважды подряд — счётчик не работает
        (Linux/pyperclip). Переключаемся на сравнение содержимого.
        """
        try:
            c1 = self._platform.get_change_count()
            time.sleep(0.05)
            c2 = self._platform.get_change_count()
            # Если оба 0 и метод get_clipboard_content существует — fallback
            if c1 == 0 and c2 == 0 and hasattr(self._platform, 'get_clipboard_content'):
                return True
        except Exception:
            pass
        return False

    @staticmethod
    def _hash(text: str) -> str:
        return hashlib.sha256(text.encode('utf-8', errors='replace')).hexdigest()

    def _loop(self):
        """Основной цикл мониторинга."""
        while self._running:
            try:
                time.sleep(0.5)

                if self._use_hash_fallback:
                    self._check_hash()
                else:
                    self._check_counter()

            except Exception as e:
                self._service._log_error("MONITOR_LOOP_FAILED", str(e))
                time.sleep(1.0)

    def _check_counter(self):
        """Режим счётчика (macOS, Windows)."""
        if self._own_change_count is None:
            return
        try:
            current = self._platform.get_change_count()
            if current != self._own_change_count:
                self._own_change_count = None
                self._service._clear_clipboard()
                self._service.on_suspicious_access()
        except Exception:
            pass

    def _check_hash(self):
        """
        FIX: Режим хэша содержимого (Linux/pyperclip).
        Сравниваем текущее содержимое буфера с нашим последним хэшем.
        Если изменилось — кто-то записал в буфер извне.
        """
        if self._own_content_hash is None:
            return
        try:
            current_content = self._platform.get_clipboard_content() or ""
            current_hash    = self._hash(current_content)
            if current_hash != self._own_content_hash:
                self._own_content_hash = None
                self._service._clear_clipboard()
                self._service.on_suspicious_access()
        except Exception:
            pass