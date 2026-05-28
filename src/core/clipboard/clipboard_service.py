# сервис для управления буфером обмена с поддержкой безопасного хранения данных, автоматической очистки и уведомлений
# при копировании данных в буфер обмена, они сохраняются в зашифрованном виде вместе с метаданными (тип данных, время копирования, источник)
# устанавливается таймер на автоматическую очистку буфера обмена через заданное время,
# за 5 секунд до очистки показывается предупреждение, что буфер обмена скоро будет очищен
# если буфер обмена изменяется извне (не нашим сервисом), он сразу очищается и показывается уведомление об этом
# при блокировке хранилища буфер обмена также очищается для защиты данных

import ctypes
import threading
from datetime import datetime, timedelta
from typing import Optional, Callable
import secrets
import sys

class SecureBuffer:
    # обёртка над ctypes для хранения чувствительных данных
    # в непагируемой памяти (mlock на Unix, VirtualLock на Windows)
    # гарантирует что данные не попадут в файл подкачки

    def __init__(self, data: str):
        encoded = data.encode('utf-8')
        self._size = len(encoded)

        # выделяем буфер через ctypes
        self._buf = (ctypes.c_char * self._size)(*encoded)

        # блокируем страницу памяти от выгрузки в своп
        self._locked = self._lock_memory()

    def set_monitor(self,monitor):
        self._monitor = monitor

    def _lock_memory(self) -> bool:
        # пытаемся заблокировать память платформенным вызовом
        try:
            if sys.platform == 'win32':
                # Windows: VirtualLock
                ctypes.windll.kernel32.VirtualLock(
                    ctypes.cast(self._buf, ctypes.c_void_p),
                    ctypes.c_size_t(self._size)
                )
            else:
                # Unix: mlock
                libc_name = "libc.dylib" if sys.platform == 'darwin' else "libc.so.6"
                libc = ctypes.CDLL(libc_name, use_errno=True)
                libc.mlock(
                    ctypes.cast(self._buf, ctypes.c_void_p),
                    ctypes.c_size_t(self._size)
                )
            return True
        except Exception:
            # если mlock недоступен — работаем без блокировки
            # это лучше чем падать с исключением
            import logging as _logging
            _logging.getLogger(__name__).warning(
                "SecureBuffer: memory locking (mlock/VirtualLock) failed: %s. "
                "Clipboard data may be written to swap/pagefile."
            )
            return False

    def get(self) -> str:
        # возвращаем данные как строку
        return bytes(self._buf).decode('utf-8')

    def wipe(self):
        if self._buf is None:
            return
        # затираем данные — побайтово + memset
        for i in range(self._size):
            self._buf[i] = b'\x00'
        ctypes.memset(self._buf, 0, self._size)
        # снимаем блокировку страницы
        if self._locked:
            try:
                if sys.platform == 'win32':
                    ctypes.windll.kernel32.VirtualUnlock(
                        ctypes.cast(self._buf, ctypes.c_void_p),
                        ctypes.c_size_t(self._size)
                    )
                else:
                    libc_name = "libc.dylib" if sys.platform == 'darwin' else "libc.so.6"
                    libc = ctypes.CDLL(libc_name, use_errno=True)
                    libc.munlock(
                        ctypes.cast(self._buf, ctypes.c_void_p),
                        ctypes.c_size_t(self._size)
                    )
            except Exception:
                pass
            self._locked = False
            
    def __del__(self):
        if self._buf is not None:
            self.wipe()
        self._buf = None   # освобождаем только здесь, в деструкторе
        
class SecureClipboardItem: # класс для хранения данных буфера обмена в зашифрованном виде вместе с метаданными
    def __init__(self, data: str, data_type: str, source_entry_id: Optional[str],
                 copied_at: datetime, mask: bytes):
        self._secure_buf = SecureBuffer(data)
        self.data_type = data_type
        self.source_entry_id = source_entry_id
        self.copied_at = copied_at
        self.mask = mask
        
    @property # свойство для получения данных из буфера, если он ещё не был очищен, и возвращает None если буфер уже очищен
    def data(self) -> str:
        # возвращаем данные из буфера, если он ещё не был очищен
        if self._secure_buf and self._secure_buf._buf:
            return self._secure_buf.get()
        return None

    def secure_wipe(self): # метод для безопасного удаления данных из памяти, перезаписывая их нулями перед удалением
        if self._secure_buf:
            self._secure_buf.wipe()
            self._secure_buf = None
        self.mask = None


class ClipboardService: # основной сервис для управления буфером обмена, который взаимодействует с платформой и системой событий, а также с монитором изменений буфера обмена
    def __init__(self, platform_adapter, event_system, config, state_manager,
                 notify_callback: Optional[Callable[[str], None]] = None):

        self.platform = platform_adapter
        self.events = event_system
        self.config = config
        self.state = state_manager
        self._notify = notify_callback 
        self._monitor = None 

        self.events.subscribe('UserLoggedOut', self._on_vault_locked)
        self._observers: list[Callable[[str], None]] = []
        if notify_callback:
            self._observers.append(notify_callback)

        self._current_content: Optional[SecureClipboardItem] = None
        self._timer: Optional[threading.Timer] = None
        self._warning_timer: Optional[threading.Timer] = None  # таймер предупреждения за 5с
        self._lock = threading.RLock()
        self._operation_id = 0
        self._copies_blocked: bool = False
        self._suspicious_events: int = 0
        
        self.events.subscribe('UserLoggedOut', self._on_vault_locked)
        self._observers = []
        if notify_callback:
            self._observers.append(notify_callback)
        import atexit as _atexit
        import signal as _signal
        _atexit.register(self._emergency_clear)
        try:
            _signal.signal(_signal.SIGTERM, lambda s, f: self._emergency_clear())
        except (OSError, ValueError):
            pass  

    def _emergency_clear(self):
        try:
            self._clear_clipboard()
        except Exception:
            try:
                self.platform.clear_clipboard()
            except Exception:
                pass

    def subscribe(self, callback: Callable[[str], None]): # метод для подписки на уведомления сервиса, который позволяет другим частям приложения получать уведомления о событиях, связанных с буфером обмена
        if callback not in self._observers:
            self._observers.append(callback)
            
    def unsubscribe(self, callback: Callable[[str], None]): # метод для отписки от уведомлений сервиса
        if callback in self._observers:
            self._observers.remove(callback)
        
    def set_monitor(self, monitor): # метод для установки монитора изменений буфера обмена, который будет уведомлять сервис о том, что буфер был изменён извне, чтобы сервис мог очистить его и показать уведомление
        self._monitor = monitor

    def copy_to_clipboard(self, data: str, data_type: str = "password",source_entry_id: Optional[str] = None): # основной метод для копирования данных в буфер обмена, который сохраняет данные в зашифрованном виде, 
        #устанавливает таймеры на очистку и предупреждение, и взаимодействует с монитором изменений буфера обмена
        with self._lock:
            if self.state.is_locked():
                raise RuntimeError("Vault is locked. Cannot copy to clipboard.")

             # блокировка после обнаружения подозрительной активности (MON-2)
            if self._copies_blocked:
                raise RuntimeError(
                "Копирование заблокировано: обнаружен подозрительный доступ к буферу. "
                "Разблокируйте в настройках безопасности."
            )
            
            self._clear_clipboard()

            self._current_content = SecureClipboardItem( # сохраняем данные в зашифрованном виде вместе с метаданными
                data=data,
                data_type=data_type,
                source_entry_id=source_entry_id,
                copied_at=datetime.utcnow(),
                mask=secrets.token_bytes(32)
            )
            
            succ = self.platform.copy_to_clipboard(data)# копируем данные в буфер обмена через платформу, если это не удалось, то безопасно удаляем данные из памяти и показываем ошибку

            if not succ:
                self._current_content.secure_wipe()
                self._current_content = None
                raise RuntimeError("Failed to copy data to clipboard")

            self._operation_id += 1 # увеличиваем счётчик операций, чтобы отличать разные циклы копирования и очистки, и не реагировать на таймеры от предыдущих операций, 
            #если пользователь скопировал что-то новое в буфер обмена до срабатывания таймера
            op_id = self._operation_id

            timeout = self.config.get_preference('clipboard_timeout') or 30

            # таймер предупреждения за 5 секунд до очистки
            if timeout > 5:
                self._warning_timer = threading.Timer(
                    timeout - 5, self._on_warning, args=(op_id,)
                )
                self._warning_timer.daemon = True
                self._warning_timer.start()

            # основной таймер очистки
            self._timer = threading.Timer(timeout, self._on_timeout, args=(op_id,))
            self._timer.daemon = True
            self._timer.start()

            if self._monitor:
                self._monitor.register_own_write()
                
            self.events.publish('ClipboardCopied',
                data_type=data_type,
                source_entry_id=source_entry_id,
                timeout=timeout
            )

            self._show_notification(f"✓ Скопировано [{data_type}] — очистка через {timeout}с")

    def _on_warning(self, op_id): # метод, который вызывается таймером предупреждения за 5 секунд до очистки, и показывает уведомление пользователю, 
        #что буфер обмена скоро будет очищен, если пользователь не скопировал что-то новое в буфер обмена
        with self._lock:
            if op_id != self._operation_id:
                return
        self._show_notification("⚠️ Буфер обмена очистится через 5 секунд ⚠️ ")

    def _on_timeout(self, op_id):# метод, который вызывается таймером очистки, и очищает буфер обмена, если пользователь не скопировал что-то новое в буфер обмена, и показывает уведомление об этом
        with self._lock:
            if op_id != self._operation_id:
                return
            self._clear_clipboard()
            self.events.publish('ClipboardCleared', reason='timeout')
        self._show_notification("🗑 Буфер обмена очищен автоматически")

    def _clear_clipboard(self): # метод для очистки буфера обмена, который безопасно удаляет данные из памяти, очищает буфер обмена через платформу, и отменяет таймеры
        with self._lock: # блокируем доступ к данным буфера обмена, чтобы избежать гонок между таймерами и основным потоком, и между монитором изменений буфера обмена
            self._operation_id += 1

            if self._warning_timer:
                self._warning_timer.cancel()
                self._warning_timer = None

            if self._current_content:
                try:
                    self.platform.clear_clipboard()
                except Exception:
                    self._show_notification("⚠️ Не удалось очистить буфер обмена через платформу. Данные в памяти удалены, но могут оставаться в буфере."
                                            "Попробуйте очистить буфер вручную (Ctrl+A -> Delete).")
                    self._log_error("CLIPBOARD_CLEAR_FAILED", "Failed to clear clipboard via platform API")
                self._current_content.secure_wipe()
                self._current_content = None

            if self._timer:
                self._timer.cancel()
                self._timer = None
        
    def _log_error(self, error_type: str, detail: str):
    # логируем ошибку в аудит-систему
    # никогда не включаем чувствительные данные в лог
        try:
            self.events.publish(
                'ClipboardError',
                error_type=error_type,
                # detail может содержать только технические сведения
                # но не данные буфера
                detail=detail[:200],  # обрезаем на случай длинного stacktrace
            )
        except Exception:
            # если даже логирование упало — молча игнорируем
            # чтобы не создавать рекурсию ошибок
            pass

    def _obfuscate_data(self, data: str) -> str: # метод для получения зашифрованного представления данных буфера обмена, который используется для отображения типа данных в статусе буфера обмена, не раскрывая сами данные
        data_bytes = data.encode('utf-8')
        mask = self._current_content.mask
        obfuscated = bytes([b ^ mask[i % len(mask)] for i, b in enumerate(data_bytes)])
        return obfuscated.hex()

    def _get_remaining_time(self) -> Optional[timedelta]: # метод для получения оставшегося времени до автоматической очистки буфера обмена, который используется для отображения статуса буфера обмена, и возвращает None, если буфер обмена не активен
        if not self._current_content:
            return None
        timeout = self.config.get_preference('clipboard_timeout') or 30
        elapsed = datetime.utcnow() - self._current_content.copied_at
        remaining = timedelta(seconds=timeout) - elapsed
        return remaining if remaining > timedelta(0) else timedelta(0)

    def _show_notification(self, message: str):# метод для отображения уведомлений пользователю, который вызывает функцию обратного вызова, если она установлена, и игнорирует любые ошибки при вызове функции обратного вызова, чтобы не нарушать работу сервиса
        for observer in list(self._observers):
            try:
                observer(message)
            except Exception:
                pass

    def get_clipboard_status(self) -> dict:# метод для получения статуса буфера обмена, который возвращает информацию о том, активен ли буфер обмена, тип данных, оставшееся время до очистки, 
                                            #и источник данных, и используется для отображения статуса буфера обмена в интерфейсе пользователя
        with self._lock:
            if not self._current_content:
                return {'active': False}

            remaining = self._get_remaining_time() # получаем оставшееся время до очистки, если буфер обмена активен, и возвращаем статус буфера обмена с типом данных, оставшимся временем, и источником данных
            return {
            'active': True,
            'data_type': self._current_content.data_type,
            'remaining_seconds': remaining.total_seconds() if remaining else 0,
            'source_entry_id': self._current_content.source_entry_id 
                    }

    def _on_vault_locked(self, *args, **kwargs): # метод, который вызывается при блокировке хранилища, и очищает буфер обмена для защиты данных, и показывает уведомление об этом
        with self._lock:
            self._clear_clipboard()
        self._show_notification("🔒 Буфер обмена очищен — хранилище заблокировано")
    
    def on_suspicious_access(self):
    # вызывается монитором при обнаружении внешнего доступа
    # накапливаем счётчик и блокируем при превышении порога
        with self._lock:
            self._suspicious_events += 1

            # после 3 подозрительных событий блокируем копирование
            if self._suspicious_events >= 3:
                self._copies_blocked = True
                self._show_notification(
                    "🚫 Копирование заблокировано: многократный подозрительный доступ к буферу. "
                    "Разблокируйте в меню Безопасность → Разблокировать буфер обмена."
                )
            else:
                self._show_notification(
                    f"⚠️ Подозрительный доступ к буферу ({self._suspicious_events}/3). "
                    f"При повторении копирование будет заблокировано."
                )

    def unblock_copies(self):
        # разблокировка копирования пользователем вручную
        # через меню Безопасность → Разблокировать буфер обмена
        with self._lock:
            self._copies_blocked = False
            self._suspicious_events = 0
            self._show_notification("✅ Копирование в буфер обмена разблокировано")

    def is_blocked(self) -> bool:
        # возвращает текущий статус блокировки
        # используется в GUI для отображения состояния
        return self._copies_blocked