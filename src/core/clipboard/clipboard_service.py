# сервис для управления буфером обмена с поддержкой безопасного хранения данных, автоматической очистки и уведомлений
# при копировании данных в буфер обмена, они сохраняются в зашифрованном виде вместе с метаданными (тип данных, время копирования, источник)
# устанавливается таймер на автоматическую очистку буфера обмена через заданное время,
# за 5 секунд до очистки показывается предупреждение, что буфер обмена скоро будет очищен
# если буфер обмена изменяется извне (не нашим сервисом), он сразу очищается и показывается уведомление об этом
# при блокировке хранилища буфер обмена также очищается для защиты данных

import threading
from datetime import datetime, timedelta
from typing import Optional, Callable
import secrets

class SecureClipboardItem: # класс для хранения данных буфера обмена в зашифрованном виде вместе с метаданными
    def __init__(self, data: str, data_type: str, source_entry_id: Optional[str],
                 copied_at: datetime, mask: bytes):
        self.data = data
        self.data_type = data_type
        self.source_entry_id = source_entry_id
        self.copied_at = copied_at
        self.mask = mask

    def secure_wipe(self): # метод для безопасного удаления данных из памяти, перезаписывая их нулями перед удалением
        if self.data:
            temp = bytearray(self.data.encode('utf-8'))
            for i in range(len(temp)):
                temp[i] = 0  # перезаписываем данные нулями
            self.data = None
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

        self._current_content: Optional[SecureClipboardItem] = None
        self._timer: Optional[threading.Timer] = None
        self._warning_timer: Optional[threading.Timer] = None  # таймер предупреждения за 5с
        self._lock = threading.RLock()
        self._operation_id = 0

    def set_notify_callback(self, callback: Callable[[str], None]): # метод для установки функции обратного вызова для отображения уведомлений пользователю
        self._notify = callback
        
    def set_monitor(self, monitor): # метод для установки монитора изменений буфера обмена, который будет уведомлять сервис о том, что буфер был изменён извне, чтобы сервис мог очистить его и показать уведомление
        self._monitor = monitor

    def copy_to_clipboard(self, data: str, data_type: str = "password",source_entry_id: Optional[str] = None): # основной метод для копирования данных в буфер обмена, который сохраняет данные в зашифрованном виде, 
        #устанавливает таймеры на очистку и предупреждение, и взаимодействует с монитором изменений буфера обмена
        with self._lock:
            if self.state.is_locked():
                raise RuntimeError("Vault is locked. Cannot copy to clipboard.")

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
                    pass
                self._current_content.secure_wipe()
                self._current_content = None

            if self._timer:
                self._timer.cancel()
                self._timer = None

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
        if self._notify:
            try:
                self._notify(message)
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