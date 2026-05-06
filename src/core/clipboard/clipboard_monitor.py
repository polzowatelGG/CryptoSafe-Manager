# модуль для мониторинга буфера обмена на изменения извне и очистки при обнаружении таких изменений
# для этого используется отдельный поток, который периодически проверяет счётчик изменений буфера обмена, предоставляемый платформой
# если счётчик изменился, значит буфер был изменён извне, и мы очищаем его и показываем уведомление пользователю

import threading
import time 

class ClipboardMonitor:
    def __init__(self,clipboard_service,platform_adapter):
        self._service = clipboard_service
        self._platform = platform_adapter
        self._running = False
        self._thread = None 
        self._own_change_count = None 
        
    def start(self): # запускаем мониторинг в отдельном потоке
        self._running = True
        self._thread = threading.Thread(target= self._loop, daemon= True)
        self._thread.start()
    
    def stop(self): # останавливаем мониторинг
        self._running = False
        
    def register_own_write(self): # регистрируем, что мы сами изменили буфер обмена, чтобы не реагировать на это изменение
        self._own_change_count = self._platform.get_change_count()
        
    def _loop(self): # основной цикл мониторинга, который периодически проверяет счётчик изменений буфера обмена
        while self._running:
            time.sleep(0.5)
            if self._own_change_count is None:
                continue
            current = self._platform.get_change_count()
            if current != self._own_change_count:
                self._own_change_count = None
                self._service._clear_clipboard()
                self._service._show_notification("Буфер изменён извне — очищено")

    