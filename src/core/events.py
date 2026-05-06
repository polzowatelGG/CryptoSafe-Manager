# этот файл содержит реализацию шины событий и заглушки для аудита. он определяет константы для различных типов событий, таких как добавление, обновление и удаление записей, вход и выход пользователей, а также операции с буфером обмена. 
# класс EventBus обеспечивает простой механизм подписки на события и публикации их с помощью потокобезопасного словаря обработчиков. класс AuditLogger является заглушкой для аудита, который подписывается на события и записывает простые строки в лог-файл с отметкой времени. он создаётся при импорте модуля, чтобы сразу ловить события.
from datetime import datetime
from pathlib import Path
import threading
from typing import Callable, Any, Dict, List


# константы событий
ENTRY_ADDED = "EntryAdded"
ENTRY_UPDATED = "EntryUpdated"
ENTRY_DELETED = "EntryDeleted"
USER_LOGGED_IN = "UserLoggedIn"
USER_LOGGED_OUT = "UserLoggedOut"
CLIPBOARD_COPIED = "ClipboardCopied"
CLIPBOARD_CLEARED = "ClipboardCleared"


class EventBus:
    # простая потокобезопасная шина событий.
    # обработчики вызываются синхронно в потоке, который вызвал `publish`.

    def __init__(self) -> None:
        self._lock = threading.Lock()  # потокобезопасность
        self._subs: Dict[str, List[Callable[..., None]]] = {}  # словарь подписок

    def subscribe(self, event: str, handler: Callable[..., None]) -> None:
        # джобавляет обработчик для события (без дубликатов)
        with self._lock:
            self._subs.setdefault(event, [])
            if handler not in self._subs[event]:
                self._subs[event].append(handler)

    def unsubscribe(self, event: str, handler: Callable[..., None]) -> None:
        # удаляет обработчик для события
        with self._lock:
            if event in self._subs and handler in self._subs[event]:
                self._subs[event].remove(handler)

    def publish(self, event: str, **kwargs: Any) -> None:
        # публикует событие: копируем список обработчиков и вызываем их
        with self._lock:
            handlers = list(self._subs.get(event, []))

        for h in handlers:
            try:
                h(**kwargs)
            except Exception:
                # в заглушке игнорируем ошибки обработчиков
                pass


# глобальная шина - 
_bus = EventBus()

def subscribe(event: str, handler: Callable[..., None]) -> None: #подписка на событие. принимает имя события и обработчик, который будет вызван при публикации этого события. он добавляет обработчик в список подписчиков для данного события в глобальной шине событий.
    #он обеспечивает потокобезопасность при добавлении обработчика, используя блокировку. если обработчик уже подписан на это событие, он не будет добавлен повторно.
    _bus.subscribe(event, handler)


def unsubscribe(event: str, handler: Callable[..., None]) -> None: #отписка от события. принимает имя события и обработчик, который нужно удалить из списка подписчиков для данного события в глобальной шине событий. 
    #он удаляет обработчик из списка подписчиков для данного события, если он там есть.
    _bus.unsubscribe(event, handler)


def publish(event: str, **kwargs: Any) -> None: #публикация события. принимает имя события и дополнительные аргументы, которые будут переданы обработчикам. 
    #он вызывает метод publish глобальной шины событий, который копирует список обработчиков для данного события и вызывает их с переданными аргументами.
    _bus.publish(event, **kwargs)


class AuditLogger:
    # заглушка аудита: подписывается на события и пишет простые строки в лог.
    # создаётся при импорте модуля, чтобы сразу ловить события.
    def __init__(self, path: str = "src/logs/audit.log") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)  # создаём папку для логов

        # подписываемся на события
        subscribe(ENTRY_ADDED, self.on_entry_added)
        subscribe(ENTRY_UPDATED, self.on_entry_updated)
        subscribe(ENTRY_DELETED, self.on_entry_deleted)
        subscribe(USER_LOGGED_IN, self.on_user_logged_in)
        subscribe(USER_LOGGED_OUT, self.on_user_logged_out)
        subscribe(CLIPBOARD_COPIED, self.on_clipboard_copied)
        subscribe(CLIPBOARD_CLEARED, self.on_clipboard_cleared)

    def _write(self, msg: str) -> None:
        # дописывает строку в файл лога с UTC-временем
        ts = datetime.utcnow().isoformat() + "Z"
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(f"{ts} - {msg}\n")
        except Exception:
            pass

    def on_entry_added(self, entry_id: str = "") -> None: #метод для обработки события добавления записи. 
        self._write(f"EntryAdded id={entry_id}")

    def on_entry_updated(self, entry_id: str = "") -> None: #метод для обработки события обновления записи. 
        self._write(f"EntryUpdated id={entry_id}")

    def on_entry_deleted(self, entry_id: str = "") -> None: #метод для обработки события удаления записи.
        self._write(f"EntryDeleted id={entry_id}")

    def on_user_logged_in(self, user_id: str = "") -> None: #метод для обработки события входа пользователя. 
        self._write(f"UserLoggedIn user={user_id}")

    def on_user_logged_out(self, user_id: str = "") -> None: #метод для обработки события выхода пользователя.
        self._write(f"UserLoggedOut user={user_id}")

    def on_clipboard_copied(self, entry_id: str = "") -> None: #метод для обработки события копирования в буфер обмена. 
        self._write(f"ClipboardCopied id={entry_id}")

    def on_clipboard_cleared(self) -> None: #метод для обработки события очистки буфера обмена.
        self._write("ClipboardCleared")


# создаём заглушку при импорте
_audit_logger = AuditLogger()

__all__ = [
    "subscribe",
    "unsubscribe",
    "publish",
    "ENTRY_ADDED",
    "ENTRY_UPDATED",
    "ENTRY_DELETED",
    "USER_LOGGED_IN",
    "USER_LOGGED_OUT",
    "CLIPBOARD_COPIED",
    "CLIPBOARD_CLEARED",
]
