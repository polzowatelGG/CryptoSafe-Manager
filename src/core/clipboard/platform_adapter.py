# этот модуль содержит адаптеры для взаимодействия с буфером обмена на разных платформах, и выбирает подходящий адаптер в зависимости от операционной системы и доступных библиотек, 
# чтобы обеспечить надежную работу с буфером обмена в сервисе буфера обмена, и позволяет легко расширять поддержку новых платформ в будщем, 
# а также обеспечивает единый интерфейс для сервиса буфера обмена, чтобы он мог работать с любым адаптером без изменений в коде сервиса 
import ctypes
from typing import Optional
import pyperclip
import platform

try: # для MacOS используем нативный API через PyObjC, который обеспечивает более надежную работу с буфером обмена и поддерживает счётчик изменений буфера обмена, который используется для мониторинга изменений буфера обмена извне
    from AppKit import NSPasteboard, NSPasteboardTypeString
    PYOBJC_AVAILABLE = True
except ImportError:
    PYOBJC_AVAILABLE = False


class MacPlatformClipboardAdapter: # адаптер для MacOS, который использует нативный API через PyObjC, и поддерживает счётчик изменений буфера обмена для мониторинга изменений буфера обмена извне
    def __init__(self):
        if not PYOBJC_AVAILABLE:
            raise RuntimeError("PyObjC is required for Mac clipboard support")
        self.pasteboard = NSPasteboard.generalPasteboard()

    def get_change_count(self) -> int:
        return self.pasteboard.changeCount()

    def copy_to_clipboard(self, data: str) -> bool:
        try:
            self.pasteboard.clearContents()
            self.pasteboard.setString_forType_(data, NSPasteboardTypeString)
            return True
        except Exception:
            return False

    def clear_clipboard(self) -> bool: 
        try:
            self.pasteboard.clearContents()
            return True
        except Exception:
            return False

    def get_clipboard_content(self) -> Optional[str]:
        try:
            return self.pasteboard.stringForType_(NSPasteboardTypeString)
        except Exception:
            return None


class WinPlatformClipboardAdapter: # адаптер для Windows, который использует библиотеку pywin32 для взаимодействия с буфером обмена, и поддерживает счётчик изменений буфера обмена для мониторинга изменений буфера обмена извне
    def __init__(self):
        import win32clipboard
        self.win32clipboard = win32clipboard

    def get_change_count(self) -> int: 
        try:
            return ctypes.windll.user32.GetClipboardSequenceNumber()
        except Exception:
            return 0


    def copy_to_clipboard(self, data: str) -> bool:
        try:
            self.win32clipboard.OpenClipboard()
            self.win32clipboard.EmptyClipboard()
            self.win32clipboard.SetClipboardText(data, self.win32clipboard.CF_UNICODETEXT)
            self.win32clipboard.CloseClipboard()
            return True
        except Exception:
            return False

    def clear_clipboard(self) -> bool:
        try:
            self.win32clipboard.OpenClipboard()
            self.win32clipboard.EmptyClipboard()
            self.win32clipboard.CloseClipboard()
            return True
        except Exception:
            return False

    def get_clipboard_content(self) -> Optional[str]:
        try:
            self.win32clipboard.OpenClipboard()
            data = self.win32clipboard.GetClipboardData(self.win32clipboard.CF_UNICODETEXT)
            self.win32clipboard.CloseClipboard()
            return data
        except Exception:
            return None


class LinuxPlatformClipboardAdapter: # адаптер для Linux, который использует библиотеку pyperclip для взаимодействия с буфером обмена
    def __init__(self):
        import pyperclip as _pyperclip
        self._pyperclip = _pyperclip

    def get_change_count(self) -> int: 
        return 0

    def copy_to_clipboard(self, data: str) -> bool:
        try:
            self._pyperclip.copy(data)
            return True
        except Exception:
            return False

    def clear_clipboard(self) -> bool:
        try:
            self._pyperclip.copy('')
            return True
        except Exception:
            return False

    def get_clipboard_content(self) -> Optional[str]:
        try:
            return self._pyperclip.paste()
        except Exception:
            return None


class PyperclipAdapter: # универсальный адаптер, который использует библиотеку pyperclip для взаимодействия с буфером обмена, и не поддерживает счётчик изменений буфера обмена, поэтому мониторинг изменений буфера обмена извне будет работать с задержкой, но это лучше, чем не работать вообще на некоторых платформах
    def __init__(self):
        self.pyperclip = pyperclip
        
    def get_change_count(self) -> int: 
        return 0

    def copy_to_clipboard(self, data: str) -> bool:
        try:
            self.pyperclip.copy(data)
            return True
        except Exception:
            return False

    def clear_clipboard(self) -> bool: 
        try:
            self.pyperclip.copy('')
            return True
        except Exception:
            return False

    def get_clipboard_content(self) -> Optional[str]:
        try:
            return self.pyperclip.paste()
        except Exception:
            return None


def get_platform_clipboard_adapter(): # функция для получения подходящего адаптера для текущей платформы, которая проверяет операционную систему и доступные библиотеки,
    #и возвращает экземпляр адаптера, который будет использоваться сервисом буфера обмена для взаимодействия с буфером обмена, и обеспечивает единый интерфейс для сервиса буфера обмена, чтобы он мог работать с любым адаптером без изменений в коде сервиса
    system = platform.system()
    if system == 'Darwin' and PYOBJC_AVAILABLE:
        try:
            return MacPlatformClipboardAdapter()
        except Exception:
            pass
    elif system == 'Windows':
        try:
            return WinPlatformClipboardAdapter()
        except Exception:
            pass
    elif system == 'Linux':
        try:
            return LinuxPlatformClipboardAdapter()
        except Exception:
            pass
    return PyperclipAdapter()


get_platform_adapter = get_platform_clipboard_adapter