# этот файл определяет класс аутентификации, который отвечает за управление процессом входа и выхода пользователя, а также за обработку неудачных попыток входа с задержкой для предотвращения атак перебором паролей.
import threading
import time
from datetime import datetime
from typing import Optional

class Authenticator: # класс аутентификации, который управляет процессом входа и выхода пользователя, а также обрабатывает неудачные попытки входа с задержкой для предотвращения атак перебором паролей.
    def __init__(self, key_manager, event_bus, state_manager):
        self.km = key_manager
        self.events = event_bus
        self.state = state_manager
        self.failed_attempts = 0
        self.login_time: Optional[datetime] = None
        self.last_activity: Optional[datetime] = None
        self._auth_lock = threading.Lock()

    def login(self, password: str) -> bool: # метод для входа пользователя, который принимает пароль и возвращает True при успешной аутентификации и False при неудачной. он также обрабатывает неудачные попытки входа с задержкой.
        with self._auth_lock:
            delay = self._calculate_delay()
        if delay > 0:
            time.sleep(delay)

        if self.km.unlock(password):
            self.failed_attempts = 0
            self.login_time = datetime.utcnow()
            self.last_activity = datetime.utcnow()
            self.state.unlock()
            self.events.publish("UserLoggedIn")

            return True

        else:
            self.failed_attempts += 1
            self.events.publish("LoginFailed")

            return False


    def logout(self): # метод для выхода пользователя, который блокирует менеджер ключей и состояние приложения, а также публикует событие "UserLoggedOut".
        self.login_time = None
        self.last_activity = None
        
        self.km.lock()
        self.state.lock()
        self.events.publish("UserLoggedOut")
        
    def record_activity(self):
        # вызывается из GUI при любом действии пользователя
        # для отслеживания времени последней активности 
        if self.login_time is not None:
            self.last_activity = datetime.utcnow()

    def get_session_info(self) -> dict:
        # возвращает данные текущей сессии для отображения в интерфейсе, такие как время входа, время последней активности и количество неудачных попыток входа.
        return {
            "login_time": self.login_time.isoformat() if self.login_time else None,
            "last_activity": self.last_activity.isoformat() if self.last_activity else None,
            "failed_attempts": self.failed_attempts,
        }

    def _calculate_delay(self) -> float: # метод для расчета задержки на основе количества неудачных попыток входа. он возвращает 1 секунду для первых 2 неудачных попыток, 5 секунд для 3-4 неудачных попыток и 30 секунд для 5 и более неудачных попыток.
        if self.failed_attempts == 0:
            return 0
        if self.failed_attempts <= 2:
            return 1
        elif self.failed_attempts <= 4:
            return 5
        else:
            return 30