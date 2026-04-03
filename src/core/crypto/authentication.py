import time

class Authenticator:
    def __init__(self, key_manager, event_bus, state_manager):
        self.km = key_manager
        self.events = event_bus
        self.state = state_manager

        self.failed_attempts = 0

    # ---------------- LOGIN ----------------

    def login(self, password: str) -> bool:
        delay = self._calculate_delay()
        time.sleep(delay)

        if self.km.unlock(password):
            self.failed_attempts = 0

            self.state.unlock()
            self.events.publish("UserLoggedIn")

            return True

        else:
            self.failed_attempts += 1
            self.events.publish("LoginFailed")

            return False

    # ---------------- LOGOUT ----------------

    def logout(self):
        self.km.lock()
        self.state.lock()
        self.events.publish("UserLoggedOut")

    # ---------------- DELAY ----------------

    def _calculate_delay(self) -> float:
        if self.failed_attempts <= 2:
            return 1
        elif self.failed_attempts <= 4:
            return 5
        else:
            return 30