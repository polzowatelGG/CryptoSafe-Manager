from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QFormLayout,
    QMessageBox, QProgressBar, QPushButton
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from gui.widgets.password_entry import PasswordEntry
from core.crypto.key_derivation import PasswordValidator


class _ChangePasswordThread(QThread):
    # сигнал успешного завершения
    finished = pyqtSignal()
    # сигнал ошибки — передаём текст
    error = pyqtSignal(str)

    def __init__(self, key_manager, entry_manager, old_password, new_password):
        super().__init__()
        self.key_manager = key_manager
        self.entry_manager = entry_manager
        self.old_password = old_password
        self.new_password = new_password

    def run(self):
        # выполняется в фоновом потоке — GUI не замерзает
        try:
            self.key_manager.change_password(
                self.old_password,
                self.new_password,
                self.entry_manager
            )
            self.finished.emit()
        except ValueError as e:
            self.error.emit(str(e))
        except Exception as e:
            self.error.emit(f"Не удалось сменить пароль: {e}")


class ChangePasswordDialog(QDialog):
    def __init__(self, key_manager, entry_manager, parent=None):
        super().__init__(parent)
        self.key_manager = key_manager
        self.entry_manager = entry_manager
        self._thread = None  # храним ссылку чтобы поток не удалился сборщиком мусора

        self.setWindowTitle("Смена мастер-пароля")
        self.setModal(True)
        self.resize(400, 250)

        layout = QVBoxLayout(self)
        form = QFormLayout()

        self.old_pass = PasswordEntry("Текущий пароль")
        self.new_pass = PasswordEntry("Новый пароль")
        self.confirm_pass = PasswordEntry("Подтверждение")

        form.addRow("Текущий пароль:", self.old_pass)
        form.addRow("Новый пароль:", self.new_pass)
        form.addRow("Подтверждение:", self.confirm_pass)

        layout.addLayout(form)

        # прогресс-бар — скрыт пока операция не запущена
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # режим "бесконечно крутится"
        self.progress_bar.hide()
        layout.addWidget(self.progress_bar)

        self.change_btn = QPushButton("Сменить пароль")
        self.change_btn.clicked.connect(self._do_change)
        layout.addWidget(self.change_btn, alignment=Qt.AlignmentFlag.AlignCenter)

    def _do_change(self):
        old = self.old_pass.text()
        new = self.new_pass.text()
        confirm = self.confirm_pass.text()

        if not old or not new:
            QMessageBox.warning(self, "Ошибка", "Все поля обязательны")
            return
        if new != confirm:
            QMessageBox.warning(self, "Ошибка", "Новый пароль и подтверждение не совпадают")
            return
        if not PasswordValidator.validate_password_strength(new):
            QMessageBox.warning(self, "Слабый пароль",
                "Пароль не соответствует требованиям: минимум 12 символов, "
                "заглавные, строчные, цифры, спецсимволы, не из списка распространённых.")
            return

        # блокируем кнопку и поля чтобы нельзя было нажать повторно
        self.change_btn.setEnabled(False)
        self.old_pass.setEnabled(False)
        self.new_pass.setEnabled(False)
        self.confirm_pass.setEnabled(False)

        # показываем прогресс-бар
        self.progress_bar.show()

        # создаём и запускаем фоновый поток
        self._thread = _ChangePasswordThread(
            self.key_manager, self.entry_manager, old, new
        )
        self._thread.finished.connect(self._on_success)
        self._thread.error.connect(self._on_error)
        self._thread.start()

    def _on_success(self):
        # вызывается из главного потока через сигнал
        self.progress_bar.hide()
        QMessageBox.information(self, "Успех", "Пароль успешно изменён. Все записи перешифрованы.")
        self.accept()

    def _on_error(self, message: str):
        # вызывается из главного потока через сигнал
        self.progress_bar.hide()

        # разблокируем поля чтобы пользователь мог исправить ошибку
        self.change_btn.setEnabled(True)
        self.old_pass.setEnabled(True)
        self.new_pass.setEnabled(True)
        self.confirm_pass.setEnabled(True)

        QMessageBox.warning(self, "Ошибка", message)