from PyQt6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QFileDialog,
    QMessageBox,
)
from gui.widgets.password_entry import PasswordEntry


class SetupWizard(QDialog):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Мастер первоначальной настройки")
        self.resize(400, 250)

        self.db_path = None

        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout()

        # --- Мастер-пароль ---
        layout.addWidget(QLabel("Создайте мастер-пароль:"))
        self.password_entry = PasswordEntry()
        layout.addWidget(self.password_entry)

        layout.addWidget(QLabel("Подтвердите мастер-пароль:"))
        self.password_confirm_entry = PasswordEntry()
        layout.addWidget(self.password_confirm_entry)

        # --- Выбор базы данных ---
        layout.addWidget(QLabel("Выберите расположение базы данных:"))
        db_layout = QHBoxLayout()
        self.db_label = QLabel("Файл не выбран")
        self.db_button = QPushButton("Выбрать...")
        self.db_button.clicked.connect(self._choose_db_file)
        db_layout.addWidget(self.db_label)
        db_layout.addWidget(self.db_button)
        layout.addLayout(db_layout)

        # --- Настройки шифрования (заглушка) ---
        layout.addWidget(QLabel("Настройки шифрования (заглушка)"))

        # --- Кнопки ---
        btn_layout = QHBoxLayout()
        self.ok_btn = QPushButton("Готово")
        self.ok_btn.clicked.connect(self._finish_setup)
        self.cancel_btn = QPushButton("Отмена")
        self.cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(self.ok_btn)
        btn_layout.addWidget(self.cancel_btn)
        layout.addLayout(btn_layout)

        self.setLayout(layout)

    # ------------------------
    # Выбор файла базы данных
    # ------------------------
    def _choose_db_file(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Выберите файл базы данных", "", "Database Files (*.db)"
        )
        if file_path:
            self.db_path = file_path
            self.db_label.setText(file_path)

    # ------------------------
    # Проверка пароля и завершение
    # ------------------------
    def _finish_setup(self):
        pwd = self.password_entry.text()
        pwd_confirm = self.password_confirm_entry.text()

        if not pwd:
            QMessageBox.warning(self, "Ошибка", "Мастер-пароль не может быть пустым")
            return

        if pwd != pwd_confirm:
            QMessageBox.warning(self, "Ошибка", "Пароли не совпадают")
            return

        if not self.db_path:
            QMessageBox.warning(self, "Ошибка", "Выберите файл базы данных")
            return

        # Заглушка: здесь можно добавить шифрование/создание базы
        QMessageBox.information(
            self,
            "Готово",
            f"Мастер-пароль установлен\nБаза: {self.db_path}\n(Шифрование пока заглушка)"
        )
        self.accept()

