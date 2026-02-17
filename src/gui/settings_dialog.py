from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QTabWidget,
    QWidget, QLabel, QSpinBox,
    QComboBox, QCheckBox,
    QPushButton, QHBoxLayout
)


class SecurityTab(QWidget):
    """
    Настройки безопасности
    """

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        self.clipboard = QSpinBox()
        self.clipboard.setRange(1, 300)
        self.clipboard.setValue(30)

        self.autolock = QSpinBox()
        self.autolock.setRange(1, 120)
        self.autolock.setValue(5)

        layout.addWidget(QLabel("Clipboard timeout"))
        layout.addWidget(self.clipboard)

        layout.addWidget(QLabel("Auto lock timeout"))
        layout.addWidget(self.autolock)

        layout.addStretch()

    def get(self):
        return {
            "clipboard": self.clipboard.value(),
            "autolock": self.autolock.value()
        }


class AppearanceTab(QWidget):
    """
    Внешний вид
    """

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        self.theme = QComboBox()
        self.theme.addItems(["System", "Light", "Dark"])

        self.lang = QComboBox()
        self.lang.addItems(["English", "Russian", "German"])

        layout.addWidget(QLabel("Theme"))
        layout.addWidget(self.theme)

        layout.addWidget(QLabel("Language"))
        layout.addWidget(self.lang)

        layout.addStretch()

    def get(self):
        return {
            "theme": self.theme.currentText(),
            "language": self.lang.currentText()
        }


class AdvancedTab(QWidget):
    """
    Дополнительные параметры
    """

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        self.backup = QCheckBox("Enable backups")
        self.export = QCheckBox("Allow export")

        self.backup.setChecked(True)
        self.export.setChecked(True)

        layout.addWidget(self.backup)
        layout.addWidget(self.export)
        layout.addStretch()

    def get(self):
        return {
            "backup": self.backup.isChecked(),
            "export": self.export.isChecked()
        }


class SettingsDialog(QDialog):
    """
    Главное окно настроек
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowTitle("Settings")

        layout = QVBoxLayout(self)

        self.tabs = QTabWidget()

        self.security = SecurityTab()
        self.appearance = AppearanceTab()
        self.advanced = AdvancedTab()

        self.tabs.addTab(self.security, "Security")
        self.tabs.addTab(self.appearance, "Appearance")
        self.tabs.addTab(self.advanced, "Advanced")

        layout.addWidget(self.tabs)

        buttons = QHBoxLayout()
        buttons.addStretch()

        save = QPushButton("Save")
        cancel = QPushButton("Cancel")

        save.clicked.connect(self.accept)
        cancel.clicked.connect(self.reject)

        buttons.addWidget(save)
        buttons.addWidget(cancel)

        layout.addLayout(buttons)

    def get_settings(self):
        """
        Сбор всех настроек
        """
        return {
            "security": self.security.get(),
            "appearance": self.appearance.get(),
            "advanced": self.advanced.get()
        }
