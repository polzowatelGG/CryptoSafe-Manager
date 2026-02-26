import sys
from pathlib import Path

# Добавляем `src` в sys.path для удобства импортов в тестах
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

import os
import pytest

from database.db import DatabasePool


@pytest.fixture(scope="session")
def test_db(tmp_path_factory):
	"""Создаёт временную sqlite БД, применяет миграции и возвращает пул и путь до файла.

	Фикстура закрывает пул соединений и удаляет файл после сессии.
	"""
	tmpdir = tmp_path_factory.mktemp("data")
	db_file = tmpdir / "test_database.db"

	pool = DatabasePool(str(db_file))
	pool.migrate()

	yield pool, str(db_file)

	try:
		pool.close()
	except Exception:
		pass
	try:
		os.remove(str(db_file))
	except Exception:
		pass


@pytest.fixture(scope="session")
def qapp():
	"""Создаёт QApplication в headless режиме (offscreen) для GUI-тестов."""
	# устанавливаем offscreen платформу до создания приложения
	os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
	try:
		from PyQt6.QtWidgets import QApplication
	except Exception:
		pytest.skip("PyQt6 не установлен, пропуск GUI тестов")

	app = QApplication([])
	yield app
	try:
		app.quit()
	except Exception:
		pass
