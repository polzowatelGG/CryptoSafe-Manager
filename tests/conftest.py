import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] # добавляем src в sys.path для доступа к модулям приложения
SRC = ROOT / "src" # путь к папке src
sys.path.insert(0, str(SRC)) # добавляем src в sys.path для доступа к модулям приложения

