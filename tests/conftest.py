import sys
from pathlib import Path

# Упрощённый conftest: добавляем `src` в sys.path для тестов.
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

