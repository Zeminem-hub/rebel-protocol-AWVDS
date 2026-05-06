import runpy
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
LOCAL_PACKAGES = ROOT / ".codex_python"

if LOCAL_PACKAGES.exists():
    sys.path.insert(0, str(LOCAL_PACKAGES))

runpy.run_path(str(ROOT / "app.py"), run_name="__main__")
