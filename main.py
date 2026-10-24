"""Точка входа для запуска из исходников: делегирует CLI uniconn или запускает dev-сервер."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
VENV_DIR = ROOT_DIR / ".venv"
VENV_BIN = VENV_DIR / ("Scripts" if os.name == "nt" else "bin")
VENV_PYTHON = VENV_BIN / ("python.exe" if os.name == "nt" else "python")
LOCAL_BIN = ROOT_DIR / ".bin"


def _ensure_venv_runtime() -> None:
    """Переключить процесс на Python 3.12 из .venv, если запущен системный Python (< 3.11)."""
    path_parts = [str(VENV_BIN), str(LOCAL_BIN), os.path.expanduser("~/.local/bin"), os.environ.get("PATH", "")]
    os.environ["PATH"] = os.pathsep.join(p for p in path_parts if p)
    src_dir = str(ROOT_DIR / "src")
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)

    if not VENV_PYTHON.exists() and sys.version_info < (3, 11):
        from examples.dashboard.server import _ensure_venv_background

        _ensure_venv_background()

    if VENV_PYTHON.exists() and os.environ.get("UNICONN_VENV_REEXEC") != "1":
        try:
            in_venv = Path(sys.prefix).resolve() == VENV_DIR.resolve() and sys.version_info >= (3, 11)
        except OSError:
            in_venv = False
        if not in_venv:
            os.environ["UNICONN_VENV_REEXEC"] = "1"
            if os.name == "nt":
                raise SystemExit(subprocess.call([str(VENV_PYTHON), *sys.argv]))
            os.execv(str(VENV_PYTHON), [str(VENV_PYTHON), *sys.argv])


def main() -> None:
    """Запустить dev-сервер дашборда (--serve) или CLI uniconn."""
    _ensure_venv_runtime()
    if "--serve" in sys.argv:
        from examples.dashboard import serve_dev_dashboard

        port = int(os.environ.get("DEFAULT_APP_PORT", "3000"))
        serve_dev_dashboard(port=port)
        return

    from uniconn.cli import main as cli_main

    cli_main()


if __name__ == "__main__":
    main()

