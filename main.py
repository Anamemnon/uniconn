"""Точка входа для запуска из исходников: делегирует CLI uniconn или запускает dev-сервер."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
VENV_DIR = ROOT_DIR / ".venv"
VENV_BIN = VENV_DIR / "bin"
VENV_PYTHON = VENV_BIN / "python"
LOCAL_BIN = ROOT_DIR / ".bin"


def _ensure_venv_runtime() -> None:
    """Переключить процесс на Python 3.12 из .venv, если запущен системный Python."""
    path_parts = [str(VENV_BIN), str(LOCAL_BIN), os.environ.get("PATH", "")]
    os.environ["PATH"] = ":".join(p for p in path_parts if p)
    src_dir = str(ROOT_DIR / "src")
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)

    if VENV_PYTHON.exists() and os.environ.get("UNICONN_VENV_REEXEC") != "1":
        try:
            in_venv = Path(sys.prefix).resolve() == VENV_DIR.resolve()
        except OSError:
            in_venv = False
        if not in_venv:
            os.environ["UNICONN_VENV_REEXEC"] = "1"
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

