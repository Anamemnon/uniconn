"""Точка входа для запуска из исходников: делегирует CLI uniconn или запускает dev-сервер."""

from __future__ import annotations

import os
from pathlib import Path
import sys

_ROOT_DIR = Path(__file__).resolve().parent
for _path_entry in (str(_ROOT_DIR), str(_ROOT_DIR / "src")):
    if _path_entry not in sys.path:
        sys.path.insert(0, _path_entry)


def main() -> None:
    """Запустить dev-сервер дашборда (--serve) или CLI uniconn."""
    if "--serve" in sys.argv:
        from examples.dashboard import serve_dev_dashboard

        port = int(os.environ.get("DEFAULT_APP_PORT", "3000"))
        serve_dev_dashboard(port=port)
        return

    from uniconn.cli import main as cli_main

    cli_main()


if __name__ == "__main__":
    main()

