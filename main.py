"""Точка входа для запуска из исходников: делегирует CLI uniconn или запускает dev-сервер."""

from __future__ import annotations

import os
import sys


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

