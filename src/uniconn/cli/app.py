# src/uniconn/cli/app.py
"""Фабрика и точка входа модульного CLI приложения uniconn на базе Cyclopts."""

from __future__ import annotations

import sys
from typing import Annotated, Any

from .._logging import configure_logging
from .cmd_cassette import register_cassette_commands
from .cmd_exec import register_exec_commands
from .cmd_files import register_file_commands
from .cmd_ops import register_ops_commands
from .cmd_screen import register_screen_commands
from .renderers import CLIOutputRenderer, Console, Parameter, check_cli_deps, cyclopts


def create_cli_app() -> Any:
    """Собрать и вернуть настроенный экземпляр ``cyclopts.App`` со всеми подкомандами."""
    check_cli_deps()

    app = cyclopts.App(
        name="uniconn",
        help="Universal CLI for remote command execution",
        result_action="sys_exit",
    )
    console = Console()
    renderer = CLIOutputRenderer(console)

    @app.meta.default
    def meta_launcher(
        *tokens: Annotated[str, Parameter(show=False, allow_leading_hyphen=True)],
        log_level: Annotated[
            str | None,
            Parameter(
                name="--log-level",
                help="Log level (DEBUG, INFO, WARNING, ERROR)",
            ),
        ] = None,
        log_format: Annotated[
            str,
            Parameter(
                name="--log-format",
                help="Structured log format: console or json",
            ),
        ] = "console",
    ) -> Any:
        """Uniconn - Universal library for remote command execution."""
        if log_level is not None or log_format != "console":
            fmt_val = "json" if log_format.lower() == "json" else "console"
            configure_logging(
                level=log_level or "INFO",
                fmt=fmt_val,
                stream=sys.stderr,
            )
        return app(tokens)

    register_exec_commands(app, console, renderer)
    register_file_commands(app, console, renderer)
    register_ops_commands(app, console, renderer)
    register_screen_commands(app, console, renderer)
    register_cassette_commands(app, console, renderer)
    return app


def main(tokens: list[str] | None = None) -> None:
    """Точка входа для CLI."""
    app = create_cli_app()
    if tokens is None:
        tokens = sys.argv[1:]
    app.meta(tokens)

