# src/uniconn/cli/__init__.py
"""Модульный CLI-пакет библиотеки uniconn на базе Cyclopts и Rich."""

from .. import Connection, ConnectionPool, __version__
from ..plugins._loader import TransportLoader
from .app import create_cli_app, main
from .renderers import (
    HAVE_CLI_DEPS,
    CLIOutputRenderer,
    CliResult,
    CliRunner,
    check_cli_deps,
)

__all__ = [
    "HAVE_CLI_DEPS",
    "CLIOutputRenderer",
    "CliResult",
    "CliRunner",
    "Connection",
    "ConnectionPool",
    "TransportLoader",
    "__version__",
    "check_cli_deps",
    "create_cli_app",
    "main",
]
