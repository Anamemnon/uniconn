# src/uniconn/transports/_base.py
"""Обратно-совместимый реэкспорт базовых абстракций транспортов из uniconn.transports.base."""

from .base import (
    BaseTransport,
    CommandTransport,
    FileCapableTransport,
    FileStat,
    ShellCapableTransport,
    ShellProcessProtocol,
    ShellStdinProtocol,
    ShellStdoutProtocol,
    TunnelCapableTransport,
    require_capability,
    supports_capability,
)

__all__ = [
    "BaseTransport",
    "CommandTransport",
    "FileCapableTransport",
    "FileStat",
    "ShellCapableTransport",
    "ShellProcessProtocol",
    "ShellStdinProtocol",
    "ShellStdoutProtocol",
    "TunnelCapableTransport",
    "require_capability",
    "supports_capability",
]
