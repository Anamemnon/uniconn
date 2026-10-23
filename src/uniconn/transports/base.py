# src/uniconn/transports/base.py
"""Публичные Capability-протоколы и базовый класс транспортов."""

from ._base import (
    BaseTransport,
    CommandTransport,
    FileCapableTransport,
    ShellCapableTransport,
    TunnelCapableTransport,
    require_capability,
    supports_capability,
)

__all__ = [
    "BaseTransport",
    "CommandTransport",
    "FileCapableTransport",
    "ShellCapableTransport",
    "TunnelCapableTransport",
    "require_capability",
    "supports_capability",
]
