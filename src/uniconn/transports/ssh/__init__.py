# src/uniconn/transports/ssh/__init__.py
"""Модульный пакет SSH-транспорта (OpenSSHConfigParser, SSHJumpChainManager, SFTPClientAdapter)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .config_parser import OpenSSHConfigParser
from .sftp import SFTPClientAdapter
from .tunnel_chain import SSHJumpChainManager

if TYPE_CHECKING:
    from .._ssh import SSHTransport


def __getattr__(name: str) -> Any:
    """Ленивый импорт SSHTransport для предотвращения циклических импортов."""
    if name == "SSHTransport":
        from .._ssh import SSHTransport

        return SSHTransport
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)


__all__ = [
    "OpenSSHConfigParser",
    "SFTPClientAdapter",
    "SSHJumpChainManager",
    "SSHTransport",
]
