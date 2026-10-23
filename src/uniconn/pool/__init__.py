# src/uniconn/pool/__init__.py
"""Пакет пулов подключений и мультиплексирования потоков."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .stream_mux import PoolStreamMultiplexer

if TYPE_CHECKING:
    from .._pool import ConnectionPool, PoolTarget
    from .._session_pool import SSHSessionPool


def __getattr__(name: str) -> Any:
    """Ленивый импорт классов пулов для предотвращения циклических зависимостей."""
    if name in ("ConnectionPool", "PoolTarget"):
        from .._pool import ConnectionPool, PoolTarget

        return ConnectionPool if name == "ConnectionPool" else PoolTarget
    if name == "SSHSessionPool":
        from .._session_pool import SSHSessionPool

        return SSHSessionPool
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)


__all__ = [
    "ConnectionPool",
    "PoolStreamMultiplexer",
    "PoolTarget",
    "SSHSessionPool",
]
