# src/uniconn/_session_pool.py
"""Реэкспорт пула SSH-сессий (каноническая реализация в ``uniconn.pool.session_pool``)."""

from .core.connection import Connection
from .pool.session_pool import (
    _CHANNEL_LIMIT_HINTS,
    SSHSessionPool,
    _PooledConnectionSlot,
)

__all__ = [
    "_CHANNEL_LIMIT_HINTS",
    "Connection",
    "SSHSessionPool",
    "_PooledConnectionSlot",
]
