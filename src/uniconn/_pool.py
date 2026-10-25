# src/uniconn/_pool.py
"""Реэкспорт пула подключений (каноническая реализация в ``uniconn.pool.connection_pool``)."""

from .core.connection import Connection
from .pool.connection_pool import ConnectionPool, PoolTarget

__all__ = ["Connection", "ConnectionPool", "PoolTarget"]
