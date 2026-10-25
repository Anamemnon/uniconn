# src/uniconn/_connection.py
"""Обратно-совместимый реэкспорт фасада Connection из uniconn.core.connection."""

from tenacity import wait_exponential_jitter

from .config.inventory import InventoryLoader
from .core.connection import (
    Connection,
    _resolve_circuit_breaker,
    _resolve_rate_limiter,
    format_command,
    render_template,
)
from .core.context import CwdContext, EnvContext, TempDirContext

_CwdContext = CwdContext
_EnvContext = EnvContext
_TempDirContext = TempDirContext
_format_command = format_command
_parse_inventory_data = InventoryLoader.parse_data
_wait_exponential_jitter = wait_exponential_jitter

__all__ = [
    "Connection",
    "_resolve_circuit_breaker",
    "_resolve_rate_limiter",
    "format_command",
    "render_template",
    "wait_exponential_jitter",
]
