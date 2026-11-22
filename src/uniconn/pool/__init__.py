# src/uniconn/pool/__init__.py
"""Пакет пулов подключений, доменных сервисов пула и мультиплексирования потоков."""

from .connection_pool import ConnectionPool, PoolTarget
from .services import (
    PoolApplyPlanContext,
    PoolFileOperationsService,
    PoolNetworkOperationsService,
    PoolNotificationBatch,
    PoolPlanContext,
    PoolStateManagementService,
)
from .session_pool import SSHSessionPool, _PooledConnectionSlot
from .stream_mux import PoolStreamMultiplexer

__all__ = [
    "ConnectionPool",
    "PoolApplyPlanContext",
    "PoolFileOperationsService",
    "PoolNetworkOperationsService",
    "PoolNotificationBatch",
    "PoolPlanContext",
    "PoolStateManagementService",
    "PoolStreamMultiplexer",
    "PoolTarget",
    "SSHSessionPool",
    "_PooledConnectionSlot",
]

