# src/uniconn/pool/__init__.py
"""Пакет пулов подключений, доменных сервисов пула и мультиплексирования потоков."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .._utils import make_lazy_package_loader

if TYPE_CHECKING:
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

_LAZY_MODULE_GROUPS: dict[str, tuple[str, ...]] = {
    ".connection_pool": ("ConnectionPool", "PoolTarget"),
    ".services": (
        "PoolApplyPlanContext",
        "PoolFileOperationsService",
        "PoolNetworkOperationsService",
        "PoolNotificationBatch",
        "PoolPlanContext",
        "PoolStateManagementService",
    ),
    ".session_pool": ("SSHSessionPool", "_PooledConnectionSlot"),
    ".stream_mux": ("PoolStreamMultiplexer",),
}

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

_LAZY_EXPORTS, __getattr__, __dir__ = make_lazy_package_loader(
    __name__, globals(), _LAZY_MODULE_GROUPS, all_names=__all__
)

