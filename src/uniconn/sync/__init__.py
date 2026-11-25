# src/uniconn/sync/__init__.py
"""Пакет синхронных обёрток и доменных сервисов."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .._utils import make_lazy_package_loader

if TYPE_CHECKING:
    from ..orchestration.flow import SyncFlow
    from ..services.remote_path import SyncRemotePath
    from .connection import SyncConnection
    from .pool import SyncConnectionPool
    from .services import (
        SyncDiagnosticSession,
        SyncFileOperationsService,
        SyncNetworkOperationsService,
        SyncPoolFileOperationsService,
        SyncPoolNetworkOperationsService,
        SyncPoolStateManagementService,
        SyncStateManagementService,
        SyncTunnelService,
    )
    from .shell import SyncShellSession

_LAZY_MODULE_GROUPS: dict[str, tuple[str, ...]] = {
    "..orchestration.flow": ("SyncFlow",),
    "..services.remote_path": ("SyncRemotePath",),
    ".connection": ("SyncConnection",),
    ".pool": ("SyncConnectionPool",),
    ".services": (
        "SyncDiagnosticSession",
        "SyncFileOperationsService",
        "SyncNetworkOperationsService",
        "SyncPoolFileOperationsService",
        "SyncPoolNetworkOperationsService",
        "SyncPoolStateManagementService",
        "SyncStateManagementService",
        "SyncTunnelService",
    ),
    ".shell": ("SyncShellSession",),
}

__all__ = [
    "SyncConnection",
    "SyncConnectionPool",
    "SyncDiagnosticSession",
    "SyncFileOperationsService",
    "SyncFlow",
    "SyncNetworkOperationsService",
    "SyncPoolFileOperationsService",
    "SyncPoolNetworkOperationsService",
    "SyncPoolStateManagementService",
    "SyncRemotePath",
    "SyncShellSession",
    "SyncStateManagementService",
    "SyncTunnelService",
]

_LAZY_EXPORTS, __getattr__, __dir__ = make_lazy_package_loader(
    __name__, globals(), _LAZY_MODULE_GROUPS, all_names=__all__
)

