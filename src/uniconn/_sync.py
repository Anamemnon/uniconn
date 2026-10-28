# src/uniconn/_sync.py
"""Реэкспорт синхронных обёрток (каноническая реализация в пакете ``uniconn.sync``)."""

from .sync import (
    SyncConnection,
    SyncConnectionPool,
    SyncDiagnosticSession,
    SyncFileOperationsService,
    SyncPoolFileOperationsService,
    SyncPoolStateManagementService,
    SyncShellSession,
    SyncStateManagementService,
    SyncTunnelService,
)

__all__ = [
    "SyncConnection",
    "SyncConnectionPool",
    "SyncDiagnosticSession",
    "SyncFileOperationsService",
    "SyncPoolFileOperationsService",
    "SyncPoolStateManagementService",
    "SyncShellSession",
    "SyncStateManagementService",
    "SyncTunnelService",
]
