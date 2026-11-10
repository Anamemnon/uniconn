# src/uniconn/sync/services.py
"""Синхронные отражения доменных сервисов подключения, пула и диагностической сессии."""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self

from ..background._diagnostic import DiagnosticResult, DiagnosticSession
from ..background._models import LogMatchEvent, StallEvent
from ..core.bridge import (
    EventLoopPortal,
    SyncProxyMixin,
    sync_context,
    sync_iter,
    sync_method,
)
from ..pool.services import (
    PoolFileOperationsService,
    PoolNetworkOperationsService,
    PoolStateManagementService,
)
from ..services.facts_models import FactsDiffReport, HostFacts
from ..services.files import FileOperationsService
from ..services.network import NetworkOperationsService
from ..services.provisioning import StateManagementService
from ..services.remote_path import RemotePath, SyncRemotePath
from ..services.tunnels import TunnelService

if TYPE_CHECKING:
    from .connection import SyncConnection
    from .pool import SyncConnectionPool


class SyncFileOperationsService(SyncProxyMixin):
    """Синхронное отражение доменного сервиса ``FileOperationsService`` (``sync_conn.files``)."""

    def __init__(self, sync_conn: SyncConnection) -> None:
        self._sync_conn = sync_conn

    @property
    def _async_target(self) -> FileOperationsService:
        return self._sync_conn._async_conn.files

    @property
    def _portal(self) -> EventLoopPortal:
        return self._sync_conn._portal

    def path(self, *pathsegments: str | os.PathLike[str]) -> SyncRemotePath:
        """Создать синхронный путь ``SyncRemotePath`` (аналог ``pathlib.Path``)."""
        return SyncRemotePath(
            RemotePath(self._sync_conn._async_conn, *pathsegments),
            self._sync_conn,
        )

    upload = sync_method(FileOperationsService.upload)
    download = sync_method(FileOperationsService.download)
    upload_xmodem = sync_method(FileOperationsService.upload_xmodem)
    upload_ymodem = sync_method(FileOperationsService.upload_ymodem)
    download_xmodem = sync_method(FileOperationsService.download_xmodem)
    download_ymodem = sync_method(FileOperationsService.download_ymodem)
    read_file = sync_method(FileOperationsService.read_file)
    write_file = sync_method(FileOperationsService.write_file)
    checksum = sync_method(FileOperationsService.checksum)
    exists = sync_method(FileOperationsService.exists)
    mkdir = sync_method(FileOperationsService.mkdir)
    chmod = sync_method(FileOperationsService.chmod)
    stat = sync_method(FileOperationsService.stat)
    listdir = sync_method(FileOperationsService.listdir)
    remove_file = sync_method(FileOperationsService.remove_file)
    write_template = sync_method(FileOperationsService.write_template)
    sync_dir = sync_method(FileOperationsService.sync_dir)


class SyncStateManagementService(SyncProxyMixin):
    """Синхронное отражение доменного сервиса ``StateManagementService`` (``sync_conn.state``)."""

    def __init__(self, sync_conn: SyncConnection) -> None:
        """Инициализировать синхронный сервис состояния."""
        self._sync_conn = sync_conn

    @property
    def _async_target(self) -> StateManagementService:
        return self._sync_conn._async_conn.state

    @property
    def _portal(self) -> EventLoopPortal:
        return self._sync_conn._portal

    def share_batches_from(
        self, other: StateManagementService | SyncStateManagementService
    ) -> None:
        """Разделить стек активных ``NotificationBatch`` с другим экземпляром сервиса состояния."""
        target_other = (
            other._async_target
            if isinstance(other, SyncStateManagementService)
            else other
        )
        self._async_target.share_batches_from(target_other)

    def discard_batch(self, batch: Any) -> None:
        """Безопасно удалить контекст ``NotificationBatch`` из стека активных батчей."""
        self._async_target.discard_batch(batch)

    batch_notifications = sync_context(StateManagementService.batch_notifications)
    gather_facts = sync_method(StateManagementService.gather_facts)
    resolve_pkg_manager = sync_method(StateManagementService.resolve_pkg_manager)
    ensure_package = sync_method(StateManagementService.ensure_package)
    ensure_service = sync_method(StateManagementService.ensure_service)
    ensure_line = sync_method(StateManagementService.ensure_line)
    ensure_file = sync_method(StateManagementService.ensure_file)
    ensure_directory = sync_method(StateManagementService.ensure_directory)
    ensure_user = sync_method(StateManagementService.ensure_user)
    ensure_authorized_key = sync_method(StateManagementService.ensure_authorized_key)
    ensure_systemd_unit = sync_method(StateManagementService.ensure_systemd_unit)
    ensure_sysctl = sync_method(StateManagementService.ensure_sysctl)
    ensure_yang = sync_method(StateManagementService.ensure_yang)
    ensure_yang_config = sync_method(StateManagementService.ensure_yang_config)


class SyncTunnelService(SyncProxyMixin):
    """Синхронное отражение доменного сервиса ``TunnelService`` (``sync_conn.tunnels``)."""

    def __init__(self, sync_conn: SyncConnection) -> None:
        self._sync_conn = sync_conn

    @property
    def _async_target(self) -> TunnelService:
        return self._sync_conn._async_conn.tunnels

    @property
    def _portal(self) -> EventLoopPortal:
        return self._sync_conn._portal

    forward_local_port = sync_context(TunnelService.forward_local_port, cast_fn=int)
    forward_remote_port = sync_context(TunnelService.forward_remote_port, cast_fn=int)


class SyncNetworkOperationsService(SyncProxyMixin):
    """Синхронное отражение доменного сервиса ``NetworkOperationsService`` (``sync_conn.net``)."""

    def __init__(self, sync_conn: SyncConnection) -> None:
        self._sync_conn = sync_conn

    @property
    def _async_target(self) -> NetworkOperationsService:
        return self._sync_conn._async_conn.net

    @property
    def _portal(self) -> EventLoopPortal:
        return self._sync_conn._portal

    get = sync_method(NetworkOperationsService.get)
    get_config = sync_method(NetworkOperationsService.get_config)
    edit = sync_method(NetworkOperationsService.edit)
    commit = sync_method(NetworkOperationsService.commit)
    commit_confirm = sync_method(NetworkOperationsService.commit_confirm)
    discard_changes = sync_method(NetworkOperationsService.discard_changes)
    validate = sync_method(NetworkOperationsService.validate)
    lock = sync_method(NetworkOperationsService.lock)
    unlock = sync_method(NetworkOperationsService.unlock)
    capabilities = sync_method(NetworkOperationsService.capabilities)
    rpc = sync_method(NetworkOperationsService.rpc)
    subscribe = sync_iter(NetworkOperationsService.subscribe)
    locked = sync_context(NetworkOperationsService.locked)
    transaction = sync_context(NetworkOperationsService.transaction)


class SyncPoolFileOperationsService(SyncProxyMixin):
    """Синхронное отражение ``PoolFileOperationsService`` (``sync_pool.files``)."""

    def __init__(self, sync_pool: SyncConnectionPool) -> None:
        self._sync_pool = sync_pool

    @property
    def _async_target(self) -> PoolFileOperationsService:
        return self._sync_pool._async_pool.files

    @property
    def _portal(self) -> EventLoopPortal:
        return self._sync_pool._portal

    upload = sync_method(PoolFileOperationsService.upload)
    download = sync_method(PoolFileOperationsService.download)
    upload_xmodem = sync_method(PoolFileOperationsService.upload_xmodem)
    upload_ymodem = sync_method(PoolFileOperationsService.upload_ymodem)
    download_xmodem = sync_method(PoolFileOperationsService.download_xmodem)
    download_ymodem = sync_method(PoolFileOperationsService.download_ymodem)
    read_file = sync_method(PoolFileOperationsService.read_file)
    write_file = sync_method(PoolFileOperationsService.write_file)
    checksum = sync_method(PoolFileOperationsService.checksum)
    exists = sync_method(PoolFileOperationsService.exists)
    mkdir = sync_method(PoolFileOperationsService.mkdir)
    chmod = sync_method(PoolFileOperationsService.chmod)
    stat = sync_method(PoolFileOperationsService.stat)
    listdir = sync_method(PoolFileOperationsService.listdir)
    remove_file = sync_method(PoolFileOperationsService.remove_file)
    write_template = sync_method(PoolFileOperationsService.write_template)
    sync_dir = sync_method(PoolFileOperationsService.sync_dir)


class SyncPoolStateManagementService(SyncProxyMixin):
    """Синхронное отражение ``PoolStateManagementService`` (``sync_pool.state``)."""

    def __init__(self, sync_pool: SyncConnectionPool) -> None:
        self._sync_pool = sync_pool

    @property
    def _async_target(self) -> PoolStateManagementService:
        return self._sync_pool._async_pool.state

    @property
    def _portal(self) -> EventLoopPortal:
        return self._sync_pool._portal

    batch_notifications = sync_context(
        PoolStateManagementService.batch_notifications
    )
    ensure_package = sync_method(PoolStateManagementService.ensure_package)
    ensure_service = sync_method(PoolStateManagementService.ensure_service)
    ensure_line = sync_method(PoolStateManagementService.ensure_line)
    ensure_file = sync_method(PoolStateManagementService.ensure_file)
    ensure_directory = sync_method(PoolStateManagementService.ensure_directory)
    ensure_user = sync_method(PoolStateManagementService.ensure_user)
    ensure_authorized_key = sync_method(
        PoolStateManagementService.ensure_authorized_key
    )
    ensure_systemd_unit = sync_method(PoolStateManagementService.ensure_systemd_unit)
    ensure_sysctl = sync_method(PoolStateManagementService.ensure_sysctl)
    ensure_yang = sync_method(PoolStateManagementService.ensure_yang)
    ensure_yang_config = sync_method(PoolStateManagementService.ensure_yang_config)


class SyncPoolNetworkOperationsService(SyncProxyMixin):
    """Синхронное отражение ``PoolNetworkOperationsService`` (``sync_pool.net``)."""

    def __init__(self, sync_pool: SyncConnectionPool) -> None:
        self._sync_pool = sync_pool

    @property
    def _async_target(self) -> PoolNetworkOperationsService:
        return self._sync_pool._async_pool.net

    @property
    def _portal(self) -> EventLoopPortal:
        return self._sync_pool._portal

    get = sync_method(PoolNetworkOperationsService.get)
    get_config = sync_method(PoolNetworkOperationsService.get_config)
    edit = sync_method(PoolNetworkOperationsService.edit)
    commit = sync_method(PoolNetworkOperationsService.commit)
    commit_confirm = sync_method(PoolNetworkOperationsService.commit_confirm)
    discard_changes = sync_method(PoolNetworkOperationsService.discard_changes)
    validate = sync_method(PoolNetworkOperationsService.validate)
    lock = sync_method(PoolNetworkOperationsService.lock)
    unlock = sync_method(PoolNetworkOperationsService.unlock)
    capabilities = sync_method(PoolNetworkOperationsService.capabilities)
    rpc = sync_method(PoolNetworkOperationsService.rpc)


class SyncDiagnosticSession(SyncProxyMixin):
    """Синхронное отражение ``DiagnosticSession`` на базе ``EventLoopPortal``."""

    def __init__(
        self,
        async_session: DiagnosticSession,
        sync_conn: SyncConnection,
    ) -> None:
        self._async_session = async_session
        self._async_target = async_session
        self._sync_conn = sync_conn

    @property
    def _portal(self) -> EventLoopPortal:
        return self._sync_conn._portal

    @property
    def workspace_dir(self) -> Path:
        """Рабочая директория текущей диагностической сессии."""
        return self._async_session.workspace_dir

    @property
    def pre_facts(self) -> HostFacts | None:
        """Слепок системных фактов до начала теста."""
        return self._async_session.pre_facts

    @property
    def post_facts(self) -> HostFacts | None:
        """Слепок системных фактов после завершения теста."""
        return self._async_session.post_facts

    @property
    def facts_diff(self) -> FactsDiffReport | None:
        """Отчёт об изменениях системных фактов (pre vs post)."""
        return self._async_session.facts_diff

    @property
    def result(self) -> DiagnosticResult | None:
        """Итоговый результат и манифест диагностической сессии."""
        return self._async_session.result

    @property
    def errors(self) -> list[str]:
        """Список зафиксированных нефатальных ошибок сессии."""
        return self._async_session.errors

    @property
    def matches(self) -> list[LogMatchEvent]:
        """Список зафиксированных совпадений по правилам ``watch_rules``."""
        return self._async_session.matches

    @property
    def stalled_streams(self) -> list[str]:
        """Список имён потоков, в которых сработал детектор зависания ``max_silence_seconds``."""
        return self._async_session.stalled_streams

    @property
    def stall_events(self) -> list[StallEvent]:
        """Список событий зависания потоков ``StallEvent``."""
        return self._async_session.stall_events

    def check_abort(self) -> None:
        """Выбросить ``HardwareFaultDetectedError``, если сработало правило с ``abort_on_match=True``."""
        self._async_session.check_abort()

    snapshot = sync_method(DiagnosticSession.snapshot)
    emit_custom_log = sync_method(DiagnosticSession.emit_custom_log)

    def __enter__(self) -> Self:
        self._sync_conn._run_coro(self._async_session.__aenter__())
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        return bool(
            self._sync_conn._run_coro(
                self._async_session.__aexit__(exc_type, exc_val, exc_tb)
            )
        )


__all__ = [
    "SyncDiagnosticSession",
    "SyncFileOperationsService",
    "SyncNetworkOperationsService",
    "SyncPoolFileOperationsService",
    "SyncPoolNetworkOperationsService",
    "SyncPoolStateManagementService",
    "SyncStateManagementService",
    "SyncTunnelService",
]

