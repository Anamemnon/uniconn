# src/uniconn/sync/services.py
"""Синхронные отражения доменных сервисов и диагностической сессии на базе ``ParamSpec``-дескрипторов."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self

from ..background._diagnostic import DiagnosticResult, DiagnosticSession
from ..core.bridge import EventLoopPortal, SyncProxyMixin, sync_context, sync_method
from ..services.facts_models import FactsDiffReport, FactSpec, HostFacts
from ..services.files import FileOperationsService
from ..services.provisioning import StateManagementService
from ..services.tunnels import TunnelService

if TYPE_CHECKING:
    from .connection import SyncConnection


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

    upload = sync_method(FileOperationsService.upload)
    download = sync_method(FileOperationsService.download)
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

    def gather_facts(
        self,
        *,
        refresh: bool = False,
        timeout: float | None = None,
        spec: FactSpec | Mapping[str, Any] | str | Path | None = None,
    ) -> HostFacts:
        """Собрать системные факты о хосте (синхронно)."""
        return self._sync_conn.gather_facts(
            refresh=refresh, timeout=timeout, spec=spec
        )

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
