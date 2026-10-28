# src/uniconn/sync/connection.py
"""Синхронная обёртка над async Connection на базе ``EventLoopPortal`` и ``ParamSpec``-дескрипторов."""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Self

from pydantic import SecretStr

from ..config.models import ConnectionConfig
from ..core.bridge import (
    EventLoopPortal,
    SyncProxyMixin,
    sync_context,
    sync_iter,
    sync_method,
)
from ..core.connection import Connection, OperationObserver
from ..core.context import CwdContext, EnvContext, ExecutionContext
from ..core.pipeline import CommandPipeline, HookCallback, HookEvent
from ..core.resilience import CircuitBreaker, RateLimiter
from ..services.facts_models import FactSpec
from ..services.files import FileOperationsService
from ..services.provisioning import StateManagementService
from ..services.tunnels import TunnelService
from ..transports.base import BaseTransport
from .services import (
    SyncDiagnosticSession,
    SyncFileOperationsService,
    SyncStateManagementService,
    SyncTunnelService,
)
from .shell import SyncShellSession

if TYPE_CHECKING:
    from ..background._diagnostic import (
        DiagnosticConfig,
        StreamSourceSpec,
    )


class SyncConnection(SyncProxyMixin):
    """Синхронная обёртка над async Connection на базе ``EventLoopPortal``."""

    def __init__(self, async_conn: Connection) -> None:
        self._async_conn = async_conn
        self._async_target = async_conn
        self._portal = EventLoopPortal(owner_name="SyncConnection")
        self.files = SyncFileOperationsService(self)
        self.state = SyncStateManagementService(self)
        self.tunnels = SyncTunnelService(self)

    # ─── Фабричные методы и клонирование ───────────────────────────

    @classmethod
    def from_uri(
        cls,
        uri: str,
        retry_attempts: int = 3,
        logger: logging.Logger | None = None,
        dry_run: bool = False,
        before_run: Sequence[HookCallback] | None = None,
        after_run: Sequence[HookCallback] | None = None,
        on_error: Sequence[HookCallback] | None = None,
        rate_limit: float | RateLimiter | None = None,
        circuit_breaker: CircuitBreaker | bool | None = None,
    ) -> Self:
        """Создать синхронное подключение напрямую из URI строки."""
        return cls(
            Connection.from_uri(
                uri,
                retry_attempts=retry_attempts,
                logger=logger,
                dry_run=dry_run,
                before_run=before_run,
                after_run=after_run,
                on_error=on_error,
                rate_limit=rate_limit,
                circuit_breaker=circuit_breaker,
            )
        )

    @classmethod
    def from_config(
        cls,
        config: ConnectionConfig,
        retry_attempts: int = 3,
        logger: logging.Logger | None = None,
        dry_run: bool = False,
        before_run: Sequence[HookCallback] | None = None,
        after_run: Sequence[HookCallback] | None = None,
        on_error: Sequence[HookCallback] | None = None,
        rate_limit: float | RateLimiter | None = None,
        circuit_breaker: CircuitBreaker | bool | None = None,
    ) -> Self:
        """Создать синхронное подключение из объекта ``ConnectionConfig``."""
        return cls(
            Connection.from_config(
                config,
                retry_attempts=retry_attempts,
                logger=logger,
                dry_run=dry_run,
                before_run=before_run,
                after_run=after_run,
                on_error=on_error,
                rate_limit=rate_limit,
                circuit_breaker=circuit_breaker,
            )
        )

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
        retry_attempts: int = 3,
        logger: logging.Logger | None = None,
        dry_run: bool = False,
    ) -> Self:
        """Создать синхронное подключение из словаря."""
        return cls(
            Connection.from_dict(
                data,
                retry_attempts=retry_attempts,
                logger=logger,
                dry_run=dry_run,
            )
        )

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        retry_attempts: int = 3,
        logger: logging.Logger | None = None,
        *,
        host: str | None = None,
        group: str | None = None,
    ) -> list[Self]:
        """Создать список синхронных подключений из JSON/YAML/TOML файла."""
        conns = Connection.from_file(
            path,
            retry_attempts=retry_attempts,
            logger=logger,
            host=host,
            group=group,
        )
        return [cls(c) for c in conns]

    @classmethod
    def from_inventory(
        cls,
        path: str | Path,
        host: str,
        retry_attempts: int = 3,
        logger: logging.Logger | None = None,
    ) -> Self:
        """Создать одиночное синхронное подключение по имени хоста из инвентарного файла."""
        return cls(
            Connection.from_inventory(
                path,
                host=host,
                retry_attempts=retry_attempts,
                logger=logger,
            )
        )

    def copy(
        self,
        host: str | None = None,
        port: int | None = None,
        username: str | None = None,
        password: str | SecretStr | None = None,
        key_file: str | None = None,
        passphrase: str | SecretStr | None = None,
        ssh_config: str | bool | None = None,
        timeout: float | None = None,
        options: dict[str, Any] | None = None,
        retry_attempts: int | None = None,
        logger: logging.Logger | None = None,
        dry_run: bool | None = None,
        rate_limit: float | RateLimiter | None = None,
        circuit_breaker: CircuitBreaker | bool | None = None,
    ) -> Self:
        """Создать копию синхронного подключения с возможностью изменения параметров."""
        return type(self)(
            self._async_conn.copy(
                host=host,
                port=port,
                username=username,
                password=password,
                key_file=key_file,
                passphrase=passphrase,
                ssh_config=ssh_config,
                timeout=timeout,
                options=options,
                retry_attempts=retry_attempts,
                logger=logger,
                dry_run=dry_run,
                rate_limit=rate_limit,
                circuit_breaker=circuit_breaker,
            )
        )

    def with_overrides(self, **overrides: Any) -> Self:
        """Создать копию синхронного подключения с переопределёнными параметрами."""
        return type(self)(self._async_conn.with_overrides(**overrides))

    # ─── Свойства и контекст ───────────────────────────────────────

    @property
    def _closed(self) -> bool:
        """Признак закрытия синхронной обёртки."""
        return self._portal.closed

    @property
    def config(self) -> ConnectionConfig:
        """Конфигурация подключения."""
        return self._async_conn.config

    @property
    def transport(self) -> BaseTransport:
        """Низкоуровневый транспорт подключения."""
        return self._async_conn.transport

    def swap_transport(self, new_transport: BaseTransport) -> BaseTransport:
        """Заменить активный транспорт подключения и вернуть предыдущий."""
        return self._async_conn.swap_transport(new_transport)

    @property
    def context(self) -> ExecutionContext:
        """Текущий контекст выполнения."""
        return self._async_conn.context

    @property
    def logger(self) -> logging.Logger:
        """Логгер подключения."""
        return self._async_conn.logger

    @property
    def retry_attempts(self) -> int:
        """Количество повторных попыток подключения."""
        return self._async_conn.retry_attempts

    @property
    def is_dry_run(self) -> bool:
        """Включён ли глобальный режим симуляции (``dry_run``)."""
        return self._async_conn.is_dry_run

    @property
    def dry_run(self) -> bool:
        """Включён ли режим dry_run для данного подключения."""
        return self._async_conn.dry_run

    @property
    def transport_name(self) -> str:
        """Имя используемого транспорта."""
        return self._async_conn.transport_name

    @property
    def current_cwd(self) -> str | None:
        """Текущая рабочая директория из активного стека ``conn.cd()``."""
        return self._async_conn.current_cwd

    @property
    def current_env(self) -> dict[str, str]:
        """Текущий объединённый словарь переменных окружения из стека ``conn.env()``."""
        return self._async_conn.current_env

    @property
    def pipeline(self) -> CommandPipeline:
        """Конвейер выполнения команд."""
        return self._async_conn.pipeline

    def get_hooks(self, event: HookEvent) -> list[HookCallback]:
        """Вернуть копию списка зарегистрированных хуков."""
        return self._async_conn.get_hooks(event)

    @property
    def operation_observers(self) -> list[OperationObserver]:
        """Список наблюдателей за не-командными операциями."""
        return self._async_conn.operation_observers

    def add_operation_observer(self, observer: OperationObserver) -> Self:
        """Зарегистрировать наблюдателя за файловыми и интерактивными операциями."""
        self._async_conn.add_operation_observer(observer)
        return self

    def _run_coro(self, coro: Any) -> Any:
        """Запустить корутину синхронно через ``EventLoopPortal``."""
        return self._portal.call(coro)

    def cd(self, path: str | Path) -> CwdContext:
        """Контекстный менеджер смены рабочей директории (синхронный)."""
        return self._async_conn.cd(path)

    def env(
        self, mapping: dict[str, str] | None = None, **env_vars: str
    ) -> EnvContext:
        """Контекстный менеджер переменных окружения (синхронный)."""
        return self._async_conn.env(mapping, **env_vars)

    @property
    def rate_limiter(self) -> RateLimiter | None:
        """Ограничитель частоты команд (Token Bucket), если настроен."""
        return self._async_conn.rate_limiter

    @rate_limiter.setter
    def rate_limiter(self, value: float | RateLimiter | None) -> None:
        self._async_conn.rate_limiter = value

    @property
    def circuit_breaker(self) -> CircuitBreaker | None:
        """Автоматический предохранитель (Circuit Breaker), если настроен."""
        return self._async_conn.circuit_breaker

    @circuit_breaker.setter
    def circuit_breaker(self, value: CircuitBreaker | None) -> None:
        self._async_conn.circuit_breaker = value

    def add_hook(self, event: HookEvent, callback: HookCallback) -> Self:
        """Зарегистрировать lifecycle-хук (``before_run``, ``after_run``, ``on_error``)."""
        self._async_conn.add_hook(event, callback)
        return self

    # ─── Команды, ожидание и потоки (дескрипторы к Connection) ────

    run = sync_method(Connection.run)
    run_bytes = sync_method(Connection.run_bytes)
    run_commands = sync_method(Connection.run_commands)
    expect = sync_method(Connection.expect)
    stream = sync_iter(Connection.stream)
    is_alive = sync_method(Connection.is_alive)
    ping = sync_method(Connection.ping)
    wait_for_connection = sync_method(Connection.wait_for_connection)
    wait_for_port = sync_method(Connection.wait_for_port)
    wait_for_path = sync_method(Connection.wait_for_path)
    run_script = sync_method(Connection.run_script)
    gather_facts = sync_method(Connection.gather_facts)
    temp_dir = sync_context(Connection.temp_dir)

    # ─── Файловые операции и туннели (делегация к self.files / self.tunnels) ─

    read_file = sync_method(FileOperationsService.read_file, delegate_attr="files")
    write_file = sync_method(FileOperationsService.write_file, delegate_attr="files")
    checksum = sync_method(FileOperationsService.checksum, delegate_attr="files")
    exists = sync_method(FileOperationsService.exists, delegate_attr="files")
    mkdir = sync_method(FileOperationsService.mkdir, delegate_attr="files")
    remove_file = sync_method(FileOperationsService.remove_file, delegate_attr="files")
    upload = sync_method(FileOperationsService.upload, delegate_attr="files")
    download = sync_method(FileOperationsService.download, delegate_attr="files")
    chmod = sync_method(FileOperationsService.chmod, delegate_attr="files")
    stat = sync_method(FileOperationsService.stat, delegate_attr="files")
    listdir = sync_method(FileOperationsService.listdir, delegate_attr="files")
    write_template = sync_method(
        FileOperationsService.write_template, delegate_attr="files"
    )
    sync_dir = sync_method(FileOperationsService.sync_dir, delegate_attr="files")

    forward_local_port = sync_context(
        TunnelService.forward_local_port, delegate_attr="tunnels", cast_fn=int
    )
    forward_remote_port = sync_context(
        TunnelService.forward_remote_port, delegate_attr="tunnels", cast_fn=int
    )

    # ─── Идемпотентное управление состоянием (делегация к self.state) ─

    ensure_package = sync_method(
        StateManagementService.ensure_package, delegate_attr="state"
    )
    ensure_service = sync_method(
        StateManagementService.ensure_service, delegate_attr="state"
    )
    ensure_line = sync_method(StateManagementService.ensure_line, delegate_attr="state")
    ensure_file = sync_method(StateManagementService.ensure_file, delegate_attr="state")
    ensure_directory = sync_method(
        StateManagementService.ensure_directory, delegate_attr="state"
    )
    ensure_user = sync_method(StateManagementService.ensure_user, delegate_attr="state")
    ensure_authorized_key = sync_method(
        StateManagementService.ensure_authorized_key, delegate_attr="state"
    )
    ensure_systemd_unit = sync_method(
        StateManagementService.ensure_systemd_unit, delegate_attr="state"
    )
    ensure_sysctl = sync_method(
        StateManagementService.ensure_sysctl, delegate_attr="state"
    )

    # ─── Специализированные синхронные сессии и жизненный цикл ─────

    def open_shell(
        self,
        term_type: str = "xterm",
        term_size: tuple[int, int] = (80, 24),
        init_posix: bool | None = None,
        **kwargs: Any,
    ) -> SyncShellSession:
        """Открыть интерактивную stateful PTY shell-сессию (синхронно)."""
        async_session = self._run_coro(
            self._async_conn.open_shell(
                term_type=term_type,
                term_size=term_size,
                init_posix=init_posix,
                **kwargs,
            )
        )
        return SyncShellSession(async_session, self)

    def diagnostic_session(
        self,
        config: DiagnosticConfig | Mapping[str, Any] | str | Path | None = None,
        *,
        spec: FactSpec | Mapping[str, Any] | str | Path | None = None,
        streams: Sequence[StreamSourceSpec | Mapping[str, Any] | str] | None = None,
        local_dir: str | Path | None = None,
        archive_path: str | Path | None = None,
        archive_format: Literal["tar.gz", "zip", "none"] | None = None,
        forward_to: SyncConnection | Connection | str | None = None,
        forward_remote_dir: str | None = None,
        fsync_realtime: bool | None = None,
        gather_pre_facts: bool | None = None,
        gather_post_facts: bool | None = None,
    ) -> SyncDiagnosticSession:
        """Открыть комплексную диагностическую сессию (синхронный контекстный менеджер)."""
        async_fwd: Connection | str | None = (
            forward_to._async_conn
            if isinstance(forward_to, SyncConnection)
            else forward_to
        )
        async_sess = self._async_conn.diagnostic_session(
            config=config,
            spec=spec,
            streams=streams,
            local_dir=local_dir,
            archive_path=archive_path,
            archive_format=archive_format,
            forward_to=async_fwd,
            forward_remote_dir=forward_remote_dir,
            fsync_realtime=fsync_realtime,
            gather_pre_facts=gather_pre_facts,
            gather_post_facts=gather_post_facts,
        )
        return SyncDiagnosticSession(async_sess, self)

    def use_cassette(
        self,
        path: str | Path,
        *,
        mode: Any = "once",
        match_on: Sequence[Literal["command", "cwd", "sudo"]] = (
            "command",
            "cwd",
            "sudo",
        ),
        normalize_temp: bool = True,
        allow_playback_repeats: bool = True,
        mask_secrets: bool = True,
    ) -> Any:
        """Синхронный контекстный менеджер записи и воспроизведения кассет взаимодействий."""
        from ..transports.replay import SyncCassetteContext

        async_ctx = self._async_conn.use_cassette(
            path,
            mode=mode,
            match_on=match_on,
            normalize_temp=normalize_temp,
            allow_playback_repeats=allow_playback_repeats,
            mask_secrets=mask_secrets,
        )
        return SyncCassetteContext(async_ctx, self)

    def close(self) -> None:
        """Закрыть подключение и освободить ресурсы фонового event loop."""
        cleanup = self._async_conn.close() if self._async_conn else None
        self._portal.close(cleanup_coro=cleanup)

    def __enter__(self) -> Self:
        self._portal.reopen()
        self._run_coro(self._async_conn.transport.connect())
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
