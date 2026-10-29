# src/uniconn/sync/connection.py
"""Синхронная обёртка над async Connection на базе ``EventLoopPortal`` и ``ParamSpec``-дескрипторов."""

from __future__ import annotations

import logging
import warnings
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Self

from ..config.models import ConnectionConfig
from ..core.bridge import (
    EventLoopPortal,
    SyncProxyMixin,
    sync_clone_method,
    sync_context,
    sync_factory,
    sync_iter,
    sync_list_factory,
    sync_method,
)
from ..core.connection import Connection, ObserverContext, OperationObserver
from ..core.context import CwdContext, EnvContext, ExecutionContext
from ..core.pipeline import CommandPipeline, HookCallback, HookEvent
from ..core.resilience import CircuitBreaker, RateLimiter
from ..services.facts_models import FactSpec
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
    """Синхронная обёртка над async Connection на базе ``EventLoopPortal``.

    Предоставляет ядро синхронного выполнения команд и интерактивных сессий,
    а также модульные доменные пространства имён:
        - ``sync_conn.files`` (``SyncFileOperationsService``)
        - ``sync_conn.state`` (``SyncStateManagementService``)
        - ``sync_conn.tunnels`` (``SyncTunnelService``)
    """

    def __init__(self, async_conn: Connection) -> None:
        self._async_conn = async_conn
        self._async_target = async_conn
        cfg_timeout = getattr(getattr(async_conn, "config", None), "timeout", None)
        default_timeout = (
            float(cfg_timeout) if isinstance(cfg_timeout, (int, float)) else None
        )
        self._portal = EventLoopPortal(
            owner_name="SyncConnection",
            default_timeout=default_timeout,
        )
        self.files = SyncFileOperationsService(self)
        self.state = SyncStateManagementService(self)
        self.tunnels = SyncTunnelService(self)

    # ─── Фабричные методы и клонирование (ParamSpec-дескрипторы) ───

    from_uri = sync_factory(Connection.from_uri)
    from_config = sync_factory(Connection.from_config)
    from_dict = sync_factory(Connection.from_dict)
    from_file = sync_list_factory(Connection.from_file)
    from_inventory = sync_factory(Connection.from_inventory)
    copy = sync_clone_method(Connection.copy)
    with_overrides = sync_clone_method(Connection.with_overrides)

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
    def dry_run(self) -> bool:
        """Включён ли режим ``dry_run`` для данного подключения."""
        return self._async_conn.dry_run

    @property
    def is_dry_run(self) -> bool:
        """Устаревший псевдоним для ``sync_conn.dry_run``."""
        warnings.warn(
            "SyncConnection.is_dry_run is deprecated, use SyncConnection.dry_run instead",
            DeprecationWarning,
            stacklevel=2,
        )
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

    def remove_operation_observer(self, observer: OperationObserver) -> Self:
        """Удалить ранее зарегистрированного наблюдателя сквозных операций."""
        self._async_conn.remove_operation_observer(observer)
        return self

    def using_observer(self, observer: OperationObserver) -> ObserverContext:
        """Контекстный менеджер временной регистрации наблюдателя с гарантированным удалением."""
        return self._async_conn.using_observer(observer)

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
