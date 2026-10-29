# src/uniconn/core/connection.py
"""Фасад Connection для работы с удалёнными и локальными хостами."""

from __future__ import annotations

import contextlib
import logging
import warnings
from collections.abc import AsyncIterator, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self

from pydantic import SecretStr
from tenacity import wait_exponential_jitter

from .._logging import log_event
from ..config.inventory import InventoryLoader
from ..config.models import ConnectionConfig
from ..result import Result
from ..services.facts import FactCollector
from ..services.facts_models import FactSpec, HostFacts
from ..services.files import FileOperationsService
from ..services.provisioning import StateManagementService
from ..services.templates import render_template as render_template
from ..services.tunnels import TunnelService
from ..transports.base import BaseTransport
from .context import CwdContext, EnvContext, ExecutionContext, TempDirContext
from .factories import (
    _resolve_circuit_breaker,
    _resolve_rate_limiter,
    build_from_config,
    build_from_dict,
    build_from_file,
    build_from_inventory,
    build_from_uri,
    clone_connection,
    open_cassette_context,
    open_diagnostic_session,
    with_overrides_connection,
)
from .pipeline import CommandPipeline, CommandRequest, HookCallback, HookEvent, format_command
from .resilience import CircuitBreaker, RateLimiter
from .scripts import ScriptExecutionManager, run_script
from .shell_facade import (
    ObserverContext,
    OperationObserver,
    expect_command,
    open_shell_session,
    raw_open_shell,
)
from .temp import HostTempManager, create_temp_dir, remove_temp_dir, temp_dir
from .waiters import ping_connection, wait_for_connection, wait_for_path, wait_for_port

if TYPE_CHECKING:
    from ..sync.connection import SyncConnection

logger = logging.getLogger(__name__)
_CwdContext = CwdContext
_EnvContext = EnvContext
_TempDirContext = TempDirContext
_format_command = format_command
_parse_inventory_data = InventoryLoader.parse_data
_wait_exponential_jitter = wait_exponential_jitter


class Connection:
    """Основной класс-фасад для работы с удалёнными и локальными хостами."""

    def __init__(
        self,
        transport: BaseTransport,
        config: ConnectionConfig,
        retry_attempts: int = 3,
        logger: logging.Logger | None = None,
        dry_run: bool = False,
        before_run: Sequence[HookCallback] | None = None,
        after_run: Sequence[HookCallback] | None = None,
        on_error: Sequence[HookCallback] | None = None,
        rate_limit: float | RateLimiter | None = None,
        circuit_breaker: CircuitBreaker | bool | None = None,
    ) -> None:
        self._transport = transport
        self._config = config
        self._retry_attempts = retry_attempts
        self._logger = logger or logging.getLogger(__name__)
        self._dry_run = dry_run
        self._rate_limiter = _resolve_rate_limiter(rate_limit, config.options)
        self._circuit_breaker = _resolve_circuit_breaker(circuit_breaker, config.options)
        self._context = ExecutionContext()
        self._cwd_stack = self._context.cwd_stack
        self._env_stack = self._context.env_stack
        self._hooks: dict[HookEvent, list[HookCallback]] = {
            "before_run": list(before_run or []),
            "after_run": list(after_run or []),
            "on_error": list(on_error or []),
        }
        self._operation_observers: list[Any] = []
        self._pipeline = CommandPipeline(self)
        self.files = FileOperationsService(self)
        self.state = StateManagementService(self)
        self.tunnels = TunnelService(self)
        self._facts_collector = FactCollector(self)

    @property
    def transport(self) -> BaseTransport:
        return self._transport

    def swap_transport(self, new_transport: BaseTransport) -> BaseTransport:
        prev, self._transport = self._transport, new_transport
        return prev

    @property
    def context(self) -> ExecutionContext:
        return self._context

    @property
    def logger(self) -> logging.Logger:
        return self._logger

    @property
    def retry_attempts(self) -> int:
        return self._retry_attempts

    @property
    def dry_run(self) -> bool:
        return self._dry_run

    @property
    def is_dry_run(self) -> bool:
        warnings.warn(
            "Connection.is_dry_run is deprecated, use Connection.dry_run instead",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._dry_run

    def get_hooks(self, event: HookEvent) -> list[HookCallback]:
        return self._hooks.get(event, [])

    @property
    def operation_observers(self) -> list[OperationObserver]:
        return self._operation_observers

    def add_operation_observer(self, observer: OperationObserver) -> None:
        if observer not in self._operation_observers:
            self._operation_observers.append(observer)

    def remove_operation_observer(self, observer: OperationObserver) -> None:
        with contextlib.suppress(ValueError):
            self._operation_observers.remove(observer)

    def using_observer(self, observer: OperationObserver) -> ObserverContext:
        return ObserverContext(self, observer)

    @property
    def pipeline(self) -> CommandPipeline:
        return self._pipeline

    @property
    def rate_limiter(self) -> RateLimiter | None:
        return self._rate_limiter

    @rate_limiter.setter
    def rate_limiter(self, value: float | RateLimiter | None) -> None:
        if isinstance(value, RateLimiter) or value is None:
            self._rate_limiter = value
        elif isinstance(value, int | float) and not isinstance(value, bool):
            self._rate_limiter = RateLimiter(float(value)) if value > 0 else None

    @property
    def circuit_breaker(self) -> CircuitBreaker | None:
        return self._circuit_breaker

    @circuit_breaker.setter
    def circuit_breaker(self, value: CircuitBreaker | None) -> None:
        self._circuit_breaker = value

    @property
    def _cached_facts(self) -> HostFacts | None:
        return self._facts_collector.cached

    @_cached_facts.setter
    def _cached_facts(self, value: HostFacts | None) -> None:
        self._facts_collector.cached = value

    # ─── Фабрики, клонирование и контекстные менеджеры ─────────────

    from_uri = classmethod(build_from_uri)
    from_config = classmethod(build_from_config)
    from_dict = classmethod(build_from_dict)
    from_file = classmethod(build_from_file)
    from_inventory = classmethod(build_from_inventory)
    copy = clone_connection
    with_overrides = with_overrides_connection

    def cd(self, path: str | Path) -> CwdContext:
        return self._context.cd(path)

    def env(self, mapping: dict[str, str] | None = None, **env_vars: str) -> EnvContext:
        return self._context.env(mapping, **env_vars)

    @property
    def current_cwd(self) -> str | None:
        return self._context.current_cwd

    @property
    def current_env(self) -> dict[str, str]:
        return self._context.current_env

    def add_hook(self, event: HookEvent, callback: HookCallback) -> Self:
        if event not in self._hooks:
            raise ValueError(
                f"Unknown hook event: {event!r}. Expected 'before_run', 'after_run', or 'on_error'"
            )
        self._hooks[event].append(callback)
        return self

    temp_dir = temp_dir
    _create_temp_dir = create_temp_dir
    _remove_temp_dir = remove_temp_dir
    use_cassette = open_cassette_context

    # ─── Выполнение команд (через CommandPipeline) ─────────────────

    async def run(
        self,
        command: str | Sequence[str],
        timeout: float | None = None,
        raise_on_error: bool = False,
        input: str | bytes | None = None,
        sudo: bool = False,
        sudo_user: str | None = None,
        sudo_password: str | SecretStr | None = None,
        sensitive: bool = False,
        dry_run: bool | None = None,
        **kwargs: Any,
    ) -> Result:
        """Выполнить команду на хосте через конвейер ``CommandPipeline``."""
        cmd_str = format_command(command)
        req = CommandRequest(
            raw_command=command,
            command=cmd_str,
            exec_command=cmd_str,
            timeout=timeout,
            raise_on_error=raise_on_error,
            input_data=input,
            sudo=sudo,
            sudo_user=sudo_user,
            sudo_password=sudo_password,
            sensitive=sensitive,
            dry_run=self._dry_run if dry_run is None else dry_run,
            output_format="text",
            transport_kwargs=dict(kwargs),
        )
        return await self._pipeline.execute(req)

    async def run_bytes(
        self,
        command: str | Sequence[str],
        timeout: float | None = None,
        raise_on_error: bool = False,
        input: str | bytes | None = None,
        sudo: bool = False,
        sudo_user: str | None = None,
        sudo_password: str | SecretStr | None = None,
        sensitive: bool = False,
        dry_run: bool | None = None,
        **kwargs: Any,
    ) -> bytes:
        """Выполнить команду через конвейер ``CommandPipeline`` и вернуть сырой байтовый вывод (``bytes``)."""
        effective_dry_run = self._dry_run if dry_run is None else dry_run
        if effective_dry_run:
            return b""
        cmd_str = format_command(command)
        req = CommandRequest(
            raw_command=command,
            command=cmd_str,
            exec_command=cmd_str,
            timeout=timeout,
            raise_on_error=raise_on_error,
            input_data=input,
            sudo=sudo,
            sudo_user=sudo_user,
            sudo_password=sudo_password,
            sensitive=sensitive,
            dry_run=effective_dry_run,
            output_format="bytes",
            transport_kwargs=dict(kwargs),
        )
        return (await self._pipeline.execute(req)).raw_bytes

    async def run_commands(
        self, commands: Sequence[str | Sequence[str]], stop_on_error: bool = True, **kwargs: Any
    ) -> list[Result]:
        """Последовательно выполнить список команд на хосте."""
        results: list[Result] = []
        for command in commands:
            result = await self.run(command, **kwargs)
            results.append(result)
            if stop_on_error and not result.ok:
                log_event(
                    self._logger,
                    logging.WARNING,
                    "command.batch_stopped",
                    f"run_commands: остановка на команде {command!r} (exit_code={result.exit_code})",
                    host=self._config.host,
                    command=format_command(command),
                    exit_code=result.exit_code,
                )
                break
        return results

    async def _raw_stream(
        self, command: str | Sequence[str], timeout: float | None = None, **kwargs: Any
    ) -> AsyncIterator[str]:
        cmd_str = format_command(command)
        self._context.apply_to_kwargs(kwargs)
        if not self._transport.is_connected:
            await self._transport.connect()
        async for line in self._transport.stream(cmd_str, timeout=timeout or self._config.timeout, **kwargs):
            yield line

    async def stream(
        self, command: str | Sequence[str], timeout: float | None = None, **kwargs: Any
    ) -> AsyncIterator[str]:
        """Потоковое получение вывода команды."""
        gen = self._raw_stream(command, timeout=timeout, **kwargs)
        for obs in self._operation_observers:
            gen = obs.observe_stream(self, command, gen)
        async for line in gen:
            yield line

    async def close(self) -> None:
        await self._transport.disconnect()

    async def is_alive(self, timeout: float | None = None) -> bool:
        return await self._transport.ping(timeout=timeout)

    # ─── Ожидание, скрипты, Shell, факты и диагностика ─────────────

    ping = ping_connection
    wait_for_connection = wait_for_connection
    wait_for_port = wait_for_port
    wait_for_path = wait_for_path
    run_script = run_script
    expect = expect_command
    _raw_open_shell = raw_open_shell
    open_shell = open_shell_session
    diagnostic_session = open_diagnostic_session

    async def gather_facts(
        self,
        refresh: bool = False,
        timeout: float | None = None,
        spec: FactSpec | Mapping[str, Any] | str | Path | None = None,
    ) -> HostFacts:
        return await self._facts_collector.gather(refresh=refresh, timeout=timeout, spec=spec)

    async def __aenter__(self) -> Self:
        await self._transport.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self._transport.disconnect()

    def to_sync(self) -> SyncConnection:
        from ..sync.connection import SyncConnection

        return SyncConnection(self)

    @property
    def config(self) -> ConnectionConfig:
        return self._config

    @property
    def transport_name(self) -> str:
        return self._transport.name


__all__ = [
    "Connection",
    "HostTempManager",
    "ObserverContext",
    "OperationObserver",
    "ScriptExecutionManager",
    "_resolve_circuit_breaker",
    "_resolve_rate_limiter",
    "format_command",
    "render_template",
    "wait_exponential_jitter",
]
