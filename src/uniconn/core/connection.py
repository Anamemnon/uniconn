# src/uniconn/core/connection.py
"""Фасад Connection для работы с удалёнными и локальными хостами.

Делегирует выполнение команд конвейеру ``CommandPipeline``, а доменные
операции — специализированным сервисам:
- ``conn.files`` (``FileOperationsService``)
- ``conn.state`` (``StateManagementService``)
- ``conn.tunnels`` (``TunnelService``)
- ``conn._facts_collector`` (``FactCollector``)
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import shlex
import shutil
import tempfile
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Protocol, Self, runtime_checkable

from pydantic import SecretStr
from tenacity import wait_exponential_jitter

from .._logging import log_event
from ..config.inventory import InventoryLoader
from ..config.models import ConnectionConfig
from ..plugins._loader import TransportLoader
from ..result import PingResult, Result, SyncResult
from ..services.facts import FactCollector
from ..services.facts_models import FactSpec, HostFacts
from ..services.files import FileOperationsService
from ..services.provisioning import StateManagementService
from ..services.templates import render_template as render_template
from ..services.tunnels import TunnelService
from ..shell.session import ShellSession
from ..transports.base import BaseTransport
from .bridge import async_delegate, context_delegate
from .context import CwdContext, EnvContext, ExecutionContext, TempDirContext
from .pipeline import (
    CircuitBreakerMiddleware,
    CommandPipeline,
    CommandRequest,
    ContextMiddleware,
    DryRunMiddleware,
    HookCallback,
    HookEvent,
    HookMiddleware,
    ObservabilityMiddleware,
    RateLimitMiddleware,
    RetryMiddleware,
    SudoMiddleware,
    format_command,
)
from .resilience import CircuitBreaker, RateLimiter

if TYPE_CHECKING:
    from ..background._diagnostic import (
        DiagnosticConfig,
        DiagnosticSession,
        StreamSourceSpec,
    )
    from ..sync.connection import SyncConnection
    from ..transports.replay import CassetteContext

logger = logging.getLogger(__name__)

# Псевдонимы для обратной совместимости внутренних импортов
_CwdContext = CwdContext
_EnvContext = EnvContext
_TempDirContext = TempDirContext
_format_command = format_command
_parse_inventory_data = InventoryLoader.parse_data
_wait_exponential_jitter = wait_exponential_jitter

@runtime_checkable
class OperationObserver(Protocol):
    """Протокол наблюдателя сквозных операций (files, shell, stream)."""

    def observe_stream(
        self,
        conn: Any,
        command: Any,
        raw_gen: AsyncIterator[str],
        /,
    ) -> AsyncIterator[str]: ...

    async def observe_open_shell(
        self,
        conn: Any,
        raw_fn: Callable[..., Awaitable[ShellSession]],
        /,
        term_type: str = "xterm",
        term_size: tuple[int, int] = (80, 24),
        init_posix: bool | None = None,
        **kwargs: Any,
    ) -> ShellSession: ...

    async def observe_upload(
        self,
        conn: Any,
        raw_fn: Callable[..., Awaitable[None]],
        local_path: str | Path,
        remote_path: str | Path,
        /,
        recurse: bool = False,
        **kwargs: Any,
    ) -> None: ...

    async def observe_download(
        self,
        conn: Any,
        raw_fn: Callable[..., Awaitable[None]],
        remote_path: str | Path,
        local_path: str | Path,
        /,
        recurse: bool = False,
        **kwargs: Any,
    ) -> None: ...

    async def observe_read_file(
        self,
        conn: Any,
        raw_fn: Callable[..., Awaitable[str | bytes]],
        remote_path: str | Path,
        /,
        encoding: str | None = "utf-8",
    ) -> str | bytes: ...

    async def observe_write_file(
        self,
        conn: Any,
        raw_fn: Callable[..., Awaitable[None]],
        remote_path: str | Path,
        content: str | bytes,
        /,
        mode: int | None = None,
        encoding: str = "utf-8",
    ) -> None: ...

    async def observe_sync_dir(
        self,
        conn: Any,
        raw_fn: Callable[..., Awaitable[SyncResult]],
        /,
        local_dir: str | Path,
        remote_dir: str | Path,
        delete: bool = False,
        exclude: Any = None,
        mtime_tolerance: float = 1.0,
        dry_run: bool | None = None,
    ) -> SyncResult: ...

    async def observe_shell_execute(
        self,
        conn: Any,
        raw_fn: Callable[..., Awaitable[Result]],
        command: Any,
        /,
        timeout: float | None = None,
    ) -> Result: ...

    async def observe_shell_expect(
        self,
        conn: Any,
        raw_fn: Callable[..., Awaitable[Result]],
        /,
        command: Any = None,
        patterns: Any = None,
        final_prompt: str | None = None,
        timeout: float | None = None,
        line_ending: str = "\n",
        sensitive: bool = False,
        allow_eof: bool = True,
    ) -> Result: ...


def _resolve_rate_limiter(
    rate_limit: float | RateLimiter | None,
    options: Mapping[str, Any],
) -> RateLimiter | None:
    """Создать или вернуть экземпляр ``RateLimiter`` из параметра или ``config.options``."""
    if isinstance(rate_limit, RateLimiter):
        return rate_limit
    if isinstance(rate_limit, int | float) and not isinstance(rate_limit, bool):
        return RateLimiter(float(rate_limit))
    opt_rate = options.get("rate_limit")
    if isinstance(opt_rate, int | float) and not isinstance(opt_rate, bool) and opt_rate > 0:
        return RateLimiter(float(opt_rate))
    return None


def _resolve_circuit_breaker(
    circuit_breaker: CircuitBreaker | bool | None,
    options: Mapping[str, Any],
) -> CircuitBreaker | None:
    """Создать или вернуть экземпляр ``CircuitBreaker`` из параметра или ``config.options``."""
    if isinstance(circuit_breaker, CircuitBreaker):
        return circuit_breaker
    if circuit_breaker is False:
        return None
    has_opt_cb = (
        options.get("circuit_breaker") is True
        or "circuit_breaker_threshold" in options
    )
    if circuit_breaker is True or (circuit_breaker is None and has_opt_cb):
        threshold = int(options.get("circuit_breaker_threshold", 5))
        recovery = float(options.get("circuit_breaker_recovery_timeout", 30.0))
        return CircuitBreaker(
            failure_threshold=threshold,
            recovery_timeout=recovery,
        )
    return None


class Connection:
    """Основной класс-фасад для работы с удалёнными и локальными хостами.

    Предоставляет как плоские фасадные методы (``conn.run``, ``conn.read_file``,
    ``conn.ensure_package``, ``conn.forward_local_port``), так и модульные
    доменные пространства имён:
        - ``conn.files`` — файловые операции, SFTP, шаблоны и ``sync_dir``
        - ``conn.state`` — идемпотентное управление пакетами, сервисами и строками конфигов
        - ``conn.tunnels`` — сетевой проброс портов (Local/Remote Port Forwarding)
    """

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
        self._circuit_breaker = _resolve_circuit_breaker(
            circuit_breaker, config.options
        )
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
        """Текущий экземпляр транспорта подключения."""
        return self._transport

    def swap_transport(self, new_transport: BaseTransport) -> BaseTransport:
        """Безопасно заменить активный транспорт (используется в ``use_cassette``) и вернуть прежний."""
        prev = self._transport
        self._transport = new_transport
        return prev

    @property
    def context(self) -> ExecutionContext:
        """Контекст выполнения (стек рабочих директорий и переменных окружения)."""
        return self._context

    @property
    def logger(self) -> logging.Logger:
        """Логгер подключения."""
        return self._logger

    @property
    def retry_attempts(self) -> int:
        """Количество повторных попыток выполнения команд при сетевых сбоях."""
        return self._retry_attempts

    @property
    def is_dry_run(self) -> bool:
        """Признак активного режима ``dry_run``."""
        return self._dry_run

    def get_hooks(self, event: HookEvent) -> list[HookCallback]:
        """Вернуть список зарегистрированных хуков для указанного события."""
        return self._hooks.get(event, [])

    @property
    def operation_observers(self) -> list[OperationObserver]:
        """Список зарегистрированных наблюдателей операций (например, ``OtelTracingHook``)."""
        return self._operation_observers

    def add_operation_observer(self, observer: OperationObserver) -> None:
        """Зарегистрировать наблюдатель сквозных операций (files, shell, stream) без monkey-patching."""
        if observer not in self._operation_observers:
            self._operation_observers.append(observer)

    @property
    def pipeline(self) -> CommandPipeline:
        """Конвейер выполнения команд (Middleware Pipeline)."""
        return self._pipeline

    @property
    def rate_limiter(self) -> RateLimiter | None:
        """Ограничитель частоты команд (Token Bucket), если настроен."""
        return self._rate_limiter

    @rate_limiter.setter
    def rate_limiter(self, value: float | RateLimiter | None) -> None:
        if isinstance(value, RateLimiter) or value is None:
            self._rate_limiter = value
        elif isinstance(value, int | float) and not isinstance(value, bool):
            self._rate_limiter = RateLimiter(float(value)) if value > 0 else None

    @property
    def circuit_breaker(self) -> CircuitBreaker | None:
        """Автоматический предохранитель (Circuit Breaker), если настроен."""
        return self._circuit_breaker

    @circuit_breaker.setter
    def circuit_breaker(self, value: CircuitBreaker | None) -> None:
        self._circuit_breaker = value

    @property
    def _cached_facts(self) -> HostFacts | None:
        """Кэшированный экземпляр HostFacts."""
        return self._facts_collector.cached

    @_cached_facts.setter
    def _cached_facts(self, value: HostFacts | None) -> None:
        self._facts_collector.cached = value

    # ─── Фабричные методы ──────────────────────────────────────────

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
        """Создать подключение из URI строки."""
        config = ConnectionConfig.from_uri(uri)
        transport_class = TransportLoader.get(config.transport)
        transport = transport_class(config)
        return cls(
            transport,
            config,
            retry_attempts,
            logger,
            dry_run=dry_run,
            before_run=before_run,
            after_run=after_run,
            on_error=on_error,
            rate_limit=rate_limit,
            circuit_breaker=circuit_breaker,
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
        """Создать подключение из конфигурации."""
        transport_class = TransportLoader.get(config.transport)
        transport = transport_class(config)
        return cls(
            transport,
            config,
            retry_attempts,
            logger,
            dry_run=dry_run,
            before_run=before_run,
            after_run=after_run,
            on_error=on_error,
            rate_limit=rate_limit,
            circuit_breaker=circuit_breaker,
        )

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
        retry_attempts: int = 3,
        logger: logging.Logger | None = None,
        dry_run: bool = False,
    ) -> Self:
        """Создать подключение из словаря."""
        retry = data.get("retry_attempts", retry_attempts)
        effective_dry_run = bool(data.get("dry_run", dry_run))
        rate_limit = data.get("rate_limit")
        circuit_breaker = data.get("circuit_breaker")
        if "uri" in data:
            conn = cls.from_uri(
                str(data["uri"]),
                retry_attempts=retry,
                logger=logger,
                dry_run=effective_dry_run,
                rate_limit=rate_limit,
                circuit_breaker=circuit_breaker,
            )
            overrides = {
                k: v
                for k, v in data.items()
                if k
                not in (
                    "uri",
                    "transport",
                    "retry_attempts",
                    "logger",
                    "dry_run",
                    "name",
                    "groups",
                    "rate_limit",
                    "circuit_breaker",
                )
                and (
                    k != "host"
                    or conn.config.host is None
                    or (
                        conn.config.transport == "local"
                        and conn.config.host == "localhost"
                    )
                )
            }
            if overrides:
                conn = conn.with_overrides(**overrides)
            return conn
        config = ConnectionConfig(
            **{
                k: v
                for k, v in data.items()
                if k
                not in (
                    "retry_attempts",
                    "logger",
                    "dry_run",
                    "name",
                    "groups",
                    "rate_limit",
                    "circuit_breaker",
                )
            }
        )
        transport_class = TransportLoader.get(config.transport)
        transport = transport_class(config)
        return cls(
            transport,
            config,
            retry,
            logger,
            dry_run=effective_dry_run,
            rate_limit=rate_limit,
            circuit_breaker=circuit_breaker,
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
        """Создать подключения из JSON/YAML файла (включая инвентарь с хостами и группами)."""
        entries = InventoryLoader.load_file(path, host=host, group=group)
        return [cls.from_dict(data, retry_attempts, logger) for data in entries]

    @classmethod
    def from_inventory(
        cls,
        path: str | Path,
        host: str,
        retry_attempts: int = 3,
        logger: logging.Logger | None = None,
    ) -> Self:
        """Создать одиночное подключение по имени хоста из инвентарного файла (YAML/JSON)."""
        conns = cls.from_file(
            path,
            retry_attempts=retry_attempts,
            logger=logger,
            host=host,
        )
        return conns[0]

    # ─── Клонирование и модификация ────────────────────────────────

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
        """Создать копию подключения с возможностью изменения параметров."""
        new_config = ConnectionConfig(
            transport=self._config.transport,
            host=host if host is not None else self._config.host,
            port=port if port is not None else self._config.port,
            username=username if username is not None else self._config.username,
            password=(
                SecretStr(password)
                if isinstance(password, str)
                else password
                if password is not None
                else self._config.password
            ),
            key_file=key_file if key_file is not None else self._config.key_file,
            passphrase=(
                SecretStr(passphrase)
                if isinstance(passphrase, str)
                else passphrase
                if passphrase is not None
                else self._config.passphrase
            ),
            ssh_config=(
                ssh_config if ssh_config is not None else self._config.ssh_config
            ),
            timeout=timeout if timeout is not None else self._config.timeout,
            options=options if options is not None else self._config.options,
        )
        transport_class = TransportLoader.get(new_config.transport)
        transport = transport_class(new_config)
        new_conn = type(self)(
            transport,
            new_config,
            (
                self._retry_attempts
                if retry_attempts is None
                else retry_attempts
            ),
            logger or self._logger,
            dry_run=self._dry_run if dry_run is None else dry_run,
            before_run=self._hooks["before_run"],
            after_run=self._hooks["after_run"],
            on_error=self._hooks["on_error"],
            rate_limit=(
                self._rate_limiter if rate_limit is None else rate_limit
            ),
            circuit_breaker=(
                self._circuit_breaker
                if circuit_breaker is None
                else circuit_breaker
            ),
        )
        for obs in self._operation_observers:
            attach_fn = getattr(obs, "_attach_connection", None)
            if callable(attach_fn):
                attach_fn(new_conn)
            else:
                new_conn.add_operation_observer(obs)

        default_mw_types = (
            ContextMiddleware,
            SudoMiddleware,
            HookMiddleware,
            DryRunMiddleware,
            ObservabilityMiddleware,
            CircuitBreakerMiddleware,
            RateLimitMiddleware,
            RetryMiddleware,
        )
        existing_mw_types = tuple(type(m) for m in new_conn.pipeline.middlewares)
        for mw in self._pipeline.middlewares:
            if not isinstance(mw, default_mw_types) and not isinstance(
                mw, existing_mw_types
            ):
                new_conn.pipeline.add_middleware(mw)
        return new_conn

    def with_overrides(self, **overrides: Any) -> Self:
        """Создать копию подключения с переопределёнными параметрами."""
        return self.copy(
            host=overrides.get("host"),
            port=overrides.get("port"),
            username=overrides.get("username"),
            password=overrides.get("password"),
            key_file=overrides.get("key_file"),
            passphrase=overrides.get("passphrase"),
            ssh_config=overrides.get("ssh_config"),
            timeout=overrides.get("timeout"),
            options=overrides.get("options"),
            retry_attempts=overrides.get("retry_attempts"),
            logger=overrides.get("logger"),
            dry_run=overrides.get("dry_run"),
            rate_limit=overrides.get("rate_limit"),
            circuit_breaker=overrides.get("circuit_breaker"),
        )

    # ─── Контекстные менеджеры cd / env / temp_dir и Hooks ─────────

    def cd(self, path: str | Path) -> CwdContext:
        """Контекстный менеджер для временной смены рабочей директории."""
        return self._context.cd(path)

    def env(
        self, mapping: dict[str, str] | None = None, **env_vars: str
    ) -> EnvContext:
        """Контекстный менеджер для временной установки переменных окружения."""
        return self._context.env(mapping, **env_vars)

    @property
    def current_cwd(self) -> str | None:
        """Текущая рабочая директория из активного стека ``conn.cd()``."""
        return self._context.current_cwd

    @property
    def current_env(self) -> dict[str, str]:
        """Текущий объединённый словарь переменных окружения из стека ``conn.env()``."""
        return self._context.current_env

    def add_hook(self, event: HookEvent, callback: HookCallback) -> Self:
        """Зарегистрировать lifecycle-хук (``before_run``, ``after_run``, ``on_error``)."""
        if event not in self._hooks:
            raise ValueError(
                f"Unknown hook event: {event!r}. "
                "Expected 'before_run', 'after_run', or 'on_error'"
            )
        self._hooks[event].append(callback)
        return self

    def temp_dir(
        self,
        prefix: str = "uniconn_",
        suffix: str = "",
        dir: str | Path | None = None,
    ) -> TempDirContext:
        """Асинхронный контекстный менеджер временной директории на хосте."""
        return TempDirContext(self, prefix=prefix, suffix=suffix, dir=dir)

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
    ) -> CassetteContext:
        """Асинхронный контекстный менеджер записи и воспроизведения кассет взаимодействий."""
        from ..transports.replay import CassetteContext

        return CassetteContext(
            self,
            path,
            mode=mode,
            match_on=match_on,
            normalize_temp=normalize_temp,
            allow_playback_repeats=allow_playback_repeats,
            mask_secrets=mask_secrets,
        )

    async def _create_temp_dir(
        self,
        prefix: str = "uniconn_",
        suffix: str = "",
        dir: str | None = None,
    ) -> str:
        """Создать временную директорию на хосте и вернуть путь к ней."""
        base_dir = dir or "/tmp"
        if self._dry_run:
            return f"{base_dir.rstrip('/')}/{prefix}dryrun{suffix}"

        if self.transport_name == "local":
            return tempfile.mkdtemp(suffix=suffix, prefix=prefix, dir=dir)

        template = f"{base_dir.rstrip('/')}/{prefix}XXXXXX{suffix}"
        res = await self.run(["mktemp", "-d", template], raise_on_error=True)
        return res.text

    async def _remove_temp_dir(self, path: str) -> None:
        """Удалить временную директорию на хосте."""
        if self._dry_run or not path:
            return
        if self.transport_name == "local":
            shutil.rmtree(path, ignore_errors=True)
            return
        await self.run(["rm", "-rf", path])

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
        effective_dry_run = self._dry_run if dry_run is None else dry_run
        request = CommandRequest(
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
            transport_kwargs=dict(kwargs),
        )
        return await self._pipeline.execute(request)

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
        cmd_str = format_command(command)
        effective_dry_run = self._dry_run if dry_run is None else dry_run
        if effective_dry_run:
            return b""
        request = CommandRequest(
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
            transport_kwargs=dict(kwargs),
        )

        async def _bytes_terminal_dispatch(req: CommandRequest) -> Result:
            t0 = time.monotonic()
            raw = await self._transport.run_bytes(
                req.exec_command,
                timeout=req.timeout,
                raise_on_error=req.raise_on_error,
                **req.transport_kwargs,
            )
            req.metadata["raw_bytes"] = raw
            return Result(
                exit_code=0,
                stdout=raw.decode("utf-8", errors="replace"),
                stderr="",
                duration=time.monotonic() - t0,
                command=req.command,
                host=self._config.host,
                sensitive=req.sensitive,
            )

        await self._pipeline.execute(
            request,
            terminal_handler=_bytes_terminal_dispatch,
        )
        return bytes(request.metadata.get("raw_bytes", b""))

    async def run_commands(
        self,
        commands: Sequence[str | Sequence[str]],
        stop_on_error: bool = True,
        **kwargs: Any,
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
                    f"run_commands: остановка на команде {command!r} "
                    f"(exit_code={result.exit_code})",
                    host=self._config.host,
                    command=format_command(command),
                    exit_code=result.exit_code,
                )
                break
        return results

    async def _raw_stream(
        self,
        command: str | Sequence[str],
        timeout: float | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        cmd_str = format_command(command)
        self._context.apply_to_kwargs(kwargs)
        if not self._transport.is_connected:
            await self._transport.connect()

        timeout = timeout or self._config.timeout
        async for line in self._transport.stream(cmd_str, timeout=timeout, **kwargs):
            yield line

    async def stream(
        self,
        command: str | Sequence[str],
        timeout: float | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Потоковое получение вывода команды."""
        gen = self._raw_stream(command, timeout=timeout, **kwargs)
        for obs in self._operation_observers:
            gen = obs.observe_stream(self, command, gen)
        async for line in gen:
            yield line

    async def close(self) -> None:
        """Закрыть подключение."""
        await self._transport.disconnect()

    async def is_alive(self, timeout: float | None = None) -> bool:
        """Проверить живость подключения."""
        return await self._transport.ping(timeout=timeout)

    async def ping(self, timeout: float | None = None) -> PingResult:
        """Проверить доступность хоста с измерением задержки (``latency_ms``)."""
        host = self._config.host or self._config.uri_safe or "localhost"
        transport = self.transport_name
        if self._dry_run:
            return PingResult(
                host=host,
                alive=True,
                latency_ms=0.0,
                transport=transport,
            )

        start = time.monotonic()
        try:
            if not self._transport.is_connected:
                await self._transport.connect()
            alive = await self._transport.ping(timeout=timeout)
            elapsed_ms = (time.monotonic() - start) * 1000.0
            return PingResult(
                host=host,
                alive=alive,
                latency_ms=elapsed_ms,
                transport=transport,
                error=None if alive else "Ping check returned False",
            )
        except Exception as exc:
            elapsed_ms = (time.monotonic() - start) * 1000.0
            return PingResult(
                host=host,
                alive=False,
                latency_ms=elapsed_ms,
                transport=transport,
                error=str(exc),
            )

    async def wait_for_connection(
        self,
        timeout: float = 120.0,
        interval: float = 2.0,
        delay: float = 0.0,
    ) -> PingResult:
        """Ожидать восстановления доступности хоста (например, после ``reboot``).

        Повторяет ``ping()`` с интервалом ``interval`` секунд до успешного ответа
        или истечения ``timeout`` (при таймауте выбрасывает ``TimeoutError``).
        """
        from ..exceptions import TimeoutError as UniconnTimeoutError

        if self._dry_run:
            return await self.ping(timeout=timeout)

        start = time.monotonic()
        deadline = start + timeout
        if delay > 0:
            await asyncio.sleep(delay)

        last_res: PingResult | None = None
        while True:
            remaining = deadline - time.monotonic()
            probe_timeout = max(0.5, min(interval * 2.0, max(0.5, remaining)))
            try:
                if not self._transport.is_connected:
                    with contextlib.suppress(Exception):
                        await self._transport.disconnect()
                last_res = await self.ping(timeout=probe_timeout)
                if last_res.alive:
                    return last_res
            except Exception as exc:
                last_res = PingResult(
                    host=self._config.host or "localhost",
                    alive=False,
                    latency_ms=0.0,
                    transport=self.transport_name,
                    error=str(exc),
                )

            now = time.monotonic()
            if now >= deadline:
                break
            await asyncio.sleep(min(interval, deadline - now))

        err_detail = last_res.error if last_res and last_res.error else "host unreachable"
        raise UniconnTimeoutError(
            f"Timed out in wait_for_connection after {timeout:.2f}s ({err_detail})",
            host=self._config.host,
        )

    async def wait_for_port(
        self,
        port: int,
        *,
        host: str | None = None,
        state: Literal["open", "closed"] = "open",
        check_from: Literal["remote", "local"] = "remote",
        timeout: float = 60.0,
        interval: float = 1.0,
        delay: float = 0.0,
    ) -> float:
        """Ожидать открытия (``open``) или закрытия (``closed``) TCP-порта.

        Параметр ``check_from`` задаёт точку проверки:
        - ``"remote"`` (по умолчанию): проверка выполняется изнутри целевого хоста;
        - ``"local"``: прямое TCP-подключение с локальной управляющей машины.
        Возвращает время ожидания в секундах (``float``).
        """
        from ..exceptions import TimeoutError as UniconnTimeoutError

        if self._dry_run:
            return 0.0

        start = time.monotonic()
        deadline = start + timeout
        if delay > 0:
            await asyncio.sleep(delay)

        if host is not None:
            target_host = host
        elif check_from == "local":
            target_host = self._config.host or "127.0.0.1"
        else:
            target_host = "127.0.0.1"

        port_num = int(port)

        while True:
            is_open = False
            if check_from == "local":
                probe_timeout = max(0.2, min(2.0, interval))
                try:
                    _reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(target_host, port_num),
                        timeout=probe_timeout,
                    )
                    writer.close()
                    with contextlib.suppress(Exception):
                        await writer.wait_closed()
                    is_open = True
                except Exception:
                    is_open = False
            else:
                q_host = shlex.quote(target_host)
                probe_cmd = (
                    f"python3 -c 'import socket,sys; s=socket.socket(); s.settimeout(1.5); "
                    f"sys.exit(0 if s.connect_ex(({target_host!r},{port_num}))==0 else 1)' 2>/dev/null "
                    f"|| nc -z -w 2 {q_host} {port_num} 2>/dev/null "
                    f"|| (echo >/dev/tcp/{q_host}/{port_num}) >/dev/null 2>&1"
                )
                with contextlib.suppress(Exception):
                    res = await self.run(probe_cmd, raise_on_error=False, dry_run=False)
                    is_open = res.ok

            if (state == "open" and is_open) or (state == "closed" and not is_open):
                return time.monotonic() - start

            now = time.monotonic()
            if now >= deadline:
                break
            await asyncio.sleep(min(interval, deadline - now))

        raise UniconnTimeoutError(
            f"Timed out in wait_for_port({target_host}:{port_num}, state={state!r}, "
            f"check_from={check_from!r}) after {timeout:.2f}s",
            host=self._config.host,
        )

    async def wait_for_path(
        self,
        remote_path: str | Path,
        *,
        state: Literal["present", "absent"] = "present",
        content_regex: str | None = None,
        timeout: float = 60.0,
        interval: float = 1.0,
        delay: float = 0.0,
        sudo: bool = False,
    ) -> float:
        """Ожидать появления (``present``) или удаления (``absent``) файла/директории/сокета.

        Если задан ``content_regex`` при ``state="present"``, дополнительно проверяет,
        что содержимое файла соответствует регулярному выражению.
        Возвращает время ожидания в секундах (``float``).
        """
        import re as _re

        from ..exceptions import TimeoutError as UniconnTimeoutError

        if self._dry_run:
            return 0.0

        start = time.monotonic()
        deadline = start + timeout
        if delay > 0:
            await asyncio.sleep(delay)

        path_str = str(remote_path)
        q_path = shlex.quote(path_str)
        compiled_re = _re.compile(content_regex) if content_regex is not None else None

        while True:
            exists = False
            with contextlib.suppress(Exception):
                if sudo:
                    chk = await self.run(
                        f"test -e {q_path}",
                        sudo=True,
                        raise_on_error=False,
                        dry_run=False,
                    )
                    exists = chk.ok
                else:
                    try:
                        exists = await self.exists(path_str)
                    except Exception:
                        chk = await self.run(
                            f"test -e {q_path}",
                            raise_on_error=False,
                            dry_run=False,
                        )
                        exists = chk.ok

            if state == "absent" and not exists:
                return time.monotonic() - start

            if state == "present" and exists:
                if compiled_re is None:
                    return time.monotonic() - start
                text_content: str | None = None
                with contextlib.suppress(Exception):
                    if sudo:
                        cat_res = await self.run(
                            f"cat {q_path}",
                            sudo=True,
                            raise_on_error=False,
                            dry_run=False,
                        )
                        if cat_res.ok:
                            text_content = cat_res.stdout
                    else:
                        raw = await self.read_file(path_str, encoding="utf-8")
                        text_content = (
                            raw if isinstance(raw, str) else raw.decode("utf-8", errors="replace")
                        )
                if text_content is not None and compiled_re.search(text_content):
                    return time.monotonic() - start

            now = time.monotonic()
            if now >= deadline:
                break
            await asyncio.sleep(min(interval, deadline - now))

        raise UniconnTimeoutError(
            f"Timed out in wait_for_path({path_str!r}, state={state!r}) after {timeout:.2f}s",
            host=self._config.host,
        )

    async def run_script(
        self,
        local_path: str | Path,
        args: Sequence[str] | None = None,
        *,
        interpreter: str | None = None,
        sudo: bool = False,
        sudo_user: str | None = None,
        sudo_password: str | SecretStr | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float | None = None,
        raise_on_error: bool = False,
        sensitive: bool = False,
        dry_run: bool | None = None,
    ) -> Result:
        """Загрузить локальный скрипт во временную директорию, выполнить и удалить."""
        script_path = Path(local_path)
        if not script_path.is_file():
            raise FileNotFoundError(f"Local script not found: {local_path}")

        effective_dry_run = self._dry_run if dry_run is None else dry_run
        async with self.temp_dir() as remote_dir:
            remote_script = f"{remote_dir.rstrip('/')}/{script_path.name}"
            if not effective_dry_run:
                await self.upload(str(script_path), remote_script)
                await self.chmod(remote_script, 0o700)

            if interpreter:
                cmd_parts: list[str] = [*shlex.split(interpreter), remote_script]
            else:
                cmd_parts = [remote_script]

            if args:
                cmd_parts.extend(str(a) for a in args)

            if env:
                with self.env(dict(env)):
                    return await self.run(
                        cmd_parts,
                        timeout=timeout,
                        raise_on_error=raise_on_error,
                        sudo=sudo,
                        sudo_user=sudo_user,
                        sudo_password=sudo_password,
                        sensitive=sensitive,
                        dry_run=dry_run,
                    )
            return await self.run(
                cmd_parts,
                timeout=timeout,
                raise_on_error=raise_on_error,
                sudo=sudo,
                sudo_user=sudo_user,
                sudo_password=sudo_password,
                sensitive=sensitive,
                dry_run=dry_run,
            )

    # ─── Файловые операции и шаблоны (делегация в conn.files) ──────

    upload = async_delegate("files", FileOperationsService.upload)
    download = async_delegate("files", FileOperationsService.download)
    read_file = async_delegate("files", FileOperationsService.read_file)
    write_file = async_delegate("files", FileOperationsService.write_file)
    checksum = async_delegate("files", FileOperationsService.checksum)
    exists = async_delegate("files", FileOperationsService.exists)
    mkdir = async_delegate("files", FileOperationsService.mkdir)
    chmod = async_delegate("files", FileOperationsService.chmod)
    stat = async_delegate("files", FileOperationsService.stat)
    listdir = async_delegate("files", FileOperationsService.listdir)
    remove_file = async_delegate("files", FileOperationsService.remove_file)
    write_template = async_delegate("files", FileOperationsService.write_template)
    sync_dir = async_delegate("files", FileOperationsService.sync_dir)

    # ─── Проброс портов (делегация в conn.tunnels) ─────────────────

    forward_local_port = context_delegate("tunnels", TunnelService.forward_local_port)
    forward_remote_port = context_delegate("tunnels", TunnelService.forward_remote_port)

    # ─── Интерактивный Shell и Expect ──────────────────────────────

    async def expect(
        self,
        command: str | Sequence[str],
        patterns: Mapping[str, str | SecretStr] | None = None,
        final_prompt: str | None = None,
        timeout: float | None = None,
        line_ending: str = "\n",
        sensitive: bool = False,
        term_type: str = "xterm",
        term_size: tuple[int, int] = (80, 24),
        **kwargs: Any,
    ) -> Result:
        """Выполнить интерактивную команду с декларативным сопоставлением regex-паттернов."""
        cmd_str = format_command(command)
        if self._dry_run:
            self._logger.info(
                f"[DRY-RUN] Skipping expect {cmd_str!r} on {self._config.uri_safe}"
            )
            return Result(
                exit_code=0,
                stdout="",
                stderr="",
                duration=0.0,
                command=cmd_str,
                host=self._config.host,
                sensitive=sensitive,
            )

        session = await self.open_shell(
            term_type=term_type,
            term_size=term_size,
            init_posix=False,
            **kwargs,
        )
        try:
            return await session.expect(
                command=cmd_str,
                patterns=patterns,
                final_prompt=final_prompt,
                timeout=timeout,
                line_ending=line_ending,
                sensitive=sensitive,
            )
        finally:
            await session.close()

    async def _raw_open_shell(
        self,
        term_type: str = "xterm",
        term_size: tuple[int, int] = (80, 24),
        init_posix: bool | None = None,
        **kwargs: Any,
    ) -> ShellSession:
        if not self._transport.is_connected:
            await self._transport.connect()

        proc = await self._transport.open_shell(
            term_type=term_type,
            term_size=term_size,
            **kwargs,
        )
        session = ShellSession(
            proc=proc,
            host=self._config.host,
            default_timeout=self._config.timeout,
            observers=list(self._operation_observers),
            conn=self,
        )
        should_init_posix = (
            (self.transport_name != "serial") if init_posix is None else init_posix
        )
        if should_init_posix:
            await session.initialize()
        else:
            session._initialized = True
        return session

    async def open_shell(
        self,
        term_type: str = "xterm",
        term_size: tuple[int, int] = (80, 24),
        init_posix: bool | None = None,
        **kwargs: Any,
    ) -> ShellSession:
        """Открыть интерактивную stateful PTY shell-сессию."""
        handler: Callable[..., Awaitable[ShellSession]] = self._raw_open_shell
        for obs in reversed(self._operation_observers):
            prev_handler = handler

            async def _step(
                *a: Any,
                _obs: Any = obs,
                _nxt: Callable[..., Awaitable[ShellSession]] = prev_handler,
                **kw: Any,
            ) -> ShellSession:
                return await _obs.observe_open_shell(self, _nxt, *a, **kw)

            handler = _step

        return await handler(
            term_type=term_type,
            term_size=term_size,
            init_posix=init_posix,
            **kwargs,
        )

    # ─── Факты о системе и идемпотентные операции (conn.state) ─────

    async def gather_facts(
        self,
        refresh: bool = False,
        timeout: float | None = None,
        spec: FactSpec | Mapping[str, Any] | str | Path | None = None,
    ) -> HostFacts:
        """Собрать системные факты о целевом хосте (базовые + декларативные источники ``FactSpec``)."""
        return await self._facts_collector.gather(
            refresh=refresh,
            timeout=timeout,
            spec=spec,
        )

    def diagnostic_session(
        self,
        config: DiagnosticConfig | Mapping[str, Any] | str | Path | None = None,
        *,
        spec: FactSpec | Mapping[str, Any] | str | Path | None = None,
        streams: Sequence[StreamSourceSpec | Mapping[str, Any] | str] | None = None,
        local_dir: str | Path | None = None,
        archive_path: str | Path | None = None,
        archive_format: Literal["tar.gz", "zip", "none"] | None = None,
        forward_to: Connection | str | None = None,
        forward_remote_dir: str | None = None,
        fsync_realtime: bool | None = None,
        gather_pre_facts: bool | None = None,
        gather_post_facts: bool | None = None,
    ) -> DiagnosticSession:
        """Открыть комплексную диагностическую сессию (слепки + фоновые потоки логов + архивация)."""
        from ..background._diagnostic import DiagnosticSession

        return DiagnosticSession(
            self,
            config=config,
            spec=spec,
            streams=streams,
            local_dir=local_dir,
            archive_path=archive_path,
            archive_format=archive_format,
            forward_to=forward_to,
            forward_remote_dir=forward_remote_dir,
            fsync_realtime=fsync_realtime,
            gather_pre_facts=gather_pre_facts,
            gather_post_facts=gather_post_facts,
        )

    ensure_package = async_delegate("state", StateManagementService.ensure_package)
    ensure_service = async_delegate("state", StateManagementService.ensure_service)
    ensure_line = async_delegate("state", StateManagementService.ensure_line)
    ensure_file = async_delegate("state", StateManagementService.ensure_file)
    ensure_directory = async_delegate("state", StateManagementService.ensure_directory)
    ensure_user = async_delegate("state", StateManagementService.ensure_user)
    ensure_authorized_key = async_delegate(
        "state", StateManagementService.ensure_authorized_key
    )
    ensure_systemd_unit = async_delegate(
        "state", StateManagementService.ensure_systemd_unit
    )
    ensure_sysctl = async_delegate("state", StateManagementService.ensure_sysctl)

    async def __aenter__(self) -> Self:
        await self._transport.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self._transport.disconnect()

    def to_sync(self) -> SyncConnection:
        """Конвертировать в синхронную версию."""
        from ..sync.connection import SyncConnection

        return SyncConnection(self)

    @property
    def config(self) -> ConnectionConfig:
        """Конфигурация подключения."""
        return self._config

    @property
    def transport_name(self) -> str:
        """Имя используемого транспорта."""
        return self._transport.name

    @property
    def dry_run(self) -> bool:
        """Включён ли режим dry_run для данного подключения."""
        return self._dry_run


__all__ = [
    "Connection",
    "OperationObserver",
    "_resolve_circuit_breaker",
    "_resolve_rate_limiter",
    "format_command",
    "render_template",
    "wait_exponential_jitter",
]
