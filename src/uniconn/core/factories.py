# src/uniconn/core/factories.py
"""Фабричные функции конструирования, клонирования и настройки ``Connection``."""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, TypeVar

from pydantic import SecretStr

from ..config.inventory import InventoryLoader
from ..config.models import ConnectionConfig
from ..plugins._loader import TransportLoader
from .pipeline import (
    CircuitBreakerMiddleware,
    ContextMiddleware,
    DryRunMiddleware,
    HookCallback,
    HookMiddleware,
    ObservabilityMiddleware,
    RateLimitMiddleware,
    RetryMiddleware,
    SudoMiddleware,
)
from .resilience import CircuitBreaker, RateLimiter

if TYPE_CHECKING:
    from ..background._diagnostic import DiagnosticConfig, DiagnosticSession, StreamSourceSpec
    from ..services.facts_models import FactSpec
    from ..transports.replay import CassetteContext
    from .connection import Connection

ConnT = TypeVar("ConnT", bound="Connection")

_META_KEYS = (
    "retry_attempts",
    "logger",
    "dry_run",
    "name",
    "groups",
    "rate_limit",
    "circuit_breaker",
)

_DEFAULT_MW_TYPES = (
    ContextMiddleware,
    SudoMiddleware,
    HookMiddleware,
    DryRunMiddleware,
    ObservabilityMiddleware,
    CircuitBreakerMiddleware,
    RateLimitMiddleware,
    RetryMiddleware,
)


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


def build_from_uri(
    cls: type[ConnT],
    uri: str,
    retry_attempts: int = 3,
    logger: logging.Logger | None = None,
    dry_run: bool = False,
    before_run: Sequence[HookCallback] | None = None,
    after_run: Sequence[HookCallback] | None = None,
    on_error: Sequence[HookCallback] | None = None,
    rate_limit: float | RateLimiter | None = None,
    circuit_breaker: CircuitBreaker | bool | None = None,
) -> ConnT:
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


def build_from_config(
    cls: type[ConnT],
    config: ConnectionConfig,
    retry_attempts: int = 3,
    logger: logging.Logger | None = None,
    dry_run: bool = False,
    before_run: Sequence[HookCallback] | None = None,
    after_run: Sequence[HookCallback] | None = None,
    on_error: Sequence[HookCallback] | None = None,
    rate_limit: float | RateLimiter | None = None,
    circuit_breaker: CircuitBreaker | bool | None = None,
) -> ConnT:
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


def build_from_dict(
    cls: type[ConnT],
    data: dict[str, Any],
    retry_attempts: int = 3,
    logger: logging.Logger | None = None,
    dry_run: bool = False,
) -> ConnT:
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
            if k not in ("uri", "transport", *_META_KEYS)
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
        **{k: v for k, v in data.items() if k not in _META_KEYS}
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


def build_from_file(
    cls: type[ConnT],
    path: str | Path,
    retry_attempts: int = 3,
    logger: logging.Logger | None = None,
    *,
    host: str | None = None,
    group: str | None = None,
) -> list[ConnT]:
    """Создать подключения из JSON/YAML/TOML файла (включая инвентарь с хостами и группами)."""
    entries = InventoryLoader.load_file(path, host=host, group=group)
    return [cls.from_dict(data, retry_attempts, logger) for data in entries]


def build_from_inventory(
    cls: type[ConnT],
    path: str | Path,
    host: str,
    retry_attempts: int = 3,
    logger: logging.Logger | None = None,
) -> ConnT:
    """Создать одиночное подключение по имени хоста из инвентарного файла (YAML/JSON)."""
    conns = cls.from_file(
        path,
        retry_attempts=retry_attempts,
        logger=logger,
        host=host,
    )
    return conns[0]


def clone_connection(
    conn: ConnT,
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
) -> ConnT:
    """Создать копию подключения с возможностью изменения параметров."""
    cfg = conn.config
    new_config = ConnectionConfig(
        transport=cfg.transport,
        host=host if host is not None else cfg.host,
        port=port if port is not None else cfg.port,
        username=username if username is not None else cfg.username,
        password=(
            SecretStr(password)
            if isinstance(password, str)
            else password
            if password is not None
            else cfg.password
        ),
        key_file=key_file if key_file is not None else cfg.key_file,
        passphrase=(
            SecretStr(passphrase)
            if isinstance(passphrase, str)
            else passphrase
            if passphrase is not None
            else cfg.passphrase
        ),
        ssh_config=ssh_config if ssh_config is not None else cfg.ssh_config,
        timeout=timeout if timeout is not None else cfg.timeout,
        options=options if options is not None else cfg.options,
    )
    transport_class = TransportLoader.get(new_config.transport)
    transport = transport_class(new_config)
    new_conn = type(conn)(
        transport,
        new_config,
        conn.retry_attempts if retry_attempts is None else retry_attempts,
        logger or conn.logger,
        dry_run=conn.dry_run if dry_run is None else dry_run,
        before_run=conn.get_hooks("before_run"),
        after_run=conn.get_hooks("after_run"),
        on_error=conn.get_hooks("on_error"),
        rate_limit=conn.rate_limiter if rate_limit is None else rate_limit,
        circuit_breaker=(
            conn.circuit_breaker if circuit_breaker is None else circuit_breaker
        ),
    )
    for obs in conn.operation_observers:
        attach_fn = getattr(obs, "_attach_connection", None)
        if callable(attach_fn):
            attach_fn(new_conn)
        else:
            new_conn.add_operation_observer(obs)

    existing_mw_types = tuple(type(m) for m in new_conn.pipeline.middlewares)
    for mw in conn.pipeline.middlewares:
        if not isinstance(mw, _DEFAULT_MW_TYPES) and not isinstance(
            mw, existing_mw_types
        ):
            new_conn.pipeline.add_middleware(mw)
    return new_conn


def with_overrides_connection(conn: ConnT, **overrides: Any) -> ConnT:
    """Создать копию подключения с переопределёнными параметрами."""
    return conn.copy(
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


def open_cassette_context(
    conn: Connection,
    path: str | Path,
    *,
    mode: Any = "once",
    match_on: Sequence[Literal["command", "cwd", "sudo"]] = ("command", "cwd", "sudo"),
    normalize_temp: bool = True,
    allow_playback_repeats: bool = True,
    mask_secrets: bool = True,
) -> CassetteContext:
    """Асинхронный контекстный менеджер записи и воспроизведения кассет взаимодействий."""
    from ..transports.replay import CassetteContext

    return CassetteContext(
        conn,
        path,
        mode=mode,
        match_on=match_on,
        normalize_temp=normalize_temp,
        allow_playback_repeats=allow_playback_repeats,
        mask_secrets=mask_secrets,
    )


def open_diagnostic_session(
    conn: Connection,
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
        conn,
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


build_from_uri.__name__ = "from_uri"
build_from_config.__name__ = "from_config"
build_from_dict.__name__ = "from_dict"
build_from_file.__name__ = "from_file"
build_from_inventory.__name__ = "from_inventory"
clone_connection.__name__ = "copy"
with_overrides_connection.__name__ = "with_overrides"
open_cassette_context.__name__ = "use_cassette"
open_diagnostic_session.__name__ = "diagnostic_session"

__all__ = [
    "_resolve_circuit_breaker",
    "_resolve_rate_limiter",
    "build_from_config",
    "build_from_dict",
    "build_from_file",
    "build_from_inventory",
    "build_from_uri",
    "clone_connection",
    "open_cassette_context",
    "open_diagnostic_session",
    "with_overrides_connection",
]
