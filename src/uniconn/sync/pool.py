# src/uniconn/sync/pool.py
"""Синхронная обёртка над ``ConnectionPool`` на базе ``EventLoopPortal`` и ``ParamSpec``-дескрипторов."""

from __future__ import annotations

import asyncio
import inspect
import logging
from collections.abc import Awaitable, Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self, TypeVar, overload

from ..core.bridge import (
    EventLoopPortal,
    SyncProxyMixin,
    sync_context,
    sync_iter,
    sync_method,
)
from ..core.connection import Connection
from ..core.resilience import CircuitBreaker, RateLimiter
from ..pool.connection_pool import ConnectionPool

if TYPE_CHECKING:
    from .connection import SyncConnection

T = TypeVar("T")


class SyncConnectionPool(SyncProxyMixin):
    """Синхронная обёртка над ``ConnectionPool`` на базе ``EventLoopPortal``."""

    def __init__(self, async_pool: ConnectionPool) -> None:
        self._async_pool = async_pool
        self._async_target = async_pool
        self._portal = EventLoopPortal(owner_name="SyncConnectionPool")

    @property
    def _closed(self) -> bool:
        """Признак закрытия синхронного пула."""
        return self._portal.closed

    @property
    def rate_limiter(self) -> RateLimiter | None:
        """Общий ограничитель частоты команд пула (если настроен)."""
        return self._async_pool.rate_limiter

    @property
    def circuit_breakers(self) -> dict[str, CircuitBreaker]:
        """Словарь предохранителей ``CircuitBreaker`` по ключам хостов пула."""
        return self._async_pool.circuit_breakers

    def add_connection_initializer(
        self, initializer: Callable[[Connection], None]
    ) -> None:
        """Зарегистрировать колбэк инициализации каждого соединения пула."""
        self._async_pool.add_connection_initializer(initializer)

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        *,
        group: str | None = None,
        host: str | None = None,
        max_concurrent: int = 10,
        retry_attempts: int = 3,
        logger: logging.Logger | None = None,
        rate_limit: float | RateLimiter | None = None,
        circuit_breaker: bool = False,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        batch_size: int | None = None,
        max_fail_ratio: float = 0.0,
    ) -> Self:
        """Создать синхронный пул подключений из JSON или YAML инвентарного файла."""
        pool = ConnectionPool.from_file(
            path,
            group=group,
            host=host,
            max_concurrent=max_concurrent,
            retry_attempts=retry_attempts,
            logger=logger,
            rate_limit=rate_limit,
            circuit_breaker=circuit_breaker,
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
            batch_size=batch_size,
            max_fail_ratio=max_fail_ratio,
        )
        return cls(pool)

    def select(
        self,
        hosts: Sequence[str] | Callable[[str], bool] | None = None,
        *,
        predicate: Callable[[str, Connection], bool] | None = None,
    ) -> SyncConnectionPool:
        """Выбрать подмножество хостов из синхронного пула с сохранением открытых сессий."""
        sub_async = self._async_pool.select(hosts=hosts, predicate=predicate)
        return SyncConnectionPool(sub_async)

    def _run_coro(self, coro: Any) -> Any:
        """Выполнить корутину пула в фоновом event loop."""
        return self._portal.call(coro)

    def connect(self) -> None:
        """Открыть и удерживать соединения ко всем хостам пула (синхронно)."""
        self._portal.reopen()
        self._run_coro(self._async_pool.connect())

    def close(self) -> None:
        """Закрыть все соединения пула и остановить фоновый event loop."""
        cleanup = self._async_pool.close() if self._async_pool else None
        self._portal.close(cleanup_coro=cleanup)

    def __enter__(self) -> Self:
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    @overload
    def apply(
        self,
        func: Callable[[Connection], Awaitable[T]],
        *,
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
    ) -> list[T]: ...

    @overload
    def apply(
        self,
        func: Callable[[SyncConnection], T],
        *,
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
    ) -> list[T]: ...

    def apply(
        self,
        func: Callable[[Any], Any],
        *,
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
    ) -> list[Any]:
        """Параллельно выполнить синхронную ``func(sync_conn)`` или async ``func(conn)`` на всех хостах пула."""
        if inspect.iscoroutinefunction(func):
            return self._run_coro(
                self._async_pool.apply(
                    func,
                    batch_size=batch_size,
                    max_fail_ratio=max_fail_ratio,
                )
            )

        from .connection import SyncConnection

        async def _sync_or_awaitable_runner(conn: Connection) -> Any:
            sync_conn = SyncConnection(conn)
            res = await asyncio.to_thread(func, sync_conn)
            if inspect.isawaitable(res):
                return await res
            return res

        return self._run_coro(
            self._async_pool.apply(
                _sync_or_awaitable_runner,
                batch_size=batch_size,
                max_fail_ratio=max_fail_ratio,
            )
        )

    # ─── Fan-out операции пула (ParamSpec-дескрипторы к ConnectionPool) ─

    map = sync_method(ConnectionPool.map)
    map_safe = sync_method(ConnectionPool.map_safe)
    map_with_callback = sync_method(ConnectionPool.map_with_callback)
    upload = sync_method(ConnectionPool.upload)
    download = sync_method(ConnectionPool.download)
    checksum = sync_method(ConnectionPool.checksum)
    sync_dir = sync_method(ConnectionPool.sync_dir)
    write_template = sync_method(ConnectionPool.write_template)
    gather_facts = sync_method(ConnectionPool.gather_facts)
    diff_facts = sync_method(ConnectionPool.diff_facts)
    ping = sync_method(ConnectionPool.ping)
    wait_for_connection = sync_method(ConnectionPool.wait_for_connection)
    wait_for_port = sync_method(ConnectionPool.wait_for_port)
    wait_for_path = sync_method(ConnectionPool.wait_for_path)
    run_script = sync_method(ConnectionPool.run_script)
    ensure_package = sync_method(ConnectionPool.ensure_package)
    ensure_service = sync_method(ConnectionPool.ensure_service)
    ensure_line = sync_method(ConnectionPool.ensure_line)
    ensure_file = sync_method(ConnectionPool.ensure_file)
    ensure_directory = sync_method(ConnectionPool.ensure_directory)
    ensure_user = sync_method(ConnectionPool.ensure_user)
    ensure_authorized_key = sync_method(ConnectionPool.ensure_authorized_key)
    ensure_systemd_unit = sync_method(ConnectionPool.ensure_systemd_unit)
    ensure_sysctl = sync_method(ConnectionPool.ensure_sysctl)
    use_cassette = sync_context(ConnectionPool.use_cassette, reopen_portal=True)
    stream = sync_iter(ConnectionPool.stream)
