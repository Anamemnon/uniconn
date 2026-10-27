# src/uniconn/pool/connection_pool.py
"""Пул подключений для параллельного выполнения команд и групповых операций.

Использует обобщённый движок параллельного распределения задач (``_fan_out_list`` /
``_fan_out_dict``) и выделенный мультиплексор потоков ``PoolStreamMultiplexer``.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Self, TypeVar

from pydantic import SecretStr

from ..config.models import ConnectionConfig
from ..core.connection import Connection, _resolve_rate_limiter, format_command
from ..core.resilience import CircuitBreaker, RateLimiter
from ..result import EnsureResult, PingResult, Result, SyncResult
from ..services.facts_models import FactsDiffReport, FactSpec, HostFacts, diff_facts
from .stream_mux import PoolStreamMultiplexer

if TYPE_CHECKING:
    from ..sync.pool import SyncConnectionPool

logger = logging.getLogger(__name__)

PoolTarget = str | ConnectionConfig | Connection
T = TypeVar("T")


class ConnectionPool:
    """Пул подключений для параллельного выполнения команд и групповых операций."""

    def __init__(
        self,
        uris: Sequence[PoolTarget],
        max_concurrent: int = 10,
        retry_attempts: int = 3,
        logger: logging.Logger | None = None,
        rate_limit: float | RateLimiter | None = None,
        circuit_breaker: bool = False,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        *,
        batch_size: int | None = None,
        max_fail_ratio: float = 0.0,
    ) -> None:
        self._uris = list(uris)
        self._max_concurrent = max_concurrent
        self._retry_attempts = retry_attempts
        self._logger = logger or logging.getLogger(__name__)
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._active_conns: dict[int, Connection] = {}
        self._cassette_conns: dict[int, Connection] = {}
        self._is_entered = False
        self._owns_active_conns = True
        self._batch_size = batch_size
        self._max_fail_ratio = max_fail_ratio
        self._stream_mux = PoolStreamMultiplexer(self)
        self._rate_limiter = _resolve_rate_limiter(rate_limit, {})
        self._circuit_breaker_enabled = circuit_breaker
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._circuit_breakers: dict[str, CircuitBreaker] = {}
        self._conn_initializers: list[Callable[[Connection], None]] = []
        for target in self._uris:
            key = self._target_key(target)
            if isinstance(target, Connection):
                if self._rate_limiter is not None and not isinstance(
                    getattr(target, "rate_limiter", None), RateLimiter
                ):
                    target.rate_limiter = self._rate_limiter
                target_cb = getattr(target, "circuit_breaker", None)
                if isinstance(target_cb, CircuitBreaker):
                    self._circuit_breakers[key] = target_cb
                elif self._circuit_breaker_enabled:
                    cb = CircuitBreaker(
                        failure_threshold=self._failure_threshold,
                        recovery_timeout=self._recovery_timeout,
                    )
                    self._circuit_breakers[key] = cb
                    target.circuit_breaker = cb
            elif self._circuit_breaker_enabled and key not in self._circuit_breakers:
                self._circuit_breakers[key] = CircuitBreaker(
                    failure_threshold=self._failure_threshold,
                    recovery_timeout=self._recovery_timeout,
                )

    @property
    def rate_limiter(self) -> RateLimiter | None:
        """Общий ограничитель частоты команд пула (если настроен)."""
        return self._rate_limiter

    @property
    def circuit_breakers(self) -> dict[str, CircuitBreaker]:
        """Словарь предохранителей ``CircuitBreaker`` по ключам хостов пула."""
        return self._circuit_breakers

    def add_connection_initializer(
        self, initializer: Callable[[Connection], None]
    ) -> None:
        """Зарегистрировать колбэк инициализации каждого соединения пула."""
        if initializer not in self._conn_initializers:
            self._conn_initializers.append(initializer)
        for target in self._uris:
            if isinstance(target, Connection):
                initializer(target)
        for conn in self._active_conns.values():
            initializer(conn)

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
        """Создать пул подключений из JSON или YAML инвентарного файла."""
        conns = Connection.from_file(
            path,
            retry_attempts=retry_attempts,
            logger=logger,
            host=host,
            group=group,
        )
        return cls(
            conns,
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

    def select(
        self,
        hosts: Sequence[str] | Callable[[str], bool] | None = None,
        *,
        predicate: Callable[[str, Connection], bool] | None = None,
    ) -> ConnectionPool:
        """Выбрать подмножество хостов из пула с сохранением открытых сессий и лимитов."""
        host_filter_fn: Callable[[str], bool] | None = None
        host_set: set[str] | None = None
        if callable(hosts):
            host_filter_fn = hosts
        elif hosts is not None:
            host_set = set(hosts)

        selected_uris: list[PoolTarget] = []
        selected_active: dict[int, Connection] = {}

        for old_idx, target in enumerate(self._uris):
            key = self._target_key(target)
            conn_obj = (
                self._active_conns[old_idx]
                if (self._is_entered and old_idx in self._active_conns)
                else self._build_conn(target, with_defaults=True)
            )
            short_host = conn_obj.config.host or key.split("://", 1)[-1]

            matched = True
            if host_set is not None:
                matched = (
                    key in host_set
                    or short_host in host_set
                    or key.split("://", 1)[-1] in host_set
                )
            if matched and host_filter_fn is not None:
                matched = bool(host_filter_fn(key) or host_filter_fn(short_host))
            if matched and predicate is not None:
                matched = bool(predicate(key, conn_obj))

            if matched:
                new_idx = len(selected_uris)
                selected_uris.append(target)
                if self._is_entered and old_idx in self._active_conns:
                    selected_active[new_idx] = self._active_conns[old_idx]

        sub_pool = ConnectionPool(
            selected_uris,
            max_concurrent=self._max_concurrent,
            retry_attempts=self._retry_attempts,
            logger=self._logger,
            rate_limit=self._rate_limiter,
            circuit_breaker=self._circuit_breaker_enabled,
            failure_threshold=self._failure_threshold,
            recovery_timeout=self._recovery_timeout,
            batch_size=self._batch_size,
            max_fail_ratio=self._max_fail_ratio,
        )
        sub_pool._semaphore = self._semaphore
        sub_pool._circuit_breakers = self._circuit_breakers
        sub_pool._conn_initializers = list(self._conn_initializers)
        if self._is_entered:
            sub_pool._active_conns = selected_active
            sub_pool._is_entered = True
            sub_pool._owns_active_conns = False
        return sub_pool

    @staticmethod
    def _target_key(target: PoolTarget) -> str:
        """Вернуть строковый ключ хоста для словаря результатов."""
        if isinstance(target, str):
            return target
        if isinstance(target, ConnectionConfig):
            return target.host or target.uri_safe
        return target.config.host or target.config.uri_safe

    def _attach_resilience(self, target: PoolTarget, conn: Connection) -> Connection:
        """Привязать пуловый ``RateLimiter``, ``CircuitBreaker`` и инициализаторы к соединению."""
        key = self._target_key(target)
        if self._rate_limiter is not None and not isinstance(
            getattr(conn, "rate_limiter", None), RateLimiter
        ):
            conn.rate_limiter = self._rate_limiter
        conn_cb = getattr(conn, "circuit_breaker", None)
        if isinstance(conn_cb, CircuitBreaker):
            self._circuit_breakers.setdefault(key, conn_cb)
        elif self._circuit_breaker_enabled:
            cb = self._circuit_breakers.setdefault(
                key,
                CircuitBreaker(
                    failure_threshold=self._failure_threshold,
                    recovery_timeout=self._recovery_timeout,
                ),
            )
            conn.circuit_breaker = cb
        for initializer in self._conn_initializers:
            initializer(conn)
        return conn

    def _build_conn(
        self, target: PoolTarget, *, with_defaults: bool = True
    ) -> Connection:
        """Создать экземпляр Connection из элемента пула."""
        if isinstance(target, Connection):
            return self._attach_resilience(target, target)
        if isinstance(target, ConnectionConfig):
            conn = Connection.from_config(
                target,
                retry_attempts=self._retry_attempts,
                logger=self._logger,
            )
            return self._attach_resilience(target, conn)
        if with_defaults:
            conn = Connection.from_uri(
                target,
                retry_attempts=self._retry_attempts,
                logger=self._logger,
            )
            return self._attach_resilience(target, conn)
        conn = Connection.from_uri(target)
        return self._attach_resilience(target, conn)

    @contextlib.asynccontextmanager
    async def _use_conn(
        self,
        idx: int,
        target: PoolTarget,
        *,
        with_defaults: bool = True,
    ) -> AsyncIterator[Connection]:
        """Получить открытое соединение (из пула или временное)."""
        if self._is_entered and idx in self._active_conns:
            yield self._active_conns[idx]
            return

        conn = self._build_conn(target, with_defaults=with_defaults)
        cb = getattr(conn, "circuit_breaker", None)
        if not isinstance(cb, CircuitBreaker):
            cb = self._circuit_breakers.get(self._target_key(target))
        if isinstance(cb, CircuitBreaker):
            cfg = getattr(conn, "config", None)
            cfg_host = getattr(cfg, "host", None)
            host = (
                cfg_host
                if isinstance(cfg_host, str) and cfg_host
                else self._target_key(target)
            )
            cb.check_or_raise(host=host, command="<connect>")
        try:
            async with conn as active:
                yield active
        except Exception as exc:
            from ..exceptions import ConnectionError as UniconnConnectionError
            from ..exceptions import TimeoutError as UniconnTimeoutError

            if isinstance(cb, CircuitBreaker) and isinstance(
                exc, UniconnConnectionError | UniconnTimeoutError | OSError
            ):
                cb.record_failure()
            raise

    @staticmethod
    def _is_failed_outcome(val: Any) -> bool:
        """Определить, является ли результат выполнения на хосте неуспешным для батчевой раскатки."""
        if isinstance(val, BaseException):
            return True
        if isinstance(val, Result | EnsureResult):
            return not val.ok
        if isinstance(val, PingResult):
            return not val.alive
        return False

    async def _execute_in_batches(
        self,
        worker: Callable[[str, Connection], Awaitable[T]],
        *,
        with_defaults: bool = True,
        log_errors: bool = False,
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
    ) -> list[tuple[str, T]]:
        """Выполнить задачи последовательными волнами ``batch_size`` с контролем ``max_fail_ratio``."""
        from ..exceptions import BatchAbortedError

        eff_batch = self._batch_size if batch_size is None else batch_size
        eff_ratio = self._max_fail_ratio if max_fail_ratio is None else max_fail_ratio
        if eff_batch is None or eff_batch <= 0:
            eff_batch = max(1, len(self._uris))

        items = list(enumerate(self._uris))
        batches = [
            items[i : i + eff_batch] for i in range(0, len(items), eff_batch)
        ]
        completed_results: dict[str, Any] = {}
        ordered_pairs: list[tuple[str, T]] = []

        async def _run_batch_item(
            idx: int, target: PoolTarget
        ) -> tuple[str, Any, bool]:
            key = self._target_key(target)
            async with self._semaphore:
                try:
                    async with self._use_conn(
                        idx, target, with_defaults=with_defaults
                    ) as conn:
                        val = await worker(key, conn)
                        return key, val, False
                except Exception as exc:
                    if log_errors:
                        self._logger.error(f"Failed to execute on {key}: {exc}")
                    return key, exc, True

        for batch_idx, batch_items in enumerate(batches):
            outcomes = await asyncio.gather(
                *(_run_batch_item(idx, target) for idx, target in batch_items)
            )
            batch_failures: dict[str, Any] = {}
            first_exc: Exception | None = None

            for key, outcome, is_exc in outcomes:
                if is_exc:
                    batch_failures[key] = outcome
                    if first_exc is None and isinstance(outcome, Exception):
                        first_exc = outcome
                else:
                    completed_results[key] = outcome
                    ordered_pairs.append((key, outcome))
                    if self._is_failed_outcome(outcome):
                        batch_failures[key] = outcome

            if batch_items and batch_failures:
                fail_ratio = len(batch_failures) / len(batch_items)
                if fail_ratio > eff_ratio:
                    raise BatchAbortedError(
                        f"Batch {batch_idx} aborted: fail_ratio={fail_ratio:.2f} "
                        f"exceeded max_fail_ratio={eff_ratio:.2f} "
                        f"({len(batch_failures)}/{len(batch_items)} failed)",
                        batch_index=batch_idx,
                        fail_ratio=fail_ratio,
                        max_fail_ratio=eff_ratio,
                        completed_results=completed_results,
                        failed_hosts=batch_failures,
                    )
            if first_exc is not None:
                raise first_exc

        return ordered_pairs

    async def _fan_out_list(
        self,
        worker: Callable[[Connection], Awaitable[T]],
        *,
        with_defaults: bool = True,
        log_errors: bool = False,
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
    ) -> list[T]:
        """Выполнить ``worker(conn)`` параллельно на всех хостах и вернуть список в порядке пула."""
        eff_batch = self._batch_size if batch_size is None else batch_size
        if eff_batch is not None or max_fail_ratio is not None:
            pairs = await self._execute_in_batches(
                lambda _key, conn: worker(conn),
                with_defaults=with_defaults,
                log_errors=log_errors,
                batch_size=batch_size,
                max_fail_ratio=max_fail_ratio,
            )
            return [val for _key, val in pairs]

        async def _run_one(idx: int, target: PoolTarget) -> T:
            async with self._semaphore:
                try:
                    async with self._use_conn(
                        idx, target, with_defaults=with_defaults
                    ) as conn:
                        return await worker(conn)
                except Exception as exc:
                    if log_errors:
                        self._logger.error(
                            f"Failed to execute on {self._target_key(target)}: {exc}"
                        )
                    raise

        try:
            async with asyncio.TaskGroup() as tg:
                tasks = [
                    tg.create_task(_run_one(idx, target))
                    for idx, target in enumerate(self._uris)
                ]
            return [task.result() for task in tasks]
        except* Exception as eg:
            if log_errors:
                self._logger.error(
                    f"Multiple failures: {len(eg.exceptions)} errors"
                )
            raise

    async def _fan_out_dict(
        self,
        worker: Callable[[str, Connection], Awaitable[T]],
        *,
        with_defaults: bool = True,
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
    ) -> dict[str, T]:
        """Выполнить ``worker(key, conn)`` параллельно на всех хостах и вернуть словарь ``{key: T}``."""
        eff_batch = self._batch_size if batch_size is None else batch_size
        if eff_batch is not None or max_fail_ratio is not None:
            pairs = await self._execute_in_batches(
                worker,
                with_defaults=with_defaults,
                batch_size=batch_size,
                max_fail_ratio=max_fail_ratio,
            )
            return dict(pairs)

        results: dict[str, T] = {}

        async def _run_one(idx: int, target: PoolTarget) -> None:
            key = self._target_key(target)
            async with (
                self._semaphore,
                self._use_conn(idx, target, with_defaults=with_defaults) as conn,
            ):
                results[key] = await worker(key, conn)

        async with asyncio.TaskGroup() as tg:
            for idx, target in enumerate(self._uris):
                tg.create_task(_run_one(idx, target))

        return results

    async def connect(self) -> None:
        """Открыть и удерживать соединения ко всем хостам пула."""
        if self._is_entered:
            return

        async def _open_one(idx: int, target: PoolTarget) -> None:
            async with self._semaphore:
                conn = self._build_conn(target, with_defaults=True)
                await conn.__aenter__()
                self._active_conns[idx] = conn

        try:
            async with asyncio.TaskGroup() as tg:
                for idx, target in enumerate(self._uris):
                    tg.create_task(_open_one(idx, target))
            self._is_entered = True
            self._owns_active_conns = True
        except* Exception:
            await self.close()
            raise

    async def close(self) -> None:
        """Закрыть все удерживаемые пулом соединения."""
        if not self._owns_active_conns:
            self._active_conns.clear()
            self._is_entered = False
            return
        conns = list(self._active_conns.values())
        self._active_conns.clear()
        self._is_entered = False
        for conn in conns:
            with contextlib.suppress(Exception):
                await conn.__aexit__(None, None, None)

    async def __aenter__(self) -> Self:
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    async def map(
        self,
        command: str | Sequence[str],
        timeout: float | None = None,
        raise_on_error: bool = False,
        *,
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
        **kwargs: Any,
    ) -> list[Result]:
        """Выполнить команду на всех хостах пула."""
        return await self._fan_out_list(
            lambda conn: conn.run(
                command,
                timeout=timeout,
                raise_on_error=raise_on_error,
                **kwargs,
            ),
            with_defaults=True,
            log_errors=True,
            batch_size=batch_size,
            max_fail_ratio=max_fail_ratio,
        )

    async def map_with_callback(
        self,
        command: str | Sequence[str],
        callback: Callable[[str, Result], None],
        timeout: float | None = None,
        **kwargs: Any,
    ) -> None:
        """Выполнить команду с callback по мере готовности результатов."""
        cmd_str = format_command(command)

        async def _run_and_notify(idx: int, target: PoolTarget) -> None:
            key = self._target_key(target)
            async with self._semaphore:
                try:
                    async with self._use_conn(
                        idx, target, with_defaults=False
                    ) as conn:
                        result = await conn.run(command, timeout=timeout, **kwargs)
                        callback(key, result)
                except Exception as e:
                    self._logger.error(f"Failed on {key}: {e}")
                    error_result = Result(
                        exit_code=-1,
                        stdout="",
                        stderr=str(e),
                        duration=0.0,
                        command=cmd_str,
                        timestamp=datetime.now(),
                        host=key,
                    )
                    callback(key, error_result)

        async with asyncio.TaskGroup() as tg:
            for idx, target in enumerate(self._uris):
                tg.create_task(_run_and_notify(idx, target))

    async def map_safe(
        self,
        command: str | Sequence[str],
        timeout: float | None = None,
        **kwargs: Any,
    ) -> dict[str, Result | Exception]:
        """Выполнить команду, возвращая результаты или исключения без выброса."""
        results: dict[str, Result | Exception] = {}

        async def _run_single(idx: int, target: PoolTarget) -> None:
            key = self._target_key(target)
            async with self._semaphore:
                try:
                    async with self._use_conn(
                        idx, target, with_defaults=False
                    ) as conn:
                        results[key] = await conn.run(
                            command, timeout=timeout, **kwargs
                        )
                except Exception as e:
                    results[key] = e

        with contextlib.suppress(BaseException):
            async with asyncio.TaskGroup() as tg:
                for idx, target in enumerate(self._uris):
                    tg.create_task(_run_single(idx, target))

        return results

    async def upload(
        self,
        local_path: str | Path,
        remote_path: str | Path,
        recurse: bool = False,
        *,
        verify: bool = False,
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
        **kwargs: Any,
    ) -> None:
        """Параллельно загрузить файл или директорию на все хосты пула."""
        await self._fan_out_list(
            lambda conn: conn.upload(
                str(local_path),
                str(remote_path),
                recurse=recurse,
                **({"verify": True} if verify else {}),
                **kwargs,
            ),
            batch_size=batch_size,
            max_fail_ratio=max_fail_ratio,
        )

    async def download(
        self,
        remote_path: str | Path,
        local_path: str | Path,
        recurse: bool = False,
        *,
        verify: bool = False,
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
        **kwargs: Any,
    ) -> dict[str, str]:
        """Параллельно скачать файл или директорию со всех хостов пула."""
        local_str = str(local_path)
        remote_name = Path(str(remote_path)).name

        async def _dl_worker(key: str, conn: Connection) -> str:
            safe_host = (
                key.split("://", 1)[-1]
                .replace("/", "_")
                .replace(":", "_")
                .replace("@", "_")
            )
            if "{host}" in local_str:
                dest = local_str.format(host=safe_host)
            elif len(self._uris) > 1:
                dest_dir = Path(local_str) / safe_host
                dest_dir.mkdir(parents=True, exist_ok=True)
                dest = str(dest_dir / remote_name)
            else:
                dest = local_str

            await conn.download(
                str(remote_path),
                dest,
                recurse=recurse,
                **({"verify": True} if verify else {}),
                **kwargs,
            )
            return dest

        return await self._fan_out_dict(
            _dl_worker,
            batch_size=batch_size,
            max_fail_ratio=max_fail_ratio,
        )

    async def checksum(
        self,
        remote_path: str | Path,
        algorithm: Literal["sha256", "sha1", "md5"] = "sha256",
        *,
        sudo: bool = False,
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
    ) -> dict[str, str]:
        """Параллельно вычислить контрольную сумму удалённого файла на всех хостах пула."""
        return await self._fan_out_dict(
            lambda _key, conn: conn.checksum(
                remote_path,
                algorithm=algorithm,
                sudo=sudo,
            ),
            batch_size=batch_size,
            max_fail_ratio=max_fail_ratio,
        )

    async def apply(
        self,
        func: Callable[[Connection], Awaitable[T]],
        *,
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
    ) -> list[T]:
        """Параллельно выполнить произвольную async-функцию ``func(conn)`` на всех хостах пула."""
        return await self._fan_out_list(
            func,
            batch_size=batch_size,
            max_fail_ratio=max_fail_ratio,
        )

    async def sync_dir(
        self,
        local_dir: str | Path,
        remote_dir: str | Path,
        delete: bool = False,
        exclude: Sequence[str] | None = None,
        mtime_tolerance: float = 1.0,
        dry_run: bool | None = None,
        *,
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
    ) -> dict[str, SyncResult]:
        """Параллельно синхронизировать директорию на всех хостах пула."""
        return await self._fan_out_dict(
            lambda _key, conn: conn.sync_dir(
                local_dir=local_dir,
                remote_dir=remote_dir,
                delete=delete,
                exclude=exclude,
                mtime_tolerance=mtime_tolerance,
                dry_run=dry_run,
            ),
            batch_size=batch_size,
            max_fail_ratio=max_fail_ratio,
        )

    async def write_template(
        self,
        remote_path: str | Path,
        template_str_or_path: str | Path,
        context: Mapping[str, Any] | None = None,
        mode: int | None = 0o644,
        encoding: str = "utf-8",
        engine: Literal["auto", "string", "jinja2"] = "auto",
        *,
        atomic: bool = False,
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
    ) -> dict[str, str]:
        """Параллельно отрендерить и записать шаблон конфигурации на всех хостах пула."""
        return await self._fan_out_dict(
            lambda _key, conn: conn.write_template(
                remote_path=remote_path,
                template_str_or_path=template_str_or_path,
                context=context,
                mode=mode,
                encoding=encoding,
                engine=engine,
                atomic=atomic,
            ),
            batch_size=batch_size,
            max_fail_ratio=max_fail_ratio,
        )

    async def gather_facts(
        self,
        refresh: bool = False,
        timeout: float | None = None,
        spec: FactSpec | Mapping[str, Any] | str | Path | None = None,
        *,
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
    ) -> dict[str, HostFacts]:
        """Параллельно собрать системные факты (``HostFacts``) со всех хостов пула."""
        return await self._fan_out_dict(
            lambda _key, conn: conn.gather_facts(
                refresh=refresh,
                timeout=timeout,
                spec=spec,
            ),
            batch_size=batch_size,
            max_fail_ratio=max_fail_ratio,
        )

    async def diff_facts(
        self,
        *,
        baseline_host: str | None = None,
        fields: Sequence[str] | None = None,
        refresh: bool = False,
        timeout: float | None = None,
        spec: FactSpec | Mapping[str, Any] | str | Path | None = None,
    ) -> FactsDiffReport:
        """Собрать системные факты со всех хостов пула и найти расхождения с эталоном."""
        facts_map = await self.gather_facts(
            refresh=refresh,
            timeout=timeout,
            spec=spec,
        )
        return diff_facts(
            facts_map,
            baseline_host=baseline_host,
            fields=fields,
        )

    async def ping(
        self,
        timeout: float | None = None,
    ) -> dict[str, PingResult]:
        """Параллельно проверить доступность всех хостов пула с измерением задержки."""
        results: dict[str, PingResult] = {}

        async def _ping_one(idx: int, target: PoolTarget) -> None:
            key = self._target_key(target)
            async with self._semaphore:
                if self._is_entered and idx in self._active_conns:
                    res = await self._active_conns[idx].ping(timeout=timeout)
                    results[key] = res
                    return
                if idx in self._cassette_conns:
                    res = await self._cassette_conns[idx].ping(timeout=timeout)
                    results[key] = res
                    return

                conn = self._build_conn(target, with_defaults=True)
                try:
                    results[key] = await conn.ping(timeout=timeout)
                finally:
                    with contextlib.suppress(Exception):
                        await conn.close()

        async with asyncio.TaskGroup() as tg:
            for idx, target in enumerate(self._uris):
                tg.create_task(_ping_one(idx, target))

        return results

    async def wait_for_connection(
        self,
        timeout: float = 120.0,
        interval: float = 2.0,
        delay: float = 0.0,
    ) -> dict[str, PingResult]:
        """Параллельно ожидать восстановления доступности всех хостов пула."""
        results: dict[str, PingResult] = {}

        async def _wait_one(idx: int, target: PoolTarget) -> None:
            key = self._target_key(target)
            async with self._semaphore:
                if self._is_entered and idx in self._active_conns:
                    results[key] = await self._active_conns[idx].wait_for_connection(
                        timeout=timeout, interval=interval, delay=delay
                    )
                    return
                if idx in self._cassette_conns:
                    results[key] = await self._cassette_conns[idx].wait_for_connection(
                        timeout=timeout, interval=interval, delay=delay
                    )
                    return

                conn = self._build_conn(target, with_defaults=True)
                try:
                    results[key] = await conn.wait_for_connection(
                        timeout=timeout, interval=interval, delay=delay
                    )
                finally:
                    with contextlib.suppress(Exception):
                        await conn.close()

        async with asyncio.TaskGroup() as tg:
            for idx, target in enumerate(self._uris):
                tg.create_task(_wait_one(idx, target))

        return results

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
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
    ) -> dict[str, float]:
        """Параллельно ожидать открытия или закрытия TCP-порта на всех хостах пула."""
        return await self._fan_out_dict(
            lambda _key, conn: conn.wait_for_port(
                port,
                host=host,
                state=state,
                check_from=check_from,
                timeout=timeout,
                interval=interval,
                delay=delay,
            ),
            batch_size=batch_size,
            max_fail_ratio=max_fail_ratio,
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
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
    ) -> dict[str, float]:
        """Параллельно ожидать появления или удаления файла/директории/сокета на всех хостах пула."""
        return await self._fan_out_dict(
            lambda _key, conn: conn.wait_for_path(
                remote_path,
                state=state,
                content_regex=content_regex,
                timeout=timeout,
                interval=interval,
                delay=delay,
                sudo=sudo,
            ),
            batch_size=batch_size,
            max_fail_ratio=max_fail_ratio,
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
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
    ) -> dict[str, Result]:
        """Параллельно загрузить, выполнить и удалить локальный скрипт на всех хостах пула."""
        return await self._fan_out_dict(
            lambda _key, conn: conn.run_script(
                local_path=local_path,
                args=args,
                interpreter=interpreter,
                sudo=sudo,
                sudo_user=sudo_user,
                sudo_password=sudo_password,
                env=env,
                timeout=timeout,
                raise_on_error=raise_on_error,
                sensitive=sensitive,
                dry_run=dry_run,
            ),
            batch_size=batch_size,
            max_fail_ratio=max_fail_ratio,
        )

    async def ensure_package(
        self,
        package: str | Sequence[str],
        state: Literal["present", "absent"] = "present",
        manager: Literal[
            "auto", "apt", "dnf", "yum", "apk", "pacman", "zypper"
        ] = "auto",
        update_cache: bool = False,
        sudo: bool = True,
        dry_run: bool | None = None,
        *,
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
    ) -> dict[str, EnsureResult]:
        """Параллельно проверить/установить/удалить пакет(ы) на всех хостах пула."""
        return await self._fan_out_dict(
            lambda _key, conn: conn.ensure_package(
                package=package,
                state=state,
                manager=manager,
                update_cache=update_cache,
                sudo=sudo,
                dry_run=dry_run,
            ),
            batch_size=batch_size,
            max_fail_ratio=max_fail_ratio,
        )

    async def ensure_service(
        self,
        service: str,
        state: Literal["started", "stopped", "restarted", "reloaded"] = "started",
        enabled: bool | None = None,
        sudo: bool = True,
        dry_run: bool | None = None,
        *,
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
    ) -> dict[str, EnsureResult]:
        """Параллельно привести состояние системного сервиса на всех хостах пула."""
        return await self._fan_out_dict(
            lambda _key, conn: conn.ensure_service(
                service=service,
                state=state,
                enabled=enabled,
                sudo=sudo,
                dry_run=dry_run,
            ),
            batch_size=batch_size,
            max_fail_ratio=max_fail_ratio,
        )

    async def ensure_line(
        self,
        remote_path: str | Path,
        line: str,
        state: Literal["present", "absent"] = "present",
        regex: str | None = None,
        create: bool = True,
        backup: bool = False,
        mode: int | None = None,
        encoding: str = "utf-8",
        dry_run: bool | None = None,
        *,
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
    ) -> dict[str, EnsureResult]:
        """Параллельно обеспечить наличие или отсутствие строки в файле на всех хостах пула."""
        return await self._fan_out_dict(
            lambda _key, conn: conn.ensure_line(
                remote_path=remote_path,
                line=line,
                state=state,
                regex=regex,
                create=create,
                backup=backup,
                mode=mode,
                encoding=encoding,
                dry_run=dry_run,
            ),
            batch_size=batch_size,
            max_fail_ratio=max_fail_ratio,
        )

    async def ensure_file(
        self,
        remote_path: str | Path,
        *,
        state: Literal["present", "absent", "link"] = "present",
        content: str | bytes | None = None,
        target: str | Path | None = None,
        mode: int | str | None = None,
        owner: str | None = None,
        group: str | None = None,
        validate: str | None = None,
        encoding: str = "utf-8",
        sudo: bool = False,
        atomic: bool = False,
        dry_run: bool | None = None,
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
    ) -> dict[str, EnsureResult]:
        """Параллельно обеспечить состояние файла или симлинка на всех хостах пула."""
        return await self._fan_out_dict(
            lambda _key, conn: conn.ensure_file(
                remote_path,
                state=state,
                content=content,
                target=target,
                mode=mode,
                owner=owner,
                group=group,
                validate=validate,
                encoding=encoding,
                sudo=sudo,
                atomic=atomic,
                dry_run=dry_run,
            ),
            batch_size=batch_size,
            max_fail_ratio=max_fail_ratio,
        )

    async def ensure_directory(
        self,
        remote_path: str | Path,
        *,
        state: Literal["present", "absent"] = "present",
        mode: int | str | None = None,
        owner: str | None = None,
        group: str | None = None,
        recurse: bool = False,
        sudo: bool = False,
        dry_run: bool | None = None,
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
    ) -> dict[str, EnsureResult]:
        """Параллельно обеспечить состояние директории на всех хостах пула."""
        return await self._fan_out_dict(
            lambda _key, conn: conn.ensure_directory(
                remote_path,
                state=state,
                mode=mode,
                owner=owner,
                group=group,
                recurse=recurse,
                sudo=sudo,
                dry_run=dry_run,
            ),
            batch_size=batch_size,
            max_fail_ratio=max_fail_ratio,
        )

    async def ensure_user(
        self,
        username: str,
        *,
        state: Literal["present", "absent"] = "present",
        uid: int | None = None,
        group: str | None = None,
        groups: Sequence[str] | None = None,
        shell: str | None = None,
        home: str | None = None,
        create_home: bool = True,
        system: bool = False,
        sudo: bool = True,
        dry_run: bool | None = None,
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
    ) -> dict[str, EnsureResult]:
        """Параллельно обеспечить состояние системного пользователя на всех хостах пула."""
        return await self._fan_out_dict(
            lambda _key, conn: conn.ensure_user(
                username,
                state=state,
                uid=uid,
                group=group,
                groups=groups,
                shell=shell,
                home=home,
                create_home=create_home,
                system=system,
                sudo=sudo,
                dry_run=dry_run,
            ),
            batch_size=batch_size,
            max_fail_ratio=max_fail_ratio,
        )

    async def ensure_authorized_key(
        self,
        user: str,
        key: str,
        *,
        state: Literal["present", "absent"] = "present",
        exclusive: bool = False,
        sudo: bool = False,
        dry_run: bool | None = None,
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
    ) -> dict[str, EnsureResult]:
        """Параллельно обеспечить наличие или отсутствие SSH-ключа на всех хостах пула."""
        return await self._fan_out_dict(
            lambda _key, conn: conn.ensure_authorized_key(
                user,
                key,
                state=state,
                exclusive=exclusive,
                sudo=sudo,
                dry_run=dry_run,
            ),
            batch_size=batch_size,
            max_fail_ratio=max_fail_ratio,
        )

    async def ensure_systemd_unit(
        self,
        name: str,
        *,
        content: str | None = None,
        state: Literal[
            "present", "absent", "started", "stopped", "restarted"
        ] = "present",
        enabled: bool | None = None,
        unit_dir: str = "/etc/systemd/system",
        daemon_reload: bool = True,
        sudo: bool = True,
        dry_run: bool | None = None,
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
    ) -> dict[str, EnsureResult]:
        """Параллельно обеспечить состояние systemd unit-файла и сервиса на всех хостах пула."""
        return await self._fan_out_dict(
            lambda _key, conn: conn.ensure_systemd_unit(
                name,
                content=content,
                state=state,
                enabled=enabled,
                unit_dir=unit_dir,
                daemon_reload=daemon_reload,
                sudo=sudo,
                dry_run=dry_run,
            ),
            batch_size=batch_size,
            max_fail_ratio=max_fail_ratio,
        )

    async def ensure_sysctl(
        self,
        name: str,
        value: str | int,
        *,
        state: Literal["present", "absent"] = "present",
        config_file: str = "/etc/sysctl.d/99-uniconn.conf",
        reload: bool = True,
        sudo: bool = True,
        dry_run: bool | None = None,
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
    ) -> dict[str, EnsureResult]:
        """Параллельно обеспечить значение параметра ядра sysctl на всех хостах пула."""
        return await self._fan_out_dict(
            lambda _key, conn: conn.ensure_sysctl(
                name,
                value,
                state=state,
                config_file=config_file,
                reload=reload,
                sudo=sudo,
                dry_run=dry_run,
            ),
            batch_size=batch_size,
            max_fail_ratio=max_fail_ratio,
        )

    @contextlib.asynccontextmanager
    async def use_cassette(
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
    ) -> AsyncIterator[dict[str, Any]]:
        """Асинхронный контекстный менеджер записи/воспроизведения кассет для всего пула хостов.

        Если ``path`` оканчивается на ``.yaml``, ``.yml`` или ``.json`` — используется
        единый общий файл кассеты для всех хостов пула. Иначе ``path`` трактуется
        как директория, в которой для каждого хоста создаётся файл ``<dir>/<host>.yaml``.
        """
        import re as _re

        from ..exceptions import CassetteError
        from ..transports.replay.models import Cassette, RecordMode
        from ..transports.replay.proxy import CassetteTransportProxy

        target_path = Path(path)
        rec_mode = RecordMode(mode)
        is_single_file = target_path.suffix.lower() in (".yaml", ".yml", ".json")

        conns_by_idx: dict[int, Connection] = {}
        keys_by_idx: dict[int, str] = {}
        for idx, target in enumerate(self._uris):
            key = self._target_key(target)
            keys_by_idx[idx] = key
            if self._is_entered and idx in self._active_conns:
                conns_by_idx[idx] = self._active_conns[idx]
            else:
                conn = self._build_conn(target, with_defaults=True)
                conns_by_idx[idx] = conn
                self._cassette_conns[idx] = conn

        try:
            if not is_single_file:
                used_names: set[str] = set()
                async with contextlib.AsyncExitStack() as stack:
                    cassettes: dict[str, Cassette] = {}
                    for idx, conn in conns_by_idx.items():
                        key = keys_by_idx[idx]
                        raw_host = key.split("://", 1)[-1]
                        safe_name = (
                            _re.sub(r"[^a-zA-Z0-9._-]+", "_", raw_host).strip("_")
                            or f"host_{idx}"
                        )
                        if safe_name in used_names:
                            safe_name = f"{safe_name}_{idx}"
                        used_names.add(safe_name)
                        host_file = target_path / f"{safe_name}.yaml"
                        cass = await stack.enter_async_context(
                            conn.use_cassette(
                                host_file,
                                mode=rec_mode,
                                match_on=match_on,
                                normalize_temp=normalize_temp,
                                allow_playback_repeats=allow_playback_repeats,
                                mask_secrets=mask_secrets,
                            )
                        )
                        cassettes[key] = cass
                    yield cassettes
            else:
                exists = target_path.is_file()
                if exists and rec_mode != RecordMode.ALL:
                    shared_cass = Cassette.load(target_path)
                else:
                    if rec_mode == RecordMode.NONE and not exists:
                        raise CassetteError(
                            f"Cassette file does not exist in RecordMode.NONE: {target_path}"
                        )
                    shared_cass = Cassette(
                        transport="pool",
                        host="pool",
                        capabilities=["exec", "stream", "file", "shell"],
                    )

                base_interactions = [
                    it.model_copy(deep=True) for it in shared_cass.interactions
                ]
                base_len = len(base_interactions)
                orig_transports: dict[int, Any] = {}
                proxies: dict[int, CassetteTransportProxy] = {}
                cassettes = {}

                for idx, conn in conns_by_idx.items():
                    key = keys_by_idx[idx]
                    orig = conn.transport
                    orig_transports[idx] = orig
                    host_cass = Cassette(
                        transport=orig.name,
                        host=conn.config.host or key,
                        capabilities=list(shared_cass.capabilities),
                        interactions=[
                            it.model_copy(deep=True) for it in base_interactions
                        ],
                    )
                    proxy = CassetteTransportProxy(
                        config=conn.config,
                        cassette=host_cass,
                        wrapped=orig,
                        mode=rec_mode,
                        cassette_exists=exists,
                        match_on=match_on,
                        normalize_temp=normalize_temp,
                        allow_playback_repeats=allow_playback_repeats,
                        mask_secrets=mask_secrets,
                    )
                    conn.swap_transport(proxy)
                    proxies[idx] = proxy
                    cassettes[key] = host_cass

                try:
                    yield cassettes
                finally:
                    any_dirty = False
                    new_items: list[Any] = []
                    for idx, conn in conns_by_idx.items():
                        proxy = proxies[idx]
                        if proxy.is_dirty:
                            any_dirty = True
                            new_items.extend(proxy.cassette.interactions[base_len:])
                        conn.swap_transport(orig_transports[idx])
                    if any_dirty:
                        shared_cass.interactions = [*base_interactions, *new_items]
                        shared_cass.save(target_path)
        finally:
            self._cassette_conns.clear()

    def stream(
        self,
        command: str | Sequence[str],
        timeout: float | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[tuple[str, str]]:
        """Мультиплексировать потоковый вывод команды со всех хостов пула в реальном времени."""
        return self._stream_mux.stream(command, timeout=timeout, **kwargs)

    def to_sync(self) -> SyncConnectionPool:
        """Конвертировать пул в синхронную обёртку ``SyncConnectionPool``."""
        from ..sync.pool import SyncConnectionPool

        return SyncConnectionPool(self)

