# src/uniconn/_pool.py
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

from ._config import ConnectionConfig
from ._connection import Connection, format_command
from ._facts import HostFacts
from .pool.stream_mux import PoolStreamMultiplexer
from .result import EnsureResult, Result, SyncResult

if TYPE_CHECKING:
    from ._sync import SyncConnectionPool

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
    ) -> None:
        self._uris = list(uris)
        self._max_concurrent = max_concurrent
        self._retry_attempts = retry_attempts
        self._logger = logger or logging.getLogger(__name__)
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._active_conns: dict[int, Connection] = {}
        self._is_entered = False
        self._stream_mux = PoolStreamMultiplexer(self)

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
        )

    @staticmethod
    def _target_key(target: PoolTarget) -> str:
        """Вернуть строковый ключ хоста для словаря результатов."""
        if isinstance(target, str):
            return target
        if isinstance(target, ConnectionConfig):
            return target.host or target.uri_safe
        return target.config.host or target.config.uri_safe

    def _build_conn(
        self, target: PoolTarget, *, with_defaults: bool = True
    ) -> Connection:
        """Создать экземпляр Connection из элемента пула."""
        if isinstance(target, Connection):
            return target
        if isinstance(target, ConnectionConfig):
            return Connection.from_config(
                target,
                retry_attempts=self._retry_attempts,
                logger=self._logger,
            )
        if with_defaults:
            return Connection.from_uri(
                target,
                retry_attempts=self._retry_attempts,
                logger=self._logger,
            )
        return Connection.from_uri(target)

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
        async with conn as active:
            yield active

    async def _fan_out_list(
        self,
        worker: Callable[[Connection], Awaitable[T]],
        *,
        with_defaults: bool = True,
        log_errors: bool = False,
    ) -> list[T]:
        """Выполнить ``worker(conn)`` параллельно на всех хостах и вернуть список в порядке пула."""

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
    ) -> dict[str, T]:
        """Выполнить ``worker(key, conn)`` параллельно на всех хостах и вернуть словарь ``{key: T}``."""
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
        except* Exception:
            await self.close()
            raise

    async def close(self) -> None:
        """Закрыть все удерживаемые пулом соединения."""
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
        **kwargs: Any,
    ) -> None:
        """Параллельно загрузить файл или директорию на все хосты пула."""
        await self._fan_out_list(
            lambda conn: conn.upload(
                str(local_path),
                str(remote_path),
                recurse=recurse,
                **kwargs,
            )
        )

    async def download(
        self,
        remote_path: str | Path,
        local_path: str | Path,
        recurse: bool = False,
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
                **kwargs,
            )
            return dest

        return await self._fan_out_dict(_dl_worker)

    async def apply(
        self,
        func: Callable[[Connection], Awaitable[T]],
    ) -> list[T]:
        """Параллельно выполнить произвольную async-функцию ``func(conn)`` на всех хостах пула."""
        return await self._fan_out_list(func)

    async def sync_dir(
        self,
        local_dir: str | Path,
        remote_dir: str | Path,
        delete: bool = False,
        exclude: Sequence[str] | None = None,
        mtime_tolerance: float = 1.0,
        dry_run: bool | None = None,
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
            )
        )

    async def write_template(
        self,
        remote_path: str | Path,
        template_str_or_path: str | Path,
        context: Mapping[str, Any] | None = None,
        mode: int | None = 0o644,
        encoding: str = "utf-8",
        engine: Literal["auto", "string", "jinja2"] = "auto",
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
            )
        )

    async def gather_facts(
        self,
        refresh: bool = False,
        timeout: float | None = None,
    ) -> dict[str, HostFacts]:
        """Параллельно собрать системные факты (``HostFacts``) со всех хостов пула."""
        return await self._fan_out_dict(
            lambda _key, conn: conn.gather_facts(refresh=refresh, timeout=timeout)
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
            )
        )

    async def ensure_service(
        self,
        service: str,
        state: Literal["started", "stopped", "restarted", "reloaded"] = "started",
        enabled: bool | None = None,
        sudo: bool = True,
        dry_run: bool | None = None,
    ) -> dict[str, EnsureResult]:
        """Параллельно привести состояние системного сервиса на всех хостах пула."""
        return await self._fan_out_dict(
            lambda _key, conn: conn.ensure_service(
                service=service,
                state=state,
                enabled=enabled,
                sudo=sudo,
                dry_run=dry_run,
            )
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
            )
        )

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
        from ._sync import SyncConnectionPool

        return SyncConnectionPool(self)
