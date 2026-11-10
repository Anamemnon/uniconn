# src/uniconn/pool/services.py
"""Доменные сервисы пула подключений: ``PoolFileOperationsService`` и ``PoolStateManagementService``."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..core.bridge import pool_fan_out_dict
from ..services.files import FileOperationsService
from ..services.network import NetworkOperationsService
from ..services.provisioning import StateManagementService

if TYPE_CHECKING:
    from ..core.connection import Connection
    from .connection_pool import ConnectionPool


class PoolFileOperationsService:
    """Доменный сервис файловых операций для ``ConnectionPool`` (``pool.files``)."""

    def __init__(self, pool: ConnectionPool) -> None:
        """Инициализировать файловый сервис пула подключений."""
        self._pool = pool

    async def upload(
        self,
        local_path: str | Path,
        remote_path: str | Path,
        recurse: bool = False,
        *,
        verify: bool = False,
        progress_callback: Callable[[int, int], None] | None = None,
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
        **kwargs: Any,
    ) -> None:
        """Параллельно загрузить файл или директорию на все хосты пула."""
        if progress_callback is not None:
            kwargs["progress_callback"] = progress_callback
        await self._pool._fan_out_list(
            lambda conn: conn.files.upload(
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
        progress_callback: Callable[[int, int], None] | None = None,
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
        **kwargs: Any,
    ) -> dict[str, str]:
        """Параллельно скачать файл или директорию со всех хостов пула."""
        if progress_callback is not None:
            kwargs["progress_callback"] = progress_callback
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
            elif len(self._pool._uris) > 1:
                dest_dir = Path(local_str) / safe_host
                dest_dir.mkdir(parents=True, exist_ok=True)
                dest = str(dest_dir / remote_name)
            else:
                dest = local_str

            await conn.files.download(
                str(remote_path),
                dest,
                recurse=recurse,
                **({"verify": True} if verify else {}),
                **kwargs,
            )
            return dest

        return await self._pool._fan_out_dict(
            _dl_worker,
            batch_size=batch_size,
            max_fail_ratio=max_fail_ratio,
        )

    upload_xmodem = pool_fan_out_dict(
        FileOperationsService.upload_xmodem, conn_attr="files"
    )
    upload_ymodem = pool_fan_out_dict(
        FileOperationsService.upload_ymodem, conn_attr="files"
    )
    download_xmodem = pool_fan_out_dict(
        FileOperationsService.download_xmodem, conn_attr="files"
    )
    download_ymodem = pool_fan_out_dict(
        FileOperationsService.download_ymodem, conn_attr="files"
    )
    read_file = pool_fan_out_dict(FileOperationsService.read_file, conn_attr="files")
    write_file = pool_fan_out_dict(FileOperationsService.write_file, conn_attr="files")
    checksum = pool_fan_out_dict(FileOperationsService.checksum, conn_attr="files")
    exists = pool_fan_out_dict(FileOperationsService.exists, conn_attr="files")
    mkdir = pool_fan_out_dict(FileOperationsService.mkdir, conn_attr="files")
    chmod = pool_fan_out_dict(FileOperationsService.chmod, conn_attr="files")
    stat = pool_fan_out_dict(FileOperationsService.stat, conn_attr="files")
    listdir = pool_fan_out_dict(FileOperationsService.listdir, conn_attr="files")
    remove_file = pool_fan_out_dict(
        FileOperationsService.remove_file, conn_attr="files"
    )
    write_template = pool_fan_out_dict(
        FileOperationsService.write_template, conn_attr="files"
    )
    sync_dir = pool_fan_out_dict(FileOperationsService.sync_dir, conn_attr="files")


class PoolNotificationBatch:
    """Групповой контекст отложенного выполнения и дедупликации ``notify`` для ``ConnectionPool``."""

    def __init__(self, pool: ConnectionPool) -> None:
        """Инициализировать батч уведомлений для пула подключений."""
        self._pool = pool
        self._batches: dict[str, Any] = {}
        self._results: dict[str, list[Any]] = {}
        self._entered_pool_here = False

    @property
    def batches(self) -> dict[str, Any]:
        """Словарь ``NotificationBatch`` по ключам хостов пула."""
        return dict(self._batches)

    @property
    def pending_count(self) -> int:
        """Суммарное число уникальных ожидающих обработчиков по всем хостам пула."""
        return sum(b.pending_count for b in self._batches.values())

    @property
    def triggered_count(self) -> int:
        """Суммарное число срабатываний ``notify`` по всем хостам пула (до дедупликации)."""
        return sum(b.triggered_count for b in self._batches.values())

    @property
    def executed_count(self) -> int:
        """Суммарное число выполненных уникальных обработчиков по всем хостам пула."""
        return sum(b.executed_count for b in self._batches.values())

    @property
    def results(self) -> dict[str, list[Any]]:
        """Словарь списков результатов выполнения обработчиков по каждому хосту пула."""
        return {host: list(b.results) for host, b in self._batches.items()}

    @property
    def ok(self) -> bool:
        """Вернуть ``True``, если все выполненные обработчики на всех хостах завершились успешно."""
        return all(b.ok for b in self._batches.values())

    async def flush(self) -> dict[str, list[Any]]:
        """Параллельно выполнить накопленные обработчики на всех хостах пула."""
        flushed: dict[str, list[Any]] = {}

        async def _flush_host(host_key: str, batch: Any) -> None:
            async with self._pool._semaphore:
                flushed[host_key] = await batch.flush()

        async with asyncio.TaskGroup() as tg:
            for key, batch in self._batches.items():
                tg.create_task(_flush_host(key, batch))

        self._results = {host: list(b.results) for host, b in self._batches.items()}
        return flushed

    async def __aenter__(self) -> PoolNotificationBatch:
        """Активировать ``NotificationBatch`` на всех соединениях пула."""
        if not self._pool._is_entered:
            await self._pool.__aenter__()
            self._entered_pool_here = True

        self._batches.clear()
        for idx, target in enumerate(self._pool._uris):
            key = self._pool._target_key(target)
            conn = self._pool._active_conns.get(idx)
            if conn is not None:
                batch = conn.state.batch_notifications()
                await batch.__aenter__()
                self._batches[key] = batch
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Снять батчи со всех соединений пула и параллельно выполнить обработчики при успехе."""
        try:
            if exc_type is None:
                await self.flush()
        finally:
            for batch in self._batches.values():
                batch._service._pop_batch(batch)
            if self._entered_pool_here:
                await self._pool.__aexit__(exc_type, exc_val, exc_tb)
                self._entered_pool_here = False


class PoolStateManagementService:
    """Доменный сервис идемпотентного управления состоянием для ``ConnectionPool`` (``pool.state``)."""

    def __init__(self, pool: ConnectionPool) -> None:
        """Инициализировать сервис управления состоянием пула подключений."""
        self._pool = pool

    def batch_notifications(self) -> PoolNotificationBatch:
        """Создать групповой контекстный менеджер дедупликации ``notify`` по всем хостам пула."""
        return PoolNotificationBatch(self._pool)

    ensure_package = pool_fan_out_dict(
        StateManagementService.ensure_package, conn_attr="state"
    )
    ensure_service = pool_fan_out_dict(
        StateManagementService.ensure_service, conn_attr="state"
    )
    ensure_line = pool_fan_out_dict(
        StateManagementService.ensure_line, conn_attr="state"
    )
    ensure_file = pool_fan_out_dict(
        StateManagementService.ensure_file, conn_attr="state"
    )
    ensure_directory = pool_fan_out_dict(
        StateManagementService.ensure_directory, conn_attr="state"
    )
    ensure_user = pool_fan_out_dict(
        StateManagementService.ensure_user, conn_attr="state"
    )
    ensure_authorized_key = pool_fan_out_dict(
        StateManagementService.ensure_authorized_key, conn_attr="state"
    )
    ensure_systemd_unit = pool_fan_out_dict(
        StateManagementService.ensure_systemd_unit, conn_attr="state"
    )
    ensure_sysctl = pool_fan_out_dict(
        StateManagementService.ensure_sysctl, conn_attr="state"
    )
    ensure_yang = pool_fan_out_dict(
        StateManagementService.ensure_yang, conn_attr="state"
    )
    ensure_yang_config = pool_fan_out_dict(
        StateManagementService.ensure_yang_config, conn_attr="state"
    )


class PoolNetworkOperationsService:
    """Доменный сервис структурированных сетевых операций для ``ConnectionPool`` (``pool.net``)."""

    def __init__(self, pool: ConnectionPool) -> None:
        """Инициализировать сетевой сервис пула подключений."""
        self._pool = pool

    get = pool_fan_out_dict(NetworkOperationsService.get, conn_attr="net")
    get_config = pool_fan_out_dict(NetworkOperationsService.get_config, conn_attr="net")
    edit = pool_fan_out_dict(NetworkOperationsService.edit, conn_attr="net")
    commit = pool_fan_out_dict(NetworkOperationsService.commit, conn_attr="net")
    commit_confirm = pool_fan_out_dict(
        NetworkOperationsService.commit_confirm, conn_attr="net"
    )
    discard_changes = pool_fan_out_dict(
        NetworkOperationsService.discard_changes, conn_attr="net"
    )
    validate = pool_fan_out_dict(NetworkOperationsService.validate, conn_attr="net")
    lock = pool_fan_out_dict(NetworkOperationsService.lock, conn_attr="net")
    unlock = pool_fan_out_dict(NetworkOperationsService.unlock, conn_attr="net")
    capabilities = pool_fan_out_dict(
        NetworkOperationsService.capabilities, conn_attr="net"
    )
    rpc = pool_fan_out_dict(NetworkOperationsService.rpc, conn_attr="net")


__all__ = [
    "PoolFileOperationsService",
    "PoolNetworkOperationsService",
    "PoolNotificationBatch",
    "PoolStateManagementService",
]

