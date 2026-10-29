# src/uniconn/pool/services.py
"""Доменные сервисы пула подключений: ``PoolFileOperationsService`` и ``PoolStateManagementService``."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..core.bridge import pool_fan_out_dict
from ..services.files import FileOperationsService
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


class PoolStateManagementService:
    """Доменный сервис идемпотентного управления состоянием для ``ConnectionPool`` (``pool.state``)."""

    def __init__(self, pool: ConnectionPool) -> None:
        """Инициализировать сервис управления состоянием пула подключений."""
        self._pool = pool

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


__all__ = [
    "PoolFileOperationsService",
    "PoolStateManagementService",
]
