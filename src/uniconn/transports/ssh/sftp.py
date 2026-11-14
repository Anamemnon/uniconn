# src/uniconn/transports/ssh/sftp.py
"""Адаптер SFTP-операций поверх активного соединения asyncssh."""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import os
import stat as stat_module
from collections.abc import Callable
from typing import Any

from ...exceptions import ConnectionError
from ..base import FileStat


class SFTPClientAdapter:
    """Инкапсулирует файловые операции SFTP для ``SSHTransport`` с переиспользованием SFTP-сессии."""

    def __init__(self, transport: Any) -> None:
        """Инициализировать адаптер для указанного SSH-транспорта."""
        self._transport = transport
        self._sftp_client: Any = None
        self._sftp_cm: Any = None
        self._sftp_conn: Any = None
        self._sftp_loop: asyncio.AbstractEventLoop | None = None
        self._sftp_lock: asyncio.Lock | None = None
        self._sftp_lock_loop: asyncio.AbstractEventLoop | None = None

    def _require_conn(self, asyncssh_mod: Any) -> Any:
        assert asyncssh_mod is not None
        if not self._transport._connected or not self._transport._conn:
            raise ConnectionError("Not connected", host=self._transport.config.host)
        return self._transport._conn

    def _get_lock(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        if self._sftp_lock is None or self._sftp_lock_loop is not loop:
            self._sftp_lock = asyncio.Lock()
            self._sftp_lock_loop = loop
        return self._sftp_lock

    async def _close_cached_locked(self) -> None:
        cm = self._sftp_cm
        client = self._sftp_client
        self._sftp_cm = None
        self._sftp_client = None
        self._sftp_conn = None
        self._sftp_loop = None
        if cm is not None and hasattr(cm, "__aexit__"):
            with contextlib.suppress(Exception):
                await cm.__aexit__(None, None, None)
        elif client is not None:
            for exit_name in ("exit", "close"):
                fn = getattr(client, exit_name, None)
                if callable(fn):
                    with contextlib.suppress(Exception):
                        res = fn()
                        if inspect.isawaitable(res):
                            await res
                    break
            wait_closed = getattr(client, "wait_closed", None)
            if callable(wait_closed):
                with contextlib.suppress(Exception):
                    wres = wait_closed()
                    if inspect.isawaitable(wres):
                        await wres

    async def close(self) -> None:
        """Закрыть закэшированную SFTP-сессию."""
        async with self._get_lock():
            await self._close_cached_locked()

    @staticmethod
    def _safe_conn_is_closed(conn: Any) -> bool:
        is_closed_fn = getattr(conn, "is_closed", None)
        if not callable(is_closed_fn) or inspect.iscoroutinefunction(is_closed_fn):
            return False
        with contextlib.suppress(Exception):
            res = is_closed_fn()
            if inspect.iscoroutine(res):
                res.close()
                return False
            if inspect.isawaitable(res):
                return False
            return bool(res)
        return False

    @classmethod
    def _is_conn_closed(cls, conn: Any, exc: BaseException) -> bool:
        if cls._safe_conn_is_closed(conn):
            return True
        cls_name = type(exc).__name__
        return cls_name in ("DisconnectError", "ChannelOpenError", "ConnectionLost", "SFTPConnectionLost")

    async def _get_sftp(self, asyncssh_mod: Any) -> Any:
        conn = self._require_conn(asyncssh_mod)
        loop = asyncio.get_running_loop()
        async with self._get_lock():
            if (
                self._sftp_client is not None
                and self._sftp_conn is conn
                and self._sftp_loop is loop
                and not self._safe_conn_is_closed(conn)
            ):
                return self._sftp_client
            if self._sftp_client is not None or self._sftp_cm is not None:
                await self._close_cached_locked()
            cm = conn.start_sftp_client()
            if hasattr(cm, "__aenter__"):
                sftp = await cm.__aenter__()
                self._sftp_cm = cm
            elif inspect.isawaitable(cm):
                sftp = await cm
                self._sftp_cm = None
            else:
                sftp = cm
                self._sftp_cm = None
            self._sftp_client = sftp
            self._sftp_conn = conn
            self._sftp_loop = loop
            return sftp

    async def upload(
        self,
        asyncssh_mod: Any,
        local_path: str,
        remote_path: str,
        recurse: bool = False,
        *,
        progress_callback: Callable[[int, int], None] | None = None,
        **kwargs: Any,
    ) -> None:
        """Загрузить файл или директорию через SFTP."""
        conn = self._require_conn(asyncssh_mod)
        if recurse is False and os.path.isdir(local_path):
            recurse = True

        if progress_callback is not None and "progress_handler" not in kwargs:
            kwargs["progress_handler"] = (
                lambda _src, _dst, copied, total: progress_callback(int(copied), int(total))
            )

        try:
            sftp = await self._get_sftp(asyncssh_mod)
            if recurse:
                await sftp.put(local_path, remote_path, recurse=True, **kwargs)
            else:
                await sftp.put(local_path, remote_path, **kwargs)
        except asyncssh_mod.Error as e:
            if self._is_conn_closed(conn, e):
                await self.close()
            raise ConnectionError(
                f"SFTP upload failed: {local_path} -> {remote_path}: {e}",
                host=self._transport.config.host,
            ) from e

    async def download(
        self,
        asyncssh_mod: Any,
        remote_path: str,
        local_path: str,
        recurse: bool = False,
        *,
        progress_callback: Callable[[int, int], None] | None = None,
        **kwargs: Any,
    ) -> None:
        """Скачать файл или директорию через SFTP."""
        conn = self._require_conn(asyncssh_mod)
        if progress_callback is not None and "progress_handler" not in kwargs:
            kwargs["progress_handler"] = (
                lambda _src, _dst, copied, total: progress_callback(int(copied), int(total))
            )

        try:
            sftp = await self._get_sftp(asyncssh_mod)
            if recurse:
                await sftp.get(remote_path, local_path, recurse=True, **kwargs)
            else:
                await sftp.get(remote_path, local_path, **kwargs)
        except asyncssh_mod.Error as e:
            if self._is_conn_closed(conn, e):
                await self.close()
            raise ConnectionError(
                f"SFTP download failed: {remote_path} -> {local_path}: {e}",
                host=self._transport.config.host,
            ) from e

    async def chmod(self, asyncssh_mod: Any, remote_path: str, mode: int) -> None:
        """Изменить права доступа к файлу через SFTP."""
        conn = self._require_conn(asyncssh_mod)
        try:
            sftp = await self._get_sftp(asyncssh_mod)
            await sftp.chmod(remote_path, mode)
        except asyncssh_mod.Error as e:
            if self._is_conn_closed(conn, e):
                await self.close()
            raise ConnectionError(
                f"SFTP chmod failed: {remote_path}: {e}",
                host=self._transport.config.host,
            ) from e

    async def stat(self, asyncssh_mod: Any, remote_path: str) -> FileStat:
        """Получить атрибуты файла через SFTP lstat (без разыменования симлинков)."""
        conn = self._require_conn(asyncssh_mod)
        try:
            sftp = await self._get_sftp(asyncssh_mod)
            attrs = await sftp.lstat(remote_path)

            perms = attrs.permissions
            is_symlink = stat_module.S_ISLNK(perms) if perms else False
            return {
                "size": attrs.size,
                "uid": attrs.uid,
                "gid": attrs.gid,
                "permissions": oct(perms) if perms is not None else None,
                "atime": attrs.atime,
                "mtime": attrs.mtime,
                "is_file": stat_module.S_ISREG(perms) if perms else False,
                "is_dir": (stat_module.S_ISDIR(perms) and not is_symlink) if perms else False,
                "is_symlink": is_symlink,
            }
        except asyncssh_mod.Error as e:
            if self._is_conn_closed(conn, e):
                await self.close()
            raise ConnectionError(
                f"SFTP stat failed: {remote_path}: {e}",
                host=self._transport.config.host,
            ) from e

    async def listdir(self, asyncssh_mod: Any, remote_path: str = ".") -> list[str]:
        """Получить список имён файлов через SFTP readdir."""
        conn = self._require_conn(asyncssh_mod)
        try:
            sftp = await self._get_sftp(asyncssh_mod)
            entries = await sftp.readdir(remote_path)
            return [entry.filename for entry in entries]
        except asyncssh_mod.Error as e:
            if self._is_conn_closed(conn, e):
                await self.close()
            raise ConnectionError(
                f"SFTP listdir failed: {remote_path}: {e}",
                host=self._transport.config.host,
            ) from e

    async def read_file(self, asyncssh_mod: Any, remote_path: str) -> bytes:
        """Прочитать файл в память через SFTP."""
        conn = self._require_conn(asyncssh_mod)
        try:
            sftp = await self._get_sftp(asyncssh_mod)
            async with sftp.open(remote_path, "rb") as f:
                data = await f.read()
            return data.encode("utf-8") if isinstance(data, str) else bytes(data)
        except asyncssh_mod.Error as e:
            if self._is_conn_closed(conn, e):
                await self.close()
            raise ConnectionError(
                f"SFTP read_file failed: {remote_path}: {e}",
                host=self._transport.config.host,
            ) from e

    async def write_file(
        self,
        asyncssh_mod: Any,
        remote_path: str,
        data: bytes,
        mode: int | None = None,
    ) -> None:
        """Записать байты в файл через SFTP."""
        conn = self._require_conn(asyncssh_mod)
        try:
            sftp = await self._get_sftp(asyncssh_mod)
            async with sftp.open(remote_path, "wb") as f:
                await f.write(data)
            if mode is not None:
                await sftp.chmod(remote_path, mode)
        except asyncssh_mod.Error as e:
            if self._is_conn_closed(conn, e):
                await self.close()
            raise ConnectionError(
                f"SFTP write_file failed: {remote_path}: {e}",
                host=self._transport.config.host,
            ) from e

    async def exists(self, asyncssh_mod: Any, remote_path: str) -> bool:
        """Проверить существование пути через SFTP lstat."""
        self._require_conn(asyncssh_mod)
        try:
            await self.stat(asyncssh_mod, remote_path)
            return True
        except ConnectionError:
            return False

    async def mkdir(
        self,
        asyncssh_mod: Any,
        remote_path: str,
        parents: bool = True,
        exist_ok: bool = True,
        mode: int | None = None,
    ) -> None:
        """Создать директорию через SFTP с поддержкой ``parents`` и ``exist_ok``."""
        conn = self._require_conn(asyncssh_mod)
        try:
            sftp = await self._get_sftp(asyncssh_mod)
            if parents and hasattr(sftp, "makedirs"):
                await sftp.makedirs(remote_path, exist_ok=exist_ok)
            elif parents:
                await self._mkdir_parents_fallback(asyncssh_mod, sftp, remote_path, exist_ok=exist_ok)
            else:
                await self._mkdir_single(asyncssh_mod, sftp, remote_path, exist_ok=exist_ok)
            if mode is not None:
                await sftp.chmod(remote_path, mode)
        except asyncssh_mod.Error as e:
            if self._is_conn_closed(conn, e):
                await self.close()
            raise ConnectionError(
                f"SFTP mkdir failed: {remote_path}: {e}",
                host=self._transport.config.host,
            ) from e

    async def _mkdir_single(
        self,
        asyncssh_mod: Any,
        sftp: Any,
        target: str,
        *,
        exist_ok: bool,
    ) -> None:
        """Создать одиночную директорию в SFTP с учётом ``exist_ok``."""
        try:
            await sftp.mkdir(target)
        except asyncssh_mod.Error:
            if not exist_ok:
                raise
            if hasattr(sftp, "isdir"):
                if await sftp.isdir(target):
                    return
            elif hasattr(sftp, "stat"):
                st = await sftp.stat(target)
                perms = getattr(st, "permissions", None)
                if perms is None or stat_module.S_ISDIR(int(perms)):
                    return
            raise

    async def _mkdir_parents_fallback(
        self,
        asyncssh_mod: Any,
        sftp: Any,
        remote_path: str,
        *,
        exist_ok: bool,
    ) -> None:
        """Пошагово создать цепочку родительских директорий, если ``sftp.makedirs`` недоступен."""
        norm = remote_path.rstrip("/") or "/"
        if norm == "/":
            return
        is_abs = norm.startswith("/")
        parts = [p for p in norm.split("/") if p]
        current = ""
        for idx, part in enumerate(parts):
            current = f"{current}/{part}" if (current or is_abs) else part
            is_last = idx == len(parts) - 1
            await self._mkdir_single(
                asyncssh_mod,
                sftp,
                current,
                exist_ok=exist_ok if is_last else True,
            )

    async def remove_file(self, asyncssh_mod: Any, remote_path: str) -> None:
        """Удалить файл через SFTP."""
        conn = self._require_conn(asyncssh_mod)
        try:
            sftp = await self._get_sftp(asyncssh_mod)
            await sftp.remove(remote_path)
        except asyncssh_mod.Error as e:
            if self._is_conn_closed(conn, e):
                await self.close()
            raise ConnectionError(
                f"SFTP remove_file failed: {remote_path}: {e}",
                host=self._transport.config.host,
            ) from e
