# src/uniconn/transports/ssh/sftp.py
"""Адаптер SFTP-операций поверх активного соединения asyncssh."""

from __future__ import annotations

import os
import stat as stat_module
from typing import Any

from ...exceptions import ConnectionError


class SFTPClientAdapter:
    """Инкапсулирует файловые операции SFTP для ``SSHTransport``."""

    def __init__(self, transport: Any) -> None:
        """Инициализировать адаптер для указанного SSH-транспорта."""
        self._transport = transport

    def _require_conn(self, asyncssh_mod: Any) -> Any:
        assert asyncssh_mod is not None
        if not self._transport._connected or not self._transport._conn:
            raise ConnectionError("Not connected", host=self._transport.config.host)
        return self._transport._conn

    async def upload(
        self,
        asyncssh_mod: Any,
        local_path: str,
        remote_path: str,
        recurse: bool = False,
        **kwargs: Any,
    ) -> None:
        """Загрузить файл или директорию через SFTP."""
        conn = self._require_conn(asyncssh_mod)
        if recurse is False and os.path.isdir(local_path):
            recurse = True

        try:
            async with conn.start_sftp_client() as sftp:
                if recurse:
                    await sftp.put(local_path, remote_path, recurse=True, **kwargs)
                else:
                    await sftp.put(local_path, remote_path, **kwargs)
        except asyncssh_mod.Error as e:
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
        **kwargs: Any,
    ) -> None:
        """Скачать файл или директорию через SFTP."""
        conn = self._require_conn(asyncssh_mod)
        try:
            async with conn.start_sftp_client() as sftp:
                if recurse:
                    await sftp.get(remote_path, local_path, recurse=True, **kwargs)
                else:
                    await sftp.get(remote_path, local_path, **kwargs)
        except asyncssh_mod.Error as e:
            raise ConnectionError(
                f"SFTP download failed: {remote_path} -> {local_path}: {e}",
                host=self._transport.config.host,
            ) from e

    async def chmod(self, asyncssh_mod: Any, remote_path: str, mode: int) -> None:
        """Изменить права доступа к файлу через SFTP."""
        conn = self._require_conn(asyncssh_mod)
        try:
            async with conn.start_sftp_client() as sftp:
                await sftp.chmod(remote_path, mode)
        except asyncssh_mod.Error as e:
            raise ConnectionError(
                f"SFTP chmod failed: {remote_path}: {e}",
                host=self._transport.config.host,
            ) from e

    async def stat(self, asyncssh_mod: Any, remote_path: str) -> dict[str, Any]:
        """Получить атрибуты файла через SFTP stat."""
        conn = self._require_conn(asyncssh_mod)
        try:
            async with conn.start_sftp_client() as sftp:
                attrs = await sftp.stat(remote_path)

            perms = attrs.permissions
            return {
                "size": attrs.size,
                "uid": attrs.uid,
                "gid": attrs.gid,
                "permissions": oct(perms) if perms is not None else None,
                "atime": attrs.atime,
                "mtime": attrs.mtime,
                "is_file": stat_module.S_ISREG(perms) if perms else False,
                "is_dir": stat_module.S_ISDIR(perms) if perms else False,
                "is_symlink": stat_module.S_ISLNK(perms) if perms else False,
            }
        except asyncssh_mod.Error as e:
            raise ConnectionError(
                f"SFTP stat failed: {remote_path}: {e}",
                host=self._transport.config.host,
            ) from e

    async def listdir(self, asyncssh_mod: Any, remote_path: str = ".") -> list[str]:
        """Получить список имён файлов через SFTP readdir."""
        conn = self._require_conn(asyncssh_mod)
        try:
            async with conn.start_sftp_client() as sftp:
                entries = await sftp.readdir(remote_path)
            return [entry.filename for entry in entries]
        except asyncssh_mod.Error as e:
            raise ConnectionError(
                f"SFTP listdir failed: {remote_path}: {e}",
                host=self._transport.config.host,
            ) from e

    async def read_file(self, asyncssh_mod: Any, remote_path: str) -> bytes:
        """Прочитать файл в память через SFTP."""
        conn = self._require_conn(asyncssh_mod)
        try:
            async with (
                conn.start_sftp_client() as sftp,
                sftp.open(remote_path, "rb") as f,
            ):
                data = await f.read()
            return data.encode("utf-8") if isinstance(data, str) else bytes(data)
        except asyncssh_mod.Error as e:
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
            async with conn.start_sftp_client() as sftp:
                async with sftp.open(remote_path, "wb") as f:
                    await f.write(data)
                if mode is not None:
                    await sftp.chmod(remote_path, mode)
        except asyncssh_mod.Error as e:
            raise ConnectionError(
                f"SFTP write_file failed: {remote_path}: {e}",
                host=self._transport.config.host,
            ) from e

    async def exists(self, asyncssh_mod: Any, remote_path: str) -> bool:
        """Проверить существование пути через SFTP stat."""
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
        """Создать директорию через SFTP."""
        conn = self._require_conn(asyncssh_mod)
        try:
            async with conn.start_sftp_client() as sftp:
                if parents and hasattr(sftp, "makedirs"):
                    await sftp.makedirs(remote_path, exist_ok=exist_ok)
                else:
                    await sftp.mkdir(remote_path)
                if mode is not None:
                    await sftp.chmod(remote_path, mode)
        except asyncssh_mod.Error as e:
            raise ConnectionError(
                f"SFTP mkdir failed: {remote_path}: {e}",
                host=self._transport.config.host,
            ) from e

    async def remove_file(self, asyncssh_mod: Any, remote_path: str) -> None:
        """Удалить файл через SFTP."""
        conn = self._require_conn(asyncssh_mod)
        try:
            async with conn.start_sftp_client() as sftp:
                await sftp.remove(remote_path)
        except asyncssh_mod.Error as e:
            raise ConnectionError(
                f"SFTP remove_file failed: {remote_path}: {e}",
                host=self._transport.config.host,
            ) from e
