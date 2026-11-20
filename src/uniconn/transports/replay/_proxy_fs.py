# src/uniconn/transports/replay/_proxy_fs.py
"""Файловые операции (SFTP/FS) записи и воспроизведения для CassetteTransportProxy."""

from __future__ import annotations

import base64
import contextlib
import hashlib
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from ...exceptions import CapabilityNotSupportedError
from ..base import BaseTransport, FileCapableTransport, FileStat, supports_capability
from ._proxy_matching import _CassetteMatchingMixin
from .models import RecordedFsInteraction

if TYPE_CHECKING:
    from ...config.models import ConnectionConfig
    from .models import Cassette


class _CassetteFsMixin(_CassetteMatchingMixin):
    """Миксин файловых операций для ``CassetteTransportProxy``."""

    if TYPE_CHECKING:
        config: ConnectionConfig
        _cassette: Cassette
        _wrapped: BaseTransport | None
        _dirty: bool

        @property
        def name(self) -> str: ...

        async def _ensure_real_connected(self) -> BaseTransport: ...

    def _check_fs_supported(self, op_name: str) -> None:
        if "file" not in self._cassette.capabilities:
            raise CapabilityNotSupportedError(
                f"{op_name} not supported for {self.name} transport",
                host=self.config.host,
            )
        if (
            self._wrapped is not None
            and not self._can_replay()
            and not supports_capability(self._wrapped, FileCapableTransport)
        ):
            raise CapabilityNotSupportedError(
                f"{op_name} not supported for {self._wrapped.name} transport",
                host=self.config.host,
            )

    async def read_file(self, remote_path: str) -> bytes:
        """Прочитать файл из кассеты или реального транспорта."""
        self._check_fs_supported("read_file")
        if self._can_replay():
            matched = self._match_fs("read_file", remote_path)
            if matched is not None:
                self._raise_recorded_error(
                    matched.error_class,
                    matched.error_message,
                    command=f"read_file {remote_path}",
                    host=self.config.host,
                )
                if matched.content_base64 is not None:
                    return base64.b64decode(matched.content_base64)
                return (matched.content_utf8 or "").encode("utf-8")
            if not self._can_record():
                self._raise_fs_miss("read_file", remote_path)

        real = await self._ensure_real_connected()
        norm_path = self._sanitize_text(remote_path, normalize=True)
        try:
            data = await real.read_file(remote_path)
        except Exception as exc:
            self._cassette.interactions.append(
                RecordedFsInteraction(
                    operation="read_file",
                    path=norm_path,
                    error_class=type(exc).__name__,
                    error_message=self._sanitize_text(str(exc)),
                )
            )
            self._dirty = True
            raise

        try:
            utf8_str = self._sanitize_text(data.decode("utf-8"))
            b64_str: str | None = None
        except UnicodeDecodeError:
            utf8_str = None
            b64_str = base64.b64encode(data).decode("ascii")

        self._cassette.interactions.append(
            RecordedFsInteraction(
                operation="read_file",
                path=norm_path,
                content_utf8=utf8_str,
                content_base64=b64_str,
                content_sha256=hashlib.sha256(data).hexdigest(),
            )
        )
        self._dirty = True
        return data

    async def write_file(
        self,
        remote_path: str,
        data: bytes,
        mode: int | None = None,
    ) -> None:
        """Записать файл в кассету или реальный транспорт."""
        self._check_fs_supported("write_file")
        if self._can_replay():
            matched = self._match_fs("write_file", remote_path)
            if matched is not None:
                self._raise_recorded_error(
                    matched.error_class,
                    matched.error_message,
                    command=f"write_file {remote_path}",
                    host=self.config.host,
                )
                return
            if not self._can_record():
                self._raise_fs_miss("write_file", remote_path)

        real = await self._ensure_real_connected()
        norm_path = self._sanitize_text(remote_path, normalize=True)
        await real.write_file(remote_path, data, mode=mode)
        try:
            utf8_str: str | None = self._sanitize_text(data.decode("utf-8"))
        except UnicodeDecodeError:
            utf8_str = None
        self._cassette.interactions.append(
            RecordedFsInteraction(
                operation="write_file",
                path=norm_path,
                mode=mode,
                content_utf8=utf8_str,
                content_sha256=hashlib.sha256(data).hexdigest(),
            )
        )
        self._dirty = True

    async def exists(self, remote_path: str) -> bool:
        """Проверить существование файла по кассете или реальному транспорту."""
        self._check_fs_supported("exists")
        if self._can_replay():
            matched = self._match_fs("exists", remote_path)
            if matched is not None:
                self._raise_recorded_error(
                    matched.error_class,
                    matched.error_message,
                    command=f"exists {remote_path}",
                    host=self.config.host,
                )
                return bool(matched.result_bool)
            if not self._can_record():
                self._raise_fs_miss("exists", remote_path)

        real = await self._ensure_real_connected()
        res = await real.exists(remote_path)
        self._cassette.interactions.append(
            RecordedFsInteraction(
                operation="exists",
                path=self._sanitize_text(remote_path, normalize=True),
                result_bool=res,
            )
        )
        self._dirty = True
        return res

    async def stat(self, remote_path: str) -> FileStat:
        """Получить stat-метаданные файла из кассеты или реального транспорта."""
        self._check_fs_supported("stat")
        if self._can_replay():
            matched = self._match_fs("stat", remote_path)
            if matched is not None:
                self._raise_recorded_error(
                    matched.error_class,
                    matched.error_message,
                    command=f"stat {remote_path}",
                    host=self.config.host,
                )
                return cast(FileStat, dict(matched.result_stat or {}))
            if not self._can_record():
                self._raise_fs_miss("stat", remote_path)

        real = await self._ensure_real_connected()
        res = await real.stat(remote_path)
        self._cassette.interactions.append(
            RecordedFsInteraction(
                operation="stat",
                path=self._sanitize_text(remote_path, normalize=True),
                result_stat=dict(res),
            )
        )
        self._dirty = True
        return res

    async def listdir(self, remote_path: str = ".") -> list[str]:
        """Получить список файлов директории из кассеты или реального транспорта."""
        self._check_fs_supported("listdir")
        if self._can_replay():
            matched = self._match_fs("listdir", remote_path)
            if matched is not None:
                self._raise_recorded_error(
                    matched.error_class,
                    matched.error_message,
                    command=f"listdir {remote_path}",
                    host=self.config.host,
                )
                return list(matched.result_list)
            if not self._can_record():
                self._raise_fs_miss("listdir", remote_path)

        real = await self._ensure_real_connected()
        res = await real.listdir(remote_path)
        self._cassette.interactions.append(
            RecordedFsInteraction(
                operation="listdir",
                path=self._sanitize_text(remote_path, normalize=True),
                result_list=list(res),
            )
        )
        self._dirty = True
        return res

    async def mkdir(
        self,
        remote_path: str,
        parents: bool = True,
        exist_ok: bool = True,
        mode: int | None = None,
    ) -> None:
        """Создать директорию через кассету или реальный транспорт."""
        self._check_fs_supported("mkdir")
        if self._can_replay():
            matched = self._match_fs("mkdir", remote_path)
            if matched is not None:
                self._raise_recorded_error(
                    matched.error_class,
                    matched.error_message,
                    command=f"mkdir {remote_path}",
                    host=self.config.host,
                )
                return
            if not self._can_record():
                self._raise_fs_miss("mkdir", remote_path)

        real = await self._ensure_real_connected()
        await real.mkdir(remote_path, parents=parents, exist_ok=exist_ok, mode=mode)
        self._cassette.interactions.append(
            RecordedFsInteraction(
                operation="mkdir",
                path=self._sanitize_text(remote_path, normalize=True),
                mode=mode,
            )
        )
        self._dirty = True

    async def remove_file(self, remote_path: str) -> None:
        """Удалить файл через кассету или реальный транспорт."""
        self._check_fs_supported("remove_file")
        if self._can_replay():
            matched = self._match_fs("remove_file", remote_path)
            if matched is not None:
                self._raise_recorded_error(
                    matched.error_class,
                    matched.error_message,
                    command=f"remove_file {remote_path}",
                    host=self.config.host,
                )
                return
            if not self._can_record():
                self._raise_fs_miss("remove_file", remote_path)

        real = await self._ensure_real_connected()
        await real.remove_file(remote_path)
        self._cassette.interactions.append(
            RecordedFsInteraction(
                operation="remove_file",
                path=self._sanitize_text(remote_path, normalize=True),
            )
        )
        self._dirty = True

    async def chmod(self, remote_path: str, mode: int) -> None:
        """Изменить права доступа через кассету или реальный транспорт."""
        self._check_fs_supported("chmod")
        if self._can_replay():
            matched = self._match_fs("chmod", remote_path)
            if matched is not None:
                self._raise_recorded_error(
                    matched.error_class,
                    matched.error_message,
                    command=f"chmod {remote_path}",
                    host=self.config.host,
                )
                return
            if not self._can_record():
                self._raise_fs_miss("chmod", remote_path)

        real = await self._ensure_real_connected()
        await real.chmod(remote_path, mode)
        self._cassette.interactions.append(
            RecordedFsInteraction(
                operation="chmod",
                path=self._sanitize_text(remote_path, normalize=True),
                mode=mode,
            )
        )
        self._dirty = True

    async def upload(self, local_path: str, remote_path: str, **kwargs: Any) -> None:
        """Загрузить файл через кассету или реальный транспорт."""
        self._check_fs_supported("upload")
        if self._can_replay():
            matched = self._match_fs("upload", remote_path)
            if matched is not None:
                self._raise_recorded_error(
                    matched.error_class,
                    matched.error_message,
                    command=f"upload {remote_path}",
                    host=self.config.host,
                )
                progress_cb = kwargs.get("progress_callback")
                if callable(progress_cb):
                    p = Path(local_path)
                    sz = p.stat().st_size if p.is_file() else 0
                    progress_cb(sz, sz)
                return
            if not self._can_record():
                self._raise_fs_miss("upload", remote_path)

        real = await self._ensure_real_connected()
        await real.upload(local_path, remote_path, **kwargs)
        self._cassette.interactions.append(
            RecordedFsInteraction(
                operation="upload",
                path=self._sanitize_text(remote_path, normalize=True),
                target_path=self._sanitize_text(local_path, normalize=True),
            )
        )
        self._dirty = True

    async def download(self, remote_path: str, local_path: str, **kwargs: Any) -> None:
        """Скачать файл из кассеты или реального транспорта."""
        self._check_fs_supported("download")
        if self._can_replay():
            matched = self._match_fs("download", remote_path)
            if matched is not None:
                self._raise_recorded_error(
                    matched.error_class,
                    matched.error_message,
                    command=f"download {remote_path}",
                    host=self.config.host,
                )
                if matched.content_base64 is not None:
                    Path(local_path).write_bytes(base64.b64decode(matched.content_base64))
                elif matched.content_utf8 is not None:
                    Path(local_path).write_text(matched.content_utf8, encoding="utf-8")
                progress_cb = kwargs.get("progress_callback")
                if callable(progress_cb):
                    p = Path(local_path)
                    sz = p.stat().st_size if p.is_file() else 0
                    progress_cb(sz, sz)
                return
            if not self._can_record():
                self._raise_fs_miss("download", remote_path)

        real = await self._ensure_real_connected()
        await real.download(remote_path, local_path, **kwargs)
        content_utf8: str | None = None
        local_file = Path(local_path)
        if local_file.is_file():
            with contextlib.suppress(Exception):
                content_utf8 = self._sanitize_text(local_file.read_text(encoding="utf-8"))
        self._cassette.interactions.append(
            RecordedFsInteraction(
                operation="download",
                path=self._sanitize_text(remote_path, normalize=True),
                target_path=self._sanitize_text(local_path, normalize=True),
                content_utf8=content_utf8,
            )
        )
        self._dirty = True


__all__ = ["_CassetteFsMixin"]
