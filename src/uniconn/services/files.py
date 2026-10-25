# src/uniconn/services/files.py
"""Доменный сервис файловых операций, SFTP и инкрементальной синхронизации директорий."""

from __future__ import annotations

import contextlib
import fnmatch
import os
import re
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from ..exceptions import ExecutionError
from ..result import SyncResult
from .templates import TemplateEngine

if TYPE_CHECKING:
    from ..core.connection import Connection

STREAM_UPLOAD_THRESHOLD = 4 * 1024 * 1024  # 4 МБ


def _compile_exclude_regex(patterns: Sequence[str]) -> re.Pattern[str] | None:
    """Скомпилировать список glob-паттернов в единое регулярное выражение (O(1) поиск)."""
    if not patterns:
        return None
    translated: list[str] = []
    for pat in patterns:
        if not pat:
            continue
        regex_str = fnmatch.translate(pat)
        translated.append(f"(?:{regex_str})")
    if not translated:
        return None
    return re.compile("|".join(translated))


class DirectorySynchronizer:
    """Алгоритм инкрементальной синхронизации локального дерева директорий с удалённым хостом."""

    def __init__(self, conn: Connection) -> None:
        """Инициализировать синхронизатор директорий."""
        self._conn = conn

    _compile_exclude_regex = staticmethod(_compile_exclude_regex)

    @staticmethod
    def is_excluded(
        rel_posix: str,
        name: str,
        patterns: Sequence[str],
        compiled_re: re.Pattern[str] | None = None,
    ) -> bool:
        """Проверить, подпадает ли относительный путь или имя файла под glob-исключения."""
        if not patterns:
            return False
        regex = compiled_re or _compile_exclude_regex(patterns)
        if regex is None:
            return False
        if regex.match(name) or regex.match(rel_posix):
            return True
        return any(regex.match(part) for part in rel_posix.split("/"))

    async def sync(
        self,
        local_dir: str | Path,
        remote_dir: str | Path,
        delete: bool = False,
        exclude: Sequence[str] | None = None,
        mtime_tolerance: float = 1.0,
        dry_run: bool | None = None,
    ) -> SyncResult:
        """Выполнить инкрементальную синхронизацию ``local_dir -> remote_dir``."""
        start_time = time.monotonic()
        is_dry = self._conn.is_dry_run if dry_run is None else dry_run
        patterns = list(exclude or [])
        compiled_exclude = _compile_exclude_regex(patterns)

        src_root = Path(local_dir)
        if not src_root.is_dir():
            raise FileNotFoundError(f"Local directory does not exist: {local_dir}")

        transport = self._conn.transport
        if not transport.is_connected and not is_dry:
            await transport.connect()

        effective_remote = self._conn.context.resolve_path(remote_dir)

        local_files: dict[str, tuple[Path, int, float]] = {}
        local_rel_dirs: set[str] = {""}

        for root, dirs, files in os.walk(src_root):
            rel_dir_path = Path(root).relative_to(src_root)
            rel_dir = "" if str(rel_dir_path) == "." else rel_dir_path.as_posix()

            kept_dirs: list[str] = []
            for d in dirs:
                d_rel = f"{rel_dir}/{d}" if rel_dir else d
                if not self.is_excluded(d_rel, d, patterns, compiled_exclude):
                    kept_dirs.append(d)
                    local_rel_dirs.add(d_rel)
            dirs[:] = kept_dirs

            for fname in files:
                f_rel = f"{rel_dir}/{fname}" if rel_dir else fname
                if self.is_excluded(f_rel, fname, patterns, compiled_exclude):
                    continue
                full_local = Path(root) / fname
                st = full_local.stat()
                local_files[f_rel] = (full_local, int(st.st_size), float(st.st_mtime))

        uploaded: list[str] = []
        skipped: list[str] = []
        deleted: list[str] = []
        bytes_transferred = 0

        if not is_dry:
            for rel_d in sorted(local_rel_dirs):
                target_d = (
                    f"{effective_remote.rstrip('/')}/{rel_d}"
                    if rel_d
                    else effective_remote
                )
                await transport.mkdir(target_d, parents=True, exist_ok=True)

        for rel_path, (full_local, l_size, l_mtime) in sorted(local_files.items()):
            target_file = f"{effective_remote.rstrip('/')}/{rel_path}"
            needs_upload = True
            if not is_dry or transport.is_connected:
                with contextlib.suppress(OSError, ExecutionError):
                    if await transport.exists(target_file):
                        r_stat = await transport.stat(target_file)
                        r_size = int(r_stat.get("size", -1))
                        r_mtime = float(r_stat.get("mtime") or 0.0)
                        if (
                            r_size == l_size
                            and r_mtime > 0
                            and (r_mtime + mtime_tolerance) >= l_mtime
                        ):
                            needs_upload = False

            if needs_upload:
                if not is_dry:
                    mode = full_local.stat().st_mode & 0o777
                    if l_size > STREAM_UPLOAD_THRESHOLD:
                        await transport.upload(str(full_local), target_file)
                        with contextlib.suppress(OSError, ExecutionError):
                            await transport.chmod(target_file, mode)
                    else:
                        data = full_local.read_bytes()
                        await transport.write_file(target_file, data, mode=mode)
                uploaded.append(rel_path)
                bytes_transferred += l_size
            else:
                skipped.append(rel_path)

        if delete and (not is_dry or transport.is_connected):

            async def _walk_remote(rel_prefix: str) -> None:
                cur_remote = (
                    f"{effective_remote.rstrip('/')}/{rel_prefix}"
                    if rel_prefix
                    else effective_remote
                )
                try:
                    entries = await transport.listdir(cur_remote)
                except (OSError, ExecutionError):
                    return

                for entry in entries:
                    if entry in (".", ".."):
                        continue
                    entry_rel = f"{rel_prefix}/{entry}" if rel_prefix else entry
                    if self.is_excluded(entry_rel, entry, patterns, compiled_exclude):
                        continue
                    entry_full = f"{effective_remote.rstrip('/')}/{entry_rel}"
                    try:
                        info = await transport.stat(entry_full)
                    except (OSError, ExecutionError):
                        continue
                    if info.get("is_dir"):
                        await _walk_remote(entry_rel)
                    elif entry_rel not in local_files:
                        if not is_dry:
                            await transport.remove_file(entry_full)
                        deleted.append(entry_rel)

            if await transport.exists(effective_remote):
                await _walk_remote("")

        duration = time.monotonic() - start_time
        return SyncResult(
            uploaded=uploaded,
            skipped=skipped,
            deleted=deleted,
            bytes_transferred=bytes_transferred,
            duration=duration,
            dry_run=is_dry,
        )


class FileOperationsService:
    """Доменный сервис файловых операций (``conn.files``).

    Обеспечивает единый интерфейс для чтения/записи файлов, SFTP-загрузки,
    рендеринга шаблонов и инкрементальной синхронизации директорий.
    """

    def __init__(self, conn: Connection) -> None:
        """Инициализировать сервис файловых операций для подключения."""
        self._conn = conn
        self._synchronizer = DirectorySynchronizer(conn)

    async def _ensure_connected(self) -> None:
        if not self._conn.transport.is_connected:
            await self._conn.transport.connect()

    async def _raw_upload(
        self,
        local_path: str | Path,
        remote_path: str | Path,
        recurse: bool = False,
        **kwargs: Any,
    ) -> None:
        await self._conn.transport.upload(
            str(local_path), str(remote_path), recurse=recurse, **kwargs
        )

    async def upload(
        self,
        local_path: str | Path,
        remote_path: str | Path,
        recurse: bool = False,
        **kwargs: Any,
    ) -> None:
        """Загрузить файл или директорию на удалённый хост."""
        for obs in self._conn.operation_observers:
            await obs.observe_upload(
                self._conn,
                self._raw_upload,
                local_path,
                remote_path,
                recurse=recurse,
                **kwargs,
            )
            return
        await self._raw_upload(local_path, remote_path, recurse=recurse, **kwargs)

    async def _raw_download(
        self,
        remote_path: str | Path,
        local_path: str | Path,
        recurse: bool = False,
        **kwargs: Any,
    ) -> None:
        await self._conn.transport.download(
            str(remote_path), str(local_path), recurse=recurse, **kwargs
        )

    async def download(
        self,
        remote_path: str | Path,
        local_path: str | Path,
        recurse: bool = False,
        **kwargs: Any,
    ) -> None:
        """Скачать файл или директорию с удалённого хоста."""
        for obs in self._conn.operation_observers:
            await obs.observe_download(
                self._conn,
                self._raw_download,
                remote_path,
                local_path,
                recurse=recurse,
                **kwargs,
            )
            return
        await self._raw_download(remote_path, local_path, recurse=recurse, **kwargs)

    async def _raw_read_file(
        self,
        remote_path: str | Path,
        encoding: str | None = "utf-8",
    ) -> str | bytes:
        await self._ensure_connected()
        effective_path = self._conn.context.resolve_path(remote_path)
        raw = await self._conn.transport.read_file(effective_path)
        if encoding is None:
            return raw
        return raw.decode(encoding)

    async def read_file(
        self,
        remote_path: str | Path,
        encoding: str | None = "utf-8",
    ) -> str | bytes:
        """Прочитать содержимое файла с хоста напрямую в память."""
        for obs in self._conn.operation_observers:
            return await obs.observe_read_file(
                self._conn,
                self._raw_read_file,
                remote_path,
                encoding=encoding,
            )
        return await self._raw_read_file(remote_path, encoding=encoding)

    async def _raw_write_file(
        self,
        remote_path: str | Path,
        content: str | bytes,
        mode: int | None = None,
        encoding: str = "utf-8",
    ) -> None:
        if self._conn.is_dry_run:
            self._conn.logger.info(
                f"[DRY-RUN] Skipping write_file to {str(remote_path)!r} on {self._conn.config.uri_safe}"
            )
            return

        await self._ensure_connected()
        effective_path = self._conn.context.resolve_path(remote_path)
        data = content.encode(encoding) if isinstance(content, str) else bytes(content)
        await self._conn.transport.write_file(effective_path, data, mode=mode)

    async def write_file(
        self,
        remote_path: str | Path,
        content: str | bytes,
        mode: int | None = None,
        encoding: str = "utf-8",
    ) -> None:
        """Записать строку или байты из памяти в файл на хосте."""
        for obs in self._conn.operation_observers:
            await obs.observe_write_file(
                self._conn,
                self._raw_write_file,
                remote_path,
                content,
                mode=mode,
                encoding=encoding,
            )
            return
        await self._raw_write_file(
            remote_path, content, mode=mode, encoding=encoding
        )

    async def exists(self, remote_path: str | Path) -> bool:
        """Проверить существование файла или директории на хосте."""
        await self._ensure_connected()
        effective_path = self._conn.context.resolve_path(remote_path)
        return await self._conn.transport.exists(effective_path)

    async def mkdir(
        self,
        remote_path: str | Path,
        parents: bool = True,
        exist_ok: bool = True,
        mode: int | None = None,
    ) -> None:
        """Создать директорию на хосте."""
        if self._conn.is_dry_run:
            self._conn.logger.info(
                f"[DRY-RUN] Skipping mkdir {str(remote_path)!r} on {self._conn.config.uri_safe}"
            )
            return

        await self._ensure_connected()
        effective_path = self._conn.context.resolve_path(remote_path)
        await self._conn.transport.mkdir(
            effective_path,
            parents=parents,
            exist_ok=exist_ok,
            mode=mode,
        )

    async def chmod(self, remote_path: str | Path, mode: int) -> None:
        """Изменить права доступа к файлу на удалённом хосте."""
        await self._conn.transport.chmod(str(remote_path), mode)

    async def stat(self, remote_path: str | Path) -> dict[str, Any]:
        """Получить метаданные файла на удалённом хосте."""
        return await self._conn.transport.stat(str(remote_path))

    async def listdir(self, remote_path: str | Path = ".") -> list[str]:
        """Получить список имён файлов в директории."""
        return await self._conn.transport.listdir(str(remote_path))

    async def remove_file(self, remote_path: str | Path) -> None:
        """Удалить файл на хосте."""
        if self._conn.is_dry_run:
            self._conn.logger.info(
                f"[DRY-RUN] Skipping remove_file {str(remote_path)!r} on {self._conn.config.uri_safe}"
            )
            return

        await self._ensure_connected()
        effective_path = self._conn.context.resolve_path(remote_path)
        await self._conn.transport.remove_file(effective_path)

    async def write_template(
        self,
        remote_path: str | Path,
        template_str_or_path: str | Path,
        context: Mapping[str, Any] | None = None,
        mode: int | None = 0o644,
        encoding: str = "utf-8",
        engine: Literal["auto", "string", "jinja2"] = "auto",
    ) -> str:
        """Отрендерить шаблон конфигурации и записать его на хост."""
        rendered = TemplateEngine.render(
            template_str_or_path=template_str_or_path,
            context=context,
            engine=engine,
        )
        await self.write_file(
            str(remote_path),
            rendered,
            mode=mode,
            encoding=encoding,
        )
        return rendered

    async def _raw_sync_dir(
        self,
        local_dir: str | Path,
        remote_dir: str | Path,
        delete: bool = False,
        exclude: Sequence[str] | None = None,
        mtime_tolerance: float = 1.0,
        dry_run: bool | None = None,
    ) -> SyncResult:
        return await self._synchronizer.sync(
            local_dir=local_dir,
            remote_dir=remote_dir,
            delete=delete,
            exclude=exclude,
            mtime_tolerance=mtime_tolerance,
            dry_run=dry_run,
        )

    async def sync_dir(
        self,
        local_dir: str | Path,
        remote_dir: str | Path,
        delete: bool = False,
        exclude: Sequence[str] | None = None,
        mtime_tolerance: float = 1.0,
        dry_run: bool | None = None,
    ) -> SyncResult:
        """Инкрементально синхронизировать локальную директорию с удалённой."""
        for obs in self._conn.operation_observers:
            return await obs.observe_sync_dir(
                self._conn,
                self._raw_sync_dir,
                local_dir=local_dir,
                remote_dir=remote_dir,
                delete=delete,
                exclude=exclude,
                mtime_tolerance=mtime_tolerance,
                dry_run=dry_run,
            )
        return await self._raw_sync_dir(
            local_dir=local_dir,
            remote_dir=remote_dir,
            delete=delete,
            exclude=exclude,
            mtime_tolerance=mtime_tolerance,
            dry_run=dry_run,
        )
