# src/uniconn/services/files.py
"""Доменный сервис файловых операций, SFTP и инкрементальной синхронизации директорий."""

from __future__ import annotations

import contextlib
import fnmatch
import hashlib
import os
import posixpath
import re
import shlex
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from ..exceptions import ExecutionError, FileTransferError
from ..result import SyncResult
from ..transports.base import FileStat
from .templates import TemplateEngine

if TYPE_CHECKING:
    from ..core.connection import Connection

STREAM_UPLOAD_THRESHOLD = 4 * 1024 * 1024  # 4 МБ
ChecksumAlgorithm = Literal["sha256", "sha1", "md5"]
_SUPPORTED_CHECKSUMS: frozenset[str] = frozenset(("sha256", "sha1", "md5"))
_CHECKSUM_HEX_LENGTHS: dict[str, int] = {
    "sha256": 64,
    "sha1": 40,
    "md5": 32,
}


def _build_checksum_command(
    path: str,
    algo: ChecksumAlgorithm = "sha256",
    os_family: str | None = None,
) -> str:
    """Построить кроссплатформенную команду расчёта хеша (Linux/macOS/BSD/OpenSSL/Windows)."""
    q_path = shlex.quote(path)
    if os_family and os_family.lower() == "windows":
        win_algo = algo.upper()
        return f"certutil -hashfile {q_path} {win_algo}"

    if algo == "sha256":
        return (
            f"if command -v sha256sum >/dev/null 2>&1; then sha256sum {q_path}; "
            f"elif command -v shasum >/dev/null 2>&1; then shasum -a 256 {q_path}; "
            f"elif command -v sha256 >/dev/null 2>&1; then sha256 -q {q_path}; "
            f"elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 -r {q_path}; "
            f"else certutil -hashfile {q_path} SHA256; fi"
        )
    if algo == "sha1":
        return (
            f"if command -v sha1sum >/dev/null 2>&1; then sha1sum {q_path}; "
            f"elif command -v shasum >/dev/null 2>&1; then shasum -a 1 {q_path}; "
            f"elif command -v sha1 >/dev/null 2>&1; then sha1 -q {q_path}; "
            f"elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha1 -r {q_path}; "
            f"else certutil -hashfile {q_path} SHA1; fi"
        )
    return (
        f"if command -v md5sum >/dev/null 2>&1; then md5sum {q_path}; "
        f"elif command -v md5 >/dev/null 2>&1; then md5 -q {q_path}; "
        f"elif command -v openssl >/dev/null 2>&1; then openssl dgst -md5 -r {q_path}; "
        f"else certutil -hashfile {q_path} MD5; fi"
    )


def _extract_checksum_digest(stdout: str, algo: ChecksumAlgorithm = "sha256") -> str | None:
    """Извлечь hex-дайджест из вывода GNU coreutils, shasum, BSD md5/sha256, openssl или certutil."""
    expected_len = _CHECKSUM_HEX_LENGTHS.get(algo, 64)
    hex_re = re.compile(rf"\b([0-9a-fA-F]{{{expected_len}}})\b")
    for line in stdout.strip().splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        match = hex_re.search(stripped)
        if match:
            return match.group(1).lower()
        compact = re.sub(r"\s+", "", stripped)
        if len(compact) == expected_len and all(c in "0123456789abcdefABCDEF" for c in compact):
            return compact.lower()
    return None


def _local_file_digest(path: str | Path, algorithm: ChecksumAlgorithm = "sha256") -> str:
    """Потоково вычислить контрольную сумму локального файла."""
    if algorithm not in _SUPPORTED_CHECKSUMS:
        raise ValueError(f"Unsupported checksum algorithm: {algorithm!r}")
    hasher = hashlib.new(algorithm)
    with Path(path).open("rb") as fp:
        while chunk := fp.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest().lower()


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
        *,
        checksum_check: bool = False,
        preserve_permissions: bool = False,
    ) -> SyncResult:
        """Выполнить инкрементальную синхронизацию ``local_dir -> remote_dir``."""
        start_time = time.monotonic()
        is_dry = self._conn.dry_run if dry_run is None else dry_run
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
            r_stat: FileStat | dict[str, Any] = {}
            if not is_dry or transport.is_connected:
                with contextlib.suppress(OSError, ExecutionError):
                    if await transport.exists(target_file):
                        r_stat = await transport.stat(target_file)
                        r_size = int(r_stat.get("size", -1))
                        r_mtime = float(r_stat.get("mtime") or 0.0)
                        if r_size == l_size:
                            if checksum_check:
                                l_hash = _local_file_digest(full_local, "sha256")
                                r_hash = await self._conn.files.checksum(
                                    target_file, "sha256"
                                )
                                if l_hash == r_hash:
                                    needs_upload = False
                            elif r_mtime > 0 and (r_mtime + mtime_tolerance) >= l_mtime:
                                needs_upload = False

            mode = full_local.stat().st_mode & 0o777
            if needs_upload:
                if not is_dry:
                    if l_size > STREAM_UPLOAD_THRESHOLD:
                        await transport.upload(str(full_local), target_file)
                        with contextlib.suppress(OSError, ExecutionError):
                            await transport.chmod(target_file, mode)
                    else:
                        data = full_local.read_bytes()
                        await transport.write_file(target_file, data, mode=mode)
                        if preserve_permissions:
                            with contextlib.suppress(OSError, ExecutionError):
                                await transport.chmod(target_file, mode)
                uploaded.append(rel_path)
                bytes_transferred += l_size
            else:
                if preserve_permissions and not is_dry:
                    r_perms_raw = r_stat.get("permissions")
                    raw_mode = r_stat.get("mode")
                    r_mode: int | None = None
                    if isinstance(r_perms_raw, str):
                        with contextlib.suppress(ValueError):
                            r_mode = int(r_perms_raw, 8) & 0o777
                    elif isinstance(raw_mode, int):
                        r_mode = raw_mode & 0o777
                    if r_mode != mode:
                        with contextlib.suppress(OSError, ExecutionError):
                            await transport.chmod(target_file, mode)
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
        if self._conn.dry_run:
            self._conn.logger.info(
                f"[DRY-RUN] Skipping upload {str(local_path)!r} -> {str(remote_path)!r} "
                f"on {self._conn.config.uri_safe}"
            )
            return

        await self._ensure_connected()
        effective_path = self._conn.context.resolve_path(remote_path)
        await self._conn.transport.upload(
            str(local_path), effective_path, recurse=recurse, **kwargs
        )

    async def upload(
        self,
        local_path: str | Path,
        remote_path: str | Path,
        recurse: bool = False,
        *,
        verify: bool = False,
        progress_callback: Callable[[int, int], None] | None = None,
        **kwargs: Any,
    ) -> None:
        """Загрузить файл или директорию на удалённый хост (с опциональной проверкой SHA-256 и прогрессом)."""
        if progress_callback is not None:
            kwargs["progress_callback"] = progress_callback

        handler = self._raw_upload
        for obs in reversed(self._conn.operation_observers):
            prev_fn = handler

            async def _step(
                l_path: str | Path,
                r_path: str | Path,
                *,
                recurse: bool = False,
                _obs: Any = obs,
                _nxt: Any = prev_fn,
                **kw: Any,
            ) -> None:
                await _obs.observe_upload(
                    self._conn,
                    _nxt,
                    l_path,
                    r_path,
                    recurse=recurse,
                    **kw,
                )

            handler = _step

        await handler(local_path, remote_path, recurse=recurse, **kwargs)
        if verify and not recurse and not self._conn.dry_run:
            local_digest = _local_file_digest(local_path, "sha256")
            remote_digest = await self.checksum(remote_path, algorithm="sha256")
            if local_digest != remote_digest:
                raise FileTransferError(
                    f"Checksum mismatch after upload of {local_path} -> {remote_path}: "
                    f"local={local_digest}, remote={remote_digest}",
                    host=self._conn.config.host,
                )

    async def _raw_download(
        self,
        remote_path: str | Path,
        local_path: str | Path,
        recurse: bool = False,
        **kwargs: Any,
    ) -> None:
        await self._ensure_connected()
        effective_path = self._conn.context.resolve_path(remote_path)
        await self._conn.transport.download(
            effective_path, str(local_path), recurse=recurse, **kwargs
        )

    async def download(
        self,
        remote_path: str | Path,
        local_path: str | Path,
        recurse: bool = False,
        *,
        verify: bool = False,
        progress_callback: Callable[[int, int], None] | None = None,
        **kwargs: Any,
    ) -> None:
        """Скачать файл или директорию с удалённого хостa (с опциональной проверкой SHA-256 и прогрессом)."""
        if progress_callback is not None:
            kwargs["progress_callback"] = progress_callback

        handler = self._raw_download
        for obs in reversed(self._conn.operation_observers):
            prev_fn = handler

            async def _step(
                r_path: str | Path,
                l_path: str | Path,
                *,
                recurse: bool = False,
                _obs: Any = obs,
                _nxt: Any = prev_fn,
                **kw: Any,
            ) -> None:
                await _obs.observe_download(
                    self._conn,
                    _nxt,
                    r_path,
                    l_path,
                    recurse=recurse,
                    **kw,
                )

            handler = _step

        await handler(remote_path, local_path, recurse=recurse, **kwargs)
        if verify and not recurse and not self._conn.dry_run:
            remote_digest = await self.checksum(remote_path, algorithm="sha256")
            local_digest = _local_file_digest(local_path, "sha256")
            if local_digest != remote_digest:
                raise FileTransferError(
                    f"Checksum mismatch after download of {remote_path} -> {local_path}: "
                    f"remote={remote_digest}, local={local_digest}",
                    host=self._conn.config.host,
                )

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
        handler = self._raw_read_file
        for obs in reversed(self._conn.operation_observers):
            prev_fn = handler

            async def _step(
                r_path: str | Path,
                *,
                encoding: str | None = "utf-8",
                _obs: Any = obs,
                _nxt: Any = prev_fn,
            ) -> str | bytes:
                return await _obs.observe_read_file(
                    self._conn,
                    _nxt,
                    r_path,
                    encoding=encoding,
                )

            handler = _step

        return await handler(remote_path, encoding=encoding)

    async def _raw_write_file(
        self,
        remote_path: str | Path,
        content: str | bytes,
        mode: int | None = None,
        encoding: str = "utf-8",
        *,
        atomic: bool = False,
    ) -> None:
        if self._conn.dry_run:
            self._conn.logger.info(
                f"[DRY-RUN] Skipping write_file to {str(remote_path)!r} on {self._conn.config.uri_safe}"
            )
            return

        await self._ensure_connected()
        effective_path = self._conn.context.resolve_path(remote_path)
        data = content.encode(encoding) if isinstance(content, str) else bytes(content)

        if not atomic:
            await self._conn.transport.write_file(effective_path, data, mode=mode)
            return

        if self._conn.transport_name == "local":
            target_p = Path(effective_path)
            target_p.parent.mkdir(parents=True, exist_ok=True)
            staged_local = target_p.parent / f".uniconn_tmp_{uuid.uuid4().hex[:12]}"
            try:
                await self._conn.transport.write_file(str(staged_local), data, mode=mode)
                os.replace(staged_local, target_p)
            except Exception:
                with contextlib.suppress(OSError):
                    staged_local.unlink(missing_ok=True)
                raise
            return

        parent_dir = posixpath.dirname(effective_path.rstrip("/")) or "."
        tmp_name = f".uniconn_tmp_{uuid.uuid4().hex[:12]}"
        staged_remote = f"/{tmp_name}" if parent_dir == "/" else f"{parent_dir}/{tmp_name}"
        try:
            await self._conn.transport.write_file(staged_remote, data, mode=mode)
            await self._conn.run(
                f"mv -f {shlex.quote(staged_remote)} {shlex.quote(effective_path)}",
                raise_on_error=True,
                dry_run=False,
            )
        except Exception:
            with contextlib.suppress(Exception):
                await self._conn.transport.remove_file(staged_remote)
            raise

    async def write_file(
        self,
        remote_path: str | Path,
        content: str | bytes,
        mode: int | None = None,
        encoding: str = "utf-8",
        *,
        atomic: bool = False,
    ) -> None:
        """Записать строку или байты из памяти в файл на хосте (опционально атомарно)."""

        async def _base_write(
            r_path: str | Path,
            c_data: str | bytes,
            *,
            mode: int | None = None,
            encoding: str = "utf-8",
        ) -> None:
            await self._raw_write_file(
                r_path, c_data, mode=mode, encoding=encoding, atomic=atomic
            )

        handler = _base_write
        for obs in reversed(self._conn.operation_observers):
            prev_fn = handler

            async def _step(
                r_path: str | Path,
                c_data: str | bytes,
                *,
                mode: int | None = None,
                encoding: str = "utf-8",
                _obs: Any = obs,
                _nxt: Any = prev_fn,
            ) -> None:
                await _obs.observe_write_file(
                    self._conn,
                    _nxt,
                    r_path,
                    c_data,
                    mode=mode,
                    encoding=encoding,
                )

            handler = _step

        await handler(
            remote_path, content, mode=mode, encoding=encoding
        )

    async def checksum(
        self,
        remote_path: str | Path,
        algorithm: ChecksumAlgorithm = "sha256",
        *,
        sudo: bool = False,
    ) -> str:
        """Вычислить контрольную сумму файла на хосте (``sha256``, ``sha1`` или ``md5``)."""
        if algorithm not in _SUPPORTED_CHECKSUMS:
            raise ValueError(
                f"Unsupported checksum algorithm: {algorithm!r}. "
                f"Expected one of {sorted(_SUPPORTED_CHECKSUMS)}"
            )
        effective_path = self._conn.context.resolve_path(remote_path)
        if self._conn.transport_name == "local" and not sudo:
            return _local_file_digest(effective_path, algorithm)

        cached_facts = getattr(self._conn, "_cached_facts", None)
        os_family = getattr(cached_facts, "os_family", None)
        cmd = _build_checksum_command(effective_path, algorithm, os_family=os_family)
        res = await self._conn.run(
            cmd,
            sudo=sudo,
            raise_on_error=False,
            dry_run=False,
        )
        if res.ok and res.stdout.strip():
            extracted = _extract_checksum_digest(res.stdout, algorithm)
            if extracted is not None:
                return extracted
            return res.stdout.strip().split()[0].lower()

        if not sudo:
            raw = await self.read_file(remote_path, encoding=None)
            raw_bytes = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)
            return hashlib.new(algorithm, raw_bytes).hexdigest().lower()

        raise ExecutionError(
            res.stderr.strip() or f"Failed to calculate {algorithm} checksum for {effective_path}",
            command=res.command,
            exit_code=res.exit_code,
            stdout=res.stdout,
            stderr=res.stderr,
            host=self._conn.config.host,
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
        if self._conn.dry_run:
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
        if self._conn.dry_run:
            self._conn.logger.info(
                f"[DRY-RUN] Skipping chmod {oct(mode)} {str(remote_path)!r} "
                f"on {self._conn.config.uri_safe}"
            )
            return

        await self._ensure_connected()
        effective_path = self._conn.context.resolve_path(remote_path)
        await self._conn.transport.chmod(effective_path, mode)

    async def stat(self, remote_path: str | Path) -> FileStat:
        """Получить метаданные файла на удалённом хосте."""
        await self._ensure_connected()
        effective_path = self._conn.context.resolve_path(remote_path)
        return await self._conn.transport.stat(effective_path)

    async def listdir(self, remote_path: str | Path = ".") -> list[str]:
        """Получить список имён файлов в директории."""
        await self._ensure_connected()
        effective_path = self._conn.context.resolve_path(remote_path)
        return await self._conn.transport.listdir(effective_path)

    async def remove_file(self, remote_path: str | Path) -> None:
        """Удалить файл на хосте."""
        if self._conn.dry_run:
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
        *,
        atomic: bool = False,
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
            atomic=atomic,
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
        *,
        checksum_check: bool = False,
        preserve_permissions: bool = False,
    ) -> SyncResult:
        return await self._synchronizer.sync(
            local_dir=local_dir,
            remote_dir=remote_dir,
            delete=delete,
            exclude=exclude,
            mtime_tolerance=mtime_tolerance,
            dry_run=dry_run,
            checksum_check=checksum_check,
            preserve_permissions=preserve_permissions,
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
        checksum_check: bool = False,
        preserve_permissions: bool = False,
    ) -> SyncResult:
        """Инкрементально синхронизировать локальную директорию с удалённой."""

        async def _base_sync(
            *,
            local_dir: str | Path,
            remote_dir: str | Path,
            delete: bool = False,
            exclude: Sequence[str] | None = None,
            mtime_tolerance: float = 1.0,
            dry_run: bool | None = None,
        ) -> SyncResult:
            return await self._raw_sync_dir(
                local_dir=local_dir,
                remote_dir=remote_dir,
                delete=delete,
                exclude=exclude,
                mtime_tolerance=mtime_tolerance,
                dry_run=dry_run,
                checksum_check=checksum_check,
                preserve_permissions=preserve_permissions,
            )

        handler = _base_sync
        for obs in reversed(self._conn.operation_observers):
            prev_fn = handler

            async def _step(
                *,
                local_dir: str | Path,
                remote_dir: str | Path,
                delete: bool = False,
                exclude: Sequence[str] | None = None,
                mtime_tolerance: float = 1.0,
                dry_run: bool | None = None,
                _obs: Any = obs,
                _nxt: Any = prev_fn,
            ) -> SyncResult:
                return await _obs.observe_sync_dir(
                    self._conn,
                    _nxt,
                    local_dir=local_dir,
                    remote_dir=remote_dir,
                    delete=delete,
                    exclude=exclude,
                    mtime_tolerance=mtime_tolerance,
                    dry_run=dry_run,
                )

            handler = _step

        return await handler(
            local_dir=local_dir,
            remote_dir=remote_dir,
            delete=delete,
            exclude=exclude,
            mtime_tolerance=mtime_tolerance,
            dry_run=dry_run,
        )
