# src/uniconn/services/files.py
"""Доменный сервис файловых операций, SFTP и инкрементальной синхронизации директорий."""

from __future__ import annotations

import hashlib
import logging
import os
import posixpath
import shlex
import uuid
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from ..exceptions import CapabilityNotSupportedError, ExecutionError, FileTransferError, TimeoutError
from ..result import SyncResult
from ..transports.base import FileStat as FileStat
from ._dir_sync import (
    _CHECKSUM_HEX_LENGTHS as _CHECKSUM_HEX_LENGTHS,
)
from ._dir_sync import (
    _SUPPORTED_CHECKSUMS as _SUPPORTED_CHECKSUMS,
)
from ._dir_sync import (
    STREAM_UPLOAD_THRESHOLD,
    ChecksumAlgorithm,
    DirectorySynchronizer,
    _build_checksum_command,
    _extract_checksum_digest,
    _is_permission_error,
    _local_file_digest,
)
from ._dir_sync import (
    _compile_exclude_regex as _compile_exclude_regex,
)
from .remote_path import RemotePath, RemoteStatResult
from .templates import TemplateEngine

if TYPE_CHECKING:
    from ..core.connection import Connection

_logger = logging.getLogger("uniconn.services.files")


class FileOperationsService:
    """Доменный сервис файловых операций (``conn.files``).

    Обеспечивает единый интерфейс для чтения/записи файлов, SFTP-загрузки,
    рендеринга шаблонов и инкрементальной синхронизации директорий.
    """

    def __init__(self, conn: Connection) -> None:
        """Инициализировать сервис файловых операций для подключения."""
        self._conn = conn
        self._synchronizer = DirectorySynchronizer(conn)

    def path(self, *pathsegments: str | os.PathLike[str]) -> RemotePath:
        """Создать объектно-ориентированный путь ``RemotePath`` (аналог ``pathlib.Path``) на хосте."""
        return RemotePath(self._conn, *pathsegments)

    async def _ensure_connected(self, op_label: str = "<file_op>") -> None:
        cb = getattr(self._conn, "circuit_breaker", None)
        if cb is not None and hasattr(cb, "check_or_raise"):
            cb.check_or_raise(host=self._conn.config.host, command=op_label)
        rl = getattr(self._conn, "rate_limiter", None)
        if rl is not None and hasattr(rl, "acquire"):
            await rl.acquire()
        if not self._conn.transport.is_connected:
            await self._conn.transport.connect()

    def _build_observed_handler(self, method_name: str, base_handler: Any) -> Any:
        """Обернуть базовый обработчик в цепочку зарегистрированных ``OperationObserver``."""
        handler = base_handler
        for obs in reversed(self._conn.operation_observers):
            prev_fn = handler
            obs_method = getattr(obs, method_name)

            async def _step(
                *args: Any,
                _obs_fn: Any = obs_method,
                _nxt: Any = prev_fn,
                **kw: Any,
            ) -> Any:
                return await _obs_fn(self._conn, _nxt, *args, **kw)

            handler = _step
        return handler

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

        handler = self._build_observed_handler("observe_upload", self._raw_upload)
        await handler(local_path, remote_path, recurse=recurse, **kwargs)
        if verify and not recurse and not self._conn.dry_run:
            if self._conn.transport_name in ("serial", "uart"):
                raise CapabilityNotSupportedError(
                    "Post-transfer SHA-256 checksum verification via shell is not supported on serial/uart transport "
                    "(CRC-16 is already verified at packet level by XMODEM/YMODEM).",
                    host=self._conn.config.host,
                )
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
        """Скачать файл или директорию с удалённого хоста (с опциональной проверкой SHA-256 и прогрессом)."""
        if progress_callback is not None:
            kwargs["progress_callback"] = progress_callback

        handler = self._build_observed_handler("observe_download", self._raw_download)
        await handler(remote_path, local_path, recurse=recurse, **kwargs)
        if verify and not recurse and not self._conn.dry_run:
            if self._conn.transport_name in ("serial", "uart"):
                raise CapabilityNotSupportedError(
                    "Post-transfer SHA-256 checksum verification via shell is not supported on serial/uart transport "
                    "(CRC-16 is already verified at packet level by XMODEM/YMODEM).",
                    host=self._conn.config.host,
                )
            remote_digest = await self.checksum(remote_path, algorithm="sha256")
            local_digest = _local_file_digest(local_path, "sha256")
            if local_digest != remote_digest:
                raise FileTransferError(
                    f"Checksum mismatch after download of {remote_path} -> {local_path}: "
                    f"remote={remote_digest}, local={local_digest}",
                    host=self._conn.config.host,
                )

    async def upload_xmodem(
        self,
        local_path: str | Path,
        *,
        mode: Literal["checksum", "crc", "1k"] = "1k",
        trigger_command: str | None = None,
        progress_callback: Callable[[int, int], None] | None = None,
        **kwargs: Any,
    ) -> int:
        """Загрузить файл по протоколу XMODEM (поддерживается для Serial/UART транспорта)."""
        if self._conn.dry_run:
            self._conn.logger.info(
                f"[DRY-RUN] Skipping XMODEM upload {str(local_path)!r} on {self._conn.config.uri_safe}"
            )
            return 0

        await self._ensure_connected()
        trans: Any = self._conn.transport
        if not hasattr(trans, "upload_xmodem"):
            raise CapabilityNotSupportedError(
                f"XMODEM upload is not supported on {trans.name} transport",
                host=self._conn.config.host,
            )
        sent_bytes = 0

        async def _do_xmodem(
            l_path: str | Path,
            _r_path: str | Path,
            *,
            recurse: bool = False,
            **kw: Any,
        ) -> None:
            nonlocal sent_bytes
            _ = recurse
            sent_bytes = int(
                await trans.upload_xmodem(
                    l_path,
                    mode=mode,
                    trigger_command=trigger_command,
                    progress_callback=progress_callback,
                    **kw,
                )
            )

        handler = self._build_observed_handler("observe_upload", _do_xmodem)
        await handler(local_path, "", recurse=False, **kwargs)
        return sent_bytes

    async def upload_ymodem(
        self,
        local_path: str | Path,
        *,
        trigger_command: str | None = None,
        progress_callback: Callable[[int, int], None] | None = None,
        **kwargs: Any,
    ) -> int:
        """Загрузить файл по протоколу YMODEM (поддерживается для Serial/UART транспорта)."""
        if self._conn.dry_run:
            self._conn.logger.info(
                f"[DRY-RUN] Skipping YMODEM upload {str(local_path)!r} on {self._conn.config.uri_safe}"
            )
            return 0

        await self._ensure_connected()
        trans: Any = self._conn.transport
        if not hasattr(trans, "upload_ymodem"):
            raise CapabilityNotSupportedError(
                f"YMODEM upload is not supported on {trans.name} transport",
                host=self._conn.config.host,
            )
        sent_bytes = 0

        async def _do_ymodem(
            l_path: str | Path,
            _r_path: str | Path,
            *,
            recurse: bool = False,
            **kw: Any,
        ) -> None:
            nonlocal sent_bytes
            _ = recurse
            sent_bytes = int(
                await trans.upload_ymodem(
                    l_path,
                    trigger_command=trigger_command,
                    progress_callback=progress_callback,
                    **kw,
                )
            )

        handler = self._build_observed_handler("observe_upload", _do_ymodem)
        await handler(local_path, "", recurse=False, **kwargs)
        return sent_bytes

    async def download_xmodem(
        self,
        local_path: str | Path,
        *,
        mode: Literal["checksum", "crc", "1k"] = "crc",
        trigger_command: str | None = None,
        progress_callback: Callable[[int, int], None] | None = None,
        **kwargs: Any,
    ) -> int:
        """Скачать файл по протоколу XMODEM (поддерживается для Serial/UART транспорта)."""
        await self._ensure_connected()
        trans: Any = self._conn.transport
        if not hasattr(trans, "download_xmodem"):
            raise CapabilityNotSupportedError(
                f"XMODEM download is not supported on {trans.name} transport",
                host=self._conn.config.host,
            )
        received_bytes = 0

        async def _do_xmodem_dl(
            _r_path: str | Path,
            l_path: str | Path,
            *,
            recurse: bool = False,
            **kw: Any,
        ) -> None:
            nonlocal received_bytes
            _ = recurse
            received_bytes = int(
                await trans.download_xmodem(
                    l_path,
                    mode=mode,
                    trigger_command=trigger_command,
                    progress_callback=progress_callback,
                    **kw,
                )
            )

        handler = self._build_observed_handler("observe_download", _do_xmodem_dl)
        await handler("", local_path, recurse=False, **kwargs)
        return received_bytes

    async def download_ymodem(
        self,
        destination_dir: str | Path,
        *,
        trigger_command: str | None = None,
        progress_callback: Callable[[int, int, str], None] | None = None,
        **kwargs: Any,
    ) -> list[Path]:
        """Скачать файлы по протоколу YMODEM-Batch в целевую директорию."""
        await self._ensure_connected()
        trans: Any = self._conn.transport
        if not hasattr(trans, "download_ymodem"):
            raise CapabilityNotSupportedError(
                f"YMODEM download is not supported on {trans.name} transport",
                host=self._conn.config.host,
            )
        received_files: list[Path] = []

        async def _do_ymodem_dl(
            _r_path: str | Path,
            l_path: str | Path,
            *,
            recurse: bool = False,
            **kw: Any,
        ) -> None:
            nonlocal received_files
            _ = recurse
            res = await trans.download_ymodem(
                l_path,
                trigger_command=trigger_command,
                progress_callback=progress_callback,
                **kw,
            )
            received_files = list(res)

        handler = self._build_observed_handler("observe_download", _do_ymodem_dl)
        await handler("", destination_dir, recurse=False, **kwargs)
        return received_files

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
        handler = self._build_observed_handler("observe_read_file", self._raw_read_file)
        return await handler(remote_path, encoding=encoding)

    async def _stage_and_sudo_move(
        self,
        effective_path: str,
        data: bytes,
        mode: int | None,
        *,
        sudo: bool = True,
    ) -> None:
        """Записать файл через временную директорию хоста и переместить с ``sudo mv -f``."""
        async with self._conn.temp_dir() as tmp_dir:
            tmp_name = f".uniconn_tmp_{uuid.uuid4().hex[:12]}"
            staged_tmp = f"{str(tmp_dir).rstrip('/')}/{tmp_name}"
            await self._conn.transport.write_file(staged_tmp, data, mode=mode)
            chmod_cmd = (
                f"chmod {oct(mode)[2:]} {shlex.quote(staged_tmp)} && "
                if mode is not None
                else ""
            )
            await self._conn.run(
                f"{chmod_cmd}mv -f {shlex.quote(staged_tmp)} {shlex.quote(effective_path)}",
                sudo=sudo,
                raise_on_error=True,
                dry_run=False,
            )

    async def _cleanup_staged_remote(self, staged_remote: str) -> None:
        """Удалить временный staging-файл на удалённом хосте без скрытия критических ошибок."""
        try:
            await self._conn.transport.remove_file(staged_remote)
        except (OSError, ExecutionError, FileTransferError, CapabilityNotSupportedError) as cleanup_exc:
            _logger.debug("Cleanup of staged file %r skipped: %s", staged_remote, cleanup_exc)

    async def _raw_write_file(
        self,
        remote_path: str | Path,
        content: str | bytes,
        mode: int | None = None,
        encoding: str = "utf-8",
        *,
        atomic: bool = False,
        sudo: bool = False,
    ) -> None:
        if self._conn.dry_run:
            self._conn.logger.info(
                f"[DRY-RUN] Skipping write_file to {str(remote_path)!r} on {self._conn.config.uri_safe}"
            )
            return

        await self._ensure_connected("write_file")
        effective_path = self._conn.context.resolve_path(remote_path)
        data = content.encode(encoding) if isinstance(content, str) else bytes(content)

        from .provisioning.windows import is_windows_connection

        is_win_remote = (
            self._conn.transport_name != "local" and is_windows_connection(self._conn)
        )
        if sudo and not is_win_remote:
            await self._stage_and_sudo_move(effective_path, data, mode, sudo=True)
            return

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
                try:
                    staged_local.unlink(missing_ok=True)
                except OSError as cleanup_exc:
                    _logger.debug("Cleanup of local staged file %s skipped: %s", staged_local, cleanup_exc)
                raise
            return

        if is_win_remote:
            sep = "\\" if ("\\" in effective_path or ":" in effective_path) else "/"
            trimmed = effective_path.rstrip("\\/")
            parent_win = (trimmed.rsplit(sep, 1)[0] or ".") if sep in trimmed else "."
            tmp_name = f".uniconn_tmp_{uuid.uuid4().hex[:12]}"
            staged_remote = f"{parent_win}{sep}{tmp_name}"
            q_staged = "'" + staged_remote.replace("'", "''") + "'"
            q_dest = "'" + effective_path.replace("'", "''") + "'"
            try:
                await self._conn.transport.write_file(staged_remote, data, mode=mode)
                await self._conn.run(
                    f"Move-Item -LiteralPath {q_staged} -Destination {q_dest} -Force -ErrorAction Stop",
                    raise_on_error=True,
                    dry_run=False,
                )
            except Exception:
                await self._cleanup_staged_remote(staged_remote)
                raise
            return

        parent_dir = posixpath.dirname(effective_path.rstrip("/")) or "."
        tmp_name = f".uniconn_tmp_{uuid.uuid4().hex[:12]}"
        staged_remote = f"/{tmp_name}" if parent_dir == "/" else f"{parent_dir}/{tmp_name}"
        try:
            await self._conn.transport.write_file(staged_remote, data, mode=mode)
            await self._conn.run(
                f"mv -f {shlex.quote(staged_remote)} {shlex.quote(effective_path)}",
                sudo=sudo,
                raise_on_error=True,
                dry_run=False,
            )
        except Exception as exc:
            await self._cleanup_staged_remote(staged_remote)
            if _is_permission_error(exc):
                has_sudo_cfg = bool(
                    sudo
                    or self._conn.config.password is not None
                    or self._conn.config.options.get("sudo_password") is not None
                )
                if has_sudo_cfg:
                    await self._stage_and_sudo_move(effective_path, data, mode, sudo=True)
                    return
            raise

    async def write_file(
        self,
        remote_path: str | Path,
        content: str | bytes,
        mode: int | None = None,
        encoding: str = "utf-8",
        *,
        atomic: bool = False,
        sudo: bool = False,
    ) -> None:
        """Записать строку или байты из памяти в файл на хосте (опционально атомарно и с ``sudo``)."""

        async def _base_write(
            r_path: str | Path,
            c_data: str | bytes,
            *,
            mode: int | None = None,
            encoding: str = "utf-8",
        ) -> None:
            await self._raw_write_file(
                r_path,
                c_data,
                mode=mode,
                encoding=encoding,
                atomic=atomic,
                sudo=sudo,
            )

        handler = self._build_observed_handler("observe_write_file", _base_write)
        await handler(remote_path, content, mode=mode, encoding=encoding)

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

        worker = getattr(self._conn, "_python_worker", None)
        if not sudo and worker is not None and worker.can_auto_accelerate():
            try:
                digest = await worker.request(
                    "checksum",
                    allow_oneshot_fallback=False,
                    path=effective_path,
                    algorithm=algorithm,
                )
                if isinstance(digest, str) and len(digest) == _CHECKSUM_HEX_LENGTHS.get(algorithm, 64):
                    return digest.lower()
            except (OSError, ExecutionError, CapabilityNotSupportedError, TimeoutError, ValueError) as exc:
                _logger.debug("Worker checksum fallback for %s: %s", effective_path, exc)

        cached_facts = getattr(self._conn, "_cached_facts", None)
        os_family = getattr(cached_facts, "os_family", None)
        if not os_family:
            from .provisioning.windows import is_windows_connection

            if is_windows_connection(self._conn):
                os_family = "windows"
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

    async def stat(self, remote_path: str | Path) -> RemoteStatResult:
        """Получить метаданные файла на удалённом хосте (совместимо с FileStat и os.stat_result)."""
        await self._ensure_connected()
        effective_path = self._conn.context.resolve_path(remote_path)
        raw_stat = await self._conn.transport.stat(effective_path)
        return RemoteStatResult.coerce(raw_stat)

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
        sudo: bool = False,
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
            sudo=sudo,
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

        handler = self._build_observed_handler("observe_sync_dir", _base_sync)
        return await handler(
            local_dir=local_dir,
            remote_dir=remote_dir,
            delete=delete,
            exclude=exclude,
            mtime_tolerance=mtime_tolerance,
            dry_run=dry_run,
        )


__all__ = [
    "STREAM_UPLOAD_THRESHOLD",
    "ChecksumAlgorithm",
    "DirectorySynchronizer",
    "FileOperationsService",
    "FileStat",
    "RemotePath",
    "RemoteStatResult",
    "TemplateEngine",
    "_build_checksum_command",
    "_extract_checksum_digest",
    "_is_permission_error",
    "_local_file_digest",
]
