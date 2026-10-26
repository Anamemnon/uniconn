# src/uniconn/transports/replay/proxy.py
"""Прокси-транспорт и автономный ReplayTransport для записи и воспроизведения кассет."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
from collections.abc import AsyncIterator, Sequence
from pathlib import Path
from typing import Any, cast

from pydantic import SecretStr

from ..._logging import SecretMaskingFilter
from ...config.models import ConnectionConfig
from ...exceptions import (
    CapabilityNotSupportedError,
    CassetteError,
    CassetteMissError,
    UniconnError,
)
from ...result import Result
from ..base import (
    BaseTransport,
    FileCapableTransport,
    FileStat,
    ShellCapableTransport,
    supports_capability,
)
from .models import (
    _ERROR_MAP,
    _SUDO_WRAPPER_RE,
    Cassette,
    FsOperationName,
    MatchField,
    RecordedExecInteraction,
    RecordedFsInteraction,
    RecordedShellInteraction,
    RecordedStreamInteraction,
    RecordMode,
    normalize_temp_paths,
)
from .shell_proxy import ReplayShellProcess, _RecordingShellProcessProxy


class CassetteTransportProxy(BaseTransport):
    """Прокси-декоратор над ``BaseTransport``, записывающий и воспроизводящий кассеты."""

    def __init__(
        self,
        config: ConnectionConfig,
        cassette: Cassette,
        *,
        wrapped: BaseTransport | None = None,
        mode: RecordMode | str = RecordMode.ONCE,
        cassette_exists: bool = False,
        match_on: Sequence[MatchField] = ("command", "cwd", "sudo"),
        normalize_temp: bool = True,
        allow_playback_repeats: bool = True,
        mask_secrets: bool = True,
    ) -> None:
        """Инициализировать прокси кассеты."""
        super().__init__(config)
        self._cassette = cassette
        self._wrapped = wrapped
        self._mode = RecordMode(mode)
        self._cassette_exists = cassette_exists
        self._match_on = set(match_on)
        self._normalize_temp = normalize_temp
        self._allow_playback_repeats = allow_playback_repeats
        self._mask_secrets = mask_secrets
        self._consumed_indices: set[int] = set()
        self._dirty = False

        if self._mode == RecordMode.ALL:
            self._cassette.interactions.clear()
            self._dirty = True

    @property
    def cassette(self) -> Cassette:
        """Активный объект кассеты."""
        return self._cassette

    @property
    def is_dirty(self) -> bool:
        """Были ли записаны новые эпизоды, требующие сохранения на диск."""
        return self._dirty

    def mark_dirty(self) -> None:
        """Пометить кассету как изменённую."""
        self._dirty = True

    @property
    def name(self) -> str:
        """Имя транспорта."""
        if self._wrapped is not None:
            return self._wrapped.name
        return self._cassette.transport or self.config.transport

    def _can_replay(self) -> bool:
        if self._mode == RecordMode.ALL:
            return False
        if self._mode == RecordMode.ONCE:
            return self._cassette_exists
        return True

    def _can_record(self) -> bool:
        if self._mode == RecordMode.NONE:
            return False
        if self._mode == RecordMode.ONCE:
            return not self._cassette_exists
        return True

    def _known_secrets(self) -> list[str]:
        secrets: list[str] = []
        for val in (
            self.config.password,
            self.config.passphrase,
            self.config.options.get("sudo_password"),
        ):
            if isinstance(val, SecretStr):
                raw = val.get_secret_value()
                if raw:
                    secrets.append(raw)
            elif isinstance(val, str) and val:
                secrets.append(val)
        return secrets

    def _sanitize_text(self, text: str, *, normalize: bool = False) -> str:
        if not text:
            return text
        res = normalize_temp_paths(text) if (normalize and self._normalize_temp) else text
        if self._mask_secrets:
            for secret in self._known_secrets():
                res = res.replace(secret, "***REDACTED***")
            res = SecretMaskingFilter._mask_string(res)
        return res

    def _norm_key(self, text: str | None) -> str | None:
        if text is None:
            return None
        res = normalize_temp_paths(text) if self._normalize_temp else text
        if self._mask_secrets:
            for secret in self._known_secrets():
                res = res.replace(secret, "***REDACTED***")
            res = SecretMaskingFilter._mask_string(res)
        return res

    @staticmethod
    def _raise_recorded_error(
        error_class: str | None,
        error_message: str | None,
        *,
        command: str | None = None,
        host: str | None = None,
    ) -> None:
        if not error_class:
            return
        exc_cls = _ERROR_MAP.get(error_class, UniconnError)
        msg = error_message or error_class
        if issubclass(exc_cls, UniconnError):
            raise exc_cls(msg, command=command, host=host)
        raise exc_cls(msg)

    async def connect(self) -> None:
        """Установить подключение (виртуально при воспроизведении или реально при записи)."""
        if self._can_record() and self._wrapped is not None and not self._can_replay():
            await self._wrapped.connect()
        self._connected = True

    async def disconnect(self) -> None:
        """Закрыть подключение."""
        if self._wrapped is not None and self._wrapped.is_connected:
            await self._wrapped.disconnect()
        self._connected = False

    async def _ensure_real_connected(self) -> BaseTransport:
        if self._wrapped is None:
            raise CassetteError(
                "Real transport is not available for recording in standalone ReplayTransport",
                host=self.config.host,
            )
        if not self._wrapped.is_connected:
            await self._wrapped.connect()
        return self._wrapped

    def _unwrap_sudo(self, cmd: str) -> str:
        stripped = cmd.strip()
        if not _SUDO_WRAPPER_RE.match(stripped):
            return stripped
        marker = "-- sh -c "
        idx = stripped.find(marker)
        if idx == -1:
            return stripped
        inner = stripped[idx + len(marker) :].strip()
        if len(inner) >= 2 and inner[0] == inner[-1] and inner[0] in ("'", '"'):
            return inner[1:-1]
        return inner

    def _match_exec(
        self,
        command: str,
        cwd: str | None,
        sudo: bool,
    ) -> RecordedExecInteraction | None:
        norm_cmd = self._norm_key(command) or ""
        norm_unwrapped = self._norm_key(self._unwrap_sudo(command)) or ""
        norm_cwd = self._norm_key(cwd)
        matched_repeat: RecordedExecInteraction | None = None

        for idx, item in enumerate(self._cassette.interactions):
            if not isinstance(item, RecordedExecInteraction):
                continue
            item_cmd = self._norm_key(item.command) or ""
            item_unwrapped = self._norm_key(self._unwrap_sudo(item.command)) or ""
            cmd_candidates = (norm_cmd, norm_unwrapped)
            if (
                "command" in self._match_on
                and item_cmd not in cmd_candidates
                and item_unwrapped not in cmd_candidates
            ):
                continue
            if "cwd" in self._match_on and self._norm_key(item.cwd) != norm_cwd:
                continue
            if "sudo" in self._match_on and item.sudo != sudo:
                continue

            if idx not in self._consumed_indices:
                self._consumed_indices.add(idx)
                return item
            matched_repeat = item

        if self._allow_playback_repeats and matched_repeat is not None:
            return matched_repeat
        return None

    async def ping(self, timeout: float | None = None) -> bool:
        """Проверить доступность транспорта в режиме записи или воспроизведения кассеты."""
        if not self._connected:
            await self.connect()

        if self._can_replay():
            matched = self._match_exec("echo ping", None, False)
            if matched is not None:
                if matched.error_class:
                    return False
                return matched.exit_code == 0
            if not self._can_record():
                return True

        if self._wrapped is not None:
            real = await self._ensure_real_connected()
            return await real.ping(timeout=timeout)
        return self._connected

    async def run(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> Result:
        """Выполнить команду из кассеты или записать результат реального транспорта."""
        if not self._connected:
            await self.connect()

        cwd = kwargs.get("cwd")
        is_sudo = bool(_SUDO_WRAPPER_RE.match(command.strip()))
        sensitive = bool(kwargs.get("sensitive", False))

        if self._can_replay():
            matched = self._match_exec(command, cwd, is_sudo)
            if matched is not None:
                self._raise_recorded_error(
                    matched.error_class,
                    matched.error_message,
                    command=command,
                    host=self.config.host,
                )
                return Result(
                    exit_code=matched.exit_code,
                    stdout=matched.stdout,
                    stderr=matched.stderr,
                    duration=matched.duration,
                    command=command,
                    host=self.config.host,
                    sensitive=sensitive,
                )
            if not self._can_record():
                candidates = [
                    it.command
                    for it in self._cassette.interactions
                    if isinstance(it, RecordedExecInteraction)
                ]
                raise CassetteMissError(
                    f"No matching exec interaction in cassette for command: {command!r}",
                    kind="exec",
                    command=command,
                    host=self.config.host,
                    candidates=candidates,
                )

        real = await self._ensure_real_connected()
        raw_env = kwargs.get("env") or {}
        sanitized_env = {
            str(k): self._sanitize_text(str(v))
            for k, v in raw_env.items()
        }
        stdin_redacted = "input" in kwargs and kwargs["input"] is not None
        sanitized_cmd = (
            "***REDACTED***"
            if sensitive
            else self._sanitize_text(command, normalize=True)
        )
        sanitized_cwd = self._sanitize_text(str(cwd), normalize=True) if cwd else None

        try:
            res = await real.run(command, timeout=timeout, **kwargs)
        except Exception as exc:
            self._cassette.interactions.append(
                RecordedExecInteraction(
                    command=sanitized_cmd,
                    cwd=sanitized_cwd,
                    env=sanitized_env,
                    sudo=is_sudo,
                    stdin_redacted=stdin_redacted,
                    error_class=type(exc).__name__,
                    error_message=self._sanitize_text(str(exc)),
                )
            )
            self._dirty = True
            raise

        rec_stdout = (
            "***REDACTED***"
            if (sensitive or res.sensitive)
            else self._sanitize_text(res.stdout)
        )
        rec_stderr = (
            "***REDACTED***"
            if (sensitive or res.sensitive)
            else self._sanitize_text(res.stderr)
        )
        self._cassette.interactions.append(
            RecordedExecInteraction(
                command=sanitized_cmd,
                cwd=sanitized_cwd,
                env=sanitized_env,
                sudo=is_sudo,
                stdin_redacted=stdin_redacted,
                exit_code=res.exit_code,
                stdout=rec_stdout,
                stderr=rec_stderr,
                duration=round(res.duration, 6),
            )
        )
        self._dirty = True
        return res

    async def run_bytes(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> bytes:
        """Выполнить команду с бинарным выводом из кассеты или реального транспорта."""
        if not self._connected:
            await self.connect()

        cwd = kwargs.get("cwd")
        is_sudo = bool(_SUDO_WRAPPER_RE.match(command.strip()))
        sensitive = bool(kwargs.get("sensitive", False))

        if self._can_replay():
            matched = self._match_exec(command, cwd, is_sudo)
            if matched is not None:
                self._raise_recorded_error(
                    matched.error_class,
                    matched.error_message,
                    command=command,
                    host=self.config.host,
                )
                if matched.stdout_base64 is not None:
                    return base64.b64decode(matched.stdout_base64)
                return matched.stdout.encode("utf-8")
            if not self._can_record():
                candidates = [
                    it.command
                    for it in self._cassette.interactions
                    if isinstance(it, RecordedExecInteraction)
                ]
                raise CassetteMissError(
                    f"No matching exec interaction in cassette for command: {command!r}",
                    kind="exec",
                    command=command,
                    host=self.config.host,
                    candidates=candidates,
                )

        real = await self._ensure_real_connected()
        raw_env = kwargs.get("env") or {}
        sanitized_env = {
            str(k): self._sanitize_text(str(v))
            for k, v in raw_env.items()
        }
        stdin_redacted = "input" in kwargs and kwargs["input"] is not None
        sanitized_cmd = (
            "***REDACTED***"
            if sensitive
            else self._sanitize_text(command, normalize=True)
        )
        sanitized_cwd = self._sanitize_text(str(cwd), normalize=True) if cwd else None

        try:
            raw_bytes = await real.run_bytes(command, timeout=timeout, **kwargs)
        except Exception as exc:
            self._cassette.interactions.append(
                RecordedExecInteraction(
                    command=sanitized_cmd,
                    cwd=sanitized_cwd,
                    env=sanitized_env,
                    sudo=is_sudo,
                    stdin_redacted=stdin_redacted,
                    error_class=type(exc).__name__,
                    error_message=self._sanitize_text(str(exc)),
                )
            )
            self._dirty = True
            raise

        if sensitive:
            rec_stdout = "***REDACTED***"
            b64_out: str | None = None
        else:
            try:
                rec_stdout = self._sanitize_text(raw_bytes.decode("utf-8"))
                b64_out = None
            except UnicodeDecodeError:
                rec_stdout = ""
                b64_out = base64.b64encode(raw_bytes).decode("ascii")

        self._cassette.interactions.append(
            RecordedExecInteraction(
                command=sanitized_cmd,
                cwd=sanitized_cwd,
                env=sanitized_env,
                sudo=is_sudo,
                stdin_redacted=stdin_redacted,
                exit_code=0,
                stdout=rec_stdout,
                stdout_base64=b64_out,
            )
        )
        self._dirty = True
        return raw_bytes

    async def stream(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Потоковое чтение вывода из кассеты или реального транспорта."""
        if not self._connected:
            await self.connect()

        cwd = kwargs.get("cwd")
        norm_cmd = self._norm_key(command) or ""
        norm_cwd = self._norm_key(cwd)

        if self._can_replay():
            matched: RecordedStreamInteraction | None = None
            matched_repeat: RecordedStreamInteraction | None = None
            for idx, item in enumerate(self._cassette.interactions):
                if not isinstance(item, RecordedStreamInteraction):
                    continue
                if (self._norm_key(item.command) or "") != norm_cmd:
                    continue
                if "cwd" in self._match_on and self._norm_key(item.cwd) != norm_cwd:
                    continue
                if idx not in self._consumed_indices:
                    self._consumed_indices.add(idx)
                    matched = item
                    break
                matched_repeat = item

            if matched is None and self._allow_playback_repeats:
                matched = matched_repeat

            if matched is not None:
                self._raise_recorded_error(
                    matched.error_class,
                    matched.error_message,
                    command=command,
                    host=self.config.host,
                )
                for line in matched.lines:
                    if matched.chunk_delay_ms > 0:
                        await asyncio.sleep(matched.chunk_delay_ms / 1000.0)
                    yield line
                return

            if not self._can_record():
                candidates = [
                    it.command
                    for it in self._cassette.interactions
                    if isinstance(it, RecordedStreamInteraction)
                ]
                raise CassetteMissError(
                    f"No matching stream interaction in cassette for command: {command!r}",
                    kind="stream",
                    command=command,
                    host=self.config.host,
                    candidates=candidates,
                )

        real = await self._ensure_real_connected()
        recorded_lines: list[str] = []
        sanitized_cmd = self._sanitize_text(command, normalize=True)
        sanitized_cwd = self._sanitize_text(str(cwd), normalize=True) if cwd else None

        try:
            async for line in real.stream(command, timeout=timeout, **kwargs):
                recorded_lines.append(self._sanitize_text(line))
                yield line
        except Exception as exc:
            self._cassette.interactions.append(
                RecordedStreamInteraction(
                    command=sanitized_cmd,
                    cwd=sanitized_cwd,
                    lines=recorded_lines,
                    error_class=type(exc).__name__,
                    error_message=self._sanitize_text(str(exc)),
                )
            )
            self._dirty = True
            raise
        else:
            self._cassette.interactions.append(
                RecordedStreamInteraction(
                    command=sanitized_cmd,
                    cwd=sanitized_cwd,
                    lines=recorded_lines,
                )
            )
            self._dirty = True

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

    def _match_fs(
        self,
        operation: FsOperationName,
        path: str,
    ) -> RecordedFsInteraction | None:
        norm_path = self._norm_key(path) or ""
        matched_repeat: RecordedFsInteraction | None = None

        for idx, item in enumerate(self._cassette.interactions):
            if not isinstance(item, RecordedFsInteraction):
                continue
            if item.operation != operation:
                continue
            if (self._norm_key(item.path) or "") != norm_path:
                continue
            if idx not in self._consumed_indices:
                self._consumed_indices.add(idx)
                return item
            matched_repeat = item

        if self._allow_playback_repeats and matched_repeat is not None:
            return matched_repeat
        return None

    def _raise_fs_miss(self, operation: FsOperationName, path: str) -> None:
        candidates = [
            f"{it.operation}:{it.path}"
            for it in self._cassette.interactions
            if isinstance(it, RecordedFsInteraction)
        ]
        raise CassetteMissError(
            f"No matching fs interaction in cassette for {operation}({path!r})",
            kind="fs",
            command=f"{operation} {path}",
            host=self.config.host,
            candidates=candidates,
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

    async def open_shell(
        self,
        term_type: str = "xterm",
        term_size: tuple[int, int] = (80, 24),
        **kwargs: Any,
    ) -> Any:
        """Открыть интерактивную PTY-сессию из кассеты или реального транспорта."""
        if "shell" not in self._cassette.capabilities:
            raise CapabilityNotSupportedError(
                f"open_shell not supported for {self.name} transport",
                host=self.config.host,
            )
        if self._can_replay():
            matched: RecordedShellInteraction | None = None
            matched_repeat: RecordedShellInteraction | None = None
            for idx, item in enumerate(self._cassette.interactions):
                if isinstance(item, RecordedShellInteraction):
                    if idx not in self._consumed_indices:
                        self._consumed_indices.add(idx)
                        matched = item
                        break
                    matched_repeat = item
            if matched is None and self._allow_playback_repeats:
                matched = matched_repeat

            exec_eps = [
                it
                for it in self._cassette.interactions
                if isinstance(it, RecordedExecInteraction)
            ]
            if matched is not None:
                return ReplayShellProcess(
                    matched,
                    exec_eps,
                    normalize_temp=self._normalize_temp,
                )
            if exec_eps:
                synth_shell = RecordedShellInteraction(
                    term_type=term_type,
                    term_size=term_size,
                    steps=[],
                )
                return ReplayShellProcess(
                    synth_shell,
                    exec_eps,
                    normalize_temp=self._normalize_temp,
                )
            if not self._can_record():
                raise CassetteMissError(
                    "No matching shell interaction in cassette for open_shell()",
                    kind="shell",
                    command="open_shell",
                    host=self.config.host,
                )

        real = await self._ensure_real_connected()
        if not supports_capability(real, ShellCapableTransport):
            raise CapabilityNotSupportedError(
                f"open_shell not supported for {real.name} transport",
                host=self.config.host,
            )
        real_proc = await real.open_shell(term_type=term_type, term_size=term_size, **kwargs)
        shell_rec = RecordedShellInteraction(
            term_type=term_type,
            term_size=term_size,
            steps=[],
        )
        self._cassette.interactions.append(shell_rec)
        self._dirty = True
        return _RecordingShellProcessProxy(real_proc, shell_rec, self)


class ReplayTransport(CassetteTransportProxy):
    """Автономный транспорт воспроизведения кассет для схемы ``replay://``."""

    def __init__(self, config: ConnectionConfig) -> None:
        """Инициализировать ReplayTransport из ``ConnectionConfig``."""
        cassette_opt = config.options.get("cassette") or config.options.get("path")
        mode_opt = str(config.options.get("mode", "none"))
        normalize_opt = str(config.options.get("normalize_temp", "true")).lower() != "false"
        repeats_opt = str(config.options.get("allow_playback_repeats", "true")).lower() != "false"

        if cassette_opt:
            cassette_path = Path(str(cassette_opt))
            cassette = Cassette.load(cassette_path)
            exists = True
        else:
            cassette = Cassette(transport="replay", host=config.host)
            exists = True

        super().__init__(
            config=config,
            cassette=cassette,
            wrapped=None,
            mode=RecordMode(mode_opt),
            cassette_exists=exists,
            normalize_temp=normalize_opt,
            allow_playback_repeats=repeats_opt,
        )

    @property
    def name(self) -> str:
        """Название транспорта."""
        return "replay"


__all__ = [
    "CassetteTransportProxy",
    "ReplayTransport",
]
