# src/uniconn/transports/replay/proxy.py
"""Прокси-транспорт и автономный ReplayTransport для записи и воспроизведения кассет."""

from __future__ import annotations

import asyncio
import base64
from collections.abc import AsyncIterator, Sequence
from pathlib import Path
from typing import Any

from ...config.models import ConnectionConfig
from ...exceptions import CassetteError, CassetteMissError
from ...result import Result
from ..base import BaseTransport
from ._proxy_advanced import _CassetteAdvancedMixin
from ._proxy_fs import _CassetteFsMixin
from .models import (
    _SUDO_WRAPPER_RE,
    Cassette,
    MatchField,
    RecordedExecInteraction,
    RecordedStreamInteraction,
    RecordMode,
)


class CassetteTransportProxy(_CassetteFsMixin, _CassetteAdvancedMixin, BaseTransport):
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
        sanitized_env = {str(k): self._sanitize_text(str(v)) for k, v in raw_env.items()}
        stdin_redacted = "input" in kwargs and kwargs["input"] is not None
        sanitized_cmd = "***REDACTED***" if sensitive else self._sanitize_text(command, normalize=True)
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

        rec_stdout = "***REDACTED***" if (sensitive or res.sensitive) else self._sanitize_text(res.stdout)
        rec_stderr = "***REDACTED***" if (sensitive or res.sensitive) else self._sanitize_text(res.stderr)
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
        sanitized_env = {str(k): self._sanitize_text(str(v)) for k, v in raw_env.items()}
        stdin_redacted = "input" in kwargs and kwargs["input"] is not None
        sanitized_cmd = "***REDACTED***" if sensitive else self._sanitize_text(command, normalize=True)
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
