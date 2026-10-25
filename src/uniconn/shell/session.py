# src/uniconn/shell/session.py
"""Интерактивная stateful PTY shell-сессия поверх SSH, Local, Telnet и Serial."""

from __future__ import annotations

import asyncio
import builtins
import contextlib
import inspect
import re
import shlex
import time
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any, Self

from pydantic import SecretStr

from ..exceptions import ConnectionError, TimeoutError
from ..result import Result
from .expect_engine import ExpectStateMachine
from .marker_protocol import PosixMarkerProtocol

if TYPE_CHECKING:
    from ..core.connection import OperationObserver


class ShellSession:
    """Асинхронная stateful PTY shell-сессия.

    Делегирует маркерный протокол в ``PosixMarkerProtocol``, а интерактивные
    regex-диалоги — в ``ExpectStateMachine``.
    """

    def __init__(
        self,
        proc: Any,
        host: str | None = None,
        default_timeout: float = 30.0,
        session_uuid: str | None = None,
        observers: Sequence[OperationObserver] | None = None,
        conn: Any = None,
    ) -> None:
        """Инициализировать интерактивную shell-сессию."""
        self._proc = proc
        self._host = host
        self._default_timeout = default_timeout
        self._protocol = PosixMarkerProtocol(session_uuid=session_uuid)
        self._uuid = self._protocol.uuid
        self._marker_pattern: re.Pattern[str] = self._protocol.pattern
        self._buffer: str = ""
        self._lock = asyncio.Lock()
        self._closed = False
        self._initialized = False
        self._observers: list[OperationObserver] = list(observers or [])
        self._conn = conn

    @property
    def is_alive(self) -> bool:
        """Проверить, что процесс оболочки активен и не завершён."""
        if self._closed or self._proc is None:
            return False
        rc = getattr(self._proc, "returncode", None)
        if isinstance(rc, int):
            return False
        exit_status = getattr(self._proc, "exit_status", None)
        return not isinstance(exit_status, int)

    async def initialize(self) -> None:
        """Выполнить начальную настройку оболочки (отключить prompt и эхо ввода)."""
        await self.send("export PS1=''; stty -echo\n")
        self._initialized = True

    async def send(self, text: str) -> None:
        """Низкоуровневая отправка текста в stdin оболочки."""
        if not self.is_alive:
            raise ConnectionError(
                "Shell session is closed or terminated",
                host=self._host,
            )
        try:
            self._proc.stdin.write(text)
            drain = getattr(self._proc.stdin, "drain", None)
            if callable(drain):
                res = drain()
                if inspect.isawaitable(res):
                    await res
        except Exception as e:
            self._closed = True
            raise ConnectionError(
                f"Failed to write to shell stdin: {e}",
                host=self._host,
            ) from e

    async def _read_chunk(self) -> str:
        """Прочитать очередную порцию данных из stdout процесса."""
        read_fn = self._proc.stdout.read
        try:
            res = read_fn(4096)
        except TypeError:
            res = read_fn()
        chunk = await res if inspect.isawaitable(res) else res
        if isinstance(chunk, bytes):
            chunk = chunk.decode("utf-8", errors="replace")
        return chunk or ""

    async def receive(self, timeout: float | None = None) -> str:
        """Низкоуровневое чтение доступного вывода из stdout оболочки."""
        if not self.is_alive:
            raise ConnectionError(
                "Shell session is closed or terminated",
                host=self._host,
            )
        if self._buffer:
            data = self._buffer
            self._buffer = ""
            return data

        effective_timeout = (
            timeout if timeout is not None else self._default_timeout
        )
        try:
            chunk = await asyncio.wait_for(
                self._read_chunk(), timeout=effective_timeout
            )
        except builtins.TimeoutError:
            raise TimeoutError(
                f"Timed out waiting for shell output after {effective_timeout}s",
                host=self._host,
            ) from None

        if chunk == "":
            self._closed = True
            raise ConnectionError(
                "Shell process terminated unexpectedly (EOF)",
                host=self._host,
            )
        return chunk

    def _clean_output(self, raw_output: str, command: str, wrapped_cmd: str) -> str:
        """Очистить вывод от CRLF, возможного эха команды и лишнего перевода строки."""
        return PosixMarkerProtocol.clean_output(raw_output, command, wrapped_cmd)

    async def _raw_execute(
        self,
        command: str | Sequence[str],
        timeout: float | None = None,
    ) -> Result:
        cmd_str = command if isinstance(command, str) else shlex.join(command)
        async with self._lock:
            if not self.is_alive:
                raise ConnectionError(
                    "Shell session is closed or terminated",
                    command=cmd_str,
                    host=self._host,
                )

            effective_timeout = (
                timeout if timeout is not None else self._default_timeout
            )
            start_time = time.monotonic()
            wrapped_cmd = self._protocol.wrap_command(cmd_str)

            await self.send(wrapped_cmd)

            async def _read_until_marker() -> tuple[str, int]:
                search_pos = 0
                while True:
                    match = self._marker_pattern.search(self._buffer, search_pos)
                    if match is not None:
                        raw_out = self._buffer[: match.start()]
                        self._buffer = self._buffer[match.end() :].lstrip("\r\n")
                        code = int(match.group(1))
                        return raw_out, code

                    # Оставляем перекрытие на длину маркера, чтобы не пропустить маркер на границе чанков
                    search_pos = max(0, len(self._buffer) - 64)

                    if not self.is_alive:
                        self._closed = True
                        raise ConnectionError(
                            "Shell process terminated during command execution",
                            command=cmd_str,
                            host=self._host,
                        )

                    chunk = await self._read_chunk()
                    if chunk == "":
                        self._closed = True
                        raise ConnectionError(
                            "Shell process closed stdout unexpectedly (EOF)",
                            command=cmd_str,
                            host=self._host,
                        )
                    self._buffer += chunk

            try:
                raw_output, exit_code = await asyncio.wait_for(
                    _read_until_marker(),
                    timeout=effective_timeout,
                )
            except builtins.TimeoutError:
                with contextlib.suppress(Exception):
                    self._proc.stdin.write("\x03")
                self._buffer = ""
                raise TimeoutError(
                    f"Shell command timed out after {effective_timeout}s",
                    command=cmd_str,
                    host=self._host,
                ) from None

            duration = time.monotonic() - start_time
            stdout = self._clean_output(raw_output, cmd_str, wrapped_cmd)

            return Result(
                exit_code=exit_code,
                stdout=stdout,
                stderr="",
                duration=duration,
                command=cmd_str,
                host=self._host,
            )

    async def execute(
        self,
        command: str | Sequence[str],
        timeout: float | None = None,
    ) -> Result:
        """Выполнить команду в stateful shell-сессии и дождаться маркера завершения."""
        handler = self._raw_execute
        for obs in reversed(self._observers):
            prev_fn = handler

            async def _step(
                cmd: str | Sequence[str],
                *,
                timeout: float | None = None,
                _obs: Any = obs,
                _nxt: Any = prev_fn,
            ) -> Result:
                return await _obs.observe_shell_execute(
                    self._conn, _nxt, cmd, timeout=timeout
                )

            handler = _step

        return await handler(command, timeout=timeout)

    def _mark_closed(self) -> None:
        self._closed = True

    async def _raw_expect(
        self,
        command: str | Sequence[str] | None = None,
        patterns: Mapping[str, str | SecretStr] | None = None,
        final_prompt: str | None = None,
        timeout: float | None = None,
        line_ending: str = "\n",
        sensitive: bool = False,
        allow_eof: bool = True,
    ) -> Result:
        if command is None:
            cmd_str = ""
        elif isinstance(command, str):
            cmd_str = command
        else:
            cmd_str = shlex.join(command)

        err_cmd = "***REDACTED***" if sensitive else cmd_str

        async with self._lock:
            if not self.is_alive:
                raise ConnectionError(
                    "Shell session is closed or terminated",
                    command=err_cmd,
                    host=self._host,
                )

            effective_timeout = (
                timeout if timeout is not None else self._default_timeout
            )
            start_time = time.monotonic()
            engine = ExpectStateMachine(
                patterns=patterns,
                final_prompt=final_prompt,
                allow_eof=allow_eof,
            )

            if command is not None:
                payload = (
                    cmd_str
                    if cmd_str.endswith(("\n", "\r"))
                    else f"{cmd_str}{line_ending}"
                )
                await self.send(payload)

            initial_buf = self._buffer
            self._buffer = ""

            try:
                raw_output, remaining = await asyncio.wait_for(
                    engine.run_dialog(
                        initial_buffer=initial_buf,
                        send_fn=self.send,
                        read_chunk_fn=self._read_chunk,
                        is_alive_fn=lambda: self.is_alive,
                        mark_closed_fn=self._mark_closed,
                        effective_timeout=effective_timeout,
                        cmd_for_error=err_cmd,
                        host=self._host,
                    ),
                    timeout=effective_timeout,
                )
                self._buffer = remaining
            except builtins.TimeoutError:
                with contextlib.suppress(Exception):
                    self._proc.stdin.write("\x03")
                self._buffer = ""
                raise TimeoutError(
                    f"Expect dialog timed out after {effective_timeout}s",
                    command=err_cmd,
                    host=self._host,
                ) from None

            duration = time.monotonic() - start_time
            cleaned = self._clean_output(raw_output, cmd_str, cmd_str)

            return Result(
                exit_code=0,
                stdout=cleaned,
                stderr="",
                duration=duration,
                command=cmd_str,
                host=self._host,
                sensitive=sensitive,
            )

    async def expect(
        self,
        command: str | Sequence[str] | None = None,
        patterns: Mapping[str, str | SecretStr] | None = None,
        final_prompt: str | None = None,
        timeout: float | None = None,
        line_ending: str = "\n",
        sensitive: bool = False,
        allow_eof: bool = True,
    ) -> Result:
        """Выполнить интерактивный диалог по регулярным выражениям (``expect``)."""
        handler = self._raw_expect
        for obs in reversed(self._observers):
            prev_fn = handler

            async def _step(
                *,
                command: str | Sequence[str] | None = None,
                patterns: Mapping[str, str | SecretStr] | None = None,
                final_prompt: str | None = None,
                timeout: float | None = None,
                line_ending: str = "\n",
                sensitive: bool = False,
                allow_eof: bool = True,
                _obs: Any = obs,
                _nxt: Any = prev_fn,
            ) -> Result:
                return await _obs.observe_shell_expect(
                    self._conn,
                    _nxt,
                    command=command,
                    patterns=patterns,
                    final_prompt=final_prompt,
                    timeout=timeout,
                    line_ending=line_ending,
                    sensitive=sensitive,
                    allow_eof=allow_eof,
                )

            handler = _step

        return await handler(
            command=command,
            patterns=patterns,
            final_prompt=final_prompt,
            timeout=timeout,
            line_ending=line_ending,
            sensitive=sensitive,
            allow_eof=allow_eof,
        )

    async def resize(self, cols: int, rows: int) -> None:
        """Изменить размер окна терминала PTY."""
        if not self.is_alive:
            raise ConnectionError(
                "Shell session is closed or terminated",
                host=self._host,
            )
        res = self._proc.change_terminal_size(cols, rows)
        if inspect.isawaitable(res):
            await res

    async def close(self) -> None:
        """Закрыть shell-сессию: отправить Ctrl-C, exit и терминировать процесс."""
        if self._closed:
            return
        self._closed = True

        if self._proc is not None:
            with contextlib.suppress(Exception):
                self._proc.stdin.write("\x03")
                self._proc.stdin.write("exit\n")
            with contextlib.suppress(Exception):
                self._proc.terminate()
            with contextlib.suppress(Exception):
                close_fn = getattr(self._proc, "close", None)
                if callable(close_fn):
                    close_fn()
            with contextlib.suppress(Exception):
                wait_closed_fn = getattr(self._proc, "wait_closed", None)
                if callable(wait_closed_fn):
                    res = wait_closed_fn()
                    if inspect.isawaitable(res):
                        await res

    async def __aenter__(self) -> Self:
        """Асинхронный вход в контекстный менеджер shell-сессии."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Асинхронный выход из контекстного менеджера с закрытием сессии."""
        await self.close()
