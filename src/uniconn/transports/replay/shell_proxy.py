# src/uniconn/transports/replay/shell_proxy.py
"""Эмуляция и запись интерактивных PTY-процессов для ReplayTransport и Cassette."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from .models import (
    _POSIX_MARKER_CMD_RE,
    _POSIX_MARKER_OUT_RE,
    RecordedExecInteraction,
    RecordedShellInteraction,
    ShellDialogStep,
    normalize_temp_paths,
)

if TYPE_CHECKING:
    from .proxy import CassetteTransportProxy


class _ReplayStdin:
    """Эмуляция stdin для ReplayShellProcess."""

    def __init__(self, owner: ReplayShellProcess) -> None:
        self._owner = owner

    def write(self, data: str | bytes) -> None:
        text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
        self._owner._on_stdin_write(text)

    async def drain(self) -> None:
        return None


class _ReplayStdout:
    """Эмуляция stdout для ReplayShellProcess."""

    def __init__(self, owner: ReplayShellProcess) -> None:
        self._owner = owner

    async def read(self, _n: int = 4096) -> str:
        return await self._owner._on_stdout_read()


class ReplayShellProcess:
    """Эмуляция PTY-процесса для воспроизведения ``ShellSession`` и ``expect()``."""

    def __init__(
        self,
        shell_interaction: RecordedShellInteraction,
        exec_interactions: Sequence[RecordedExecInteraction],
        *,
        normalize_temp: bool = True,
    ) -> None:
        """Инициализировать эмулятор PTY-процесса из записанных шагов."""
        self._shell_interaction = shell_interaction
        self._exec_interactions = list(exec_interactions)
        self._normalize_temp = normalize_temp
        self._step_index = 0
        self._out_queue: asyncio.Queue[str] = asyncio.Queue()
        self.stdin = _ReplayStdin(self)
        self.stdout = _ReplayStdout(self)
        self.returncode: int | None = None
        self.exit_status: int | None = None
        self.term_size: tuple[int, int] = shell_interaction.term_size

    def _norm(self, text: str) -> str:
        return normalize_temp_paths(text) if self._normalize_temp else text

    def _find_step(self, cmd: str) -> tuple[str, int]:
        norm_cmd = self._norm(cmd.strip())
        steps = self._shell_interaction.steps
        for idx in range(self._step_index, len(steps)):
            step = steps[idx]
            if self._norm(step.expect_input.strip()) == norm_cmd:
                self._step_index = idx + 1
                return step.response_output, step.exit_code
        for step in steps:
            if self._norm(step.expect_input.strip()) == norm_cmd:
                return step.response_output, step.exit_code
        for exec_ep in self._exec_interactions:
            if self._norm(exec_ep.command.strip()) == norm_cmd:
                return exec_ep.stdout, exec_ep.exit_code
        return "", 0

    def _on_stdin_write(self, text: str) -> None:
        stripped = text.strip()
        if stripped == "export PS1=''; stty -echo":
            return
        if text == "\x03":
            return

        marker_match = _POSIX_MARKER_CMD_RE.match(stripped)
        if marker_match is not None:
            inner_cmd = marker_match.group(1)
            marker_prefix = marker_match.group(2)
            out_text, code = self._find_step(inner_cmd)
            payload = f"{out_text}\n{marker_prefix}{code}\n"
            self._out_queue.put_nowait(payload)
            return

        out_text, _code = self._find_step(stripped)
        if out_text:
            self._out_queue.put_nowait(out_text)
        if self._step_index >= len(self._shell_interaction.steps):
            self._out_queue.put_nowait("")

    async def _on_stdout_read(self) -> str:
        if self.returncode is not None and self._out_queue.empty():
            return ""
        chunk = await self._out_queue.get()
        if chunk == "":
            self.returncode = 0
            self.exit_status = 0
        return chunk

    def change_terminal_size(self, width: int, height: int) -> None:
        """Изменить размер виртуального терминала (совместимо с ``ShellProcessProtocol``)."""
        self.term_size = (width, height)

    def set_term_size(self, cols: int, rows: int) -> None:
        """Обновить размер виртуального терминала."""
        self.term_size = (cols, rows)

    def is_closing(self) -> bool:
        """Проверить, закрыт ли виртуальный процесс."""
        return self.returncode is not None

    def close(self) -> None:
        """Закрыть виртуальный процесс."""
        self.returncode = 0
        self.exit_status = 0
        self._out_queue.put_nowait("")


class _RecordingShellProcessProxy:
    """Прокси над реальным PTY-процессом для записи диалогов ``ShellSession`` в кассету."""

    def __init__(
        self,
        real_proc: Any,
        interaction: RecordedShellInteraction,
        proxy: CassetteTransportProxy,
    ) -> None:
        self._real = real_proc
        self._interaction = interaction
        self._proxy = proxy
        self._pending_cmd: str | None = None
        self._accumulated_out: str = ""
        self.stdin = self
        self.stdout = self

    @property
    def returncode(self) -> int | None:
        return getattr(self._real, "returncode", None)

    @property
    def exit_status(self) -> int | None:
        return getattr(self._real, "exit_status", None)

    def write(self, data: str | bytes) -> None:
        text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
        stripped = text.strip()
        if stripped != "export PS1=''; stty -echo" and text != "\x03":
            if self._pending_cmd is not None and self._accumulated_out:
                self._flush_pending_step(0)
            marker_match = _POSIX_MARKER_CMD_RE.match(stripped)
            raw_cmd = marker_match.group(1) if marker_match else stripped
            self._pending_cmd = self._proxy._sanitize_text(raw_cmd, normalize=True)
            self._accumulated_out = ""
        self._real.stdin.write(data)

    async def drain(self) -> None:
        drain_fn = getattr(self._real.stdin, "drain", None)
        if callable(drain_fn):
            res = drain_fn()
            if inspect.isawaitable(res):
                await res

    def _flush_pending_step(self, exit_code: int) -> None:
        if self._pending_cmd is None:
            return
        cleaned = _POSIX_MARKER_OUT_RE.sub("", self._accumulated_out)
        cleaned = self._proxy._sanitize_text(cleaned, normalize=False)
        self._interaction.steps.append(
            ShellDialogStep(
                expect_input=self._pending_cmd,
                response_output=cleaned,
                exit_code=exit_code,
            )
        )
        self._pending_cmd = None
        self._accumulated_out = ""
        self._proxy.mark_dirty()

    async def read(self, n: int = 4096) -> str | bytes:
        read_fn = self._real.stdout.read
        try:
            res = read_fn(n)
        except TypeError:
            res = read_fn()
        chunk = await res if inspect.isawaitable(res) else res
        text = chunk.decode("utf-8", errors="replace") if isinstance(chunk, bytes) else (chunk or "")
        if self._pending_cmd is not None:
            self._accumulated_out += text
            marker_match = _POSIX_MARKER_OUT_RE.search(self._accumulated_out)
            if marker_match is not None:
                code = int(marker_match.group(1))
                self._flush_pending_step(code)
            elif text == "":
                self._flush_pending_step(0)
        return chunk

    def change_terminal_size(self, width: int, height: int) -> Any:
        fn = getattr(self._real, "change_terminal_size", None) or getattr(
            self._real, "set_term_size", None
        )
        if callable(fn):
            return fn(width, height)
        return None

    def set_term_size(self, cols: int, rows: int) -> Any:
        return self.change_terminal_size(cols, rows)

    def is_closing(self) -> bool:
        fn = getattr(self._real, "is_closing", None)
        if callable(fn):
            return bool(fn())
        return self.returncode is not None

    def close(self) -> Any:
        if self._pending_cmd is not None:
            self._flush_pending_step(0)
        fn = getattr(self._real, "close", None)
        if callable(fn):
            return fn()
        return None


__all__ = [
    "ReplayShellProcess",
    "_RecordingShellProcessProxy",
    "_ReplayStdin",
    "_ReplayStdout",
]
