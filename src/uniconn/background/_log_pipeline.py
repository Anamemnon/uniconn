# src/uniconn/background/_log_pipeline.py
"""Конвейер обработки фоновых логов (LogPipeline) и сборщик потоков (DirectStreamCollector)."""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import logging
import time
from collections.abc import AsyncIterator, Sequence
from typing import TYPE_CHECKING

from ..exceptions import ConfigurationError
from ._log_handlers import (
    ArchiveHandler,
    ForwardHandler,
    LocalFileHandler,
    NullHandler,
    StreamHandler,
    TimelineHandler,
)
from ._log_rules import (
    _ALLOWED_TEMPLATE_FIELDS,
    _SAFE_NAME_CHARS,
    BUILTIN_WATCH_RULES,
    HARDWARE_ERROR_RULES,
    KERNEL_PANIC_RULES,
    TELECOM_BS_RULES,
    LogHandler,
    LogWatchRule,
    MatchCallback,
    PatternTriggerHandler,
    StallCallback,
    _iter_clean_lines,
    _sanitize_name,
    _utc_now_iso,
    resolve_watch_rules,
)
from ._models import StallEvent

if TYPE_CHECKING:
    from ..core.connection import Connection

logger = logging.getLogger(__name__)


class DirectStreamCollector:
    """Фоновый сборщик потоковых логов через ``conn.stream()`` без требования GNU screen.

    Позволяет захватывать ``dmesg -w``, ``journalctl -f`` или вывод Serial/SOL
    в реальном времени и передавать каждую строку в ``LogPipeline.emit()``.
    Устойчив к внезапному обрыву связи при зависании или перезагрузке хоста,
    а также поддерживает детектор зависания потока ``max_silence_seconds`` (Watchdog).
    """

    def __init__(
        self,
        connection: Connection,
        name: str,
        command: str,
        pipeline: LogPipeline,
        timeout: float | None = None,
        restart_on_exit: bool = False,
        restart_delay: float = 1.0,
        timestamp_lines: bool = False,
        max_silence_seconds: float | None = None,
        on_stall: StallCallback | None = None,
        timeline: TimelineHandler | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._connection = connection
        self.name = name
        self.command = command
        self._pipeline = pipeline
        self._timeout = timeout
        self._restart_on_exit = restart_on_exit
        self._restart_delay = restart_delay
        self._timestamp_lines = timestamp_lines
        if max_silence_seconds is not None and max_silence_seconds <= 0:
            raise ConfigurationError("max_silence_seconds must be > 0")
        self._max_silence_seconds = (
            float(max_silence_seconds) if max_silence_seconds is not None else None
        )
        self._on_stall = on_stall
        self._timeline = timeline
        self._logger = logger or logging.getLogger(__name__)
        self._task: asyncio.Task[None] | None = None
        self._stop_event = asyncio.Event()
        self.lines_collected: int = 0
        self.error: str | None = None
        self.stalled: bool = False
        self.stall_event: StallEvent | None = None

    @property
    def is_running(self) -> bool:
        """Активна ли фоновая задача чтения потока."""
        return self._task is not None and not self._task.done()

    def start(self) -> asyncio.Task[None]:
        """Запустить фоновую задачу чтения потока."""
        if self._task is not None and not self._task.done():
            return self._task
        self._stop_event.clear()
        self._task = asyncio.create_task(
            self._run_loop(), name=f"uniconn-stream-{self.name}"
        )
        return self._task

    async def _wait_restart_delay(self) -> bool:
        """Подождать ``_restart_delay`` секунд или мгновенно прерваться по ``_stop_event``."""
        if self._restart_delay <= 0:
            return self._stop_event.is_set()
        try:
            await asyncio.wait_for(self._stop_event.wait(), timeout=self._restart_delay)
            return True
        except TimeoutError:
            return self._stop_event.is_set()

    def _format_line(self, line: str) -> str:
        """Нормализовать перевод строки и опционально добавить ISO-8601 UTC таймстамп."""
        normalized = line if line.endswith("\n") else f"{line}\n"
        if not self._timestamp_lines:
            return normalized
        ts = _utc_now_iso()
        return f"[{ts}] {normalized}"

    async def _handle_stall(self, silence_sec: float) -> None:
        """Зафиксировать зависание потока, записать в timeline и вызвать колбэк ``on_stall``."""
        self.stalled = True
        msg = (
            f"Stream {self.name!r} ({self.command!r}) stalled: "
            f"no output for {silence_sec}s"
        )
        self.error = msg
        event = StallEvent(
            session_id=self.name,
            command=self.command,
            silence_seconds=silence_sec,
            timestamp_utc=_utc_now_iso(),
            monotonic_sec=time.monotonic(),
        )
        self.stall_event = event
        self._logger.warning(msg)

        if self._timeline is not None:
            self._timeline.record_event(
                stream=self.name,
                kind="stall",
                text=msg,
                extra={"silence_seconds": silence_sec, "command": self.command},
            )

        if self._on_stall is not None:
            try:
                res = self._on_stall(event)
                if inspect.isawaitable(res):
                    await res
            except Exception as exc:
                self._logger.warning(
                    f"Ошибка в пользовательском колбэке on_stall для {self.name!r}: {exc}"
                )

    async def _consume_stream_with_watchdog(
        self, stream_iter: AsyncIterator[str], silence_limit: float
    ) -> None:
        """Читать итератор потока с контролем таймаута молчания ``silence_limit``."""
        ait = stream_iter.__aiter__()
        try:
            while not self._stop_event.is_set():
                try:
                    line = await asyncio.wait_for(
                        ait.__anext__(), timeout=silence_limit
                    )
                except StopAsyncIteration:
                    break
                except TimeoutError:
                    if not self._stop_event.is_set():
                        await self._handle_stall(silence_limit)
                    break
                if self._stop_event.is_set():
                    break
                await self._pipeline.emit(self.name, [self._format_line(line)])
                self.lines_collected += 1
        finally:
            aclose = getattr(ait, "aclose", None)
            if callable(aclose):
                with contextlib.suppress(Exception):
                    close_res = aclose()
                    if inspect.isawaitable(close_res):
                        await close_res

    async def _run_loop(self) -> None:
        """Основной цикл чтения ``conn.stream`` с передачей строк в ``LogPipeline``."""
        while not self._stop_event.is_set():
            try:
                stream_iter = self._connection.stream(
                    self.command, timeout=self._timeout
                )
                if self._max_silence_seconds is not None:
                    await self._consume_stream_with_watchdog(
                        stream_iter, self._max_silence_seconds
                    )
                    if self.stalled:
                        break
                else:
                    async for line in stream_iter:
                        if self._stop_event.is_set():
                            break
                        await self._pipeline.emit(self.name, [self._format_line(line)])
                        self.lines_collected += 1

                if not self._restart_on_exit or self._stop_event.is_set():
                    break
                if await self._wait_restart_delay():
                    break
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self.error = str(exc)
                self._logger.warning(
                    f"Поток {self.name!r} ({self.command!r}) прерван: {exc}"
                )
                if not self._restart_on_exit or self._stop_event.is_set():
                    break
                if await self._wait_restart_delay():
                    break

    async def stop(self, timeout: float = 1.0) -> None:
        """Корректно остановить фоновую задачу чтения потока."""
        self._stop_event.set()
        if self._task is not None:
            if not self._task.done():
                try:
                    await asyncio.wait_for(asyncio.shield(self._task), timeout=timeout)
                except (TimeoutError, asyncio.CancelledError, Exception):
                    self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task
            self._task = None


class LogPipeline:
    """Pipeline обработки логов: рассылает порции всем обработчикам."""

    def __init__(self, handlers: Sequence[LogHandler]):
        self._handlers = list(handlers)

    @property
    def handlers(self) -> list[LogHandler]:
        """Список зарегистрированных обработчиков конвейера."""
        return list(self._handlers)

    async def emit(self, session_id: str, chunk: list[str]) -> None:
        """Отправить порцию лога всем обработчикам по цепочке."""
        for h in self._handlers:
            await h.handle(session_id, chunk)

    async def finalize(self) -> None:
        """Финализировать все обработчики конвейера (сброс буферов)."""
        for handler in self._handlers:
            if isinstance(handler, LocalFileHandler):
                await handler.finalize_all()
            elif isinstance(handler, (ForwardHandler, ArchiveHandler, TimelineHandler)):
                await handler.finalize()


__all__ = [
    "BUILTIN_WATCH_RULES",
    "HARDWARE_ERROR_RULES",
    "KERNEL_PANIC_RULES",
    "TELECOM_BS_RULES",
    "_ALLOWED_TEMPLATE_FIELDS",
    "_SAFE_NAME_CHARS",
    "ArchiveHandler",
    "DirectStreamCollector",
    "ForwardHandler",
    "LocalFileHandler",
    "LogHandler",
    "LogPipeline",
    "LogWatchRule",
    "MatchCallback",
    "NullHandler",
    "PatternTriggerHandler",
    "StallCallback",
    "StreamHandler",
    "TimelineHandler",
    "_iter_clean_lines",
    "_sanitize_name",
    "_utc_now_iso",
    "resolve_watch_rules",
]
