# src/uniconn/background/_log_pipeline.py
from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import shlex
import tarfile
import time
import zipfile
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Sequence
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from ._models import LogEvent

if TYPE_CHECKING:
    from ..core.connection import Connection

logger = logging.getLogger(__name__)

# Символы, безопасные для подстановки в имя файла (без разделителей путей)
_SAFE_NAME_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
)


def _sanitize_name(value: str) -> str:
    r"""Санитизировать значение для подстановки в шаблон имени файла.

    Все символы вне ``[A-Za-z0-9._-]`` (в т.ч. ``/``, ``\\``, пробелы)
    заменяются на ``_``; значение из одних точек (``""``, ``"."``, ``".."``)
    тоже заменяется — иначе возможен выход за пределы ``local_dir``.
    """
    sanitized = "".join(c if c in _SAFE_NAME_CHARS else "_" for c in value)
    if not sanitized.strip("."):
        return "_"
    return sanitized


class LogHandler(ABC):
    """Абстрактный обработчик порций логов screen-сессии или фонового потока."""

    @abstractmethod
    async def handle(self, session_id: str, chunk: list[str]) -> None:
        """Обработать порцию строк лога."""


class NullHandler(LogHandler):
    """Обработчик-заглушка: ничего не делает (режим collect=False)."""

    async def handle(self, session_id: str, chunk: list[str]) -> None:
        """Игнорировать порцию лога."""
        return None


class LocalFileHandler(LogHandler):
    """Запись логов в локальный файл.

    Имя файла задаётся шаблоном с переменными:
    ``{pool_id}``, ``{session_id}``, ``{idx}``, ``{timestamp}``,
    ``{host}``, ``{command}``. Для ``{timestamp}`` поддерживается
    format spec, например ``{timestamp:%Y%m%d_%H%M%S}``.

    Стратегии записи (download_strategy):
    - ``realtime`` — каждая порция сразу дописывается в файл (опционально с ``fsync``);
    - ``periodic`` — порции буферизуются и сбрасываются не чаще,
      чем раз в ``periodic_interval`` секунд;
    - ``on_complete`` — порции буферизуются, запись выполняется
      при вызове ``finalize()``.
    """

    DEFAULT_TEMPLATE = "{session_id}.log"

    def __init__(
        self,
        local_dir: str | Path,
        name_template: str | None = None,
        pool_id: str = "",
        idx: int = 0,
        host: str = "",
        command: str = "",
        strategy: str = "on_complete",
        periodic_interval: float = 5.0,
        fsync: bool = False,
        logger: logging.Logger | None = None,
    ):
        self._local_dir = Path(local_dir)
        self._name_template = name_template or self.DEFAULT_TEMPLATE
        self._pool_id = pool_id
        self._idx = idx
        self._host = host
        self._command = command
        self._strategy = strategy
        self._periodic_interval = periodic_interval
        self._fsync = fsync
        self._logger = logger or logging.getLogger(__name__)
        self._paths: dict[str, Path] = {}
        self._buffers: dict[str, list[str]] = {}
        self._last_flush: dict[str, float] = {}

    def local_path(self, session_id: str) -> Path:
        r"""Путь к локальному файлу лога сессии (резолвится один раз).

        Подставляемые в шаблон значения санитизируются: опасные символы
        (``/``, ``\\``, ``..`` и т.п.) заменяются на ``_``, чтобы команда
        или имя хоста не могли вывести путь за пределы ``local_dir``.
        """
        if session_id not in self._paths:
            name = self._name_template.format(
                pool_id=_sanitize_name(self._pool_id),
                session_id=_sanitize_name(session_id),
                idx=self._idx,
                timestamp=datetime.now(),
                host=_sanitize_name(self._host),
                command=_sanitize_name(self._command),
            )
            self._paths[session_id] = self._local_dir / name
        return self._paths[session_id]

    @property
    def written_paths(self) -> dict[str, Path]:
        """Словарь всех созданных файлов логов ``{session_id: Path}``."""
        return dict(self._paths)

    def _write(self, session_id: str, lines: list[str]) -> None:
        """Дописать строки в локальный файл (создаёт директории)."""
        path = self.local_path(session_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.writelines(lines)
            if self._fsync:
                f.flush()
                os.fsync(f.fileno())

    async def handle(self, session_id: str, chunk: list[str]) -> None:
        """Обработать порцию лога согласно стратегии."""
        if self._strategy == "realtime":
            self._write(session_id, chunk)
        elif self._strategy == "periodic":
            buffer = self._buffers.setdefault(session_id, [])
            buffer.extend(chunk)
            now = time.monotonic()
            last = self._last_flush.setdefault(session_id, now)
            if now - last >= self._periodic_interval:
                self._write(session_id, buffer)
                buffer.clear()
                self._last_flush[session_id] = now
        else:  # on_complete
            self._buffers.setdefault(session_id, []).extend(chunk)

    async def finalize(self, session_id: str) -> Path:
        """Записать накопленный буфер (для periodic/on_complete) и вернуть путь."""
        buffer = self._buffers.pop(session_id, [])
        if buffer:
            self._write(session_id, buffer)
        return self.local_path(session_id)

    async def finalize_all(self) -> dict[str, Path]:
        """Сбросить буферы всех активных сессий и вернуть словарь путей."""
        for sid in list(self._buffers.keys()):
            await self.finalize(sid)
        return dict(self._paths)


class ForwardHandler(LogHandler):
    """Пересылка логов на другой хост (дописывание в удалённый файл).

    Best-effort: при ошибке пересылки пишет warning в лог и не падает —
    лог остаётся доступен через другие обработчики.
    Поддерживает подстановку ``{session_id}`` в ``remote_path``.
    """

    def __init__(
        self,
        connection: Connection,
        remote_path: str,
        flush_interval: float = 0.0,
        logger: logging.Logger | None = None,
    ):
        self._connection = connection
        self._remote_path = remote_path
        self._flush_interval = flush_interval
        self._logger = logger or logging.getLogger(__name__)
        self._buffers: dict[str, list[str]] = {}
        self._last_flush: dict[str, float] = {}

    def resolve_remote_path(self, session_id: str) -> str:
        """Разрешить удалённый путь с учётом шаблона ``{session_id}``."""
        if "{session_id}" in self._remote_path:
            return self._remote_path.format(session_id=_sanitize_name(session_id))
        return self._remote_path

    async def _send(self, session_id: str, lines: list[str]) -> None:
        """Отправить накопленные строки в файл на удалённом хосте."""
        if not lines:
            return
        text = "".join(lines)
        target_path = self.resolve_remote_path(session_id)
        try:
            await self._connection.run(
                f"printf '%s' {shlex.quote(text)} >> {shlex.quote(target_path)}"
            )
        except Exception as exc:
            self._logger.warning(
                f"Forward логов сессии {session_id} на {target_path} "
                f"не удался: {exc}"
            )

    async def handle(self, session_id: str, chunk: list[str]) -> None:
        """Дописать порцию лога в файл на удалённом хосте."""
        if self._flush_interval <= 0.0:
            await self._send(session_id, chunk)
            return

        buf = self._buffers.setdefault(session_id, [])
        buf.extend(chunk)
        now = time.monotonic()
        last = self._last_flush.setdefault(session_id, now)
        if now - last >= self._flush_interval:
            to_send = list(buf)
            buf.clear()
            self._last_flush[session_id] = now
            await self._send(session_id, to_send)

    async def finalize(self, session_id: str | None = None) -> None:
        """Сбросить буферизованные чанки на удалённый хост."""
        if session_id is not None:
            buf = self._buffers.pop(session_id, [])
            if buf:
                await self._send(session_id, buf)
            return

        for sid in list(self._buffers.keys()):
            buf = self._buffers.pop(sid, [])
            if buf:
                await self._send(sid, buf)


class StreamHandler(LogHandler):
    """Отдача логов в Python-код через очередь событий LogEvent."""

    def __init__(self) -> None:
        self._queue: asyncio.Queue[LogEvent] = asyncio.Queue()

    async def handle(self, session_id: str, chunk: list[str]) -> None:
        """Положить каждую строку порции в очередь как LogEvent."""
        for line in chunk:
            await self._queue.put(LogEvent(session_id=session_id, line=line))

    async def events(self) -> AsyncIterator[LogEvent]:
        """Бесконечный асинхронный итератор событий лога."""
        while True:
            yield await self._queue.get()


class ArchiveHandler(LogHandler):
    """Упаковщик собранных логов и диагностических артефактов в ``.tar.gz`` или ``.zip``."""

    def __init__(
        self,
        source_dir: str | Path,
        archive_path: str | Path,
        fmt: Literal["tar.gz", "zip"] = "tar.gz",
    ) -> None:
        self._source_dir = Path(source_dir)
        self._archive_path = Path(archive_path)
        self._fmt: Literal["tar.gz", "zip"] = fmt

    async def handle(self, session_id: str, chunk: list[str]) -> None:
        """ArchiveHandler работает на этапе финализации директории."""
        return None

    async def finalize(self) -> Path:
        """Упаковать все файлы из ``source_dir`` в итоговый архив."""
        return await asyncio.to_thread(
            self.build_archive,
            self._source_dir,
            self._archive_path,
            self._fmt,
        )

    @staticmethod
    def build_archive(
        source_dir: str | Path,
        archive_path: str | Path,
        fmt: Literal["tar.gz", "zip"] = "tar.gz",
    ) -> Path:
        """Создать ``.tar.gz`` или ``.zip`` архив из содержимого ``source_dir``."""
        src = Path(source_dir)
        dest = Path(archive_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        resolved_dest = dest.resolve()

        if fmt == "zip":
            with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                if src.exists():
                    for item in sorted(src.rglob("*")):
                        if item.is_file() and item.resolve() != resolved_dest:
                            zf.write(item, arcname=str(item.relative_to(src)))
            return dest

        with tarfile.open(dest, "w:gz") as tf:
            if src.exists():
                for item in sorted(src.rglob("*")):
                    if item.is_file() and item.resolve() != resolved_dest:
                        tf.add(item, arcname=str(item.relative_to(src)))
        return dest


class DirectStreamCollector:
    """Фоновый сборщик потоковых логов через ``conn.stream()`` без требования GNU screen.

    Позволяет захватывать ``dmesg -w``, ``journalctl -f`` или вывод Serial/SOL
    в реальном времени и передавать каждую строку в ``LogPipeline.emit()``.
    Устойчив к внезапному обрыву связи при зависании или перезагрузке хоста.
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
        logger: logging.Logger | None = None,
    ) -> None:
        self._connection = connection
        self.name = name
        self.command = command
        self._pipeline = pipeline
        self._timeout = timeout
        self._restart_on_exit = restart_on_exit
        self._restart_delay = restart_delay
        self._logger = logger or logging.getLogger(__name__)
        self._task: asyncio.Task[None] | None = None
        self._stop_event = asyncio.Event()
        self.lines_collected: int = 0
        self.error: str | None = None

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

    async def _run_loop(self) -> None:
        """Основной цикл чтения ``conn.stream`` с передачей строк в ``LogPipeline``."""
        while not self._stop_event.is_set():
            try:
                async for line in self._connection.stream(
                    self.command, timeout=self._timeout
                ):
                    if self._stop_event.is_set():
                        break
                    normalized = line if line.endswith("\n") else f"{line}\n"
                    self.lines_collected += 1
                    await self._pipeline.emit(self.name, [normalized])
                if not self._restart_on_exit or self._stop_event.is_set():
                    break
                await asyncio.sleep(self._restart_delay)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self.error = str(exc)
                self._logger.warning(
                    f"Поток {self.name!r} ({self.command!r}) прерван: {exc}"
                )
                if not self._restart_on_exit or self._stop_event.is_set():
                    break
                await asyncio.sleep(self._restart_delay)

    async def stop(self) -> None:
        """Корректно остановить фоновую задачу чтения потока."""
        self._stop_event.set()
        if self._task is not None:
            if not self._task.done():
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
        """Отправить порцию лога всем обработчикам параллельно."""
        await asyncio.gather(
            *(h.handle(session_id, chunk) for h in self._handlers)
        )

    async def finalize(self) -> None:
        """Финализировать все обработчики конвейера (сброс буферов)."""
        for handler in self._handlers:
            if isinstance(handler, LocalFileHandler):
                await handler.finalize_all()
            elif isinstance(handler, (ForwardHandler, ArchiveHandler)):
                await handler.finalize()

