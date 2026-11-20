# src/uniconn/background/_log_handlers.py
"""Обработчики вывода фоновых логов: файл, пересылка, стрим, timeline и архив."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import shlex
import string
import tarfile
import threading
import time
import zipfile
from collections.abc import AsyncIterator, Mapping
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from ..exceptions import ConfigurationError
from ._log_rules import (
    _ALLOWED_TEMPLATE_FIELDS,
    LogHandler,
    _iter_clean_lines,
    _sanitize_name,
    _utc_now_iso,
)
from ._models import LogEvent

if TYPE_CHECKING:
    from ..core.connection import Connection


class NullHandler(LogHandler):
    """Обработчик-заглушка: ничего не делает (режим collect=False)."""

    async def handle(self, session_id: str, chunk: list[str]) -> None:
        """Игнорировать порцию лога."""
        return None


class LocalFileHandler(LogHandler):
    """Запись логов в локальный файл с ротацией и стратегиями буферизации."""

    DEFAULT_TEMPLATE = "{session_id}.log"

    @staticmethod
    def _validate_name_template(template: str) -> str:
        """Проверить шаблон имени файла на допустимые поля форматирования и отсутствие обхода пути."""
        if not template or "\x00" in template:
            raise ConfigurationError("LocalFileHandler name_template must be a non-empty valid string")
        try:
            parsed = list(string.Formatter().parse(template))
        except ValueError as exc:
            raise ConfigurationError(f"Invalid LocalFileHandler name_template {template!r}: {exc}") from exc
        for _literal, field_name, format_spec, conversion in parsed:
            if field_name is None:
                continue
            if not field_name or any(ch in field_name for ch in (".", "[", "]")):
                raise ConfigurationError(
                    f"Unsupported attribute/index access in name_template field: {field_name!r}"
                )
            if field_name not in _ALLOWED_TEMPLATE_FIELDS:
                raise ConfigurationError(
                    f"Unsupported placeholder {field_name!r} in LocalFileHandler name_template"
                )
            if conversion is not None:
                raise ConfigurationError(
                    f"Format conversions are not allowed in name_template: {field_name!r}"
                )
            if format_spec and field_name != "timestamp":
                raise ConfigurationError(
                    f"Format specifiers are only allowed for 'timestamp' in name_template: {field_name!r}"
                )
        return template

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
        max_bytes: int = 10 * 1024 * 1024,
        backup_count: int = 3,
        logger: logging.Logger | None = None,
    ):
        self._local_dir = Path(local_dir)
        self._name_template = self._validate_name_template(name_template or self.DEFAULT_TEMPLATE)
        self._pool_id = pool_id
        self._idx = idx
        self._host = host
        self._command = command
        self._strategy = strategy
        self._periodic_interval = periodic_interval
        self._fsync = fsync
        self._max_bytes = max_bytes
        self._backup_count = backup_count
        self._logger = logger or logging.getLogger(__name__)
        self._paths: dict[str, Path] = {}
        self._buffers: dict[str, list[str]] = {}
        self._last_flush: dict[str, float] = {}

    def local_path(self, session_id: str) -> Path:
        r"""Путь к локальному файлу лога сессии (резолвится один раз)."""
        if session_id not in self._paths:
            name = self._name_template.format(
                pool_id=_sanitize_name(self._pool_id),
                session_id=_sanitize_name(session_id),
                idx=self._idx,
                timestamp=datetime.now(),
                host=_sanitize_name(self._host),
                command=_sanitize_name(self._command),
            )
            base_resolved = self._local_dir.resolve()
            candidate = self._local_dir / name
            candidate_resolved = candidate.resolve()
            if candidate_resolved == base_resolved or not candidate_resolved.is_relative_to(base_resolved):
                raise ConfigurationError(
                    f"Resolved log path {candidate!s} escapes local_dir {self._local_dir!s}"
                )
            self._paths[session_id] = candidate
        return self._paths[session_id]

    @property
    def written_paths(self) -> dict[str, Path]:
        """Словарь всех созданных файлов логов ``{session_id: Path}``."""
        return dict(self._paths)

    def _rotate_if_needed(self, path: Path, incoming_bytes: int) -> None:
        """Выполнить ротацию файла лога при превышении ``max_bytes``."""
        if self._max_bytes <= 0 or not path.exists():
            return
        try:
            current_size = path.stat().st_size
        except OSError:
            return
        if current_size + incoming_bytes <= self._max_bytes:
            return

        if self._backup_count <= 0:
            with contextlib.suppress(OSError):
                path.unlink(missing_ok=True)
            return

        oldest = path.with_name(f"{path.name}.{self._backup_count}")
        with contextlib.suppress(OSError):
            oldest.unlink(missing_ok=True)

        for idx in range(self._backup_count - 1, 0, -1):
            src = path.with_name(f"{path.name}.{idx}")
            dst = path.with_name(f"{path.name}.{idx + 1}")
            if src.exists():
                with contextlib.suppress(OSError):
                    src.replace(dst)

        first_backup = path.with_name(f"{path.name}.1")
        with contextlib.suppress(OSError):
            path.replace(first_backup)

    def _write(self, session_id: str, lines: list[str]) -> None:
        """Дописать строки в локальный файл (создаёт директории и выполняет ротацию)."""
        if not lines:
            return
        path = self.local_path(session_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = "".join(lines)
        incoming_bytes = len(payload.encode("utf-8", errors="replace"))
        self._rotate_if_needed(path, incoming_bytes)
        with path.open("a", encoding="utf-8", newline="") as f:
            f.write(payload)
            if self._fsync:
                f.flush()
                os.fsync(f.fileno())

    async def handle(self, session_id: str, chunk: list[str]) -> None:
        """Обработать порцию лога согласно стратегии."""
        if self._strategy == "realtime":
            await asyncio.to_thread(self._write, session_id, chunk)
        elif self._strategy == "periodic":
            buffer = self._buffers.setdefault(session_id, [])
            buffer.extend(chunk)
            now = time.monotonic()
            last = self._last_flush.setdefault(session_id, now)
            if now - last >= self._periodic_interval:
                to_write = list(buffer)
                buffer.clear()
                self._last_flush[session_id] = now
                await asyncio.to_thread(self._write, session_id, to_write)
        else:  # on_complete
            self._buffers.setdefault(session_id, []).extend(chunk)

    async def finalize(self, session_id: str) -> Path:
        """Записать накопленный буфер (для periodic/on_complete) и вернуть путь."""
        buffer = self._buffers.pop(session_id, [])
        if buffer:
            await asyncio.to_thread(self._write, session_id, buffer)
        return self.local_path(session_id)

    async def finalize_all(self) -> dict[str, Path]:
        """Сбросить буферы всех активных сессий и вернуть словарь путей."""
        for sid in list(self._buffers.keys()):
            await self.finalize(sid)
        return dict(self._paths)


class ForwardHandler(LogHandler):
    """Пересылка логов на другой хост (дописывание в удалённый файл)."""

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
            if len(text) > 65536:
                await self._connection.run(
                    f"cat >> {shlex.quote(target_path)}",
                    input=text,
                )
            else:
                await self._connection.run(
                    f"printf '%s' {shlex.quote(text)} >> {shlex.quote(target_path)}"
                )
        except Exception as exc:
            self._logger.warning(
                f"Forward логов сессии {session_id} на {target_path} не удался: {exc}"
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


class TimelineHandler(LogHandler):
    """Обработчик единой хронологической шкалы событий (``timeline.jsonl``)."""

    def __init__(
        self,
        timeline_path: str | Path,
        *,
        fsync: bool = False,
        started_mono: float | None = None,
    ) -> None:
        self._path = Path(timeline_path)
        self._fsync = fsync
        self._started_mono = started_mono if started_mono is not None else time.monotonic()
        self._seq: int = 0
        self._dir_ensured: bool = False
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        """Путь к файлу ``timeline.jsonl``."""
        return self._path

    @property
    def entries_written(self) -> int:
        """Общее количество записанных событий в хронологический лог."""
        return self._seq

    def _write_records_locked(self, records: list[dict[str, Any]]) -> None:
        if not self._dir_ensured:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._dir_ensured = True
        payload = "".join(json.dumps(rec, ensure_ascii=False) + "\n" for rec in records)
        with self._path.open("a", encoding="utf-8", newline="\n") as f:
            f.write(payload)
            if self._fsync:
                f.flush()
                os.fsync(f.fileno())

    def _append_records(self, records: list[dict[str, Any]]) -> None:
        if not records:
            return
        with self._lock:
            self._write_records_locked(records)

    def record_event(
        self,
        stream: str,
        kind: Literal["line", "match", "stall", "marker"],
        text: str,
        *,
        extra: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Сформировать и синхронно записать одиночное событие в ``timeline.jsonl``."""
        with self._lock:
            self._seq += 1
            now_mono = time.monotonic()
            elapsed_ms = round(max(0.0, (now_mono - self._started_mono) * 1000.0), 3)
            rec: dict[str, Any] = {
                "seq": self._seq,
                "timestamp_utc": _utc_now_iso(),
                "elapsed_ms": elapsed_ms,
                "stream": stream,
                "kind": kind,
                "text": text.rstrip("\r\n"),
            }
            if extra:
                rec.update(extra)
            self._write_records_locked([rec])
            return rec

    def _append_chunk_sync(
        self,
        session_id: str,
        lines: list[str],
        ts_utc: str,
        elapsed_ms: float,
    ) -> None:
        with self._lock:
            records: list[dict[str, Any]] = []
            for clean_line in lines:
                self._seq += 1
                records.append(
                    {
                        "seq": self._seq,
                        "timestamp_utc": ts_utc,
                        "elapsed_ms": elapsed_ms,
                        "stream": session_id,
                        "kind": "line",
                        "text": clean_line,
                    }
                )
            self._write_records_locked(records)

    async def handle(self, session_id: str, chunk: list[str]) -> None:
        """Записать порцию строк потока как события ``kind='line'``."""
        lines = _iter_clean_lines(chunk)
        if not lines:
            return
        now_mono = time.monotonic()
        elapsed_ms = round(max(0.0, (now_mono - self._started_mono) * 1000.0), 3)
        ts_utc = _utc_now_iso()
        await asyncio.to_thread(self._append_chunk_sync, session_id, lines, ts_utc, elapsed_ms)

    async def finalize(self) -> Path:
        """Завершить работу с файлом хронологической шкалы и вернуть его путь."""
        return self._path


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
                            zf.write(item, arcname=item.relative_to(src).as_posix())
            return dest

        with tarfile.open(dest, "w:gz") as tf:
            if src.exists():
                for item in sorted(src.rglob("*")):
                    if item.is_file() and item.resolve() != resolved_dest:
                        tf.add(item, arcname=item.relative_to(src).as_posix())
        return dest


__all__ = [
    "ArchiveHandler",
    "ForwardHandler",
    "LocalFileHandler",
    "NullHandler",
    "StreamHandler",
    "TimelineHandler",
]
