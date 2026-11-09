# src/uniconn/background/_log_pipeline.py
from __future__ import annotations

import asyncio
import contextlib
import inspect
import json
import logging
import os
import re
import shlex
import tarfile
import threading
import time
import zipfile
from abc import ABC, abstractmethod
from collections import deque
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, PrivateAttr, field_validator

from ..exceptions import ConfigurationError, HardwareFaultDetectedError
from ._models import LogEvent, LogMatchEvent, StallEvent

if TYPE_CHECKING:
    from ..core.connection import Connection

logger = logging.getLogger(__name__)

# Символы, безопасные для подстановки в имя файла (без разделителей путей)
_SAFE_NAME_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
)

MatchCallback = Callable[[LogMatchEvent], Any]
StallCallback = Callable[[StallEvent], Any]


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


def _utc_now_iso() -> str:
    """Вернуть текущий UTC таймстамп в формате ISO-8601 с миллисекундами."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class LogWatchRule(BaseModel):
    """Правило реактивного отслеживания аномалий и сбоев в потоке логов."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    name: str
    pattern: str
    severity: Literal["info", "warning", "critical"] = "critical"
    abort_on_match: bool = False
    context_lines: int = 5
    _compiled: re.Pattern[str] = PrivateAttr()

    def __init__(self, **data: Any) -> None:
        try:
            super().__init__(**data)
        except Exception as exc:
            if isinstance(exc, ConfigurationError):
                raise
            raise ConfigurationError(str(exc)) from exc

    @field_validator("pattern", mode="before")
    @classmethod
    def _coerce_pattern(cls, value: Any) -> str:
        if isinstance(value, re.Pattern):
            return value.pattern
        if isinstance(value, str) and value.strip():
            return value
        raise ConfigurationError("LogWatchRule.pattern must be a non-empty regex string")

    @field_validator("context_lines")
    @classmethod
    def _validate_context_lines(cls, value: int) -> int:
        return max(0, int(value))

    def model_post_init(self, __context: Any) -> None:
        try:
            self._compiled = re.compile(self.pattern, re.IGNORECASE)
        except re.error as exc:
            raise ConfigurationError(
                f"Invalid regex pattern in LogWatchRule {self.name!r}: {exc}"
            ) from exc

    @property
    def compiled_pattern(self) -> re.Pattern[str]:
        """Скомпилированное регулярное выражение правила."""
        return self._compiled

    def matches(self, line: str) -> bool:
        """Проверить, соответствует ли строка регулярному выражению правила."""
        return self._compiled.search(line) is not None

    @classmethod
    def coerce(cls, item: LogWatchRule | Mapping[str, Any] | str) -> Self:
        """Привести словарь, строку паттерна или экземпляр к ``LogWatchRule``."""
        if isinstance(item, cls):
            return item
        if isinstance(item, Mapping):
            return cls(**item)
        if isinstance(item, str):
            safe = _sanitize_name(item[:32])
            return cls(name=safe, pattern=item)
        raise TypeError(f"Unsupported LogWatchRule item: {type(item).__name__}")


KERNEL_PANIC_RULES: tuple[LogWatchRule, ...] = (
    LogWatchRule(
        name="kernel_panic",
        pattern=r"Kernel panic\s*-\s*not syncing",
        severity="critical",
        abort_on_match=True,
    ),
    LogWatchRule(
        name="kernel_oops",
        pattern=r"\bOops:\s*\d+|\bInternal error:\s*Oops",
        severity="critical",
        abort_on_match=True,
    ),
    LogWatchRule(
        name="soft_lockup",
        pattern=r"BUG:\s*soft lockup\s*-\s*CPU#\d+\s*stuck",
        severity="critical",
        abort_on_match=True,
    ),
    LogWatchRule(
        name="hard_lockup",
        pattern=r"BUG:\s*hard lockup|Watchdog detected hard LOCKUP",
        severity="critical",
        abort_on_match=True,
    ),
)

HARDWARE_ERROR_RULES: tuple[LogWatchRule, ...] = (
    LogWatchRule(
        name="edac_uncorrected",
        pattern=r"EDAC\s+.*?\b(?:UE|Uncorrected)\b",
        severity="critical",
        abort_on_match=True,
    ),
    LogWatchRule(
        name="pcie_aer_uncorrected",
        pattern=r"AER:\s*Uncorrected\s*\((?:Fatal|Non-Fatal)\)",
        severity="critical",
        abort_on_match=True,
    ),
    LogWatchRule(
        name="mce_hardware_error",
        pattern=r"Machine check events logged|mce:\s*\[Hardware Error\]",
        severity="critical",
        abort_on_match=True,
    ),
    LogWatchRule(
        name="nvme_io_error",
        pattern=r"I/O error,\s*dev\s+nvme\d+n\d+|nvme\s+nvme\d+:\s*controller is down",
        severity="critical",
        abort_on_match=False,
    ),
    LogWatchRule(
        name="thermal_critical_trip",
        pattern=r"critical temperature reached|Thermal trip|above threshold, cpu clock throttled",
        severity="critical",
        abort_on_match=True,
    ),
)

TELECOM_BS_RULES: tuple[LogWatchRule, ...] = (
    LogWatchRule(
        name="cpri_los",
        pattern=r"CPRI\s+.*?\b(?:LOS|LOF|link\s+down)\b",
        severity="critical",
        abort_on_match=True,
    ),
    LogWatchRule(
        name="ecpri_timeout",
        pattern=r"eCPRI\s+.*?\b(?:timeout|link\s+down|sync\s+lost)\b",
        severity="critical",
        abort_on_match=True,
    ),
    LogWatchRule(
        name="ptp_freerun",
        pattern=r"PTP\s+.*?\b(?:FREERUN|FAULTY|SYNCHRONIZATION_FAULT)\b",
        severity="warning",
        abort_on_match=False,
    ),
    LogWatchRule(
        name="pll_unlock",
        pattern=r"\bPLL\s+(?:unlock|unlocked|loss of lock)\b",
        severity="critical",
        abort_on_match=True,
    ),
    LogWatchRule(
        name="vswr_alarm",
        pattern=r"\bVSWR\s+(?:alarm|high|critical|fault)\b",
        severity="critical",
        abort_on_match=True,
    ),
    LogWatchRule(
        name="pa_overtemp",
        pattern=r"\bPA\s+(?:overtemp|over-temperature|thermal shutdown)\b",
        severity="critical",
        abort_on_match=True,
    ),
)

BUILTIN_WATCH_RULES: dict[str, tuple[LogWatchRule, ...]] = {
    "kernel_panic": KERNEL_PANIC_RULES,
    "hardware_errors": HARDWARE_ERROR_RULES,
    "telecom_bs": TELECOM_BS_RULES,
    "all": (*KERNEL_PANIC_RULES, *HARDWARE_ERROR_RULES, *TELECOM_BS_RULES),
}


def _iter_clean_lines(chunk: Sequence[str]) -> list[str]:
    r"""Разбить порцию строк (включая многострочные элементы) на отдельные строки без ``\r\n``."""
    lines: list[str] = []
    for raw in chunk:
        if not raw:
            continue
        stripped = raw.rstrip("\r\n")
        if "\n" in stripped:
            for part in stripped.splitlines():
                lines.append(part.rstrip("\r"))
        else:
            lines.append(stripped)
    return lines


def resolve_watch_rules(
    rules: Sequence[LogWatchRule | Mapping[str, Any] | str]
    | Mapping[str, Any]
    | str
    | None,
) -> list[LogWatchRule]:
    """Развернуть список правил, словарей или имён встроенных профилей в ``list[LogWatchRule]``."""
    if rules is None:
        return []
    if isinstance(rules, str):
        if rules.lower() in BUILTIN_WATCH_RULES:
            return list(BUILTIN_WATCH_RULES[rules.lower()])
        return [LogWatchRule.coerce(rules)]

    resolved: list[LogWatchRule] = []
    if isinstance(rules, Mapping):
        if "pattern" in rules and isinstance(rules.get("name"), str):
            return [LogWatchRule.coerce(rules)]
        for k, v in rules.items():
            if isinstance(v, str):
                resolved.append(LogWatchRule(name=str(k), pattern=v))
            elif isinstance(v, Mapping):
                rule_dict = dict(v)
                rule_dict.setdefault("name", str(k))
                resolved.append(LogWatchRule(**rule_dict))
            elif isinstance(v, LogWatchRule):
                resolved.append(v)
            else:
                raise ConfigurationError(
                    f"Unsupported watch rule entry for {k!r}: {type(v).__name__}"
                )
        return resolved

    for item in rules:
        if isinstance(item, str) and item.lower() in BUILTIN_WATCH_RULES:
            resolved.extend(BUILTIN_WATCH_RULES[item.lower()])
        else:
            resolved.append(LogWatchRule.coerce(item))
    return resolved


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
        max_bytes: int = 10 * 1024 * 1024,
        backup_count: int = 3,
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
        self._max_bytes = max_bytes
        self._backup_count = backup_count
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


class TimelineHandler(LogHandler):
    """Обработчик единой хронологической шкалы событий (``timeline.jsonl``).

    Записывает все строки потоков, пользовательские метки, срабатывания триггеров
    ``PatternTriggerHandler`` и события зависания ``StallEvent`` в единый
    упорядоченный JSONL-файл с UTC и монотонными временными метками.
    """

    def __init__(
        self,
        timeline_path: str | Path,
        *,
        fsync: bool = False,
        started_mono: float | None = None,
    ) -> None:
        self._path = Path(timeline_path)
        self._fsync = fsync
        self._started_mono = (
            started_mono if started_mono is not None else time.monotonic()
        )
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

    def _append_records(self, records: list[dict[str, Any]]) -> None:
        if not records:
            return
        with self._lock:
            if not self._dir_ensured:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                self._dir_ensured = True
            payload = "".join(
                json.dumps(rec, ensure_ascii=False) + "\n" for rec in records
            )
            with self._path.open("a", encoding="utf-8", newline="\n") as f:
                f.write(payload)
                if self._fsync:
                    f.flush()
                    os.fsync(f.fileno())

    def record_event(
        self,
        stream: str,
        kind: Literal["line", "match", "stall", "marker"],
        text: str,
        *,
        extra: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Сформировать и синхронно записать одиночное событие в ``timeline.jsonl``."""
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
        self._append_records([rec])
        return rec

    async def handle(self, session_id: str, chunk: list[str]) -> None:
        """Записать порцию строк потока как события ``kind='line'``."""
        lines = _iter_clean_lines(chunk)
        if not lines:
            return
        now_mono = time.monotonic()
        elapsed_ms = round(max(0.0, (now_mono - self._started_mono) * 1000.0), 3)
        ts_utc = _utc_now_iso()
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
        await asyncio.to_thread(self._append_records, records)

    async def finalize(self) -> Path:
        """Завершить работу с файлом хронологической шкалы и вернуть его путь."""
        return self._path


class PatternTriggerHandler(LogHandler):
    """Реактивный обработчик поиска паттернов ошибок и аномалий в потоках логов.

    Хранит кольцевой буфер последних ``N`` строк отдельно для каждого потока,
    проверяет входящие строки против скомпилированных правил ``LogWatchRule``,
    формирует ``LogMatchEvent``, вызывает колбэк ``on_match`` и выставляет
    флаг аварийного прерывания при ``abort_on_match=True``.
    """

    def __init__(
        self,
        rules: Sequence[LogWatchRule | Mapping[str, Any] | str]
        | Mapping[str, Any]
        | str
        | None = None,
        *,
        on_match: MatchCallback | None = None,
        timeline: TimelineHandler | None = None,
        host: str | None = None,
    ) -> None:
        self._rules = resolve_watch_rules(rules)
        self._on_match = on_match
        self._timeline = timeline
        self._host = host
        self._max_context = max(
            (r.context_lines for r in self._rules), default=0
        )
        self._ring_buffers: dict[str, deque[str]] = {}
        self._matches: list[LogMatchEvent] = []
        self._abort_event = asyncio.Event()
        self._first_abort_match: LogMatchEvent | None = None

    @property
    def rules(self) -> list[LogWatchRule]:
        """Список активных правил мониторинга."""
        return list(self._rules)

    @property
    def matches(self) -> list[LogMatchEvent]:
        """Список всех зафиксированных срабатываний правил."""
        return list(self._matches)

    @property
    def abort_triggered(self) -> bool:
        """Сработало ли хотя бы одно правило с ``abort_on_match=True``."""
        return self._abort_event.is_set()

    @property
    def first_abort_match(self) -> LogMatchEvent | None:
        """Первое событие совпадения, вызвавшее ``abort_on_match=True``."""
        return self._first_abort_match

    def check_abort(self) -> None:
        """Выбросить ``HardwareFaultDetectedError``, если сработало правило с ``abort_on_match=True``."""
        if self._first_abort_match is not None:
            m = self._first_abort_match
            raise HardwareFaultDetectedError(
                f"Log watch rule {m.rule_name!r} ({m.severity}) triggered abort on stream "
                f"{m.session_id!r}: {m.matched_line.strip()}",
                match=m,
                matches=list(self._matches),
                host=self._host,
            )

    async def handle(self, session_id: str, chunk: list[str]) -> None:
        """Проверить каждую строку чанка по всем правилам и обновить кольцевой буфер контекста."""
        if not chunk or not self._rules:
            return
        lines = _iter_clean_lines(chunk)
        if not lines:
            return

        ring = self._ring_buffers.get(session_id)
        if ring is None and self._max_context > 0:
            ring = deque(maxlen=self._max_context)
            self._ring_buffers[session_id] = ring

        for clean_line in lines:
            for rule in self._rules:
                if rule.matches(clean_line):
                    ctx_before: tuple[str, ...] = ()
                    if ring is not None and rule.context_lines > 0:
                        buf_list = list(ring)
                        ctx_before = tuple(buf_list[-rule.context_lines :])

                    event = LogMatchEvent(
                        rule_name=rule.name,
                        session_id=session_id,
                        severity=rule.severity,
                        matched_line=clean_line,
                        pattern=rule.pattern,
                        timestamp_utc=_utc_now_iso(),
                        monotonic_sec=time.monotonic(),
                        context_before=ctx_before,
                        abort_triggered=rule.abort_on_match,
                    )
                    self._matches.append(event)
                    if rule.abort_on_match:
                        if self._first_abort_match is None:
                            self._first_abort_match = event
                        self._abort_event.set()

                    if self._timeline is not None:
                        self._timeline.record_event(
                            stream=session_id,
                            kind="match",
                            text=clean_line,
                            extra={
                                "rule_name": rule.name,
                                "severity": rule.severity,
                                "abort_triggered": rule.abort_on_match,
                                "context_before": list(ctx_before),
                            },
                        )

                    if self._on_match is not None:
                        try:
                            res = self._on_match(event)
                            if inspect.isawaitable(res):
                                await res
                        except Exception as exc:
                            logger.warning(
                                f"Ошибка в пользовательском колбэке on_match для {rule.name!r}: {exc}"
                            )

            if ring is not None:
                ring.append(clean_line)


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
