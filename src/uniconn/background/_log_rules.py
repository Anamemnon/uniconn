# src/uniconn/background/_log_rules.py
"""Правила мониторинга логов, встроенные профили сбоев и PatternTriggerHandler."""

from __future__ import annotations

import asyncio
import inspect
import logging
import re
import time
from abc import ABC, abstractmethod
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, PrivateAttr, field_validator

from ..exceptions import ConfigurationError, HardwareFaultDetectedError
from ._models import LogMatchEvent, StallEvent

if TYPE_CHECKING:
    from ._log_handlers import TimelineHandler

logger = logging.getLogger(__name__)

# Символы, безопасные для подстановки в имя файла (без разделителей путей)
_SAFE_NAME_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
)
_ALLOWED_TEMPLATE_FIELDS = frozenset(
    {"pool_id", "session_id", "idx", "timestamp", "host", "command"}
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


class PatternTriggerHandler(LogHandler):
    """Реактивный обработчик поиска паттернов ошибок и аномалий в потоках логов."""

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
        self._max_context = max((r.context_lines for r in self._rules), default=0)
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


__all__ = [
    "BUILTIN_WATCH_RULES",
    "HARDWARE_ERROR_RULES",
    "KERNEL_PANIC_RULES",
    "TELECOM_BS_RULES",
    "_ALLOWED_TEMPLATE_FIELDS",
    "_SAFE_NAME_CHARS",
    "LogHandler",
    "LogWatchRule",
    "MatchCallback",
    "PatternTriggerHandler",
    "StallCallback",
    "_iter_clean_lines",
    "_sanitize_name",
    "_utc_now_iso",
    "resolve_watch_rules",
]
