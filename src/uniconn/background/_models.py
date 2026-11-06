# src/uniconn/background/_models.py
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class LogEvent:
    """Событие лога — одна строка вывода фоновой сессии."""

    session_id: str
    line: str
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass(frozen=True, slots=True)
class LogMatchEvent:
    """Событие совпадения строки потока с правилом мониторинга ``LogWatchRule``."""

    rule_name: str
    session_id: str
    severity: str
    matched_line: str
    pattern: str
    timestamp_utc: str
    monotonic_sec: float
    context_before: tuple[str, ...] = ()
    abort_triggered: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Преобразовать событие совпадения в сериализуемый словарь."""
        return {
            "rule_name": self.rule_name,
            "session_id": self.session_id,
            "severity": self.severity,
            "matched_line": self.matched_line,
            "pattern": self.pattern,
            "timestamp_utc": self.timestamp_utc,
            "monotonic_sec": round(self.monotonic_sec, 6),
            "context_before": list(self.context_before),
            "abort_triggered": self.abort_triggered,
        }


@dataclass(frozen=True, slots=True)
class StallEvent:
    """Событие зависания (молчания) потока дольше ``max_silence_seconds``."""

    session_id: str
    command: str
    silence_seconds: float
    timestamp_utc: str
    monotonic_sec: float

    def to_dict(self) -> dict[str, Any]:
        """Преобразовать событие зависания потока в сериализуемый словарь."""
        return {
            "session_id": self.session_id,
            "command": self.command,
            "silence_seconds": round(self.silence_seconds, 3),
            "timestamp_utc": self.timestamp_utc,
            "monotonic_sec": round(self.monotonic_sec, 6),
        }


@dataclass(frozen=True, slots=True)
class StatusEvent:
    """Событие статуса фоновой сессии (результат опроса)."""

    session_id: str
    alive: bool
    pid: int | None = None
    exit_code: int | None = None


@dataclass(frozen=True, slots=True)
class BackgroundResult:
    """Итоговый результат завершившейся фоновой сессии."""

    session_id: str
    exit_code: int
    remote_log_path: str
    local_log_path: str | None = None
    duration: float = 0.0
    backend: str = "nohup"

