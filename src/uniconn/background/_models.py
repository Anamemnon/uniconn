# src/uniconn/background/_models.py
from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class LogEvent:
    """Событие лога — одна строка вывода screen-сессии."""

    session_id: str
    line: str
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass(frozen=True)
class StatusEvent:
    """Событие статуса screen-сессии (результат опроса)."""

    session_id: str
    alive: bool
    pid: int | None = None
    exit_code: int | None = None


@dataclass(frozen=True)
class ScreenResult:
    """Итоговый результат завершившейся screen-сессии."""

    session_id: str
    exit_code: int
    remote_log_path: str
    local_log_path: str | None = None
    duration: float = 0.0
