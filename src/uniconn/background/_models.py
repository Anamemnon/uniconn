# src/uniconn/background/_models.py
from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True, slots=True)
class LogEvent:
    """Событие лога — одна строка вывода фоновой сессии."""

    session_id: str
    line: str
    timestamp: datetime = field(default_factory=datetime.now)


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
