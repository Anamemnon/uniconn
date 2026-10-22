# src/uniconn/result.py
"""Модель результата выполнения команды."""

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class Result:
    """Результат выполнения команды."""

    exit_code: int
    stdout: str
    stderr: str
    duration: float
    command: str
    timestamp: datetime = field(default_factory=datetime.now)
    host: str | None = None
    sensitive: bool = False

    @property
    def ok(self) -> bool:
        """True если exit_code == 0."""
        return self.exit_code == 0

    def raise_for_status(self) -> None:
        """Raise ExecutionError if exit_code != 0."""
        from .exceptions import ExecutionError
        if not self.ok:
            raise ExecutionError(
                f"Command failed with exit code {self.exit_code}",
                command="***REDACTED***" if self.sensitive else self.command,
                exit_code=self.exit_code,
                stdout="***REDACTED***" if self.sensitive else self.stdout,
                stderr="***REDACTED***" if self.sensitive else self.stderr,
            )

    def __repr__(self) -> str:
        """Вернуть отладочное представление результата (с маскировкой при sensitive=True)."""
        stdout_repr = "'***REDACTED***'" if self.sensitive else repr(self.stdout)
        stderr_repr = "'***REDACTED***'" if self.sensitive else repr(self.stderr)
        cmd_repr = "'***REDACTED***'" if self.sensitive else repr(self.command)
        return (
            f"Result(exit_code={self.exit_code!r}, stdout={stdout_repr}, "
            f"stderr={stderr_repr}, duration={self.duration!r}, "
            f"command={cmd_repr}, timestamp={self.timestamp!r}, "
            f"host={self.host!r}, sensitive={self.sensitive!r})"
        )

    def __str__(self) -> str:
        """Вернуть краткое строковое представление результата."""
        return f"Result(exit_code={self.exit_code}, duration={self.duration:.2f}s)"
