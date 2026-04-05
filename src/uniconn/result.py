# src/uniconn/result.py
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
                command=self.command,
                exit_code=self.exit_code,
                stdout=self.stdout,
                stderr=self.stderr
            )

    def __str__(self) -> str:
        return f"Result(exit_code={self.exit_code}, duration={self.duration:.2f}s)"
