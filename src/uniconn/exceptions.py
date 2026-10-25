# src/uniconn/exceptions.py
"""Иерархия исключений библиотеки uniconn."""


class UniconnError(Exception):
    """Базовое исключение библиотеки."""

    def __init__(
        self,
        message: str,
        *,
        command: str | None = None,
        exit_code: int | None = None,
        stdout: str | None = None,
        stderr: str | None = None,
        host: str | None = None
    ):
        """Инициализировать исключение с контекстом выполнения команды."""
        super().__init__(message)
        self.command = command
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.host = host

    def __str__(self) -> str:
        """Вернуть строковое представление ошибки с командой и хостом."""
        parts = [super().__str__()]
        if self.command:
            parts.append(f"command={self.command!r}")
        if self.host:
            parts.append(f"host={self.host}")
        return " | ".join(parts)


class ConnectionError(UniconnError):
    """Ошибки подключения (сеть, auth, timeout)."""

    pass


class ExecutionError(UniconnError):
    """Ошибки выполнения команды (non-zero exit code)."""

    pass


class TimeoutError(UniconnError):
    """Таймаут операции (исключение uniconn, не путать со встроенным TimeoutError)."""

    pass


class TransportNotFoundError(UniconnError):
    """Транспорт не найден (не установлен extra)."""

    pass


class AuthenticationError(ConnectionError):
    """Ошибка аутентификации."""

    pass


class BMCCapabilityError(UniconnError):
    """BMC не поддерживает запрошенную операцию."""

    pass


class ScreenError(UniconnError):
    """Базовое исключение подсистемы screen-сессий."""

    pass


class ScreenNotFoundError(ScreenError):
    """GNU screen не установлен на удалённом хосте."""

    pass


class ScreenSessionExistsError(ScreenError):
    """Screen-сессия с таким именем уже существует на хосте."""

    pass


class ScreenPoolFullError(ScreenError):
    """Достигнут лимит одновременных сессий в пуле (max_screens)."""

    pass


class CapabilityNotSupportedError(UniconnError, NotImplementedError):
    """Транспорт не поддерживает запрошенную возможность (SFTP, PTY, Tunnel и т.д.).

    Наследуется одновременно от ``UniconnError`` и ``NotImplementedError`` для
    совместимости со стандартными проверками возможностей.
    """

    pass


class CircuitOpenError(ConnectionError):
    """Цепь CircuitBreaker разомкнута (OPEN) — вызов отклонён без обращения к сети."""

    def __init__(
        self,
        message: str,
        *,
        host: str | None = None,
        remaining_seconds: float = 0.0,
        command: str | None = None,
    ) -> None:
        """Инициализировать ошибку разомкнутого CircuitBreaker."""
        super().__init__(message, command=command, host=host)
        self.remaining_seconds = remaining_seconds


class CassetteError(UniconnError):
    """Базовое исключение подсистемы записи и воспроизведения кассет (Replay/Cassette)."""

    pass


class CassetteMissError(CassetteError):
    """Эпизод взаимодействия не найден в кассете при воспроизведении."""

    def __init__(
        self,
        message: str,
        *,
        kind: str = "exec",
        command: str | None = None,
        host: str | None = None,
        candidates: list[str] | None = None,
    ) -> None:
        """Инициализировать ошибку промаха кассеты с диагностикой кандидатов."""
        super().__init__(message, command=command, host=host)
        self.kind = kind
        self.candidates: list[str] = candidates or []
