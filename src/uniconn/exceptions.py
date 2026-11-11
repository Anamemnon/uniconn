# src/uniconn/exceptions.py
"""Иерархия исключений библиотеки uniconn."""

import builtins


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
        host: str | None = None,
        diagnostic: object | None = None,
    ) -> None:
        """Инициализировать исключение с контекстом выполнения команды."""
        super().__init__(message)
        self.command = command
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.host = host
        self.diagnostic = diagnostic

    def __str__(self) -> str:
        """Вернуть строковое представление ошибки с командой и хостом."""
        parts = [super().__str__()]
        if self.command:
            parts.append(f"command={self.command!r}")
        if self.host:
            parts.append(f"host={self.host}")
        return " | ".join(parts)


class ConfigurationError(UniconnError, ValueError):
    """Ошибка валидации конфигурации, URI, инвентаря или спецификации фактов."""


class ConnectionError(UniconnError, builtins.ConnectionError):
    """Ошибки подключения (сеть, auth, timeout)."""


class ExecutionError(UniconnError):
    """Ошибки выполнения команды (non-zero exit code)."""


class FileTransferError(UniconnError):
    """Ошибка передачи файла или несовпадения контрольной суммы (verify=True)."""


class TimeoutError(UniconnError, builtins.TimeoutError):
    """Таймаут операции (совместим со встроенным builtins.TimeoutError)."""


class TransportNotFoundError(UniconnError):
    """Транспорт не найден (не установлен extra)."""


class AuthenticationError(ConnectionError):
    """Ошибка аутентификации."""


class BMCCapabilityError(UniconnError):
    """BMC не поддерживает запрошенную операцию."""


class BackgroundError(UniconnError):
    """Базовое исключение подсистемы фоновых задач."""


class BackgroundBackendError(BackgroundError):
    """Выбранный бэкенд фоновых задач недоступен или завершился с ошибкой."""


class BackgroundSessionExistsError(BackgroundError):
    """Фоновая сессия с таким именем уже существует на хосте."""


class BackgroundPoolFullError(BackgroundError):
    """Достигнут лимит одновременных сессий в пуле (max_sessions)."""


class HardwareFaultDetectedError(BackgroundError):
    """В потоке логов обнаружена аппаратная или системная ошибка (правило с abort_on_match=True)."""

    def __init__(
        self,
        message: str,
        *,
        match: object | None = None,
        matches: list[object] | None = None,
        host: str | None = None,
        command: str | None = None,
    ) -> None:
        """Инициализировать исключение обнаруженного аппаратного сбоя."""
        super().__init__(message, command=command, host=host)
        self.match = match
        self.matches: list[object] = list(matches or ([match] if match is not None else []))



class CapabilityNotSupportedError(UniconnError, NotImplementedError):
    """Транспорт не поддерживает запрошенную возможность (SFTP, PTY, Tunnel и т.д.).

    Наследуется одновременно от ``UniconnError`` и ``NotImplementedError`` для
    совместимости со стандартными проверками возможностей.
    """


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


class BatchAbortedError(UniconnError):
    """Раскатка по батчам в ConnectionPool прервана из-за превышения порога ошибок max_fail_ratio."""

    def __init__(
        self,
        message: str,
        *,
        batch_index: int = 0,
        fail_ratio: float = 0.0,
        max_fail_ratio: float = 0.0,
        completed_results: dict[str, object] | None = None,
        failed_hosts: dict[str, object] | None = None,
    ) -> None:
        """Инициализировать ошибку прерывания батчевой раскатки с частичными результатами."""
        super().__init__(message)
        self.batch_index = batch_index
        self.fail_ratio = fail_ratio
        self.max_fail_ratio = max_fail_ratio
        self.completed_results: dict[str, object] = dict(completed_results or {})
        self.failed_hosts: dict[str, object] = dict(failed_hosts or {})


class ModemTransferError(FileTransferError):
    """Базовое исключение для ошибок модемных протоколов передачи файлов (XMODEM/YMODEM/ZMODEM)."""


class ModemHandshakeTimeoutError(ModemTransferError):
    """Превышен таймаут ожидания стартового символа хэндшейка ('C' или NAK)."""


class ModemCancelledError(ModemTransferError):
    """Передача отменена удалённой стороной или пользователем (получена последовательность CAN CAN)."""


class ModemMaxRetriesError(ModemTransferError):
    """Превышено максимальное количество повторных попыток отправки или приёма пакета."""


class ModemProtocolError(ModemTransferError):
    """Нарушение спецификации протокола или некорректный ответ удалённого узла."""


class ModemChecksumMismatchError(ModemTransferError):
    """Несовпадение контрольной суммы или CRC-16 полученного пакета."""


class CyclicDependencyError(ConfigurationError):
    """Обнаружена циклическая зависимость в графе задач (Flow DAG)."""

    def __init__(
        self,
        message: str,
        *,
        cycle: list[str] | tuple[str, ...] | None = None,
    ) -> None:
        """Инициализировать ошибку циклической зависимости с маршрутом цикла."""
        super().__init__(message)
        self.cycle: list[str] = [str(item) for item in (cycle or ())]


class FlowExecutionError(ExecutionError):
    """Сценарий оркестрации Flow завершился с ошибкой на одном или нескольких хостах."""

    def __init__(
        self,
        message: str,
        *,
        report: object | None = None,
        failed_hosts: list[str] | None = None,
    ) -> None:
        """Инициализировать ошибку выполнения Flow со ссылкой на сводный отчёт FlowReport."""
        super().__init__(message)
        self.report = report
        self.failed_hosts: list[str] = list(failed_hosts or [])


class ParsingError(UniconnError, ValueError):
    """Базовое исключение ошибки семантического парсинга или валидации схемы вывода."""


class ParserNotFoundError(ParsingError, LookupError):
    """Движок парсинга или шаблон для указанной спецификации не найден."""


class OptionalDependencyError(ParsingError, ImportError):
    """Требуемая для парсинга опциональная библиотека не установлена (uniconn[parsing])."""


