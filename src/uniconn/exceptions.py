# src/uniconn/exceptions.py
from typing import Optional

class UniconnError(Exception):
    """Базовое исключение библиотеки"""
    def __init__(
        self,
        message: str,
        *,
        command: Optional[str] = None,
        exit_code: Optional[int] = None,
        stdout: Optional[str] = None,
        stderr: Optional[str] = None,
        host: Optional[str] = None
    ):
        super().__init__(message)
        self.command = command
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.host = host
    
    def __str__(self) -> str:
        parts = [super().__str__()]
        if self.command:
            parts.append(f"command={self.command!r}")
        if self.host:
            parts.append(f"host={self.host}")
        return " | ".join(parts)


class ConnectionError(UniconnError):
    """Ошибки подключения (сеть, auth, timeout)"""
    pass


class ExecutionError(UniconnError):
    """Ошибки выполнения команды (non-zero exit code)"""
    pass


class TimeoutError(UniconnError):
    """Таймаут операции (исключение uniconn, не путать со встроенным TimeoutError)"""
    pass


class TransportNotFoundError(UniconnError):
    """Транспорт не найден (не установлен extra)"""
    pass


class AuthenticationError(ConnectionError):
    """Ошибка аутентификации"""
    pass


class BMCCapabilityError(UniconnError):
    """BMC не поддерживает запрошенную операцию"""
    pass