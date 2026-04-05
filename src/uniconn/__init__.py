# src/uniconn/__init__.py
"""uniconn - Универсальная библиотека для выполнения команд на удалённых хостах.

Эта библиотека предоставляет единый интерфейс для подключения и выполнения
команд через различные транспорты: SSH, Telnet, Serial, IPMI, Redfish и локальный.

Основные компоненты:
    - Connection: Главный класс для работы с удалёнными хостами (async)
    - SyncConnection: Синхронная обёртка над Connection
    - ConnectionPool: Пул подключений для параллельного выполнения
    - ConnectionConfig: Конфигурация подключения (Pydantic модель)
    - Result: Результат выполнения команды

Пример использования:
    >>> from uniconn import Connection
    >>>
    >>> # Асинхронное использование
    >>> async with Connection.from_uri("ssh://user:pass@host") as conn:
    ...     result = await conn.run("uptime")
    ...     print(result.stdout)

    >>> # Синхронное использование
    >>> with Connection.from_uri("ssh://user:pass@host").to_sync() as conn:
    ...     result = conn.run("uptime")
    ...     print(result.stdout)

    >>> # Параллельное выполнение
    >>> from uniconn import ConnectionPool
    >>> pool = ConnectionPool(["ssh://host1", "ssh://host2"])
    >>> results = await pool.map("uptime")
"""

from ._config import ConnectionConfig
from ._connection import Connection
from ._logging import SecretMaskingFilter, get_logger
from ._pool import ConnectionPool
from ._sync import SyncConnection
from .exceptions import (
    AuthenticationError,
    BMCCapabilityError,
    ConnectionError,
    ExecutionError,
    TimeoutError,
    TransportNotFoundError,
    UniconnError,
)
from .result import Result

__version__ = "0.1.0"
__all__ = [
    # Основные классы
    "Connection",
    "SyncConnection",
    "ConnectionPool",
    "ConnectionConfig",
    "Result",
    # Исключения
    "UniconnError",
    "ConnectionError",
    "AuthenticationError",
    "ExecutionError",
    "TimeoutError",
    "TransportNotFoundError",
    "BMCCapabilityError",
    # Логирование
    "get_logger",
    "SecretMaskingFilter",
]
