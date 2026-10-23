# src/uniconn/__init__.py
"""uniconn - Универсальная библиотека для выполнения команд на удалённых хостах.

Эта библиотека предоставляет единый интерфейс для подключения и выполнения
команд через различные транспорты: SSH, Telnet, Serial, IPMI и локальный.

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

    >>> # Пул SSH-сессий для одного хоста (мультиплексинг каналов)
    >>> from uniconn import SSHSessionPool
    >>> pool = SSHSessionPool("ssh://host", max_sessions_per_conn=6)
    >>> results = await pool.map(["lshw", "dmidecode", "nvme list"])
"""

from importlib.metadata import PackageNotFoundError, version
from shlex import quote

from ._config import ConnectionConfig
from ._connection import Connection, render_template
from ._facts import DiskInfo, HostFacts, NetworkInterface
from ._logging import (
    SecretMaskingFilter,
    bind_log_context,
    clear_log_context,
    configure_logging,
    get_log_context,
    get_logger,
    get_struct_logger,
    log_context,
    setup_file_logging,
    unbind_log_context,
)
from ._pool import ConnectionPool
from ._session_pool import SSHSessionPool
from ._shell import ShellSession
from ._sync import SyncConnection, SyncConnectionPool, SyncShellSession
from .background import LogConfig, ScreenPool, ScreenResult, ScreenSession
from .exceptions import (
    AuthenticationError,
    BMCCapabilityError,
    ConnectionError,
    ExecutionError,
    ScreenError,
    ScreenNotFoundError,
    ScreenPoolFullError,
    ScreenSessionExistsError,
    TimeoutError,
    TransportNotFoundError,
    UniconnError,
)
from .hooks import (
    MetricsCollector,
    allowlist_hook,
    audit_log_hook,
    blocklist_hook,
    metrics_collector_hook,
    structured_log_hook,
)
from .result import EnsureResult, Result, SyncResult

try:
    __version__ = version("uniconn")
except PackageNotFoundError:  # пакет не установлен (запуск из исходников)
    __version__ = "0.0.0+unknown"
__all__ = [
    # Основные классы
    "Connection",
    "SyncConnection",
    "ShellSession",
    "SyncShellSession",
    "ConnectionPool",
    "SyncConnectionPool",
    "SSHSessionPool",
    "ConnectionConfig",
    "Result",
    "SyncResult",
    "EnsureResult",
    "HostFacts",
    "DiskInfo",
    "NetworkInterface",
    "render_template",
    "quote",
    # Готовые хуки аудита, безопасности и метрик (v0.6.0)
    "audit_log_hook",
    "allowlist_hook",
    "blocklist_hook",
    "MetricsCollector",
    "metrics_collector_hook",
    "structured_log_hook",
    # Screen-сессии (background)
    "ScreenPool",
    "ScreenSession",
    "ScreenResult",
    "LogConfig",
    # Исключения
    "UniconnError",
    "ConnectionError",
    "AuthenticationError",
    "ExecutionError",
    "TimeoutError",
    "TransportNotFoundError",
    "BMCCapabilityError",
    "ScreenError",
    "ScreenNotFoundError",
    "ScreenSessionExistsError",
    "ScreenPoolFullError",
    # Логирование (stdlib + structlog)
    "get_logger",
    "setup_file_logging",
    "SecretMaskingFilter",
    "configure_logging",
    "get_struct_logger",
    "log_context",
    "bind_log_context",
    "unbind_log_context",
    "clear_log_context",
    "get_log_context",
]
