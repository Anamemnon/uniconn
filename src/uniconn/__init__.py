# src/uniconn/__init__.py
"""uniconn - Универсальная библиотека для выполнения команд на удалённых хостах.

Предоставляет единый фасад ``Connection`` с конвейером ``CommandPipeline``
и модульными доменными сервисами (``conn.files``, ``conn.state``, ``conn.tunnels``)
для работы поверх SSH, Telnet, Serial, IPMI и Local транспортов.
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
from ._shell import ExpectStateMachine, PosixMarkerProtocol, ShellSession
from ._sync import (
    SyncConnection,
    SyncConnectionPool,
    SyncFileOperationsService,
    SyncShellSession,
    SyncStateManagementService,
    SyncTunnelService,
)
from .background import LogConfig, ScreenPool, ScreenResult, ScreenSession
from .config import InventoryLoader
from .core import (
    CommandMiddleware,
    CommandPipeline,
    CommandRequest,
    ContextMiddleware,
    DryRunMiddleware,
    EventLoopPortal,
    ExecutionContext,
    HookMiddleware,
    ObservabilityMiddleware,
    RetryMiddleware,
    SudoMiddleware,
    SyncContextBridge,
)
from .exceptions import (
    AuthenticationError,
    BMCCapabilityError,
    CapabilityNotSupportedError,
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
from .pool.stream_mux import PoolStreamMultiplexer
from .result import EnsureResult, Result, SyncResult
from .services import (
    ApkStrategy,
    AptStrategy,
    DirectorySynchronizer,
    DnfYumStrategy,
    FactCollector,
    FileOperationsService,
    OpenRCStrategy,
    PackageManagerStrategy,
    PacmanStrategy,
    ServiceManagerStrategy,
    StateManagementService,
    SystemdStrategy,
    SysVStrategy,
    TemplateEngine,
    TunnelService,
    ZypperStrategy,
)
from .transports.base import (
    BaseTransport,
    CommandTransport,
    FileCapableTransport,
    ShellCapableTransport,
    TunnelCapableTransport,
    require_capability,
    supports_capability,
)
from .transports.ssh import OpenSSHConfigParser, SFTPClientAdapter, SSHJumpChainManager

try:
    __version__ = version("uniconn")
except PackageNotFoundError:  # пакет не установлен (запуск из исходников)
    __version__ = "0.0.0+unknown"

__all__ = [
    # Основные классы и фасады
    "Connection",
    "SyncConnection",
    "ShellSession",
    "SyncShellSession",
    "ConnectionPool",
    "SyncConnectionPool",
    "PoolStreamMultiplexer",
    "SSHSessionPool",
    "ConnectionConfig",
    "InventoryLoader",
    "Result",
    "SyncResult",
    "EnsureResult",
    "HostFacts",
    "DiskInfo",
    "NetworkInterface",
    "render_template",
    "quote",
    # Ядро, конвейер команд и портал синхронизации
    "CommandPipeline",
    "CommandRequest",
    "CommandMiddleware",
    "ContextMiddleware",
    "SudoMiddleware",
    "HookMiddleware",
    "DryRunMiddleware",
    "ObservabilityMiddleware",
    "RetryMiddleware",
    "ExecutionContext",
    "EventLoopPortal",
    "SyncContextBridge",
    "PosixMarkerProtocol",
    "ExpectStateMachine",
    # Доменные сервисы и стратегии
    "FileOperationsService",
    "SyncFileOperationsService",
    "DirectorySynchronizer",
    "StateManagementService",
    "SyncStateManagementService",
    "PackageManagerStrategy",
    "AptStrategy",
    "ApkStrategy",
    "DnfYumStrategy",
    "PacmanStrategy",
    "ZypperStrategy",
    "ServiceManagerStrategy",
    "SystemdStrategy",
    "OpenRCStrategy",
    "SysVStrategy",
    "TunnelService",
    "SyncTunnelService",
    "FactCollector",
    "TemplateEngine",
    # Протоколы возможностей транспортов (ISP) и SSH-компоненты
    "BaseTransport",
    "CommandTransport",
    "FileCapableTransport",
    "ShellCapableTransport",
    "TunnelCapableTransport",
    "require_capability",
    "supports_capability",
    "OpenSSHConfigParser",
    "SSHJumpChainManager",
    "SFTPClientAdapter",
    # Готовые хуки аудита, безопасности и метрик
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
    "CapabilityNotSupportedError",
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
