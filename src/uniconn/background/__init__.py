# src/uniconn/background/__init__.py
"""Подсистема фонового выполнения команд и потоковой диагностики.

Позволяет запускать долгоживущие команды на удалённом хосте через сменные
стратегии (``tmux``, GNU ``screen``, POSIX ``nohup``/``disown`` с автовыбором),
собирать их логи порциями (polling + tail) и гарантированно очищать ресурсы.
"""

from ._backends import (
    BackgroundBackendStrategy,
    BackgroundBackendType,
    NohupBackend,
    ScreenBackend,
    TmuxBackend,
    WindowsJobBackend,
    get_backend_by_name,
    resolve_backend,
)
from ._cleanup import BackgroundCleanupManager
from ._config import BackgroundPoolConfig, LogConfig, LogRule
from ._diagnostic import (
    DiagnosticConfig,
    DiagnosticResult,
    DiagnosticSession,
    StreamSourceSpec,
)
from ._log_collector import BackgroundLogCollector
from ._log_pipeline import (
    ArchiveHandler,
    DirectStreamCollector,
    ForwardHandler,
    LocalFileHandler,
    LogHandler,
    LogPipeline,
    NullHandler,
    StreamHandler,
)
from ._models import BackgroundResult, LogEvent, StatusEvent
from ._pool import BackgroundPool
from ._session import BackgroundSession

__all__ = [
    "ArchiveHandler",
    "BackgroundBackendStrategy",
    "BackgroundBackendType",
    "BackgroundCleanupManager",
    "BackgroundLogCollector",
    "BackgroundPool",
    "BackgroundPoolConfig",
    "BackgroundResult",
    "BackgroundSession",
    "DiagnosticConfig",
    "DiagnosticResult",
    "DiagnosticSession",
    "DirectStreamCollector",
    "ForwardHandler",
    "LocalFileHandler",
    "LogConfig",
    "LogEvent",
    "LogHandler",
    "LogPipeline",
    "LogRule",
    "NohupBackend",
    "NullHandler",
    "ScreenBackend",
    "StatusEvent",
    "StreamHandler",
    "StreamSourceSpec",
    "TmuxBackend",
    "WindowsJobBackend",
    "get_backend_by_name",
    "resolve_backend",
]
