# src/uniconn/background/__init__.py
"""Подсистема фонового выполнения команд в GNU screen сессиях.

Позволяет запускать долгоживущие команды на удалённом хосте через SSH
в detached screen-сессиях, собирать их логи порциями (polling + tail)
и гарантированно очищать ресурсы при завершении клиента.
"""

from ._cleanup import ScreenCleanupManager
from ._config import LogConfig, LogRule, ScreenPoolConfig
from ._diagnostic import (
    DiagnosticConfig,
    DiagnosticResult,
    DiagnosticSession,
    StreamSourceSpec,
)
from ._log_collector import ScreenLogCollector
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
from ._models import LogEvent, ScreenResult, StatusEvent
from ._pool import ScreenPool
from ._session import ScreenSession

__all__ = [
    # Пул, сессии и диагностика
    "ScreenPool",
    "ScreenSession",
    "DiagnosticSession",
    "DiagnosticConfig",
    "DiagnosticResult",
    "StreamSourceSpec",
    # Модели
    "LogEvent",
    "StatusEvent",
    "ScreenResult",
    # Конфигурация
    "LogRule",
    "LogConfig",
    "ScreenPoolConfig",
    # Логи и потоки
    "LogHandler",
    "LocalFileHandler",
    "ForwardHandler",
    "StreamHandler",
    "ArchiveHandler",
    "NullHandler",
    "LogPipeline",
    "ScreenLogCollector",
    "DirectStreamCollector",
    # Очистка
    "ScreenCleanupManager",
]

