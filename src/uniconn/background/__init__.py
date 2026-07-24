# src/uniconn/background/__init__.py
"""Подсистема фонового выполнения команд в GNU screen сессиях.

Позволяет запускать долгоживущие команды на удалённом хосте через SSH
в detached screen-сессиях, собирать их логи порциями (polling + tail)
и гарантированно очищать ресурсы при завершении клиента.
"""

from ._cleanup import ScreenCleanupManager
from ._config import LogConfig, LogRule, ScreenPoolConfig
from ._log_collector import ScreenLogCollector
from ._log_pipeline import (
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
    # Пул и сессии
    "ScreenPool",
    "ScreenSession",
    # Модели
    "LogEvent",
    "StatusEvent",
    "ScreenResult",
    # Конфигурация
    "LogRule",
    "LogConfig",
    "ScreenPoolConfig",
    # Логи
    "LogHandler",
    "LocalFileHandler",
    "ForwardHandler",
    "StreamHandler",
    "NullHandler",
    "LogPipeline",
    "ScreenLogCollector",
    # Очистка
    "ScreenCleanupManager",
]
