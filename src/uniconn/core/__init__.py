# src/uniconn/core/__init__.py
"""Ядро архитектуры uniconn: фасад Connection, конвейер команд, контекст и портал циклов событий."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..telemetry import TracingMiddleware
from .bridge import EventLoopPortal, SyncContextBridge
from .context import CwdContext, EnvContext, ExecutionContext, TempDirContext
from .pipeline import (
    CircuitBreakerMiddleware,
    CommandMiddleware,
    CommandPipeline,
    CommandRequest,
    ContextMiddleware,
    DryRunMiddleware,
    HookCallback,
    HookEvent,
    HookMiddleware,
    ObservabilityMiddleware,
    RateLimitMiddleware,
    RetryMiddleware,
    SudoMiddleware,
    format_command,
    prepare_sudo_command,
)
from .resilience import CircuitBreaker, CircuitState, RateLimiter

if TYPE_CHECKING:
    from .connection import Connection


def __getattr__(name: str) -> Any:
    """Ленивый импорт Connection для предотвращения циклических импортов."""
    if name == "Connection":
        from .connection import Connection

        return Connection
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)


__all__ = [
    "CircuitBreaker",
    "CircuitBreakerMiddleware",
    "CircuitState",
    "CommandMiddleware",
    "CommandPipeline",
    "CommandRequest",
    "Connection",
    "ContextMiddleware",
    "CwdContext",
    "DryRunMiddleware",
    "EnvContext",
    "EventLoopPortal",
    "ExecutionContext",
    "HookCallback",
    "HookEvent",
    "HookMiddleware",
    "ObservabilityMiddleware",
    "RateLimitMiddleware",
    "RateLimiter",
    "RetryMiddleware",
    "SudoMiddleware",
    "SyncContextBridge",
    "TempDirContext",
    "TracingMiddleware",
    "format_command",
    "prepare_sudo_command",
]

