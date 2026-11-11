# src/uniconn/core/__init__.py
"""Ядро архитектуры uniconn: фасад Connection, конвейер команд, контекст и портал циклов событий."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..telemetry import TracingMiddleware
from .auto_diagnostics import (
    ClassificationMatch,
    ContainerDiagnosticStrategy,
    DiagnosticStrategy,
    ErrorClassifier,
    LinuxDiagnosticStrategy,
    PassiveDiagnosticStrategy,
    WindowsDiagnosticStrategy,
    resolve_diagnostic_strategy,
)
from .bridge import EventLoopPortal, SyncContextBridge
from .context import CwdContext, EnvContext, ExecutionContext, TempDirContext
from .pipeline import (
    AutoDiagnosticMiddleware,
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
from .python_worker import CallableSerializer, RemotePythonWorker, run_python
from .resilience import CircuitBreaker, CircuitState, RateLimiter
from .scripts import ScriptExecutionManager
from .shell_facade import ObserverContext
from .temp import HostTempManager

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
    "AutoDiagnosticMiddleware",
    "CallableSerializer",
    "CircuitBreaker",
    "CircuitBreakerMiddleware",
    "CircuitState",
    "ClassificationMatch",
    "CommandMiddleware",
    "CommandPipeline",
    "CommandRequest",
    "Connection",
    "ContainerDiagnosticStrategy",
    "ContextMiddleware",
    "CwdContext",
    "DiagnosticStrategy",
    "DryRunMiddleware",
    "EnvContext",
    "ErrorClassifier",
    "EventLoopPortal",
    "ExecutionContext",
    "HookCallback",
    "HookEvent",
    "HookMiddleware",
    "HostTempManager",
    "LinuxDiagnosticStrategy",
    "ObservabilityMiddleware",
    "ObserverContext",
    "PassiveDiagnosticStrategy",
    "RateLimitMiddleware",
    "RateLimiter",
    "RemotePythonWorker",
    "RetryMiddleware",
    "ScriptExecutionManager",
    "SudoMiddleware",
    "SyncContextBridge",
    "TempDirContext",
    "TracingMiddleware",
    "WindowsDiagnosticStrategy",
    "format_command",
    "prepare_sudo_command",
    "resolve_diagnostic_strategy",
    "run_python",
]

