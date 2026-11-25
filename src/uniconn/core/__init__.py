# src/uniconn/core/__init__.py
"""Ядро архитектуры uniconn: фасад Connection, конвейер команд, контекст и портал циклов событий."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .._utils import make_lazy_package_loader

if TYPE_CHECKING:
    from ..telemetry import TracingMiddleware
    from .auto_diagnostics import (
        ClassificationMatch,
        DiagnosticStrategy,
        ErrorClassifier,
        LinuxDiagnosticStrategy,
        PassiveDiagnosticStrategy,
        WindowsDiagnosticStrategy,
        resolve_diagnostic_strategy,
    )
    from .bridge import EventLoopPortal, SyncContextBridge
    from .connection import Connection, OperationObserver
    from .context import CwdContext, EnvContext, ExecutionContext, TempDirContext
    from .pipeline import (
        AutoDiagnosticMiddleware,
        CircuitBreakerMiddleware,
        CommandMiddleware,
        CommandPipeline,
        CommandRequest,
        ContextMiddleware,
        DryRunMiddleware,
        HITLApprovalMiddleware,
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

_LAZY_MODULE_GROUPS: dict[str, tuple[str, ...]] = {
    "..telemetry": ("TracingMiddleware",),
    ".auto_diagnostics": (
        "ClassificationMatch",
        "DiagnosticStrategy",
        "ErrorClassifier",
        "LinuxDiagnosticStrategy",
        "PassiveDiagnosticStrategy",
        "WindowsDiagnosticStrategy",
        "resolve_diagnostic_strategy",
    ),
    ".bridge": ("EventLoopPortal", "SyncContextBridge"),
    ".connection": ("Connection", "OperationObserver"),
    ".context": ("CwdContext", "EnvContext", "ExecutionContext", "TempDirContext"),
    ".pipeline": (
        "AutoDiagnosticMiddleware",
        "CircuitBreakerMiddleware",
        "CommandMiddleware",
        "CommandPipeline",
        "CommandRequest",
        "ContextMiddleware",
        "DryRunMiddleware",
        "HITLApprovalMiddleware",
        "HookCallback",
        "HookEvent",
        "HookMiddleware",
        "ObservabilityMiddleware",
        "RateLimitMiddleware",
        "RetryMiddleware",
        "SudoMiddleware",
        "format_command",
        "prepare_sudo_command",
    ),
    ".python_worker": ("CallableSerializer", "RemotePythonWorker", "run_python"),
    ".resilience": ("CircuitBreaker", "CircuitState", "RateLimiter"),
    ".scripts": ("ScriptExecutionManager",),
    ".shell_facade": ("ObserverContext",),
    ".temp": ("HostTempManager",),
}

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
    "ContextMiddleware",
    "CwdContext",
    "DiagnosticStrategy",
    "DryRunMiddleware",
    "EnvContext",
    "ErrorClassifier",
    "EventLoopPortal",
    "ExecutionContext",
    "HITLApprovalMiddleware",
    "HookCallback",
    "HookEvent",
    "HookMiddleware",
    "HostTempManager",
    "LinuxDiagnosticStrategy",
    "ObservabilityMiddleware",
    "ObserverContext",
    "OperationObserver",
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

_LAZY_EXPORTS, __getattr__, __dir__ = make_lazy_package_loader(
    __name__, globals(), _LAZY_MODULE_GROUPS, all_names=__all__
)
