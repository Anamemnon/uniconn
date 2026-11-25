# src/uniconn/core/auto_diagnostics.py
"""Движок автоматической классификации сбоев (ErrorClassifier) и кроссплатформенные стратегии зондирования."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from ._diag_classifier import (
    ClassificationMatch,
    ErrorClassifier,
    ProbeRunner,
    _build_hint_and_actions,
    _sanitize_lines,
)
from ._diag_strategies import (
    DiagnosticStrategy,
    LinuxDiagnosticStrategy,
    PassiveDiagnosticStrategy,
    WindowsDiagnosticStrategy,
    _extract_json_dict,
)

if TYPE_CHECKING:
    from .connection import Connection

_PASSIVE_TRANSPORTS = frozenset(
    {"ipmi", "redfish", "netconf", "restconf", "gnmi", "replay", "serial", "uart"}
)
_WINDOWS_TRANSPORTS = frozenset({"winrm", "wsman"})


def resolve_diagnostic_strategy(conn: Connection) -> DiagnosticStrategy:
    """Выбрать оптимальную стратегию зондирования для текущего транспорта и ОС хоста."""
    t_name = conn.transport_name.lower()
    cfg_name = conn.config.transport.lower()
    if (
        t_name in _PASSIVE_TRANSPORTS
        or cfg_name in _PASSIVE_TRANSPORTS
        or hasattr(conn.transport, "cassette")
    ):
        return PassiveDiagnosticStrategy()
    if t_name in _WINDOWS_TRANSPORTS or cfg_name in _WINDOWS_TRANSPORTS:
        return WindowsDiagnosticStrategy()
    cached_facts = getattr(conn, "_cached_facts", None)
    if cached_facts is not None and getattr(cached_facts, "os_family", "").lower() == "windows":
        return WindowsDiagnosticStrategy()
    if t_name == "local" and sys.platform == "win32":
        return WindowsDiagnosticStrategy()
    return LinuxDiagnosticStrategy()


__all__ = [
    "ClassificationMatch",
    "DiagnosticStrategy",
    "ErrorClassifier",
    "LinuxDiagnosticStrategy",
    "PassiveDiagnosticStrategy",
    "ProbeRunner",
    "WindowsDiagnosticStrategy",
    "_build_hint_and_actions",
    "_extract_json_dict",
    "_sanitize_lines",
    "resolve_diagnostic_strategy",
]
