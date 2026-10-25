# src/uniconn/transports/__init__.py
"""Транспорты для uniconn.

Этот пакет содержит реализации различных транспортов для подключения
и выполнения команд на удалённых хостах.

Доступные транспорты:
    - LocalTransport: Локальное выполнение через subprocess
    - SSHTransport: SSH подключение через asyncssh
    - TelnetTransport: Telnet через telnetlib3
    - SerialTransport: Serial/UART через pyserial-asyncio
    - IPMITransport: IPMI BMC через pyghmi
"""

from ._base import BaseTransport
from ._local import LocalTransport
from .replay import (
    Cassette,
    CassetteContext,
    CassetteTransportProxy,
    RecordedExecInteraction,
    RecordedFsInteraction,
    RecordedShellInteraction,
    RecordedStreamInteraction,
    RecordMode,
    ReplayShellProcess,
    ReplayTransport,
    ShellDialogStep,
    SyncCassetteContext,
    normalize_temp_paths,
)

__all__ = [
    "BaseTransport",
    "Cassette",
    "CassetteContext",
    "CassetteTransportProxy",
    "LocalTransport",
    "RecordMode",
    "RecordedExecInteraction",
    "RecordedFsInteraction",
    "RecordedShellInteraction",
    "RecordedStreamInteraction",
    "ReplayShellProcess",
    "ReplayTransport",
    "ShellDialogStep",
    "SyncCassetteContext",
    "normalize_temp_paths",
]
