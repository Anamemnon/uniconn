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

from ._docker import DockerTransport, PodmanTransport
from ._kubectl import KubectlTransport
from ._local import LocalTransport
from .base import BaseTransport
from .bmc import IPMITransport, RedfishTransport
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
    "DockerTransport",
    "IPMITransport",
    "KubectlTransport",
    "LocalTransport",
    "PodmanTransport",
    "RecordMode",
    "RecordedExecInteraction",
    "RecordedFsInteraction",
    "RecordedShellInteraction",
    "RecordedStreamInteraction",
    "RedfishTransport",
    "ReplayShellProcess",
    "ReplayTransport",
    "ShellDialogStep",
    "SyncCassetteContext",
    "normalize_temp_paths",
]
