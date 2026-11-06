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
from ._serial import SerialPortInfo, SerialTransport, list_serial_ports
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
from .serial_protocols import (
    AsyncXmodemReceiver,
    AsyncXmodemSender,
    AsyncYmodemReceiver,
    AsyncYmodemSender,
    ModemCancelledError,
    ModemChecksumMismatchError,
    ModemHandshakeTimeoutError,
    ModemMaxRetriesError,
    ModemProtocolError,
    ModemTransferError,
    ZmodemSubprocessAdapter,
    compute_checksum8,
    compute_crc16,
)

__all__ = [
    "AsyncXmodemReceiver",
    "AsyncXmodemSender",
    "AsyncYmodemReceiver",
    "AsyncYmodemSender",
    "BaseTransport",
    "Cassette",
    "CassetteContext",
    "CassetteTransportProxy",
    "DockerTransport",
    "IPMITransport",
    "KubectlTransport",
    "LocalTransport",
    "ModemCancelledError",
    "ModemChecksumMismatchError",
    "ModemHandshakeTimeoutError",
    "ModemMaxRetriesError",
    "ModemProtocolError",
    "ModemTransferError",
    "PodmanTransport",
    "RecordMode",
    "RecordedExecInteraction",
    "RecordedFsInteraction",
    "RecordedShellInteraction",
    "RecordedStreamInteraction",
    "RedfishTransport",
    "ReplayShellProcess",
    "ReplayTransport",
    "SerialPortInfo",
    "SerialTransport",
    "ShellDialogStep",
    "SyncCassetteContext",
    "ZmodemSubprocessAdapter",
    "compute_checksum8",
    "compute_crc16",
    "list_serial_ports",
    "normalize_temp_paths",
]
