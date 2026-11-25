# src/uniconn/transports/__init__.py
"""Транспорты для uniconn.

Этот пакет содержит реализации различных транспортов для подключения
и выполнения команд на удалённых хостах, BMC, сетевых устройствах и виртуальных машинах.
Импорты реализаций выполняются лениво по стандарту PEP 562.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .._utils import make_lazy_package_loader

if TYPE_CHECKING:
    from ._local import LocalTransport
    from ._serial import SerialPortInfo, SerialTransport, list_serial_ports
    from ._winrm import WinRMTransport
    from .base import BaseTransport
    from .bmc import IPMITransport, RedfishTransport
    from .network import (
        GnmiPath,
        GnmiPathElem,
        GnmiTransport,
        GnmiWireCodec,
        NetconfFrameCodec,
        NetconfTransport,
        NetconfVendorAdapter,
        RestconfClient,
        RestconfTransport,
        StructuredNetworkTransport,
    )
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
    from .virtualization import (
        LocalUnixSocketChannel,
        PveHttpClient,
        PveTransport,
        QgaChannelProtocol,
        QgaProtocolClient,
        QgaTransport,
        SshUnixSocketChannel,
        VirshCommandChannel,
        parse_qga_network_interfaces,
    )

_LAZY_MODULE_GROUPS: dict[str, tuple[str, ...]] = {
    "._local": ("LocalTransport",),
    "._serial": ("SerialPortInfo", "SerialTransport", "list_serial_ports"),
    "._winrm": ("WinRMTransport",),
    ".base": ("BaseTransport",),
    ".bmc": ("IPMITransport", "RedfishTransport"),
    ".network": (
        "GnmiPath",
        "GnmiPathElem",
        "GnmiTransport",
        "GnmiWireCodec",
        "NetconfFrameCodec",
        "NetconfTransport",
        "NetconfVendorAdapter",
        "RestconfClient",
        "RestconfTransport",
        "StructuredNetworkTransport",
    ),
    ".replay": (
        "Cassette",
        "CassetteContext",
        "CassetteTransportProxy",
        "RecordedExecInteraction",
        "RecordedFsInteraction",
        "RecordedShellInteraction",
        "RecordedStreamInteraction",
        "RecordMode",
        "ReplayShellProcess",
        "ReplayTransport",
        "ShellDialogStep",
        "SyncCassetteContext",
        "normalize_temp_paths",
    ),
    ".serial_protocols": (
        "AsyncXmodemReceiver",
        "AsyncXmodemSender",
        "AsyncYmodemReceiver",
        "AsyncYmodemSender",
        "ModemCancelledError",
        "ModemChecksumMismatchError",
        "ModemHandshakeTimeoutError",
        "ModemMaxRetriesError",
        "ModemProtocolError",
        "ModemTransferError",
        "ZmodemSubprocessAdapter",
        "compute_checksum8",
        "compute_crc16",
    ),
    ".virtualization": (
        "LocalUnixSocketChannel",
        "PveHttpClient",
        "PveTransport",
        "QgaChannelProtocol",
        "QgaProtocolClient",
        "QgaTransport",
        "SshUnixSocketChannel",
        "VirshCommandChannel",
        "parse_qga_network_interfaces",
    ),
}

__all__ = [
    "AsyncXmodemReceiver",
    "AsyncXmodemSender",
    "AsyncYmodemReceiver",
    "AsyncYmodemSender",
    "BaseTransport",
    "Cassette",
    "CassetteContext",
    "CassetteTransportProxy",
    "GnmiPath",
    "GnmiPathElem",
    "GnmiTransport",
    "GnmiWireCodec",
    "IPMITransport",
    "LocalTransport",
    "LocalUnixSocketChannel",
    "ModemCancelledError",
    "ModemChecksumMismatchError",
    "ModemHandshakeTimeoutError",
    "ModemMaxRetriesError",
    "ModemProtocolError",
    "ModemTransferError",
    "NetconfFrameCodec",
    "NetconfTransport",
    "NetconfVendorAdapter",
    "PveHttpClient",
    "PveTransport",
    "QgaChannelProtocol",
    "QgaProtocolClient",
    "QgaTransport",
    "RecordMode",
    "RecordedExecInteraction",
    "RecordedFsInteraction",
    "RecordedShellInteraction",
    "RecordedStreamInteraction",
    "RedfishTransport",
    "ReplayShellProcess",
    "ReplayTransport",
    "RestconfClient",
    "RestconfTransport",
    "SerialPortInfo",
    "SerialTransport",
    "ShellDialogStep",
    "SshUnixSocketChannel",
    "StructuredNetworkTransport",
    "SyncCassetteContext",
    "VirshCommandChannel",
    "WinRMTransport",
    "ZmodemSubprocessAdapter",
    "compute_checksum8",
    "compute_crc16",
    "list_serial_ports",
    "normalize_temp_paths",
    "parse_qga_network_interfaces",
]

_LAZY_EXPORTS, __getattr__, __dir__ = make_lazy_package_loader(
    __name__, globals(), _LAZY_MODULE_GROUPS, all_names=__all__
)

