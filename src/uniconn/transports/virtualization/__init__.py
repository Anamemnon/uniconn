# src/uniconn/transports/virtualization/__init__.py
"""Пакет out-of-band транспортов виртуализации (QEMU Guest Agent и Proxmox VE)."""

from .guest_base import GuestAgentTransportBase, parse_qga_network_interfaces
from .pve import PveTransport
from .pve_client import PveHttpClient
from .qga import QgaTransport
from .qga_protocol import (
    LocalUnixSocketChannel,
    NamedPipeQgaChannel,
    QgaChannelProtocol,
    QgaProtocolClient,
    SshUnixSocketChannel,
    TcpQgaChannel,
    VirshCommandChannel,
)

__all__ = [
    "GuestAgentTransportBase",
    "LocalUnixSocketChannel",
    "NamedPipeQgaChannel",
    "PveHttpClient",
    "PveTransport",
    "QgaChannelProtocol",
    "QgaProtocolClient",
    "QgaTransport",
    "SshUnixSocketChannel",
    "TcpQgaChannel",
    "VirshCommandChannel",
    "parse_qga_network_interfaces",
]
