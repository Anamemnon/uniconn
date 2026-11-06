# src/uniconn/transports/serial_protocols/__init__.py
"""Протоколы передачи файлов по Serial/UART: XMODEM, YMODEM и ZMODEM."""

from __future__ import annotations

from .constants import (
    ACK,
    CAN,
    CRC_CHR,
    DEFAULT_HANDSHAKE_TIMEOUT,
    DEFAULT_INTER_BYTE_TIMEOUT,
    DEFAULT_MAX_RETRIES,
    DEFAULT_PACKET_TIMEOUT,
    EOT,
    NAK,
    PACKET_SIZE_1K,
    PACKET_SIZE_128,
    SOH,
    STX,
    SUB,
)
from .crc import compute_checksum8, compute_crc16
from .exceptions import (
    ModemCancelledError,
    ModemChecksumMismatchError,
    ModemHandshakeTimeoutError,
    ModemMaxRetriesError,
    ModemProtocolError,
    ModemTransferError,
)
from .xmodem import (
    AsyncXmodemReceiver,
    AsyncXmodemSender,
    XmodemMode,
    build_xmodem_packet,
)
from .ymodem import (
    AsyncYmodemReceiver,
    AsyncYmodemSender,
    build_ymodem_header_packet,
    parse_ymodem_header_payload,
)
from .zmodem import ZmodemSubprocessAdapter

__all__ = [
    "ACK",
    "CAN",
    "CRC_CHR",
    "DEFAULT_HANDSHAKE_TIMEOUT",
    "DEFAULT_INTER_BYTE_TIMEOUT",
    "DEFAULT_MAX_RETRIES",
    "DEFAULT_PACKET_TIMEOUT",
    "EOT",
    "NAK",
    "PACKET_SIZE_1K",
    "PACKET_SIZE_128",
    "SOH",
    "STX",
    "SUB",
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
    "XmodemMode",
    "ZmodemSubprocessAdapter",
    "build_xmodem_packet",
    "build_ymodem_header_packet",
    "compute_checksum8",
    "compute_crc16",
    "parse_ymodem_header_payload",
]
