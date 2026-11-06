# src/uniconn/transports/serial_protocols/constants.py
"""Управляющие байты и константы протоколов передачи файлов XMODEM / YMODEM / ZMODEM."""

from __future__ import annotations

from typing import Final

# ASCII Control Characters
SOH: Final[bytes] = b"\x01"      # Start of Header (128-byte packet)
STX: Final[bytes] = b"\x02"      # Start of Header (1024-byte packet / 1K)
EOT: Final[bytes] = b"\x04"      # End of Transmission
ACK: Final[bytes] = b"\x06"      # Acknowledge
NAK: Final[bytes] = b"\x15"      # Negative Acknowledge
CAN: Final[bytes] = b"\x18"      # Cancel transmission (2 consecutive CANs)
CRC_CHR: Final[bytes] = b"C"     # ASCII 'C' (0x43) — Request 16-bit CRC mode
SUB: Final[bytes] = b"\x1a"      # Ctrl-Z (0x1A) — Padding byte for XMODEM

# Размеры блоков данных
PACKET_SIZE_128: Final[int] = 128
PACKET_SIZE_1K: Final[int] = 1024

# Лимиты и таймауты по умолчанию
DEFAULT_MAX_RETRIES: Final[int] = 10
DEFAULT_HANDSHAKE_TIMEOUT: Final[float] = 60.0
DEFAULT_PACKET_TIMEOUT: Final[float] = 10.0
DEFAULT_INTER_BYTE_TIMEOUT: Final[float] = 0.5

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
]
