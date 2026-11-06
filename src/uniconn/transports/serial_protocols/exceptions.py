# src/uniconn/transports/serial_protocols/exceptions.py
"""Иерархия исключений модемных протоколов передачи файлов (XMODEM / YMODEM / ZMODEM)."""

from __future__ import annotations

from ...exceptions import (
    ModemCancelledError,
    ModemChecksumMismatchError,
    ModemHandshakeTimeoutError,
    ModemMaxRetriesError,
    ModemProtocolError,
    ModemTransferError,
)

__all__ = [
    "ModemCancelledError",
    "ModemChecksumMismatchError",
    "ModemHandshakeTimeoutError",
    "ModemMaxRetriesError",
    "ModemProtocolError",
    "ModemTransferError",
]
