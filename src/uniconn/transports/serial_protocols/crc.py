# src/uniconn/transports/serial_protocols/crc.py
"""Высокопроизводительный расчёт CRC-16-CCITT (poly 0x1021) и 8-битной контрольной суммы."""

from __future__ import annotations


def _generate_crc_table() -> tuple[int, ...]:
    """Генерация 256-элементной таблицы CRC-16-CCITT (полином 0x1021, init 0x0000)."""
    table: list[int] = []
    for byte in range(256):
        crc = byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else ((crc << 1) & 0xFFFF)
        table.append(crc)
    return tuple(table)


_CRC16_TABLE: tuple[int, ...] = _generate_crc_table()


def compute_crc16(data: bytes | bytearray | memoryview, crc: int = 0x0000) -> int:
    """Табличный расчёт CRC-16-CCITT (XMODEM/YMODEM, poly 0x1021, init 0x0000).

    Тестовый вектор: ``compute_crc16(b"123456789") == 0x31C3``.
    """
    table = _CRC16_TABLE
    for byte in data:
        crc = ((crc << 8) & 0xFFFF) ^ table[((crc >> 8) ^ byte) & 0xFF]
    return crc & 0xFFFF


def compute_checksum8(data: bytes | bytearray | memoryview) -> int:
    """Расчёт 8-битной аддитивной контрольной суммы XMODEM (``sum(data) & 0xFF``)."""
    return sum(data) & 0xFF


__all__ = [
    "compute_checksum8",
    "compute_crc16",
]
