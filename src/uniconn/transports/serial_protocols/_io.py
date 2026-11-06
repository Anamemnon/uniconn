# src/uniconn/transports/serial_protocols/_io.py
"""Низкоуровневые примитивы ввода-вывода и кадрирования пакетов для модемных протоколов."""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import time
from typing import Any

from .constants import (
    ACK,
    CAN,
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
    ModemHandshakeTimeoutError,
    ModemMaxRetriesError,
    ModemProtocolError,
)


async def write_and_drain(writer: Any, data: bytes) -> None:
    """Безопасная запись в StreamWriter с ожиданием drain (совместимо с MagicMock)."""
    writer.write(data)
    drain_fn = getattr(writer, "drain", None)
    if callable(drain_fn):
        res = drain_fn()
        if inspect.isawaitable(res):
            await res


async def send_cancel_sequence(writer: Any) -> None:
    """Отправить последовательность CAN для аварийного сброса удалённого загрузчика."""
    with contextlib.suppress(Exception):
        await write_and_drain(writer, CAN * 5)


class BufferedByteReader:
    """Буферизованный побайтовый адаптер поверх StreamReader или мок-ридера."""

    def __init__(self, reader: Any) -> None:
        self._reader = reader
        self._buf = bytearray()

    @property
    def buffer(self) -> bytearray:
        """Внутренний буфер непрочитанных байт."""
        return self._buf

    async def read_exact(self, n: int, timeout: float) -> bytes:
        """Прочитать ровно n байт с учётом общего таймаута."""
        deadline = time.monotonic() + timeout
        while len(self._buf) < n:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Timed out reading from serial stream")
            needed = n - len(self._buf)
            chunk = await asyncio.wait_for(self._reader.read(needed), timeout=remaining)
            if not chunk:
                raise TimeoutError("EOF reached on serial stream")
            self._buf.extend(chunk)
        result = bytes(self._buf[:n])
        del self._buf[:n]
        return result

    async def read_byte(self, timeout: float) -> bytes:
        """Прочитать ровно 1 байт с таймаутом."""
        return await self.read_exact(1, timeout)


def build_xmodem_packet(
    seq: int,
    payload: bytes,
    *,
    block_size: int = PACKET_SIZE_128,
    use_crc: bool = True,
    pad_byte: bytes = SUB,
) -> bytes:
    """Сформировать фрейм пакета XMODEM/YMODEM (SOH/STX + SEQ + ~SEQ + DATA + CRC/CSUM)."""
    header = STX if block_size == PACKET_SIZE_1K else SOH
    seq_byte = seq & 0xFF
    comp_byte = (0xFF - seq_byte) & 0xFF
    if len(payload) < block_size:
        payload = payload + pad_byte * (block_size - len(payload))
    elif len(payload) > block_size:
        payload = payload[:block_size]

    prefix = header + bytes((seq_byte, comp_byte)) + payload
    if use_crc:
        crc_val = compute_crc16(payload)
        return prefix + crc_val.to_bytes(2, "big")
    csum_val = compute_checksum8(payload)
    return prefix + bytes((csum_val,))


async def read_validated_frame(
    reader: BufferedByteReader,
    writer: Any,
    expected_seq: int,
    *,
    use_crc: bool = True,
    packet_timeout: float,
    max_retries: int,
    request_char: bytes | None = None,
    cancel_event: asyncio.Event | None = None,
    protocol_label: str = "XMODEM",
) -> tuple[bytes, int, bytes]:
    """Прочитать и провалидировать один пакет (SOH/STX/EOT) с обработкой повторов и дубликатов.

    Возвращает кортеж ``(hdr, seq, data)``, где ``hdr`` — ``SOH``, ``STX`` или ``EOT``.
    Примечание: ACK на валидный пакет данных вызывающая сторона отправляет самостоятельно
    после сохранения данных (а для дубликата предыдущего пакета ACK отправляется внутри).
    """
    retries = 0
    can_count = 0
    if request_char is not None:
        await write_and_drain(writer, request_char)

    while True:
        if cancel_event is not None and cancel_event.is_set():
            await send_cancel_sequence(writer)
            raise ModemCancelledError(f"{protocol_label} receive cancelled via cancel_event")

        try:
            hdr = await reader.read_byte(packet_timeout)
        except TimeoutError as exc:
            retries += 1
            if retries >= max_retries:
                await send_cancel_sequence(writer)
                if request_char is not None:
                    raise ModemHandshakeTimeoutError(
                        f"{protocol_label} receive handshake timed out waiting for packet"
                    ) from exc
                raise ModemMaxRetriesError(
                    f"{protocol_label} receive timed out waiting for packet #{expected_seq}"
                ) from exc
            await write_and_drain(writer, request_char or NAK)
            continue

        if hdr == EOT:
            return (EOT, expected_seq, b"")

        if hdr == CAN:
            can_count += 1
            if can_count >= 2:
                raise ModemCancelledError(f"{protocol_label} transfer cancelled by remote sender (CAN CAN)")
            try:
                nxt = await reader.read_byte(0.5)
                if nxt == CAN:
                    raise ModemCancelledError(
                        f"{protocol_label} transfer cancelled by remote sender (CAN CAN)"
                    )
            except TimeoutError:
                pass
            continue
        can_count = 0

        if hdr not in (SOH, STX):
            retries += 1
            if retries >= max_retries:
                await send_cancel_sequence(writer)
                raise ModemMaxRetriesError(f"Invalid {protocol_label} header byte received: {hdr!r}")
            await write_and_drain(writer, NAK)
            continue

        block_size = PACKET_SIZE_1K if hdr == STX else PACKET_SIZE_128
        check_len = 2 if use_crc else 1

        try:
            rest = await reader.read_exact(2 + block_size + check_len, packet_timeout)
        except TimeoutError:
            retries += 1
            if retries >= max_retries:
                await send_cancel_sequence(writer)
                raise ModemMaxRetriesError(f"Incomplete {protocol_label} packet payload") from None
            await write_and_drain(writer, NAK)
            continue

        seq = rest[0]
        comp = rest[1]
        data = rest[2 : 2 + block_size]
        check_bytes = rest[2 + block_size :]

        if (seq + comp) & 0xFF != 0xFF:
            retries += 1
            if retries >= max_retries:
                await send_cancel_sequence(writer)
                raise ModemMaxRetriesError(f"{protocol_label} sequence complement mismatch")
            await write_and_drain(writer, NAK)
            continue

        if use_crc:
            valid = int.from_bytes(check_bytes, "big") == compute_crc16(data)
        else:
            valid = check_bytes[0] == compute_checksum8(data)

        if not valid:
            retries += 1
            if retries >= max_retries:
                await send_cancel_sequence(writer)
                raise ModemMaxRetriesError(f"{protocol_label} checksum/CRC mismatch limit exceeded")
            await write_and_drain(writer, NAK)
            continue

        if seq == ((expected_seq - 1) & 0xFF):
            # Дубликат предыдущего пакета (потерялся наш ACK) — подтверждаем и ждём следующий
            await write_and_drain(writer, ACK)
            retries = 0
            request_char = None
            continue

        if seq != expected_seq:
            await send_cancel_sequence(writer)
            raise ModemProtocolError(
                f"Out-of-sequence {protocol_label} packet: expected {expected_seq}, got {seq}"
            )

        return (hdr, seq, data)


__all__ = [
    "BufferedByteReader",
    "build_xmodem_packet",
    "read_validated_frame",
    "send_cancel_sequence",
    "write_and_drain",
]
