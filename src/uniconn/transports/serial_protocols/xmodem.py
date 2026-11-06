# src/uniconn/transports/serial_protocols/xmodem.py
"""Асинхронный конечный автомат протокола XMODEM (Checksum, CRC-16, XMODEM-1K)."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from typing import Any, BinaryIO, Literal

from ._io import (
    BufferedByteReader,
    build_xmodem_packet,
    read_validated_frame,
    send_cancel_sequence,
    write_and_drain,
)
from .constants import (
    ACK,
    CAN,
    CRC_CHR,
    DEFAULT_HANDSHAKE_TIMEOUT,
    DEFAULT_MAX_RETRIES,
    DEFAULT_PACKET_TIMEOUT,
    EOT,
    NAK,
    PACKET_SIZE_1K,
    PACKET_SIZE_128,
    SUB,
)
from .exceptions import (
    ModemCancelledError,
    ModemHandshakeTimeoutError,
    ModemMaxRetriesError,
    ModemProtocolError,
)

XmodemMode = Literal["checksum", "crc", "1k"]


class AsyncXmodemSender:
    """Асинхронный передатчик XMODEM (поддерживает режимы checksum, crc и 1k)."""

    def __init__(
        self,
        reader: asyncio.StreamReader | Any,
        writer: asyncio.StreamWriter | Any,
        *,
        logger: Any = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
        packet_timeout: float = DEFAULT_PACKET_TIMEOUT,
        handshake_timeout: float = DEFAULT_HANDSHAKE_TIMEOUT,
    ) -> None:
        self._reader = BufferedByteReader(reader)
        self._writer = writer
        self._logger = logger
        self._max_retries = max_retries
        self._packet_timeout = packet_timeout
        self._handshake_timeout = handshake_timeout

    async def _wait_handshake(
        self,
        requested_mode: XmodemMode,
        cancel_event: asyncio.Event | None = None,
    ) -> bool:
        """Дождаться стартового символа 'C' (CRC) или NAK (checksum). Возвращает use_crc."""
        deadline = time.monotonic() + self._handshake_timeout
        can_count = 0

        while True:
            if cancel_event is not None and cancel_event.is_set():
                await send_cancel_sequence(self._writer)
                raise ModemCancelledError("XMODEM transfer cancelled via cancel_event")

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ModemHandshakeTimeoutError(
                    f"XMODEM handshake timed out after {self._handshake_timeout:.1f}s waiting for 'C' or NAK"
                )

            try:
                ch = await self._reader.read_byte(min(remaining, self._packet_timeout))
            except TimeoutError:
                continue

            if ch == CAN:
                can_count += 1
                if can_count >= 2:
                    raise ModemCancelledError("XMODEM transfer cancelled by remote receiver (CAN CAN)")
                continue
            can_count = 0

            if ch == CRC_CHR:
                if requested_mode == "checksum":
                    # В режиме строгого checksum ждём перехода получателя на NAK
                    continue
                return True
            if ch == NAK:
                return False

    async def _send_packet_with_retries(
        self,
        packet: bytes,
        seq: int,
        cancel_event: asyncio.Event | None = None,
    ) -> None:
        """Отправить сформированный пакет и дождаться ACK (с повторами при NAK/таймауте)."""
        retries = 0
        can_count = 0

        while True:
            if cancel_event is not None and cancel_event.is_set():
                await send_cancel_sequence(self._writer)
                raise ModemCancelledError("XMODEM transfer cancelled via cancel_event")

            await write_and_drain(self._writer, packet)

            try:
                resp = await self._reader.read_byte(self._packet_timeout)
            except TimeoutError as exc:
                retries += 1
                if retries >= self._max_retries:
                    await send_cancel_sequence(self._writer)
                    raise ModemMaxRetriesError(
                        f"Max retries ({self._max_retries}) exceeded on packet #{seq} (timeout)"
                    ) from exc
                continue

            if resp == ACK:
                return

            if resp == CAN:
                can_count += 1
                if can_count >= 2:
                    raise ModemCancelledError(
                        f"XMODEM transfer cancelled by remote receiver on packet #{seq} (CAN CAN)"
                    )
                try:
                    next_b = await self._reader.read_byte(0.5)
                    if next_b == CAN:
                        raise ModemCancelledError(
                            f"XMODEM transfer cancelled by remote receiver on packet #{seq} (CAN CAN)"
                        )
                except TimeoutError:
                    pass

            retries += 1
            if retries >= self._max_retries:
                await send_cancel_sequence(self._writer)
                raise ModemMaxRetriesError(
                    f"Max retries ({self._max_retries}) exceeded on packet #{seq} (last byte: {resp!r})"
                )

    async def _finish_eot(self, cancel_event: asyncio.Event | None = None) -> None:
        """Выполнить финальное рукопожатие EOT -> (NAK -> EOT) -> ACK."""
        can_count = 0
        for _ in range(self._max_retries):
            if cancel_event is not None and cancel_event.is_set():
                await send_cancel_sequence(self._writer)
                raise ModemCancelledError("XMODEM transfer cancelled via cancel_event")

            await write_and_drain(self._writer, EOT)
            try:
                resp = await self._reader.read_byte(self._packet_timeout)
            except TimeoutError:
                continue
            if resp == ACK:
                return
            if resp == CAN:
                can_count += 1
                if can_count >= 2:
                    raise ModemCancelledError("XMODEM transfer cancelled during EOT handshake (CAN CAN)")
                try:
                    nxt = await self._reader.read_byte(0.5)
                    if nxt == CAN:
                        raise ModemCancelledError("XMODEM transfer cancelled during EOT handshake (CAN CAN)")
                except TimeoutError:
                    pass
                continue
            can_count = 0
        await send_cancel_sequence(self._writer)
        raise ModemMaxRetriesError("Failed to receive ACK for EOT")

    async def send(
        self,
        stream: BinaryIO,
        total_size: int | None = None,
        *,
        mode: XmodemMode = "1k",
        progress_callback: Callable[[int, int], None] | None = None,
        cancel_event: asyncio.Event | None = None,
    ) -> int:
        """Передать поток байтов по протоколу XMODEM. Возвращает число переданных байт."""
        if mode not in ("checksum", "crc", "1k"):
            raise ModemProtocolError(f"Unsupported XMODEM mode: {mode!r}")

        try:
            use_crc = await self._wait_handshake(mode, cancel_event=cancel_event)

            block_size = PACKET_SIZE_1K if (mode == "1k" and use_crc) else PACKET_SIZE_128
            seq = 1
            bytes_sent = 0
            known_total = total_size if total_size is not None else 0

            while True:
                chunk = stream.read(block_size)
                if not chunk:
                    break

                packet = build_xmodem_packet(
                    seq,
                    chunk,
                    block_size=block_size,
                    use_crc=use_crc,
                    pad_byte=SUB,
                )
                await self._send_packet_with_retries(packet, seq, cancel_event=cancel_event)
                bytes_sent += len(chunk)
                seq = (seq + 1) & 0xFF

                if progress_callback is not None:
                    progress_callback(bytes_sent, known_total or bytes_sent)

            await self._finish_eot(cancel_event=cancel_event)
            return bytes_sent
        except asyncio.CancelledError:
            await send_cancel_sequence(self._writer)
            raise


class AsyncXmodemReceiver:
    """Асинхронный приёмник XMODEM (поддерживает CRC-16, Checksum и 1K блоки с потоковой записью)."""

    def __init__(
        self,
        reader: asyncio.StreamReader | Any,
        writer: asyncio.StreamWriter | Any,
        *,
        logger: Any = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
        packet_timeout: float = DEFAULT_PACKET_TIMEOUT,
    ) -> None:
        self._reader = BufferedByteReader(reader)
        self._writer = writer
        self._logger = logger
        self._max_retries = max_retries
        self._packet_timeout = packet_timeout

    async def receive(
        self,
        output_stream: BinaryIO,
        *,
        mode: XmodemMode = "crc",
        strip_padding: bool = True,
        progress_callback: Callable[[int, int], None] | None = None,
        cancel_event: asyncio.Event | None = None,
    ) -> int:
        """Принять поток байтов по протоколу XMODEM. Возвращает число записанных байт."""
        if mode not in ("checksum", "crc", "1k"):
            raise ModemProtocolError(f"Unsupported XMODEM mode: {mode!r}")

        use_crc = mode in ("crc", "1k")
        start_char = CRC_CHR if use_crc else NAK
        expected_seq = 1
        total_received = 0
        written = 0
        pending_chunk: bytes | None = None
        first_packet = True

        try:
            while True:
                hdr, _, data = await read_validated_frame(
                    self._reader,
                    self._writer,
                    expected_seq,
                    use_crc=use_crc,
                    packet_timeout=self._packet_timeout,
                    max_retries=self._max_retries,
                    request_char=start_char if first_packet else None,
                    cancel_event=cancel_event,
                    protocol_label="XMODEM",
                )
                first_packet = False

                if hdr == EOT:
                    if pending_chunk is not None:
                        final_chunk = pending_chunk.rstrip(SUB) if strip_padding else pending_chunk
                        output_stream.write(final_chunk)
                        written += len(final_chunk)
                        pending_chunk = None
                    await write_and_drain(self._writer, ACK)
                    break

                if pending_chunk is not None:
                    output_stream.write(pending_chunk)
                    written += len(pending_chunk)

                pending_chunk = data
                total_received += len(data)
                expected_seq = (expected_seq + 1) & 0xFF
                await write_and_drain(self._writer, ACK)

                if progress_callback is not None:
                    progress_callback(total_received, total_received)

            return written
        except asyncio.CancelledError:
            await send_cancel_sequence(self._writer)
            raise


__all__ = [
    "AsyncXmodemReceiver",
    "AsyncXmodemSender",
    "XmodemMode",
    "build_xmodem_packet",
]
