# src/uniconn/transports/serial_protocols/ymodem.py
"""Асинхронный конечный автомат протокола YMODEM / YMODEM-Batch (Packet 0, 1K/128B блоки)."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

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
)
from .exceptions import (
    ModemCancelledError,
    ModemHandshakeTimeoutError,
    ModemMaxRetriesError,
)


def build_ymodem_header_packet(
    filename: str = "",
    filesize: int = 0,
    mtime: int = 0,
    mode: int = 0o644,
) -> bytes:
    """Сформировать Пакет 0 (File Header Block или End-of-Batch Null Packet) для YMODEM.

    Если ``filename == ""``, формируется завершающий End-of-Batch пакет из 128 нулевых байт.
    """
    if not filename:
        payload = b"\x00" * PACKET_SIZE_128
        return build_xmodem_packet(0, payload, block_size=PACKET_SIZE_128, use_crc=True, pad_byte=b"\x00")

    clean_name = Path(filename).name.encode("utf-8")
    meta_str = f"{filesize} {mtime:o} {mode:o}".encode("ascii")
    raw = clean_name + b"\x00" + meta_str + b"\x00"
    if len(raw) > PACKET_SIZE_128:
        raw = clean_name + b"\x00" + f"{filesize}".encode("ascii") + b"\x00"
    payload = raw.ljust(PACKET_SIZE_128, b"\x00")[:PACKET_SIZE_128]
    return build_xmodem_packet(0, payload, block_size=PACKET_SIZE_128, use_crc=True, pad_byte=b"\x00")


def parse_ymodem_header_payload(payload: bytes) -> tuple[str, int, int | None, int | None]:
    """Распарсить 128-байтный payload Пакета 0 YMODEM.

    Возвращает ``(filename, filesize, mtime, mode)``. Для End-of-Batch пакета ``filename == ""``.
    """
    if not payload or payload[0] == 0:
        return ("", 0, None, None)

    parts = payload.split(b"\x00")
    filename = parts[0].decode("utf-8", errors="replace").strip()
    if not filename:
        return ("", 0, None, None)

    filesize = 0
    mtime: int | None = None
    mode: int | None = None

    if len(parts) > 1 and parts[1]:
        fields = parts[1].decode("ascii", errors="replace").strip().split()
        if len(fields) >= 1:
            try:
                filesize = int(fields[0], 10)
            except ValueError:
                filesize = 0
        if len(fields) >= 2:
            try:
                mtime = int(fields[1], 8)
            except ValueError:
                mtime = None
        if len(fields) >= 3:
            try:
                mode = int(fields[2], 8)
            except ValueError:
                mode = None

    return (filename, filesize, mtime, mode)


class AsyncYmodemSender:
    """Асинхронный передатчик YMODEM (поддерживает одиночную и пакетную Batch-передачу)."""

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

    async def _wait_for_crc_request(
        self,
        timeout: float,
        cancel_event: asyncio.Event | None = None,
    ) -> None:
        """Дождаться символа 'C' от получателя."""
        deadline = time.monotonic() + timeout
        can_count = 0

        while True:
            if cancel_event is not None and cancel_event.is_set():
                await send_cancel_sequence(self._writer)
                raise ModemCancelledError("YMODEM transfer cancelled via cancel_event")

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ModemHandshakeTimeoutError(
                    f"YMODEM timed out after {timeout:.1f}s waiting for 'C' from receiver"
                )

            try:
                ch = await self._reader.read_byte(min(remaining, self._packet_timeout))
            except TimeoutError:
                continue

            if ch == CAN:
                can_count += 1
                if can_count >= 2:
                    raise ModemCancelledError("YMODEM transfer cancelled by remote receiver (CAN CAN)")
                continue
            can_count = 0

            if ch == CRC_CHR:
                return

    async def _send_packet_expect_ack(
        self,
        packet: bytes,
        seq: int,
        *,
        allow_merged_crc: bool = False,
        cancel_event: asyncio.Event | None = None,
    ) -> bool:
        """Отправить пакет и дождаться ACK. Возвращает True, если вместе с ACK уже пришёл 'C'."""
        retries = 0
        can_count = 0

        while True:
            if cancel_event is not None and cancel_event.is_set():
                await send_cancel_sequence(self._writer)
                raise ModemCancelledError("YMODEM transfer cancelled via cancel_event")

            await write_and_drain(self._writer, packet)

            try:
                resp = await self._reader.read_byte(self._packet_timeout)
            except TimeoutError as exc:
                retries += 1
                if retries >= self._max_retries:
                    await send_cancel_sequence(self._writer)
                    raise ModemMaxRetriesError(
                        f"YMODEM max retries ({self._max_retries}) exceeded on packet #{seq}"
                    ) from exc
                continue

            if resp == ACK:
                buf = self._reader.buffer
                if allow_merged_crc and buf and buf[0:1] == CRC_CHR:
                    del buf[:1]
                    return True
                return False

            if resp == CAN:
                can_count += 1
                if can_count >= 2:
                    raise ModemCancelledError("YMODEM transfer cancelled by receiver (CAN CAN)")
                try:
                    nxt = await self._reader.read_byte(0.5)
                    if nxt == CAN:
                        raise ModemCancelledError("YMODEM transfer cancelled by receiver (CAN CAN)")
                except TimeoutError:
                    pass

            retries += 1
            if retries >= self._max_retries:
                await send_cancel_sequence(self._writer)
                raise ModemMaxRetriesError(
                    f"YMODEM max retries ({self._max_retries}) exceeded on packet #{seq} (last={resp!r})"
                )

    async def _complete_file_eot(self, cancel_event: asyncio.Event | None = None) -> None:
        """Завершить передачу данных файла (EOT -> [NAK -> EOT] -> ACK -> 'C')."""
        ack_received = False
        can_count = 0

        for _ in range(self._max_retries):
            if cancel_event is not None and cancel_event.is_set():
                await send_cancel_sequence(self._writer)
                raise ModemCancelledError("YMODEM transfer cancelled via cancel_event")

            await write_and_drain(self._writer, EOT)
            try:
                resp = await self._reader.read_byte(self._packet_timeout)
            except TimeoutError:
                continue

            if resp == ACK:
                ack_received = True
                break
            if resp == CAN:
                can_count += 1
                if can_count >= 2:
                    raise ModemCancelledError("YMODEM cancelled during EOT handshake (CAN CAN)")
                try:
                    nxt = await self._reader.read_byte(0.5)
                    if nxt == CAN:
                        raise ModemCancelledError("YMODEM cancelled during EOT handshake (CAN CAN)")
                except TimeoutError:
                    pass
                continue
            can_count = 0
            if resp == NAK:
                await write_and_drain(self._writer, EOT)
                try:
                    resp2 = await self._reader.read_byte(self._packet_timeout)
                except TimeoutError:
                    continue
                if resp2 == ACK:
                    ack_received = True
                    break
                if resp2 == CAN:
                    raise ModemCancelledError("YMODEM cancelled during EOT handshake")

        if not ack_received:
            await send_cancel_sequence(self._writer)
            raise ModemMaxRetriesError("Failed to receive ACK for YMODEM EOT")

        await self._wait_for_crc_request(self._packet_timeout, cancel_event=cancel_event)

    async def _send_single_file_in_session(
        self,
        path: Path,
        *,
        progress_callback: Callable[[int, int], None] | None = None,
        batch_progress_callback: Callable[[int, int, str], None] | None = None,
        cancel_event: asyncio.Event | None = None,
    ) -> int:
        if not path.is_file():
            raise FileNotFoundError(f"Local file does not exist: {path}")

        stat_info = path.stat()
        filesize = int(stat_info.st_size)
        mtime = int(stat_info.st_mtime)
        fmode = int(stat_info.st_mode & 0o777) or 0o644

        pkt0 = build_ymodem_header_packet(path.name, filesize, mtime=mtime, mode=fmode)
        got_c = await self._send_packet_expect_ack(
            pkt0,
            0,
            allow_merged_crc=True,
            cancel_event=cancel_event,
        )
        if not got_c:
            await self._wait_for_crc_request(self._packet_timeout, cancel_event=cancel_event)

        if filesize == 0:
            if progress_callback is not None:
                progress_callback(0, 0)
            if batch_progress_callback is not None:
                batch_progress_callback(0, 0, path.name)
            await self._complete_file_eot(cancel_event=cancel_event)
            return 0

        seq = 1
        sent = 0
        with path.open("rb") as fp:
            while sent < filesize:
                remaining_bytes = filesize - sent
                block_size = PACKET_SIZE_1K if remaining_bytes >= PACKET_SIZE_1K else PACKET_SIZE_128
                chunk = fp.read(block_size)
                if not chunk:
                    break
                pkt = build_xmodem_packet(
                    seq,
                    chunk,
                    block_size=block_size,
                    use_crc=True,
                    pad_byte=b"\x00",
                )
                await self._send_packet_expect_ack(pkt, seq, cancel_event=cancel_event)
                sent += len(chunk)
                seq = (seq + 1) & 0xFF

                if progress_callback is not None:
                    progress_callback(sent, filesize)
                if batch_progress_callback is not None:
                    batch_progress_callback(sent, filesize, path.name)

        await self._complete_file_eot(cancel_event=cancel_event)
        return filesize

    async def send_file(
        self,
        local_path: str | Path,
        *,
        progress_callback: Callable[[int, int], None] | None = None,
        cancel_event: asyncio.Event | None = None,
    ) -> int:
        """Передать один файл по протоколу YMODEM с метаданными и закрывающим Null Packet 0."""
        path = Path(local_path)
        if not path.is_file():
            raise FileNotFoundError(f"Local file does not exist: {path}")

        try:
            await self._wait_for_crc_request(self._handshake_timeout, cancel_event=cancel_event)
            total_sent = await self._send_single_file_in_session(
                path,
                progress_callback=progress_callback,
                cancel_event=cancel_event,
            )
            null_pkt = build_ymodem_header_packet("")
            await self._send_packet_expect_ack(null_pkt, 0, cancel_event=cancel_event)
            return total_sent
        except asyncio.CancelledError:
            await send_cancel_sequence(self._writer)
            raise

    async def send_batch(
        self,
        local_paths: Sequence[str | Path],
        *,
        progress_callback: Callable[[int, int, str], None] | None = None,
        cancel_event: asyncio.Event | None = None,
    ) -> int:
        """Передать список файлов в рамках единой YMODEM-Batch сессии."""
        paths = [Path(p) for p in local_paths]
        for p in paths:
            if not p.is_file():
                raise FileNotFoundError(f"Local file does not exist: {p}")

        try:
            await self._wait_for_crc_request(self._handshake_timeout, cancel_event=cancel_event)
            total_bytes = 0
            for path in paths:
                total_bytes += await self._send_single_file_in_session(
                    path,
                    batch_progress_callback=progress_callback,
                    cancel_event=cancel_event,
                )
            null_pkt = build_ymodem_header_packet("")
            await self._send_packet_expect_ack(null_pkt, 0, cancel_event=cancel_event)
            return total_bytes
        except asyncio.CancelledError:
            await send_cancel_sequence(self._writer)
            raise


class AsyncYmodemReceiver:
    """Асинхронный приёмник YMODEM-Batch (сохраняет файлы с точным размером из Пакета 0)."""

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

    async def receive_batch(
        self,
        destination_dir: str | Path,
        *,
        progress_callback: Callable[[int, int, str], None] | None = None,
        cancel_event: asyncio.Event | None = None,
    ) -> list[Path]:
        """Принять файлы YMODEM-Batch сессии и сохранить их с точными размерами."""
        dest_root = Path(destination_dir)
        dest_root.mkdir(parents=True, exist_ok=True)
        saved_files: list[Path] = []

        try:
            while True:
                _, _, pkt0_data = await read_validated_frame(
                    self._reader,
                    self._writer,
                    0,
                    use_crc=True,
                    packet_timeout=self._packet_timeout,
                    max_retries=self._max_retries,
                    request_char=CRC_CHR,
                    cancel_event=cancel_event,
                    protocol_label="YMODEM",
                )
                filename, filesize, _, _ = parse_ymodem_header_payload(pkt0_data)
                if not filename:
                    await write_and_drain(self._writer, ACK)
                    break

                safe_name = Path(filename).name
                target_path = dest_root / safe_name
                await write_and_drain(self._writer, ACK + CRC_CHR)

                expected_seq = 1
                bytes_written = 0
                with target_path.open("wb") as fp:
                    while True:
                        hdr, _, data = await read_validated_frame(
                            self._reader,
                            self._writer,
                            expected_seq,
                            use_crc=True,
                            packet_timeout=self._packet_timeout,
                            max_retries=self._max_retries,
                            request_char=None,
                            cancel_event=cancel_event,
                            protocol_label="YMODEM",
                        )
                        if hdr == EOT:
                            await write_and_drain(self._writer, ACK)
                            break

                        if filesize > 0:
                            remaining = max(0, filesize - bytes_written)
                            to_write = data[: min(len(data), remaining)]
                        else:
                            to_write = data

                        fp.write(to_write)
                        bytes_written += len(to_write)
                        expected_seq = (expected_seq + 1) & 0xFF
                        await write_and_drain(self._writer, ACK)

                        if progress_callback is not None:
                            progress_callback(bytes_written, filesize or bytes_written, safe_name)

                saved_files.append(target_path)

            return saved_files
        except asyncio.CancelledError:
            await send_cancel_sequence(self._writer)
            raise


__all__ = [
    "AsyncYmodemReceiver",
    "AsyncYmodemSender",
    "build_ymodem_header_packet",
    "parse_ymodem_header_payload",
]
