"""Работа с последовательными консолями Serial / UART (Linux и Windows) и прошивка по XMODEM/YMODEM.

Демонстрирует:
- Кроссплатформенные URI: ``uart:///dev/ttyUSB0:115200``, ``uart://COM3:115200`` и поиск по ``vid``/``pid``
- Автоматический thread-backed адаптер на Windows (``ProactorEventLoop``) через ``io_backend=auto|threaded``
- Аппаратное управление линиями (DTR, RTS, ``pulse_dtr_rts``, ``send_break``) и опрос CTS/DSR/CD/RI
- Двоичный обмен ``run_bytes`` и загрузку прошивки по протоколу XMODEM-1K (``upload_xmodem``)
"""

from __future__ import annotations

import asyncio
import queue
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from uniconn import Connection, ConnectionConfig
from uniconn.transports import SerialTransport

# ─── Боевые примеры подключения к реальным UART-платам (Linux / Windows) ─────


async def linux_and_windows_serial_reference() -> None:
    """Справочный пример подключения к плате на Linux и Windows и загрузки образа по YMODEM."""
    # Linux: выбор адаптера по USB VID/PID (Silicon Labs CP210x)
    async with Connection.from_uri("serial://?vid=10c4&pid=ea60&baudrate=115200") as board:
        transport = board.transport
        assert isinstance(transport, SerialTransport)
        await transport.pulse_dtr_rts(dtr=False, rts=True, duration=0.1)
        transport.send_break(duration=0.25)
        sent = await board.files.upload_ymodem("u-boot.bin", trigger_command="loady 0x82000000\r")
        print(f"YMODEM uploaded {sent} bytes")

    # Windows: COM-порт с автоматическим переключением в thread-backed режим для ProactorEventLoop
    async with Connection.from_uri("uart://COM3:115200?parity=N&stopbits=1&io_backend=auto") as win_board:
        res = await win_board.run("AT+GMR", line_ending="\r\n", read_until="OK", timeout=3.0)
        print("Modem firmware:", res.text)


# ─── Самодостаточный локальный имитатор UART для офлайн-демонстрации ─────────


class _LoopbackSerialDevice:
    """Потокобезопасный имитатор ``serial.Serial`` (для демонстрации без физического COM-порта)."""

    def __init__(
        self,
        port: str = "COM3",
        *,
        on_write: Callable[[bytes, _LoopbackSerialDevice], None] | None = None,
        timeout: float = 0.05,
        **kwargs: Any,
    ) -> None:
        self.port = port
        self.timeout = timeout
        self.kwargs = kwargs
        self.is_open = True
        self.dtr = False
        self.rts = False
        self.cts = True
        self.dsr = True
        self.ri = False
        self.cd = True
        self.break_calls: list[float] = []
        self._rx_queue: queue.Queue[bytes] = queue.Queue()
        self._on_write = on_write

    def feed_rx(self, data: bytes) -> None:
        self._rx_queue.put(data)

    @property
    def in_waiting(self) -> int:
        return 0 if self._rx_queue.empty() else 1

    def read(self, _size: int = 1) -> bytes:
        if not self.is_open:
            return b""
        try:
            return self._rx_queue.get(timeout=max(0.01, float(self.timeout or 0.05)))
        except queue.Empty:
            return b""

    def write(self, data: bytes) -> int:
        if not self.is_open:
            raise OSError("Port is closed")
        raw = bytes(data)
        if self._on_write is not None:
            self._on_write(raw, self)
        return len(raw)

    def flush(self) -> None:
        return None

    def reset_input_buffer(self) -> None:
        while not self._rx_queue.empty():
            try:
                self._rx_queue.get_nowait()
            except queue.Empty:
                break

    def send_break(self, duration: float = 0.25) -> None:
        self.break_calls.append(duration)

    def cancel_read(self) -> None:
        self._rx_queue.put(b"")

    def close(self) -> None:
        self.is_open = False
        self._rx_queue.put(b"")


async def main() -> None:
    """Локальная демонстрация Serial/UART (threaded-адаптер, DTR/RTS, AT-команда и XMODEM)."""
    soh, stx, eot, ack, crc_req = 0x01, 0x02, 0x04, 0x06, ord("C")
    xmodem_started = {"flag": False}

    def _on_write(data: bytes, dev: _LoopbackSerialDevice) -> None:
        if data == b"AT\r\n":
            dev.feed_rx(b"OK\r\n")
        elif data == b"\xaa\x55":
            dev.feed_rx(b"\x55\xaa")
        elif data.startswith(b"loadx"):
            # Эмулируем запрос 'C' от загрузчика U-Boot после команды loadx
            def _send_crc_handshake() -> None:
                time.sleep(0.02)
                if dev.is_open and not xmodem_started["flag"]:
                    xmodem_started["flag"] = True
                    dev.feed_rx(bytes([crc_req]))

            threading.Thread(target=_send_crc_handshake, daemon=True).start()
        elif data and data[0] in (soh, stx, eot):
            dev.feed_rx(bytes([ack]))

    cfg = ConnectionConfig(
        transport="serial",
        host="COM3",
        timeout=2.0,
        options={
            "baudrate": 115200,
            "io_backend": "threaded",
            "serial_factory": lambda url, **kw: _LoopbackSerialDevice(port=url, on_write=_on_write, **kw),
        },
    )
    transport = SerialTransport(cfg)

    async with Connection(transport, cfg) as board:
        print("=== 1. Параметры и аппаратные линии UART ===")
        print("Capabilities:", transport.capabilities)
        await transport.pulse_dtr_rts(dtr=False, rts=True, duration=0.01)
        transport.send_break(0.1)
        print(f"Modem lines: CTS={transport.get_cts()}, DSR={transport.get_dsr()}, CD={transport.get_cd()}")

        print("\n=== 2. Текстовая AT-команда и бинарный обмен run_bytes ===")
        res = await board.run("AT", line_ending="\r\n", read_until="OK", timeout=2.0)
        print("AT response:", res.text)
        raw_reply = await transport.run_bytes(b"\xaa\x55", read_until=b"\x55\xaa", timeout=2.0)
        print("Binary reply:", raw_reply.hex())

        print("\n=== 3. Прошивка образа по протоколу XMODEM-1K ===")
        with tempfile.TemporaryDirectory(prefix="uniconn_uart_") as tmpdir:
            fw_path = Path(tmpdir) / "bootloader.bin"
            fw_path.write_bytes(b"U-BOOT-IMAGE-PAYLOAD-" * 16)
            sent_bytes = await board.files.upload_xmodem(
                fw_path,
                mode="1k",
                trigger_command="loadx 0x82000000\r",
                trigger_delay=0.02,
                timeout=3.0,
            )
            print(f"XMODEM transfer completed: {sent_bytes} bytes")


if __name__ == "__main__":
    asyncio.run(main())
