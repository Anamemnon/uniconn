# tests/unit/transports/test_stage3a_serial_qga_telnet.py
"""Unit-тесты для Шага 3A: SerialTransport (Windows/Proactor + ZMODEM), QgaTransport (TCP/Pipe), TelnetTransport (POSIX/CLI)."""

from __future__ import annotations

import asyncio
import base64
import json
import queue
import re
import threading
import time
from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from uniconn import (
    Cassette,
    Connection,
    RecordedExecInteraction,
    RecordedShellInteraction,
    ShellDialogStep,
    URIParser,
)
from uniconn.config.models import ConnectionConfig
from uniconn.exceptions import (
    CapabilityNotSupportedError,
    ConfigurationError,
    ConnectionError,
)
from uniconn.exceptions import (
    TimeoutError as UniconnTimeoutError,
)
from uniconn.mock import MockTelnetServer
from uniconn.transports import (
    NamedPipeQgaChannel,
    QgaTransport,
    SerialTransport,
    TcpQgaChannel,
    ZmodemSubprocessAdapter,
)
from uniconn.transports._serial_threaded import (
    ThreadedSerialWriter,
    should_use_threaded_serial,
)
from uniconn.transports._telnet import TelnetTransport
from uniconn.transports.virtualization.qga_protocol import (
    is_windows_pipe_path,
    normalize_windows_pipe_path,
)

# ============================================================================
# 1. SerialTransport: Thread-backed Windows/Proactor adapter & ZMODEM capabilities
# ============================================================================


class _FakeSerialDevice:
    """Потокобезопасный имитатор ``serial.Serial`` для тестирования ``ThreadedSerialWriter``."""

    def __init__(
        self,
        port: str = "COM4",
        *,
        on_write: Callable[[bytes, _FakeSerialDevice], None] | None = None,
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
        self.written: list[bytes] = []
        self._rx_queue: queue.Queue[bytes] = queue.Queue()
        self._on_write = on_write
        self._lock = threading.Lock()

    def feed_rx(self, data: bytes) -> None:
        self._rx_queue.put(data)

    @property
    def in_waiting(self) -> int:
        return 0 if self._rx_queue.empty() else 1

    def read(self, size: int = 1) -> bytes:
        if not self.is_open:
            return b""
        try:
            chunk = self._rx_queue.get(timeout=max(0.01, float(self.timeout or 0.05)))
        except queue.Empty:
            return b""
        return chunk

    def write(self, data: bytes) -> int:
        if not self.is_open:
            raise OSError("Port is closed")
        raw = bytes(data)
        with self._lock:
            self.written.append(raw)
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


class TestSerialThreadedAndZmodem:
    """Тесты thread-backed адаптера SerialTransport и платформенных capabilities ZMODEM."""

    def test_should_use_threaded_serial_modes(self) -> None:
        assert should_use_threaded_serial("threaded") is True
        assert should_use_threaded_serial("asyncio") is False

        with pytest.raises(ConfigurationError, match="Unsupported serial io_backend"):
            should_use_threaded_serial("unknown")

        class _FakeProactorEventLoop:
            pass

        with patch("uniconn.transports._serial_threaded.sys.platform", "linux"):
            assert should_use_threaded_serial("auto", loop=_FakeProactorEventLoop()) is True  # type: ignore[arg-type]

        with patch("uniconn.transports._serial_threaded.sys.platform", "win32"):
            assert should_use_threaded_serial("auto") is True

    @pytest.mark.asyncio
    async def test_threaded_serial_full_lifecycle_and_hardware_lines(self) -> None:
        """Симуляция Windows (ProactorEventLoop, без pyserial-asyncio): run, run_bytes, stream, shell, DTR/RTS."""
        created_ports: list[_FakeSerialDevice] = []

        def _on_write(data: bytes, dev: _FakeSerialDevice) -> None:
            if data == b"AT\r\n":
                dev.feed_rx(b"OK\r\n")
            elif data == b"\x01\x02":
                dev.feed_rx(b"\xaa\xbb")
            elif data == b"logs\n":
                dev.feed_rx(b"boot-1\nboot-2\n")
            elif data == b"whoami\n":
                dev.feed_rx(b"root\n")

        def _factory(url: str, **kw: Any) -> _FakeSerialDevice:
            dev = _FakeSerialDevice(port=url, on_write=_on_write, **kw)
            created_ports.append(dev)
            return dev

        cfg = ConnectionConfig(
            transport="serial",
            host="COM4",
            timeout=2.0,
            options={
                "baudrate": 115200,
                "io_backend": "auto",
                "serial_factory": _factory,
            },
        )

        # Эмулируем Windows без установленного serial_asyncio
        with (
            patch("uniconn.transports._serial_threaded.sys.platform", "win32"),
            patch("uniconn.transports._serial.serial_asyncio", None),
        ):
            transport = SerialTransport(cfg)
            await transport.connect()
            try:
                assert transport.is_connected is True
                assert isinstance(transport._writer, ThreadedSerialWriter)
                assert transport.capabilities["io_backend"] == "threaded"
                assert transport.capabilities["xmodem"] is True
                assert transport.capabilities["ymodem"] is True
                assert transport.serial_instance is created_ports[0]

                # Аппаратные линии
                transport.set_dtr(True)
                transport.set_rts(True)
                transport.send_break(0.15)
                assert created_ports[0].dtr is True
                assert created_ports[0].rts is True
                assert created_ports[0].break_calls == [0.15]
                assert transport.get_cts() is True
                assert transport.get_dsr() is True
                assert transport.get_ri() is False
                assert transport.get_cd() is True
                await transport.pulse_dtr_rts(dtr=False, rts=True, duration=0.01)
                assert created_ports[0].dtr is True
                assert created_ports[0].rts is False

                # run()
                res = await transport.run("AT", line_ending="\r\n", read_until="OK", timeout=2.0)
                assert res.ok
                assert res.stdout == "OK"

                # run_bytes()
                raw = await transport.run_bytes(b"\x01\x02", read_until=b"\xaa\xbb", timeout=2.0)
                assert raw == b"\xaa\xbb"

                # stream()
                lines: list[str] = []
                async for line in transport.stream("logs", timeout=0.15):
                    lines.append(line)
                assert lines == ["boot-1", "boot-2"]

                # open_shell()
                proc = await transport.open_shell()
                proc.stdin.write("whoami\n")
                await proc.stdin.drain()
                shell_out = await asyncio.wait_for(proc.stdout.read(64), timeout=1.0)
                assert "root" in shell_out
            finally:
                await transport.disconnect()

            assert transport.is_connected is False
            assert created_ports[0].is_open is False

    @pytest.mark.asyncio
    async def test_threaded_serial_xmodem_upload(self, tmp_path: Any) -> None:
        """Проверка работы XMODEM поверх ThreadedSerialWriter (Windows-совместимый путь)."""
        soh, eot, ack, crc_request = 0x01, 0x04, 0x06, ord("C")
        payload = b"firmware-v1-image-bytes"
        fw_file = tmp_path / "fw.bin"
        fw_file.write_bytes(payload)

        state = {"handshake_sent": False}

        def _on_write(data: bytes, dev: _FakeSerialDevice) -> None:
            if data and data[0] in (soh, eot):
                dev.feed_rx(bytes([ack]))

        def _factory(url: str, **kw: Any) -> _FakeSerialDevice:
            dev = _FakeSerialDevice(port=url, on_write=_on_write, **kw)
            # Загрузчик шлёт запрос CRC ('C') чуть позже после сброса буфера
            def _send_c() -> None:
                time.sleep(0.05)
                if dev.is_open and not state["handshake_sent"]:
                    state["handshake_sent"] = True
                    dev.feed_rx(bytes([crc_request]))

            threading.Thread(target=_send_c, daemon=True).start()
            return dev

        cfg = ConnectionConfig(
            transport="serial",
            host="COM5",
            options={"io_backend": "threaded", "serial_factory": _factory},
        )
        transport = SerialTransport(cfg)
        await transport.connect()
        try:
            sent = await transport.upload_xmodem(fw_file, mode="crc", timeout=3.0)
            assert sent == len(payload)
        finally:
            await transport.disconnect()

    @pytest.mark.asyncio
    async def test_zmodem_platform_restriction_on_windows_and_capabilities(self, tmp_path: Any) -> None:
        """На Windows ZMODEM явно помечен как неподдерживаемый и бросает CapabilityNotSupportedError."""
        sample = tmp_path / "data.bin"
        sample.write_bytes(b"abc")

        with (
            patch("uniconn.transports.serial_protocols.zmodem.sys.platform", "win32"),
            patch("uniconn.transports.serial_protocols.zmodem.shutil.which", return_value="/usr/bin/sz"),
        ):
            assert ZmodemSubprocessAdapter.is_platform_supported() is False
            assert ZmodemSubprocessAdapter.is_available() is False

            with pytest.raises(CapabilityNotSupportedError, match="not supported on Windows"):
                await ZmodemSubprocessAdapter.send_file("COM3", 115200, sample)

            with pytest.raises(CapabilityNotSupportedError, match="not supported on Windows"):
                await ZmodemSubprocessAdapter.receive_files("COM3", 115200, tmp_path)

            cfg = ConnectionConfig(transport="serial", host="COM3", options={"io_backend": "threaded"})
            transport = SerialTransport(cfg)
            caps = transport.capabilities
            assert caps["zmodem"] is False
            assert caps["zmodem_platform_supported"] is False
            assert caps["xmodem"] is True
            assert caps["ymodem"] is True

        with (
            patch("uniconn.transports.serial_protocols.zmodem.sys.platform", "linux"),
            patch("uniconn.transports.serial_protocols.zmodem.shutil.which", return_value="/usr/bin/sz"),
        ):
            assert ZmodemSubprocessAdapter.is_platform_supported() is True
            assert ZmodemSubprocessAdapter.is_available() is True
            cfg = ConnectionConfig(transport="serial", host="/dev/ttyUSB0", options={"io_backend": "threaded"})
            transport = SerialTransport(cfg)
            caps = transport.capabilities
            assert caps["zmodem"] is True
            assert caps["zmodem_platform_supported"] is True

    @pytest.mark.asyncio
    async def test_threaded_serial_drain_does_not_hang_on_concurrent_close(self) -> None:
        """Конкурентный close() во время drain() не приводит к зависанию, а последующие write/drain дают OSError."""
        write_started = threading.Event()
        release_write = threading.Event()

        class _BlockingWriteSerial(_FakeSerialDevice):
            def write(self, data: bytes) -> int:
                write_started.set()
                release_write.wait(timeout=2.0)
                return super().write(data)

        dev = _BlockingWriteSerial(port="COM9")
        reader = asyncio.StreamReader()
        loop = asyncio.get_running_loop()
        writer = ThreadedSerialWriter(dev, reader, loop)
        try:
            writer.write(b"first")
            assert await asyncio.to_thread(write_started.wait, 1.0) is True
            drain_task = asyncio.create_task(writer.drain())
            await asyncio.sleep(0.02)
            writer.close()
            release_write.set()
            # Ожидающий drain() корректно завершается без зависания
            await asyncio.wait_for(drain_task, timeout=2.0)
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)

            # После close() любые write()/drain() немедленно бросают OSError
            with pytest.raises(OSError, match="Serial writer is closed"):
                writer.write(b"after-close")
            with pytest.raises(OSError, match="Serial writer is closed"):
                await writer.drain()
        finally:
            release_write.set()
            writer.close()

    @pytest.mark.asyncio
    async def test_threaded_serial_flush_input_clears_buffered_unsolicited_bytes(self) -> None:
        """flush_input() сбрасывает не только буфер порта, но и уже вычитанный RX-мусор в StreamReader."""
        created: list[_FakeSerialDevice] = []

        def _on_write(data: bytes, dev: _FakeSerialDevice) -> None:
            if data == b"AT\r\n":
                dev.feed_rx(b"OK\r\n")

        def _factory(url: str, **kw: Any) -> _FakeSerialDevice:
            dev = _FakeSerialDevice(port=url, on_write=_on_write, **kw)
            created.append(dev)
            return dev

        cfg = ConnectionConfig(
            transport="serial",
            host="COM8",
            timeout=2.0,
            options={"io_backend": "threaded", "serial_factory": _factory},
        )
        transport = SerialTransport(cfg)
        await transport.connect()
        try:
            # Имитируем нежелательный баннер, который успел попасть в asyncio.StreamReader до вызова run()
            created[0].feed_rx(b"UNSOLICITED_NOISE\r\n")
            await asyncio.sleep(0.08)
            assert transport._reader is not None
            assert len(transport._reader._buffer) > 0  # type: ignore[attr-defined]

            res = await transport.run("AT", line_ending="\r\n", read_until="OK", timeout=2.0)
            assert res.ok
            assert res.stdout == "OK"
            assert "UNSOLICITED_NOISE" not in res.stdout
        finally:
            await transport.disconnect()


# ============================================================================
# 2. QgaTransport: TcpQgaChannel, NamedPipeQgaChannel & URIParser
# ============================================================================


class _MiniQgaResponder:
    """Минимальный обработчик QGA JSON-RPC для локального TCP-сервера и фейкового Named Pipe."""

    def __init__(self) -> None:
        self.files: dict[str, bytearray] = {}
        self.handles: dict[int, tuple[str, str, int]] = {}
        self._next_handle = 10
        self._next_pid = 1000
        self._execs: dict[int, dict[str, Any]] = {}

    def handle_raw_line(self, raw_line: bytes) -> bytes:
        has_sentinel = b"\xff" in raw_line
        if has_sentinel:
            raw_line = raw_line.split(b"\xff")[-1]
        req = json.loads(raw_line.decode("utf-8"))
        cmd = req.get("execute")
        args = req.get("arguments") or {}

        if cmd == "guest-sync-delimited":
            resp = {"return": args["id"]}
            # Эмулируем мусорные байты до 0xff, чтобы проверить отсечение по маркеру синхронизации
            return b"stale-garbage\xff" + json.dumps(resp).encode("utf-8") + b"\n"
        if cmd == "guest-ping":
            return json.dumps({"return": {}}).encode("utf-8") + b"\n"
        if cmd == "guest-get-osinfo":
            return json.dumps(
                {"return": {"id": "ubuntu", "name": "Ubuntu", "pretty-name": "Ubuntu 24.04"}}
            ).encode("utf-8") + b"\n"
        if cmd == "guest-get-host-name":
            return json.dumps({"return": {"host-name": "qemu-vm-01"}}).encode("utf-8") + b"\n"
        if cmd == "guest-network-get-interfaces":
            return json.dumps({"return": []}).encode("utf-8") + b"\n"
        if cmd == "guest-get-fsinfo":
            return json.dumps({"return": []}).encode("utf-8") + b"\n"
        if cmd == "guest-get-vcpus":
            return json.dumps({"return": [{"logical-id": 0, "online": True}]}).encode("utf-8") + b"\n"
        if cmd == "guest-exec":
            pid = self._next_pid
            self._next_pid += 1
            cmd_args = args.get("arg") or []
            shell_cmd = cmd_args[-1] if cmd_args else ""
            if "fail" in shell_cmd:
                self._execs[pid] = {
                    "exited": True,
                    "exitcode": 7,
                    "out-data": base64.b64encode(b"").decode("ascii"),
                    "err-data": base64.b64encode(b"boom\n").decode("ascii"),
                }
            else:
                out = f"ran:{shell_cmd}\n".encode()
                self._execs[pid] = {
                    "exited": True,
                    "exitcode": 0,
                    "out-data": base64.b64encode(out).decode("ascii"),
                    "err-data": "",
                }
            return json.dumps({"return": {"pid": pid}}).encode("utf-8") + b"\n"
        if cmd == "guest-exec-status":
            pid = int(args["pid"])
            return json.dumps({"return": self._execs[pid]}).encode("utf-8") + b"\n"
        if cmd == "guest-file-open":
            path = str(args["path"])
            mode = str(args.get("mode", "r"))
            if "w" in mode:
                self.files[path] = bytearray()
            elif path not in self.files:
                return json.dumps({"error": {"class": "GenericError", "desc": "not found"}}).encode("utf-8") + b"\n"
            h = self._next_handle
            self._next_handle += 1
            self.handles[h] = (path, mode, 0)
            return json.dumps({"return": h}).encode("utf-8") + b"\n"
        if cmd == "guest-file-write":
            h = int(args["handle"])
            path, mode, pos = self.handles[h]
            raw = base64.b64decode(args.get("buf-b64", ""))
            self.files[path].extend(raw)
            self.handles[h] = (path, mode, pos + len(raw))
            return json.dumps({"return": {"count": len(raw), "eof": False}}).encode("utf-8") + b"\n"
        if cmd == "guest-file-read":
            h = int(args["handle"])
            path, mode, pos = self.handles[h]
            count = int(args.get("count", 4096))
            data = bytes(self.files[path][pos : pos + count])
            new_pos = pos + len(data)
            self.handles[h] = (path, mode, new_pos)
            eof = new_pos >= len(self.files[path])
            return json.dumps(
                {
                    "return": {
                        "count": len(data),
                        "buf-b64": base64.b64encode(data).decode("ascii"),
                        "eof": eof,
                    }
                }
            ).encode("utf-8") + b"\n"
        if cmd in ("guest-file-flush", "guest-file-close"):
            if cmd == "guest-file-close":
                self.handles.pop(int(args["handle"]), None)
            return json.dumps({"return": {}}).encode("utf-8") + b"\n"
        return json.dumps({"error": {"desc": f"Unknown command: {cmd}"}}).encode("utf-8") + b"\n"


class _FakeNamedPipeHandle:
    """Синхронный бинарный дескриптор, имитирующий Windows Named Pipe поверх ``_MiniQgaResponder``."""

    def __init__(self, responder: _MiniQgaResponder) -> None:
        self._responder = responder
        self._rx = bytearray()
        self._tx = bytearray()
        self.closed = False

    def write(self, data: bytes) -> int:
        if self.closed:
            raise OSError("Pipe closed")
        self._tx.extend(data)
        while b"\n" in self._tx:
            idx = self._tx.find(b"\n")
            line = bytes(self._tx[: idx + 1])
            del self._tx[: idx + 1]
            self._rx.extend(self._responder.handle_raw_line(line))
        return len(data)

    def flush(self) -> None:
        return None

    def read(self, size: int = 4096) -> bytes:
        if self.closed or not self._rx:
            return b""
        chunk = bytes(self._rx[:size])
        del self._rx[:size]
        return chunk

    def close(self) -> None:
        self.closed = True


class TestQgaTcpAndNamedPipe:
    """Тесты TcpQgaChannel, NamedPipeQgaChannel и URIParser для локального QEMU / Windows."""

    @pytest.mark.asyncio
    async def test_tcp_qga_channel_end_to_end_over_real_local_server(self) -> None:
        """Реальный локальный TCP QGA-сервер: автодетект localhost:port, sync, run, read/write, facts."""
        responder = _MiniQgaResponder()

        async def _client_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                while True:
                    line = await reader.readline()
                    if not line:
                        break
                    writer.write(responder.handle_raw_line(line))
                    await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(_client_handler, "127.0.0.1", 0)
        port = int(server.sockets[0].getsockname()[1])

        try:
            # Автоопределение TCP-бэкенда по localhost/127.0.0.1 + port
            async with Connection.from_uri(f"qga://127.0.0.1:{port}") as conn:
                transport = conn.transport
                assert isinstance(transport, QgaTransport)
                assert transport.backend == "tcp"
                assert isinstance(transport.client.channel, TcpQgaChannel)  # type: ignore[union-attr]

                ping_res = await conn.ping()
                assert ping_res.alive is True
                assert bool(ping_res) is True
                res_ok = await conn.run("uname -a")
                assert res_ok.ok
                assert res_ok.text == "ran:uname -a"

                res_fail = await conn.run("fail_cmd")
                assert res_fail.exit_code == 7
                assert "boom" in res_fail.stderr

                await conn.files.write_file("/etc/demo.conf", b"hello-tcp-qga")
                content = await conn.files.read_file("/etc/demo.conf")
                assert content == "hello-tcp-qga"

                facts = await transport.gather_qga_native_facts()
                assert facts["hostname"] == "qemu-vm-01"
                assert facts["osinfo"]["id"] == "ubuntu"
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_named_pipe_qga_channel_end_to_end_and_platform_guard(self) -> None:
        """NamedPipeQgaChannel: нормализация путей, отказ на non-Windows и полный протокол с opener."""
        assert is_windows_pipe_path(r"\\.\pipe\qga-vm1") is True
        assert is_windows_pipe_path("//./pipe/qga-vm1") is True
        assert is_windows_pipe_path("/var/run/qga.sock") is False

        assert normalize_windows_pipe_path("qga-vm1") == r"\\.\pipe\qga-vm1"
        assert normalize_windows_pipe_path("//./pipe/qga-vm1") == r"\\.\pipe\qga-vm1"
        assert normalize_windows_pipe_path(r"\\.\pipe\qga-vm1") == r"\\.\pipe\qga-vm1"

        # На Linux без подмены opener должен быть понятный ConnectionError
        with patch("uniconn.transports.virtualization.qga_protocol.sys.platform", "linux"):
            ch = NamedPipeQgaChannel(r"\\.\pipe\qga-vm1")
            with pytest.raises(ConnectionError, match="only supported on Windows"):
                await ch.open(timeout=1.0)

        # Полный цикл через QgaTransport с инъекцией _pipe_opener
        responder = _MiniQgaResponder()
        opened_paths: list[str] = []

        def _fake_opener(path: str) -> _FakeNamedPipeHandle:
            opened_paths.append(path)
            return _FakeNamedPipeHandle(responder)

        cfg = ConnectionConfig(
            transport="qga",
            host=r"\\.\pipe\qga-vm1",
            options={"backend": "pipe", "pipe": r"\\.\pipe\qga-vm1", "_pipe_opener": _fake_opener},
        )
        transport = QgaTransport(cfg)
        await transport.connect()
        try:
            assert transport.backend == "pipe"
            assert isinstance(transport.client.channel, NamedPipeQgaChannel)  # type: ignore[union-attr]
            assert opened_paths == [r"\\.\pipe\qga-vm1"]
            assert await transport.ping() is True

            res = await transport.run("echo pipe-ok")
            assert res.ok
            assert res.text == "ran:echo pipe-ok"

            await transport.write_file("/tmp/pipe.txt", b"pipe-payload")
            assert await transport.read_file("/tmp/pipe.txt") == b"pipe-payload"
        finally:
            await transport.disconnect()

    def test_uri_parser_qga_tcp_and_pipe_roundtrip(self) -> None:
        """Разбор и обратная сборка URI для qga tcp и Windows named pipe."""
        cfg_tcp_auto = URIParser.parse("qga://127.0.0.1:4444")
        assert cfg_tcp_auto.host == "127.0.0.1"
        assert cfg_tcp_auto.port == 4444
        assert cfg_tcp_auto.options["backend"] == "tcp"

        cfg_tcp_remote = URIParser.parse("qemu-ga://qemu-lab.local:4455?backend=tcp")
        assert cfg_tcp_remote.transport == "qemu-ga"
        assert cfg_tcp_remote.host == "qemu-lab.local"
        assert cfg_tcp_remote.port == 4455
        assert cfg_tcp_remote.options["backend"] == "tcp"
        rebuilt_tcp = URIParser.from_config(cfg_tcp_remote)
        reparsed_tcp = URIParser.parse(rebuilt_tcp)
        assert reparsed_tcp.host == "qemu-lab.local"
        assert reparsed_tcp.port == 4455
        assert reparsed_tcp.options["backend"] == "tcp"

        cfg_pipe = URIParser.parse(r"qga://?backend=pipe&pipe=\\.\pipe\qga-win11")
        assert cfg_pipe.options["backend"] == "pipe"
        assert cfg_pipe.options["pipe"] == r"\\.\pipe\qga-win11"
        rebuilt_pipe = URIParser.from_config(cfg_pipe)
        reparsed_pipe = URIParser.parse(rebuilt_pipe)
        assert reparsed_pipe.options["backend"] == "pipe"
        assert reparsed_pipe.options["pipe"] == r"\\.\pipe\qga-win11"

        cfg_pipe_auto = URIParser.parse(r"qga://?socket=\\.\pipe\qga-auto")
        assert cfg_pipe_auto.options["backend"] == "pipe"
        assert cfg_pipe_auto.options["pipe"] == r"\\.\pipe\qga-auto"

        # IPv6 loopback автоопределяется как tcp и корректно проходит roundtrip через URIParser.from_config()
        cfg_ipv6 = URIParser.parse("qga://[::1]:4444")
        assert cfg_ipv6.host == "::1"
        assert cfg_ipv6.port == 4444
        assert cfg_ipv6.options["backend"] == "tcp"
        rebuilt_ipv6 = URIParser.from_config(cfg_ipv6)
        assert "[::1]:4444" in rebuilt_ipv6
        reparsed_ipv6 = URIParser.parse(rebuilt_ipv6)
        assert reparsed_ipv6.host == "::1"
        assert reparsed_ipv6.port == 4444
        assert reparsed_ipv6.options["backend"] == "tcp"

    def test_qga_invalid_backend_raises_configuration_error(self) -> None:
        """Неподдерживаемый backend в QgaTransport явно отвергается с ConfigurationError."""
        cfg = ConnectionConfig(
            transport="qga",
            host="127.0.0.1",
            port=4444,
            options={"backend": "grpc"},
        )
        with pytest.raises(ConfigurationError, match="Unsupported QGA backend"):
            QgaTransport(cfg)

    @pytest.mark.asyncio
    async def test_named_pipe_qga_open_timeout_closes_orphaned_handle(self) -> None:
        """Если opener вернул дескриптор уже после таймаута open(), дескриптор закрывается без утечки."""
        opened_handles: list[_FakeNamedPipeHandle] = []
        release_open = threading.Event()
        closed_evt = threading.Event()

        class _TrackedPipeHandle(_FakeNamedPipeHandle):
            def close(self) -> None:
                super().close()
                closed_evt.set()

        def _slow_opener(path: str) -> _TrackedPipeHandle:
            _ = path
            release_open.wait(timeout=2.0)
            handle = _TrackedPipeHandle(_MiniQgaResponder())
            opened_handles.append(handle)
            return handle

        ch = NamedPipeQgaChannel(r"\\.\pipe\qga-slow", opener=_slow_opener)
        with pytest.raises(UniconnTimeoutError, match="Timed out opening QGA named pipe"):
            await ch.open(timeout=0.05)

        release_open.set()
        assert await asyncio.to_thread(closed_evt.wait, 1.0) is True
        assert len(opened_handles) == 1
        assert opened_handles[0].closed is True
        assert ch.is_open is False


# ============================================================================
# 3. TelnetTransport: auto POSIX/CLI detection, real exit_code, OOB profiles & pagination
# ============================================================================


class _DuplexTelnetPeer:
    """Асинхронный дуплексный имитатор Telnet reader/writer для POSIX и OOB CLI устройств."""

    def __init__(self, handler: Callable[[str, _DuplexTelnetPeer], None]) -> None:
        self._handler = handler
        self._rx_queue: asyncio.Queue[str] = asyncio.Queue()
        self.sent: list[str] = []
        self.closed = False

    def push(self, chunk: str) -> None:
        self._rx_queue.put_nowait(chunk)

    def make_reader_writer(self) -> tuple[Any, Any]:
        peer = self

        class _Reader:
            async def read(self, n: int = 4096) -> str:
                _ = n
                if peer.closed and peer._rx_queue.empty():
                    return ""
                return await peer._rx_queue.get()

            async def readline(self) -> str:
                return await self.read(4096)

        class _Writer:
            def write(self, data: str) -> None:
                peer.sent.append(data)
                peer._handler(data, peer)

            async def drain(self) -> None:
                return None

            def close(self) -> None:
                peer.closed = True
                peer._rx_queue.put_nowait("")

            async def wait_closed(self) -> None:
                return None

        return _Reader(), _Writer()


class TestTelnetPosixAndCliModes:
    """Тесты POSIX-маркеров, автоопределения и OOB CLI-режима (профили, пагинация, ошибки)."""

    def test_invalid_shell_mode_or_profile_raises(self) -> None:
        with patch("uniconn.transports._telnet.telnetlib3", MagicMock()):
            with pytest.raises(ConfigurationError, match="Unsupported telnet shell_mode"):
                TelnetTransport(
                    ConnectionConfig(transport="telnet", host="127.0.0.1", options={"shell_mode": "fish"})
                )
            with pytest.raises(ConfigurationError, match="Unsupported telnet profile"):
                TelnetTransport(
                    ConnectionConfig(transport="telnet", host="127.0.0.1", options={"profile": "unknown_os"})
                )

    @pytest.mark.asyncio
    async def test_telnet_auto_detects_posix_and_returns_real_exit_codes(self) -> None:
        """В режиме auto пробник подтверждает POSIX, после чего run() возвращает реальный exit_code."""
        marker_cmd_re = re.compile(r'^(.*);\s*echo\s+"\\n(__UNICONN_[0-9a-f]+__)\$\?"$')

        def _posix_handler(data: str, peer: _DuplexTelnetPeer) -> None:
            cmd_line = data.strip()
            m = marker_cmd_re.match(cmd_line)
            if not m:
                peer.push(f"{cmd_line}\r\n$ ")
                return
            inner, prefix = m.group(1).strip(), m.group(2)
            if inner == ":":
                peer.push(f"user@box:~$ {cmd_line}\r\n\r\n{prefix}0\r\nuser@box:~$ ")
            elif inner == "echo hello":
                peer.push(
                    f"user@box:~$ {cmd_line}\r\n"
                    f"\x1b[32mhello\x1b[0m\r\n"
                    f"line2\r\n"
                    f"\r\n{prefix}0\r\nuser@box:~$ "
                )
            elif inner == "false":
                peer.push(f"{cmd_line}\r\n\r\n{prefix}1\r\n$ ")
            elif inner == "exit 42":
                peer.push(f"{cmd_line}\r\nfailed detail\r\n\r\n{prefix}42\r\n$ ")

        peer = _DuplexTelnetPeer(_posix_handler)
        telnet_mock = MagicMock()
        telnet_mock.open_connection = MagicMock(
            side_effect=lambda **kw: asyncio.sleep(0, result=peer.make_reader_writer())
        )

        cfg = ConnectionConfig(transport="telnet", host="posix-box", timeout=3.0)
        with patch("uniconn.transports._telnet.telnetlib3", telnet_mock):
            transport = TelnetTransport(cfg)
            assert transport.shell_mode == "auto"
            assert transport.resolved_shell_mode is None

            await transport.connect()
            try:
                res_ok = await transport.run("echo hello")
                assert transport.resolved_shell_mode == "posix"
                assert res_ok.exit_code == 0
                assert res_ok.ok is True
                assert res_ok.text == "hello\nline2"

                res_fail = await transport.run("false")
                assert res_fail.exit_code == 1
                assert res_fail.ok is False

                res_42 = await transport.run("exit 42")
                assert res_42.exit_code == 42
                assert res_42.text == "failed detail"
            finally:
                await transport.disconnect()
            # После disconnect в режиме auto состояние сбрасывается
            assert transport.resolved_shell_mode is None

    @pytest.mark.asyncio
    async def test_telnet_auto_fallback_to_cli_cisco_pagination_and_errors(self) -> None:
        """На не-POSIX Cisco CLI auto откатывается в cli, пролистывает --More-- и ловит % Invalid input."""
        page_idx = {"n": 0}

        def _cisco_handler(data: str, peer: _DuplexTelnetPeer) -> None:
            if data == " ":
                page_idx["n"] += 1
                if page_idx["n"] == 1:
                    peer.push("\r        \rinterface Gi0/2\r\n description Uplink\r\n--More--")
                else:
                    peer.push("\r        \rend\r\nCoreSW01# ")
                return

            cmd = data.strip()
            if "__UNICONN_" in cmd:
                # Cisco IOS не понимает POSIX-пробник и отвечает ошибкой синтаксиса + промптом
                peer.push(f"{cmd}\r\n% Invalid input detected at '^' marker.\r\nCoreSW01# ")
            elif cmd == "show running-config":
                page_idx["n"] = 0
                peer.push(
                    "CoreSW01# show running-config\r\n"
                    "interface Gi0/1\r\n"
                    " description Access\r\n"
                    "--More--"
                )
            elif cmd == "show bogus":
                peer.push(
                    "show bogus\r\n"
                    "           ^\r\n"
                    "% Invalid input detected at '^' marker.\r\n"
                    "CoreSW01# "
                )

        peer = _DuplexTelnetPeer(_cisco_handler)
        telnet_mock = MagicMock()
        telnet_mock.open_connection = MagicMock(
            side_effect=lambda **kw: asyncio.sleep(0, result=peer.make_reader_writer())
        )

        cfg = ConnectionConfig(
            transport="telnet",
            host="core-sw01",
            timeout=3.0,
            options={"shell_mode": "auto", "profile": "cisco", "pagination": True},
        )
        with patch("uniconn.transports._telnet.telnetlib3", telnet_mock):
            transport = TelnetTransport(cfg)
            await transport.connect()
            try:
                res = await transport.run("show running-config")
                assert transport.resolved_shell_mode == "cli"
                assert res.exit_code == 0
                assert "--More--" not in res.stdout
                assert "interface Gi0/1" in res.stdout
                assert "interface Gi0/2" in res.stdout
                assert "end" in res.stdout
                assert "CoreSW01#" not in res.stdout
                assert peer.sent.count(" ") == 2

                res_err = await transport.run("show bogus")
                assert res_err.exit_code == 1
                assert res_err.ok is False
                assert "% Invalid input detected" in res_err.stderr

                # stream() также пролистывает --More-- и останавливается на промпте
                streamed: list[str] = []
                async for line in transport.stream("show running-config"):
                    if line.strip():
                        streamed.append(line.strip())
                assert "interface Gi0/1" in streamed
                assert "interface Gi0/2" in streamed
                assert "end" in streamed
                assert all("--More--" not in ln for ln in streamed)
            finally:
                await transport.disconnect()

    @pytest.mark.asyncio
    async def test_telnet_cli_uboot_and_custom_prompt_regex(self) -> None:
        """Явный shell_mode=cli с профилем uboot и кастомным prompt_regex."""

        def _uboot_handler(data: str, peer: _DuplexTelnetPeer) -> None:
            cmd = data.strip()
            if cmd == "printenv":
                peer.push("printenv\r\nbaudrate=115200\r\nbootcmd=run distro_bootcmd\r\n=> ")
            elif cmd == "badcmd":
                peer.push("badcmd\r\nUnknown command 'badcmd' - try 'help'\r\n=> ")

        peer = _DuplexTelnetPeer(_uboot_handler)
        telnet_mock = MagicMock()
        telnet_mock.open_connection = MagicMock(
            side_effect=lambda **kw: asyncio.sleep(0, result=peer.make_reader_writer())
        )

        cfg = ConnectionConfig(
            transport="telnet",
            host="board-console",
            timeout=2.0,
            options={"shell_mode": "cli", "profile": "uboot"},
        )
        with patch("uniconn.transports._telnet.telnetlib3", telnet_mock):
            transport = TelnetTransport(cfg)
            assert transport.resolved_shell_mode == "cli"
            await transport.connect()
            try:
                res = await transport.run("printenv")
                assert res.ok
                assert "baudrate=115200" in res.stdout
                assert "=>" not in res.stdout

                res_bad = await transport.run("badcmd")
                assert res_bad.exit_code == 1
                assert "Unknown command" in res_bad.stderr
            finally:
                await transport.disconnect()

    @pytest.mark.asyncio
    async def test_telnet_with_real_mock_telnet_server_posix_exit_codes(self) -> None:
        """Интеграция обновлённого TelnetTransport с MockTelnetServer (реальные exit_code через auto/posix)."""
        cassette = Cassette(
            transport="telnet",
            host="mock-router",
            capabilities=["exec", "shell"],
            interactions=[
                RecordedShellInteraction(
                    steps=[
                        ShellDialogStep(
                            expect_input="uname -s",
                            response_output="Linux\n",
                            exit_code=0,
                        ),
                        ShellDialogStep(
                            expect_input="systemctl status missing",
                            response_output="Unit missing.service could not be found.\n",
                            exit_code=4,
                        ),
                    ]
                ),
                RecordedExecInteraction(
                    command="id",
                    exit_code=0,
                    stdout="uid=0(root)\n",
                ),
            ],
        )

        async with MockTelnetServer.from_cassette(cassette) as srv:
            async with Connection.from_uri(srv.uri, retry_attempts=1) as conn:
                res1 = await conn.run("uname -s", timeout=5.0)
                assert res1.ok
                assert res1.exit_code == 0
                assert res1.text == "Linux"

                res2 = await conn.run("systemctl status missing", timeout=5.0)
                assert res2.exit_code == 4
                assert res2.ok is False
                assert "could not be found" in res2.text

                res3 = await conn.run("id", timeout=5.0)
                assert res3.ok
                assert res3.text == "uid=0(root)"

    @pytest.mark.asyncio
    async def test_telnet_posix_split_packets_and_following_stream(self) -> None:
        """Разбитый на пакеты промпт в POSIX-режиме не протекает в stdout и не ломает последующий stream()."""
        marker_cmd_re = re.compile(r'^(.*);\s*echo\s+"\\n(__UNICONN_[0-9a-f]+__)\$\?"$')

        def _split_posix_handler(data: str, peer: _DuplexTelnetPeer) -> None:
            cmd_line = data.strip()
            m = marker_cmd_re.match(cmd_line)
            if m:
                inner, prefix = m.group(1).strip(), m.group(2)
                if inner == ":":
                    peer.push(f"{cmd_line}\r\n\r\n{prefix}0")
                    peer.push("\r\nuser@box:~$ ")
                elif inner == "echo first":
                    peer.push(f"{cmd_line}\r\nfirst-out\r\n\r\n{prefix}0")
                    peer.push("\r\nuser@box:~$ ")
                elif inner == "echo second":
                    peer.push(f"{cmd_line}\r\nsecond-out\r\n\r\n{prefix}0\r\nuser@box:~$ ")
                return
            if cmd_line == "tail -n 2 app.log":
                peer.push("tail -n 2 app.log\r\nlog-1\r\nlog-2\r\nuser@box:~$ ")

        peer = _DuplexTelnetPeer(_split_posix_handler)
        telnet_mock = MagicMock()
        telnet_mock.open_connection = MagicMock(
            side_effect=lambda **kw: asyncio.sleep(0, result=peer.make_reader_writer())
        )

        cfg = ConnectionConfig(transport="telnet", host="split-posix", timeout=3.0)
        with patch("uniconn.transports._telnet.telnetlib3", telnet_mock):
            transport = TelnetTransport(cfg)
            await transport.connect()
            try:
                r1 = await transport.run("echo first")
                assert r1.ok
                assert r1.text == "first-out"

                r2 = await transport.run("echo second")
                assert r2.ok
                assert r2.text == "second-out"

                # Следующий stream() не должен завершиться раньше времени из-за idle-промпта
                streamed = [line async for line in transport.stream("tail -n 2 app.log")]
                assert streamed == ["log-1", "log-2"]
            finally:
                await transport.disconnect()

    @pytest.mark.asyncio
    async def test_telnet_cli_split_pager_cr_overwrite_and_embedded_prompt_chars(self) -> None:
        """Разбитый --More--, перезапись \\r и строки с '>'/'#' внутри вывода не обрывают CLI-команду."""
        page_idx = {"n": 0}

        def _edge_cisco_handler(data: str, peer: _DuplexTelnetPeer) -> None:
            if data == " ":
                page_idx["n"] += 1
                peer.push("\r        \rinterface Gi0/2\r\n# trailing comment\r\nCoreSW01# ")
                return
            cmd = data.strip()
            if cmd == "show xml":
                page_idx["n"] = 0
                peer.push("CoreSW01# show xml\r\n<config>\r\n# header\r\ninterface Gi0/1\r\n--Mo")
                peer.push("re--")

        peer = _DuplexTelnetPeer(_edge_cisco_handler)
        telnet_mock = MagicMock()
        telnet_mock.open_connection = MagicMock(
            side_effect=lambda **kw: asyncio.sleep(0, result=peer.make_reader_writer())
        )

        cfg = ConnectionConfig(
            transport="telnet",
            host="edge-sw01",
            timeout=3.0,
            options={"shell_mode": "cli", "profile": "cisco", "pagination": True},
        )
        with patch("uniconn.transports._telnet.telnetlib3", telnet_mock):
            transport = TelnetTransport(cfg)
            await transport.connect()
            try:
                res = await transport.run("show xml")
                assert res.ok
                assert res.stdout == "<config>\n# header\ninterface Gi0/1\ninterface Gi0/2\n# trailing comment"
                assert "\n\n" not in res.stdout
                assert peer.sent.count(" ") == 1
            finally:
                await transport.disconnect()
