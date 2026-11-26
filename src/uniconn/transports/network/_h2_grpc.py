# src/uniconn/transports/network/_h2_grpc.py
"""Асинхронный HTTP/2 gRPC клиент и сервер поверх ``h2`` / ``jh2`` для OpenConfig gNMI."""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import ssl
import struct
import time
from collections import deque
from collections.abc import Awaitable, Callable, Iterable, Mapping
from typing import Any
from urllib.parse import quote, unquote

from ..._logging import get_logger
from ...exceptions import (
    AuthenticationError,
    ExecutionError,
)
from ...exceptions import (
    ConnectionError as UniconnConnectionError,
)
from ...exceptions import (
    TimeoutError as UniconnTimeoutError,
)
from .gnmi_proto import pack_grpc_frame

_logger = get_logger("uniconn.transports.network._h2_grpc")

_H2_CANDIDATE_PACKAGES = ("h2", "jh2")


def _resolve_h2_modules() -> tuple[Any, Any, Any]:
    """Лениво загрузить совместимую библиотеку HTTP/2 (``h2`` или ``jh2``)."""
    for pkg in _H2_CANDIDATE_PACKAGES:
        try:
            config_mod = importlib.import_module(f"{pkg}.config")
            conn_mod = importlib.import_module(f"{pkg}.connection")
            events_mod = importlib.import_module(f"{pkg}.events")
            return config_mod, conn_mod, events_mod
        except ImportError:
            continue
    raise ImportError(
        "HTTP/2 library (h2 or jh2) not installed. "
        "Run: pip install uniconn[gnmi]"
    )


def _decode_header_item(raw_key: Any, raw_val: Any) -> tuple[str, str]:
    key = (
        bytes(raw_key).decode("latin-1")
        if isinstance(raw_key, bytes | bytearray)
        else str(raw_key)
    ).lower()
    val = (
        bytes(raw_val).decode("utf-8", errors="replace")
        if isinstance(raw_val, bytes | bytearray)
        else str(raw_val)
    )
    return key, val


def _headers_to_dict(raw_headers: Iterable[tuple[Any, Any]] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    if not raw_headers:
        return out
    for raw_k, raw_v in raw_headers:
        k, v = _decode_header_item(raw_k, raw_v)
        out[k] = v
    return out


class _GrpcFrameBuffer:
    """Инкрементальный O(1) буфер 5-байтовых gRPC Length-Prefixed кадров."""

    def __init__(self) -> None:
        self._buf = bytearray()
        self._ready: deque[bytes] = deque()

    def feed(self, chunk: bytes) -> None:
        """Добавить сырой кусок HTTP/2 DATA и извлечь завершённые gRPC-кадры."""
        if not chunk:
            return
        self._buf.extend(chunk)
        while len(self._buf) >= 5:
            compressed, msg_len = struct.unpack(">BI", self._buf[:5])
            if compressed not in (0, 1):
                raise ExecutionError(
                    f"Invalid gRPC compression flag: {compressed}",
                    command="gnmi.grpc",
                    exit_code=1,
                )
            if compressed == 1:
                raise ExecutionError(
                    "Compressed gRPC frames are not supported (expected grpc-encoding=identity)",
                    command="gnmi.grpc",
                    exit_code=12,
                )
            if len(self._buf) < 5 + msg_len:
                break
            payload = bytes(self._buf[5 : 5 + msg_len])
            del self._buf[: 5 + msg_len]
            self._ready.append(payload)

    def pop_frame(self) -> bytes | None:
        """Вернуть следующий готовый Protobuf-кадр, если он уже буферизован."""
        return self._ready.popleft() if self._ready else None

    @property
    def trailing_bytes(self) -> int:
        """Количество неполных хвостовых байт в незавершённом gRPC-кадре."""
        return len(self._buf)


def grpc_status_to_exception(
    status_code: int,
    grpc_message: str,
    *,
    command: str,
    host: str | None = None,
) -> Exception:
    """Преобразовать код состояния gRPC в соответствующее исключение ``uniconn``."""
    msg = unquote(grpc_message) if grpc_message else ""
    if status_code in (16, 7):
        return AuthenticationError(
            msg or f"gNMI authentication/permission denied (grpc-status={status_code})",
            host=host,
        )
    if status_code == 4:
        return UniconnTimeoutError(
            msg or f"gNMI call deadline exceeded ({command})",
            command=command,
            host=host,
        )
    return ExecutionError(
        msg or f"{command} failed with grpc-status={status_code}",
        command=command,
        exit_code=status_code,
        stderr=msg,
        host=host,
    )


async def _send_h2_data_chunks(
    *,
    h2_conn: Any,
    writer: asyncio.StreamWriter,
    write_lock: asyncio.Lock,
    is_closed: Callable[[], bool],
    stream_id: int,
    data: bytes,
    end_stream: bool,
    wait_window: Callable[[], Awaitable[None]],
    on_closed: Callable[[], Exception | None],
) -> None:
    """Отправить HTTP/2 DATA-кадры по частям с учётом flow-control окна и ``max_outbound_frame_size``."""
    offset = 0
    total = len(data)
    while offset < total or (total == 0 and end_stream):
        if is_closed():
            err = on_closed()
            if err is not None:
                raise err
            return

        if total == 0:
            async with write_lock:
                if is_closed():
                    err = on_closed()
                    if err is not None:
                        raise err
                    return
                h2_conn.send_data(stream_id, b"", end_stream=end_stream)
                out = h2_conn.data_to_send()
                if out:
                    writer.write(out)
                    await writer.drain()
            return

        window = int(h2_conn.local_flow_control_window(stream_id))
        if window <= 0:
            await wait_window()
            continue

        max_frame = int(getattr(h2_conn, "max_outbound_frame_size", 16384) or 16384)
        chunk_end = min(total, offset + min(window, max_frame))
        chunk = data[offset:chunk_end]
        is_last = end_stream and chunk_end == total
        async with write_lock:
            if is_closed():
                err = on_closed()
                if err is not None:
                    raise err
                return
            h2_conn.send_data(stream_id, chunk, end_stream=is_last)
            out = h2_conn.data_to_send()
            if out:
                writer.write(out)
                await writer.drain()
        offset = chunk_end
        if chunk_end == total:
            return


class _ClientStreamChannel:
    """Внутреннее состояние одного мультиплексированного клиентского HTTP/2 потока."""

    def __init__(self, stream_id: int, owner: AsyncGrpcHttp2Client) -> None:
        self.stream_id = stream_id
        self._owner = owner
        self.events: asyncio.Queue[tuple[str, Any]] = asyncio.Queue()
        self.window_event = asyncio.Event()
        self.window_event.set()
        self.send_closed = False
        self.recv_closed = False
        self._frame_buf = _GrpcFrameBuffer()
        self.response_headers: dict[str, str] = {}
        self.trailers: dict[str, str] = {}

    async def send_message(self, payload: bytes, *, end_stream: bool = False) -> None:
        """Отправить одиночное Protobuf-сообщение в виде 5-байтового gRPC-фрейма."""
        framed = pack_grpc_frame(payload)
        await self._owner._send_stream_bytes(self.stream_id, framed, end_stream=end_stream)
        if end_stream:
            self.send_closed = True

    async def close_send(self) -> None:
        """Закрыть исходящую сторону потока (half-close END_STREAM)."""
        if not self.send_closed:
            await self._owner._end_stream(self.stream_id)
            self.send_closed = True

    async def cancel(self) -> None:
        """Сбросить поток при отмене или раннем завершении чтения."""
        if not self.recv_closed or not self.send_closed:
            self.recv_closed = True
            self.send_closed = True
            await self._owner._reset_stream(self.stream_id)

    def _validate_http_status(self, headers: Mapping[str, str], command: str) -> None:
        status_raw = headers.get(":status")
        if not status_raw:
            return
        try:
            http_status = int(status_raw)
        except ValueError:
            return
        if http_status in (401, 403):
            raise AuthenticationError(
                f"gNMI HTTP {http_status} authentication failed",
                host=self._owner.host,
            )
        if http_status != 200:
            raise ExecutionError(
                f"Unexpected HTTP {http_status} status for gRPC endpoint {command}",
                command=command,
                exit_code=http_status,
                host=self._owner.host,
            )

    def _check_trailers(self, command: str) -> None:
        raw_status = self.trailers.get("grpc-status") or self.response_headers.get("grpc-status")
        if raw_status is None:
            if not self.response_headers:
                raise UniconnConnectionError(
                    f"gRPC stream ended before receiving response headers for {command}",
                    host=self._owner.host,
                )
            raise ExecutionError(
                f"gRPC stream ended without grpc-status trailer for {command}",
                command=command,
                exit_code=13,
                host=self._owner.host,
            )
        try:
            code = int(raw_status)
        except ValueError:
            code = 2
        if code != 0:
            msg = self.trailers.get("grpc-message") or self.response_headers.get("grpc-message") or ""
            raise grpc_status_to_exception(code, msg, command=command, host=self._owner.host)

    async def read_frame(self, *, command: str, timeout: float | None = None) -> bytes | None:
        """Прочитать очередное Protobuf-сообщение или вернуть ``None`` по завершении потока."""
        queued = self._frame_buf.pop_frame()
        if queued is not None:
            return queued

        deadline = (time.monotonic() + timeout) if (timeout is not None and timeout > 0) else None
        while True:
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise UniconnTimeoutError(
                        f"gNMI {command} timed out waiting for gRPC response",
                        command=command,
                        host=self._owner.host,
                    )
                try:
                    kind, val = await asyncio.wait_for(self.events.get(), timeout=remaining)
                except TimeoutError as exc:
                    raise UniconnTimeoutError(
                        f"gNMI {command} timed out waiting for gRPC response",
                        command=command,
                        host=self._owner.host,
                    ) from exc
            else:
                kind, val = await self.events.get()

            if kind == "headers":
                self.response_headers.update(val)
                self._validate_http_status(self.response_headers, command)
            elif kind == "data":
                self._frame_buf.feed(val)
                ready = self._frame_buf.pop_frame()
                if ready is not None:
                    return ready
            elif kind == "trailers":
                self.trailers.update(val)
            elif kind == "error":
                raise val
            elif kind == "end":
                if self._frame_buf.trailing_bytes:
                    raise ExecutionError(
                        f"Truncated gRPC payload ({self._frame_buf.trailing_bytes} trailing bytes) for {command}",
                        command=command,
                        exit_code=13,
                        host=self._owner.host,
                    )
                self._check_trailers(command)
                return None

    async def wait_end(self, *, command: str, timeout: float | None = None) -> None:
        """Дождаться завершения потока и проверить ``grpc-status`` в trailers."""
        while True:
            frame = await self.read_frame(command=command, timeout=timeout)
            if frame is None:
                return


class AsyncGrpcHttp2Client:
    """Мультиплексированный HTTP/2 gRPC-клиент поверх ``asyncio`` и ``h2`` / ``jh2``."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        ssl_context: ssl.SSLContext | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.host = host
        self.port = port
        self.ssl_context = ssl_context
        self.timeout = timeout

        self._config_mod: Any = None
        self._conn_mod: Any = None
        self._events_mod: Any = None
        self._h2: Any = None
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._write_lock = asyncio.Lock()
        self._streams: dict[int, _ClientStreamChannel] = {}
        self._conn_window_event = asyncio.Event()
        self._conn_window_event.set()
        self._recv_task: asyncio.Task[None] | None = None
        self._closed = False

    @property
    def is_connected(self) -> bool:
        """Открыто ли HTTP/2 соединение и запущен ли цикл приёма."""
        return (
            not self._closed
            and self._h2 is not None
            and self._writer is not None
            and self._recv_task is not None
            and not self._recv_task.done()
        )

    @staticmethod
    def ensure_dependency() -> tuple[Any, Any, Any]:
        """Убедиться, что библиотека ``h2`` или ``jh2`` доступна."""
        return _resolve_h2_modules()

    async def connect(self) -> None:
        """Открыть TCP/TLS соединение и выполнить HTTP/2 handshake."""
        if self.is_connected:
            return
        self._config_mod, self._conn_mod, self._events_mod = _resolve_h2_modules()
        self._closed = False

        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port, ssl=self.ssl_context),
                timeout=self.timeout,
            )
        except TimeoutError as exc:
            raise UniconnTimeoutError(
                f"gNMI HTTP/2 connection to {self.host}:{self.port} timed out after {self.timeout}s",
                host=self.host,
            ) from exc
        except Exception as exc:
            raise UniconnConnectionError(
                f"Failed to connect HTTP/2 gNMI endpoint {self.host}:{self.port}: {exc}",
                host=self.host,
            ) from exc

        cfg = self._config_mod.H2Configuration(client_side=True, header_encoding="utf-8")
        self._h2 = self._conn_mod.H2Connection(config=cfg)
        self._h2.initiate_connection()
        await self._flush_pending()
        self._recv_task = asyncio.create_task(
            self._recv_loop(),
            name=f"uniconn-gnmi-h2-{self.host}:{self.port}",
        )

    async def _flush_pending(self) -> None:
        if self._h2 is None or self._writer is None or self._closed:
            return
        async with self._write_lock:
            if self._h2 is None or self._writer is None or self._closed:
                return
            out = self._h2.data_to_send()
            if out:
                self._writer.write(out)
                await self._writer.drain()

    async def _send_stream_bytes(
        self,
        stream_id: int,
        data: bytes,
        *,
        end_stream: bool = False,
    ) -> None:
        if self._closed or self._h2 is None or self._writer is None:
            raise UniconnConnectionError("HTTP/2 gRPC connection is closed", host=self.host)

        async def _wait_window() -> None:
            stream = self._streams.get(stream_id)
            if stream is not None:
                stream.window_event.clear()
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(stream.window_event.wait(), timeout=0.02)
            else:
                self._conn_window_event.clear()
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self._conn_window_event.wait(), timeout=0.02)

        await _send_h2_data_chunks(
            h2_conn=self._h2,
            writer=self._writer,
            write_lock=self._write_lock,
            is_closed=lambda: self._closed or self._h2 is None or self._writer is None,
            stream_id=stream_id,
            data=data,
            end_stream=end_stream,
            wait_window=_wait_window,
            on_closed=lambda: UniconnConnectionError("HTTP/2 gRPC connection is closed", host=self.host),
        )

    async def _end_stream(self, stream_id: int) -> None:
        if self._closed or self._h2 is None:
            return
        async with self._write_lock:
            if self._h2 is None or self._writer is None or self._closed:
                return
            with contextlib.suppress(Exception):
                self._h2.end_stream(stream_id)
                out = self._h2.data_to_send()
                if out:
                    self._writer.write(out)
                    await self._writer.drain()

    async def _reset_stream(self, stream_id: int) -> None:
        if self._closed or self._h2 is None:
            return
        self._streams.pop(stream_id, None)
        async with self._write_lock:
            if self._h2 is None or self._writer is None or self._closed:
                return
            with contextlib.suppress(Exception):
                self._h2.reset_stream(stream_id)
                out = self._h2.data_to_send()
                if out:
                    self._writer.write(out)
                    await self._writer.drain()

    async def _recv_loop(self) -> None:
        ev_mod = self._events_mod
        reader = self._reader
        if reader is None or self._h2 is None:
            return

        try:
            while not self._closed:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                events = self._h2.receive_data(chunk)
                for ev in events:
                    if isinstance(ev, ev_mod.ResponseReceived):
                        stream = self._streams.get(ev.stream_id)
                        if stream is not None:
                            hdrs = _headers_to_dict(ev.headers)
                            stream.events.put_nowait(("headers", hdrs))
                            if getattr(ev, "stream_ended", None) is not None:
                                stream.events.put_nowait(("trailers", hdrs))
                    elif isinstance(ev, ev_mod.DataReceived):
                        fcl = int(getattr(ev, "flow_controlled_length", 0) or 0)
                        if fcl > 0:
                            self._h2.acknowledge_received_data(fcl, ev.stream_id)
                        stream = self._streams.get(ev.stream_id)
                        if stream is not None and ev.data:
                            stream.events.put_nowait(("data", bytes(ev.data)))
                    elif isinstance(ev, ev_mod.TrailersReceived):
                        stream = self._streams.get(ev.stream_id)
                        if stream is not None:
                            stream.events.put_nowait(("trailers", _headers_to_dict(ev.headers)))
                    elif isinstance(ev, ev_mod.StreamEnded):
                        stream = self._streams.pop(ev.stream_id, None)
                        if stream is not None:
                            stream.recv_closed = True
                            stream.events.put_nowait(("end", None))
                    elif isinstance(ev, ev_mod.StreamReset):
                        stream = self._streams.pop(ev.stream_id, None)
                        if stream is not None:
                            stream.recv_closed = True
                            code = int(getattr(ev, "error_code", 1) or 1)
                            stream.events.put_nowait(
                                (
                                    "error",
                                    ExecutionError(
                                        f"HTTP/2 stream {ev.stream_id} reset (error_code={code})",
                                        command="gnmi.http2",
                                        exit_code=code,
                                        host=self.host,
                                    ),
                                )
                            )
                    elif isinstance(ev, ev_mod.WindowUpdated):
                        self._conn_window_event.set()
                        if ev.stream_id == 0:
                            for s in self._streams.values():
                                s.window_event.set()
                        else:
                            stream = self._streams.get(ev.stream_id)
                            if stream is not None:
                                stream.window_event.set()
                    elif isinstance(ev, ev_mod.ConnectionTerminated):
                        err_code = int(getattr(ev, "error_code", 0) or 0)
                        self._fail_all_streams(
                            UniconnConnectionError(
                                f"gNMI HTTP/2 connection terminated (error_code={err_code})",
                                host=self.host,
                            )
                        )
                        return

                await self._flush_pending()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._fail_all_streams(
                UniconnConnectionError(
                    f"gNMI HTTP/2 connection lost: {exc}",
                    host=self.host,
                )
            )
            return
        self._fail_all_streams(
            UniconnConnectionError("gNMI HTTP/2 connection closed by peer", host=self.host)
        )

    def _fail_all_streams(self, exc: Exception) -> None:
        while self._streams:
            _sid, stream = self._streams.popitem()
            stream.recv_closed = True
            stream.window_event.set()
            stream.events.put_nowait(("error", exc))
        self._conn_window_event.set()

    def _build_grpc_headers(
        self,
        path: str,
        *,
        metadata: Mapping[str, str] | None = None,
    ) -> list[tuple[str, str]]:
        scheme = "https" if self.ssl_context is not None else "http"
        authority = f"[{self.host}]:{self.port}" if ":" in self.host else f"{self.host}:{self.port}"
        hdrs: list[tuple[str, str]] = [
            (":method", "POST"),
            (":path", path),
            (":authority", authority),
            (":scheme", scheme),
            ("content-type", "application/grpc"),
            ("te", "trailers"),
            ("grpc-encoding", "identity"),
            ("user-agent", "uniconn-gnmi/1.0"),
        ]
        if metadata:
            for k, v in metadata.items():
                if v is not None and str(v) != "":
                    hdrs.append((str(k).lower(), str(v)))
        return hdrs

    async def open_stream(
        self,
        path: str,
        *,
        initial_payload: bytes | None = None,
        metadata: Mapping[str, str] | None = None,
        end_stream: bool = False,
    ) -> _ClientStreamChannel:
        """Открыть новый мультиплексированный HTTP/2 gRPC поток."""
        if not self.is_connected:
            await self.connect()

        if self._h2 is None:
            raise UniconnConnectionError("HTTP/2 client not initialized", host=self.host)

        hdrs = self._build_grpc_headers(path, metadata=metadata)
        async with self._write_lock:
            if self._h2 is None or self._writer is None or self._closed:
                raise UniconnConnectionError("HTTP/2 gRPC connection is closed", host=self.host)
            stream_id = int(self._h2.get_next_available_stream_id())
            stream = _ClientStreamChannel(stream_id, self)
            self._streams[stream_id] = stream
            headers_only_end = end_stream and initial_payload is None
            self._h2.send_headers(stream_id, hdrs, end_stream=headers_only_end)
            out = self._h2.data_to_send()
            if out:
                self._writer.write(out)
                await self._writer.drain()

        if initial_payload is not None:
            await stream.send_message(initial_payload, end_stream=end_stream)
        elif headers_only_end:
            stream.send_closed = True
        return stream

    async def unary_call(
        self,
        path: str,
        payload: bytes,
        *,
        metadata: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> bytes:
        """Выполнить унарный HTTP/2 gRPC вызов и вернуть декодированный Protobuf-ответ."""
        eff_timeout = timeout if timeout is not None else self.timeout
        stream = await self.open_stream(
            path,
            initial_payload=payload,
            metadata=metadata,
            end_stream=True,
        )
        command_name = path.rsplit("/", 1)[-1]
        resp = await stream.read_frame(command=f"gnmi.{command_name}", timeout=eff_timeout)
        if resp is None:
            return b""
        await stream.wait_end(command=f"gnmi.{command_name}", timeout=eff_timeout)
        return resp

    async def close(self) -> None:
        """Корректно завершить HTTP/2 соединение и остановить фоновый цикл приёма."""
        self._closed = True
        if self._recv_task is not None and not self._recv_task.done():
            self._recv_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._recv_task
        self._recv_task = None

        if self._h2 is not None and self._writer is not None:
            with contextlib.suppress(Exception):
                self._h2.close_connection()
                out = self._h2.data_to_send()
                if out:
                    self._writer.write(out)
                    await self._writer.drain()

        if self._writer is not None:
            with contextlib.suppress(Exception):
                self._writer.close()
                await self._writer.wait_closed()

        self._h2 = None
        self._reader = None
        self._writer = None
        self._fail_all_streams(
            UniconnConnectionError("HTTP/2 gRPC client closed", host=self.host)
        )


class GrpcServerStream:
    """Серверный HTTP/2 gRPC поток для обработки входящих RPC в ``MockGnmiServer``."""

    def __init__(
        self,
        stream_id: int,
        headers: dict[str, str],
        session: _GrpcServerSession,
    ) -> None:
        self.stream_id = stream_id
        self.headers = headers
        self.path = headers.get(":path", "")
        self._session = session
        self._rx_queue: asyncio.Queue[tuple[str, Any]] = asyncio.Queue()
        self._frame_buf = _GrpcFrameBuffer()
        self.window_event = asyncio.Event()
        self.window_event.set()
        self.headers_sent = False
        self.finished = False

    async def read_frame(self, *, timeout: float = 30.0) -> bytes | None:
        """Прочитать очередной 5-байтовый gRPC Protobuf-кадр от клиента."""
        queued = self._frame_buf.pop_frame()
        if queued is not None:
            return queued

        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                kind, val = await asyncio.wait_for(self._rx_queue.get(), timeout=remaining)
            except TimeoutError:
                return None
            if kind == "data":
                self._frame_buf.feed(val)
                ready = self._frame_buf.pop_frame()
                if ready is not None:
                    return ready
            elif kind == "end":
                if self._frame_buf.trailing_bytes:
                    raise ExecutionError(
                        f"Truncated client gRPC payload ({self._frame_buf.trailing_bytes} trailing bytes)",
                        command=self.path or "gnmi.server",
                        exit_code=13,
                    )
                return None

    async def send_frame(self, payload: bytes) -> None:
        """Отправить gRPC DATA-кадр клиенту (автоматически открывая заголовки 200 OK)."""
        if self.finished:
            return
        if not self.headers_sent:
            await self._session._send_response_headers(self.stream_id)
            self.headers_sent = True
        await self._session._send_response_data(self.stream_id, pack_grpc_frame(payload))

    async def finish(
        self,
        *,
        grpc_status: int = 0,
        grpc_message: str = "",
    ) -> None:
        """Завершить серверный поток с отправкой gRPC trailers (в т.ч. Trailers-Only)."""
        if self.finished:
            return
        self.finished = True
        trailers: list[tuple[str, str]] = [("grpc-status", str(grpc_status))]
        if grpc_message:
            trailers.append(("grpc-message", quote(grpc_message)))
        if not self.headers_sent:
            initial_hdrs = [
                (":status", "200"),
                ("content-type", "application/grpc"),
                *trailers,
            ]
            await self._session._send_headers(self.stream_id, initial_hdrs, end_stream=True)
            self.headers_sent = True
            return
        await self._session._send_headers(self.stream_id, trailers, end_stream=True)


class _GrpcServerSession:
    """Сокетный обработчик серверного HTTP/2 соединения для ``MockGnmiServer``."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        handler: Callable[[GrpcServerStream], Awaitable[None]],
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._handler = handler
        config_mod, conn_mod, events_mod = _resolve_h2_modules()
        self._events_mod = events_mod
        cfg = config_mod.H2Configuration(client_side=False, header_encoding="utf-8")
        self._h2 = conn_mod.H2Connection(config=cfg)
        self._write_lock = asyncio.Lock()
        self._conn_window_event = asyncio.Event()
        self._conn_window_event.set()
        self._streams: dict[int, GrpcServerStream] = {}
        self._tasks: set[asyncio.Task[None]] = set()
        self._closed = False

    async def _flush(self) -> None:
        if self._closed:
            return
        out = self._h2.data_to_send()
        if out:
            self._writer.write(out)
            await self._writer.drain()

    async def _send_headers(
        self,
        stream_id: int,
        headers: list[tuple[str, str]],
        *,
        end_stream: bool = False,
    ) -> None:
        if self._closed:
            return
        async with self._write_lock:
            if self._closed:
                return
            with contextlib.suppress(Exception):
                self._h2.send_headers(stream_id, headers, end_stream=end_stream)
                await self._flush()

    async def _send_response_headers(self, stream_id: int) -> None:
        await self._send_headers(
            stream_id,
            [(":status", "200"), ("content-type", "application/grpc")],
            end_stream=False,
        )

    async def _send_response_data(self, stream_id: int, data: bytes) -> None:
        if self._closed:
            return

        async def _wait_window() -> None:
            stream = self._streams.get(stream_id)
            if stream is not None:
                stream.window_event.clear()
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(stream.window_event.wait(), timeout=0.02)
            else:
                self._conn_window_event.clear()
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self._conn_window_event.wait(), timeout=0.02)

        with contextlib.suppress(Exception):
            await _send_h2_data_chunks(
                h2_conn=self._h2,
                writer=self._writer,
                write_lock=self._write_lock,
                is_closed=lambda: self._closed,
                stream_id=stream_id,
                data=data,
                end_stream=False,
                wait_window=_wait_window,
                on_closed=lambda: None,
            )

    async def serve(self) -> None:
        """Запустить цикл обработки HTTP/2 кадров до закрытия соединения."""
        ev_mod = self._events_mod
        self._h2.initiate_connection()
        async with self._write_lock:
            await self._flush()

        try:
            while not self._closed:
                chunk = await self._reader.read(65536)
                if not chunk:
                    break
                events = self._h2.receive_data(chunk)
                for ev in events:
                    if isinstance(ev, ev_mod.RequestReceived):
                        hdrs = _headers_to_dict(ev.headers)
                        stream = GrpcServerStream(ev.stream_id, hdrs, self)
                        self._streams[ev.stream_id] = stream
                        task = asyncio.create_task(self._run_stream_handler(stream))
                        self._tasks.add(task)
                        task.add_done_callback(self._tasks.discard)
                        if getattr(ev, "stream_ended", None) is not None:
                            stream._rx_queue.put_nowait(("end", None))
                    elif isinstance(ev, ev_mod.DataReceived):
                        fcl = int(getattr(ev, "flow_controlled_length", 0) or 0)
                        if fcl > 0:
                            self._h2.acknowledge_received_data(fcl, ev.stream_id)
                        stream = self._streams.get(ev.stream_id)
                        if stream is not None and ev.data:
                            stream._rx_queue.put_nowait(("data", bytes(ev.data)))
                    elif isinstance(ev, ev_mod.StreamEnded):
                        stream = self._streams.get(ev.stream_id)
                        if stream is not None:
                            stream._rx_queue.put_nowait(("end", None))
                    elif isinstance(ev, ev_mod.StreamReset):
                        stream = self._streams.pop(ev.stream_id, None)
                        if stream is not None:
                            stream.finished = True
                            stream.window_event.set()
                            stream._rx_queue.put_nowait(("end", None))
                    elif isinstance(ev, ev_mod.WindowUpdated):
                        self._conn_window_event.set()
                        if ev.stream_id == 0:
                            for s in self._streams.values():
                                s.window_event.set()
                        else:
                            stream = self._streams.get(ev.stream_id)
                            if stream is not None:
                                stream.window_event.set()
                    elif isinstance(ev, ev_mod.ConnectionTerminated):
                        return

                async with self._write_lock:
                    await self._flush()
        except (ConnectionResetError, BrokenPipeError, EOFError):
            pass
        except Exception as exc:
            _logger.debug("Mock HTTP/2 gRPC session terminated with error: %s", exc)
        finally:
            self._closed = True
            self._conn_window_event.set()
            for stream in self._streams.values():
                stream.window_event.set()
            for task in list(self._tasks):
                task.cancel()
            with contextlib.suppress(Exception):
                self._writer.close()
                await self._writer.wait_closed()

    async def _run_stream_handler(self, stream: GrpcServerStream) -> None:
        try:
            await self._handler(stream)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            await stream.finish(grpc_status=13, grpc_message=str(exc))
        finally:
            if not stream.finished:
                await stream.finish(grpc_status=0)
            self._streams.pop(stream.stream_id, None)


async def serve_grpc_http2_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    handler: Callable[[GrpcServerStream], Awaitable[None]],
) -> None:
    """Обслужить одно входящее HTTP/2 gRPC соединение на стороне сервера."""
    session = _GrpcServerSession(reader, writer, handler)
    await session.serve()


__all__ = [
    "AsyncGrpcHttp2Client",
    "GrpcServerStream",
    "grpc_status_to_exception",
    "serve_grpc_http2_client",
]
