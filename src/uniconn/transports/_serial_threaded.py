# src/uniconn/transports/_serial_threaded.py
"""Потоковый (thread-backed) async-адаптер поверх ``pyserial.Serial``.

Используется в ``SerialTransport`` на Windows (где дефолтный ``ProactorEventLoop``
несовместим с ``pyserial-asyncio``) и при явном выборе ``?io_backend=threaded``.
"""

from __future__ import annotations

import asyncio
import contextlib
import queue
import sys
import threading
import time
from collections.abc import Callable, Iterable
from typing import Any

from ..exceptions import ConfigurationError

_DEFAULT_POLL_INTERVAL = 0.05
_SUPPORTED_IO_BACKENDS = ("auto", "threaded", "asyncio")


def should_use_threaded_serial(
    io_backend: str = "auto",
    loop: asyncio.AbstractEventLoop | None = None,
) -> bool:
    """Определить, следует ли использовать thread-backed адаптер вместо ``pyserial-asyncio``."""
    mode = (io_backend or "auto").strip().lower()
    if mode not in _SUPPORTED_IO_BACKENDS:
        raise ConfigurationError(
            f"Unsupported serial io_backend {io_backend!r}. "
            f"Supported: {', '.join(_SUPPORTED_IO_BACKENDS)}"
        )
    if mode == "threaded":
        return True
    if mode == "asyncio":
        return False
    if sys.platform == "win32":
        return True
    return loop is not None and "proactor" in type(loop).__name__.lower()


class _ThreadedSerialTransportView:
    """Лёгкая обёртка ``writer.transport`` для совместимости с ``SerialTransport.serial_instance``."""

    def __init__(self, serial_obj: Any, writer: ThreadedSerialWriter) -> None:
        self.serial = serial_obj
        self._serial = serial_obj
        self._writer = writer

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        if name in ("serial", "serial_instance"):
            return self.serial
        if name == "io_backend":
            return "threaded"
        return default

    def is_closing(self) -> bool:
        return self._writer.is_closing()

    def close(self) -> None:
        self._writer.close()


class ThreadedSerialWriter:
    """Асинхронный StreamWriter-совместимый адаптер поверх синхронного ``serial.Serial``.

    Запись выполняется через выделенный фоновый TX-поток в строгом FIFO-порядке,
    а чтение — через фоновый RX-поток, подающий байты в ``asyncio.StreamReader``
    через ``loop.call_soon_threadsafe(...)``.
    """

    def __init__(
        self,
        serial_obj: Any,
        reader: asyncio.StreamReader,
        loop: asyncio.AbstractEventLoop,
        *,
        read_chunk_size: int = 4096,
    ) -> None:
        self._serial = serial_obj
        self._reader = reader
        self._loop = loop
        self._read_chunk_size = max(1, int(read_chunk_size))
        self._transport = _ThreadedSerialTransportView(serial_obj, self)

        self._stop_event = threading.Event()
        self._tx_queue: queue.SimpleQueue[tuple[bytes, asyncio.Future[None] | None] | None] = (
            queue.SimpleQueue()
        )
        self._tx_error: Exception | None = None
        self._tx_error_lock = threading.Lock()
        self._closing = False
        self._closed = False
        self._close_lock = threading.Lock()

        self._rx_thread = threading.Thread(
            target=self._rx_loop,
            name=f"uniconn-serial-rx-{getattr(serial_obj, 'port', 'port')}",
            daemon=True,
        )
        self._tx_thread = threading.Thread(
            target=self._tx_loop,
            name=f"uniconn-serial-tx-{getattr(serial_obj, 'port', 'port')}",
            daemon=True,
        )
        self._rx_thread.start()
        self._tx_thread.start()

    @property
    def transport(self) -> _ThreadedSerialTransportView:
        """Совместимый объект ``transport`` с атрибутом ``.serial``."""
        return self._transport

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        """Получить дополнительные атрибуты транспорта (включая ``'serial'``)."""
        return self._transport.get_extra_info(name, default)

    def is_closing(self) -> bool:
        """Проверить, закрывается ли или уже закрыт writer."""
        return self._closing or self._closed

    def flush_input(self) -> None:
        """Сбросить аппаратный входной буфер порта и уже накопленные байты в ``StreamReader``."""
        if hasattr(self._serial, "reset_input_buffer"):
            with contextlib.suppress(Exception):
                self._serial.reset_input_buffer()
        buf = getattr(self._reader, "_buffer", None)
        if isinstance(buf, bytearray):
            buf.clear()

    def _safe_call_soon(self, callback: Callable[..., Any], *args: Any) -> None:
        if not self._loop.is_closed():
            with contextlib.suppress(RuntimeError):
                self._loop.call_soon_threadsafe(callback, *args)

    def _resolve_future(
        self,
        fut: asyncio.Future[None] | None,
        exc: Exception | None = None,
    ) -> None:
        if fut is None:
            return

        def _finish() -> None:
            if fut.done():
                return
            if exc is not None:
                fut.set_exception(exc)
            else:
                fut.set_result(None)

        self._safe_call_soon(_finish)

    def _rx_loop(self) -> None:
        """Фоновый цикл чтения байт из ``serial.Serial`` в ``asyncio.StreamReader``."""
        try:
            while not self._stop_event.is_set():
                if hasattr(self._serial, "is_open") and not self._serial.is_open:
                    break
                in_waiting = 0
                with contextlib.suppress(Exception):
                    in_waiting = int(getattr(self._serial, "in_waiting", 0) or 0)
                to_read = min(self._read_chunk_size, max(1, in_waiting))
                t0 = time.monotonic()
                data = self._serial.read(to_read)
                if data:
                    self._safe_call_soon(self._reader.feed_data, bytes(data))
                else:
                    # Защита от busy-spin на неблокирующих/фейковых портах с timeout=0
                    if (time.monotonic() - t0) < 0.002 and not self._stop_event.is_set():
                        self._stop_event.wait(0.005)
        except Exception as exc:
            if not self._stop_event.is_set():
                self._safe_call_soon(self._reader.set_exception, exc)
                return
        finally:
            self._safe_call_soon(self._reader.feed_eof)

    def _fail_remaining_tx_futures(self, exc: Exception) -> None:
        """Завершить все оставшиеся в очереди ``drain()`` future ошибкой при закрытии потока."""
        while True:
            try:
                rem = self._tx_queue.get_nowait()
            except queue.Empty:
                break
            if rem is not None and rem[1] is not None:
                self._resolve_future(rem[1], exc)

    def _tx_loop(self) -> None:
        """Фоновый цикл потокобезопасной записи в ``serial.Serial``."""
        try:
            while True:
                item = self._tx_queue.get()
                if item is None:
                    break
                payload, fut = item
                try:
                    if payload:
                        if hasattr(self._serial, "is_open") and not self._serial.is_open:
                            raise OSError("Serial port is not open")
                        self._serial.write(payload)
                        flush_fn = getattr(self._serial, "flush", None)
                        if callable(flush_fn):
                            flush_fn()
                    if fut is not None:
                        with self._tx_error_lock:
                            err = self._tx_error
                            self._tx_error = None
                        self._resolve_future(fut, err)
                except Exception as exc:
                    if fut is not None:
                        self._resolve_future(fut, exc)
                    else:
                        with self._tx_error_lock:
                            self._tx_error = exc
        finally:
            self._fail_remaining_tx_futures(OSError("Serial writer is closed"))

    def write(self, data: bytes | bytearray | memoryview) -> None:
        """Поставить байты в очередь записи в последовательный порт."""
        raw = bytes(data)
        with self._close_lock:
            if self._closing or self._closed:
                raise OSError("Serial writer is closed")
            if not raw:
                return
            self._tx_queue.put((raw, None))

    def writelines(self, data: Iterable[bytes | bytearray | memoryview]) -> None:
        """Поставить последовательность чанков в очередь записи."""
        for chunk in data:
            self.write(chunk)

    async def drain(self) -> None:
        """Дождаться завершения всех поставленных в очередь операций записи."""
        with self._tx_error_lock:
            pending_err = self._tx_error
            self._tx_error = None
        if pending_err is not None:
            raise pending_err

        with self._close_lock:
            if self._closing or self._closed:
                raise OSError("Serial writer is closed")
            fut: asyncio.Future[None] = self._loop.create_future()
            self._tx_queue.put((b"", fut))
        await fut

    def close(self) -> None:
        """Остановить фоновые потоки и закрыть последовательный порт."""
        with self._close_lock:
            if self._closing:
                return
            self._closing = True
            self._stop_event.set()
            cancel_read = getattr(self._serial, "cancel_read", None)
            if callable(cancel_read):
                with contextlib.suppress(Exception):
                    cancel_read()
            cancel_write = getattr(self._serial, "cancel_write", None)
            if callable(cancel_write):
                with contextlib.suppress(Exception):
                    cancel_write()
            self._tx_queue.put(None)

    async def wait_closed(self, timeout: float = 2.0) -> None:
        """Дождаться завершения фоновых потоков и физического закрытия порта."""
        self.close()

        def _join_and_close() -> None:
            if self._tx_thread.is_alive() and threading.current_thread() is not self._tx_thread:
                self._tx_thread.join(timeout=timeout)
            if self._rx_thread.is_alive() and threading.current_thread() is not self._rx_thread:
                self._rx_thread.join(timeout=timeout)
            with contextlib.suppress(Exception):
                if getattr(self._serial, "is_open", True):
                    self._serial.close()
            self._closed = True

        await asyncio.to_thread(_join_and_close)


async def open_threaded_serial_connection(
    *,
    url: str,
    loop: asyncio.AbstractEventLoop | None = None,
    limit: int = 2**16,
    serial_factory: Callable[..., Any] | None = None,
    **kwargs: Any,
) -> tuple[asyncio.StreamReader, ThreadedSerialWriter]:
    """Открыть последовательный порт через ``pyserial.Serial`` и фоновые потоки I/O.

    Совместим с ``ProactorEventLoop`` на Windows и любым другим циклом событий ``asyncio``.
    """
    active_loop = loop or asyncio.get_running_loop()
    factory = serial_factory
    if factory is None:
        try:
            import serial as pyserial
        except ImportError as exc:
            raise ImportError(
                "pyserial not installed. Run: pip install uniconn[serial]"
            ) from exc
        factory = pyserial.serial_for_url

    open_kwargs = dict(kwargs)
    # Короткий таймаут чтения гарантирует быстрый выход фонового RX-потока при disconnect()
    req_timeout = open_kwargs.get("timeout")
    if req_timeout is None or float(req_timeout) > _DEFAULT_POLL_INTERVAL:
        open_kwargs["timeout"] = _DEFAULT_POLL_INTERVAL
    if "write_timeout" not in open_kwargs and req_timeout is not None:
        open_kwargs["write_timeout"] = float(req_timeout)

    serial_obj = await asyncio.to_thread(factory, url, **open_kwargs)
    reader = asyncio.StreamReader(limit=limit, loop=active_loop)
    writer = ThreadedSerialWriter(serial_obj, reader, active_loop)
    return reader, writer


__all__ = [
    "ThreadedSerialWriter",
    "open_threaded_serial_connection",
    "should_use_threaded_serial",
]
