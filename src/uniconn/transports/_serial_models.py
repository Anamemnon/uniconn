# src/uniconn/transports/_serial_models.py
"""Модели портов, утилиты обнаружения и адаптеры shell-процесса для SerialTransport."""

from __future__ import annotations

import contextlib
import inspect
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SerialPortInfo:
    """Информация об обнаруженном последовательном порте."""

    device: str
    name: str = ""
    description: str = ""
    hwid: str = ""
    vid: int | None = None
    pid: int | None = None
    serial_number: str | None = None
    manufacturer: str | None = None
    product: str | None = None
    interface: str | None = None

    @property
    def vid_pid_hex(self) -> str | None:
        """Строковое представление VID:PID в формате '10C4:EA60'."""
        if self.vid is not None and self.pid is not None:
            return f"{self.vid:04X}:{self.pid:04X}"
        return None


def list_serial_ports() -> list[SerialPortInfo]:
    """Получить список доступных в системе последовательных портов."""
    try:
        import serial.tools.list_ports

        comports_iter = serial.tools.list_ports.comports()
    except Exception:
        return []

    results: list[SerialPortInfo] = []
    for p in comports_iter:
        results.append(
            SerialPortInfo(
                device=p.device or "",
                name=getattr(p, "name", "") or "",
                description=getattr(p, "description", "") or "",
                hwid=getattr(p, "hwid", "") or "",
                vid=getattr(p, "vid", None),
                pid=getattr(p, "pid", None),
                serial_number=getattr(p, "serial_number", None),
                manufacturer=getattr(p, "manufacturer", None),
                product=getattr(p, "product", None),
                interface=getattr(p, "interface", None),
            )
        )
    return results


def _parse_vid_pid(val: Any) -> int | None:
    """Безопасный парсинг VID/PID из строки (hex '10c4', '0x10c4' или dec '4292') или int."""
    if val is None:
        return None
    if isinstance(val, int):
        return val
    s = str(val).strip()
    if not s:
        return None
    if s.lower().startswith("0x"):
        with contextlib.suppress(ValueError):
            return int(s, 16)
    if any(c in "abcdefABCDEF" for c in s) or (
        len(s) == 4 and all(c in "0123456789abcdefABCDEF" for c in s)
    ):
        with contextlib.suppress(ValueError):
            return int(s, 16)
    with contextlib.suppress(ValueError):
        return int(s, 10)
    with contextlib.suppress(ValueError):
        return int(s, 16)
    return None


class _SerialShellStdin:
    """Адаптер текстовой записи поверх байтового StreamWriter для SerialTransport."""

    def __init__(self, writer: Any) -> None:
        self._writer = writer

    def write(self, text: str | bytes) -> None:
        data = text.encode("utf-8") if isinstance(text, str) else bytes(text)
        self._writer.write(data)

    async def drain(self) -> None:
        drain_fn = getattr(self._writer, "drain", None)
        if callable(drain_fn):
            res = drain_fn()
            if inspect.isawaitable(res):
                await res


class _SerialShellStdout:
    """Адаптер текстового чтения поверх байтового StreamReader для SerialTransport."""

    def __init__(self, reader: Any) -> None:
        self._reader = reader

    async def read(self, n: int = 4096) -> str:
        chunk = await self._reader.read(n)
        if isinstance(chunk, bytes):
            return chunk.decode("utf-8", errors="replace")
        return chunk or ""


class _SerialShellProcess:
    """Адаптер Serial reader/writer для работы с ``ShellSession`` и ``expect()``."""

    def __init__(
        self,
        reader: Any,
        writer: Any,
        term_size: tuple[int, int] = (80, 24),
    ) -> None:
        self._reader = reader
        self._writer = writer
        self.stdin = _SerialShellStdin(writer)
        self.stdout = _SerialShellStdout(reader)
        self.term_size = term_size
        self.returncode: int | None = None
        self.terminated = False
        self.closed = False

    def change_terminal_size(self, width: int = 80, height: int = 24, **kwargs: Any) -> None:
        w = kwargs.get("cols", width)
        h = kwargs.get("rows", height)
        self.term_size = (w, h)

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = 0

    def close(self) -> None:
        self.closed = True
        self.returncode = 0

    def is_closing(self) -> bool:
        """Проверить, закрывается ли процесс оболочки (ShellProcessProtocol)."""
        if self.closed or self.terminated:
            return True
        is_closing_fn = getattr(self._writer, "is_closing", None)
        if callable(is_closing_fn) and type(is_closing_fn).__name__ != "AsyncMock":
            try:
                res = is_closing_fn()
                if not inspect.isawaitable(res):
                    return bool(res)
            except Exception:
                pass
        return False


__all__ = [
    "SerialPortInfo",
    "_SerialShellProcess",
    "_SerialShellStdin",
    "_SerialShellStdout",
    "_parse_vid_pid",
    "list_serial_ports",
]
