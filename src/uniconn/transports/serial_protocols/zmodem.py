# src/uniconn/transports/serial_protocols/zmodem.py
"""Адаптер ZMODEM поверх внешних утилит sz / rz из пакета lrzsz."""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from ...exceptions import CapabilityNotSupportedError
from .exceptions import ModemTransferError


@contextmanager
def _open_serial_fd(port_path: str, serial_fd: int | None) -> Iterator[int | None]:
    """Получить файловый дескриптор открытого порта или временно открыть устройство на POSIX."""
    if serial_fd is not None:
        yield serial_fd
        return
    if sys.platform != "win32" and port_path and Path(port_path).exists():
        flags = os.O_RDWR | getattr(os, "O_NOCTTY", 0)
        fd = os.open(port_path, flags)
        try:
            yield fd
        finally:
            os.close(fd)
        return
    yield None


class ZmodemSubprocessAdapter:
    """Асинхронный адаптер ZMODEM (вызов ``sz`` и ``rz`` с привязкой к дескриптору порта)."""

    @staticmethod
    def is_available() -> bool:
        """Проверить доступность утилит ``sz`` и ``rz`` в операционной системе."""
        return shutil.which("sz") is not None and shutil.which("rz") is not None

    @classmethod
    async def send_file(
        cls,
        port_path: str,
        baudrate: int,
        local_path: str | Path,
        *,
        trigger_command: str | None = None,
        serial_fd: int | None = None,
        timeout: float = 120.0,
    ) -> int:
        """Отправить файл по протоколу ZMODEM с использованием утилиты ``sz``."""
        if not cls.is_available():
            raise CapabilityNotSupportedError(
                "ZMODEM requires 'sz' and 'rz' binaries from lrzsz package. "
                "Install it: sudo apt install lrzsz (Linux) or brew install lrzsz (macOS).",
                host=port_path,
            )

        path = Path(local_path)
        if not path.is_file():
            raise FileNotFoundError(f"Local file does not exist: {path}")

        _ = (baudrate, trigger_command)
        sz_bin = shutil.which("sz") or "sz"

        with _open_serial_fd(port_path, serial_fd) as fd:
            stdin_arg: Any = fd if fd is not None else asyncio.subprocess.DEVNULL
            stdout_arg: Any = fd if fd is not None else asyncio.subprocess.PIPE

            proc = await asyncio.create_subprocess_exec(
                sz_bin,
                "--zmodem",
                str(path),
                stdin=stdin_arg,
                stdout=stdout_arg,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except TimeoutError as exc:
                proc.kill()
                await proc.wait()
                raise ModemTransferError(
                    f"ZMODEM transfer timed out after {timeout:.1f}s for {path}",
                    host=port_path,
                ) from exc

        if proc.returncode != 0:
            err_text = stderr.decode("utf-8", errors="replace").strip()
            raise ModemTransferError(
                f"ZMODEM transfer failed (exit code {proc.returncode}): {err_text}",
                exit_code=proc.returncode,
                stderr=err_text,
                host=port_path,
            )

        return int(path.stat().st_size)

    @classmethod
    async def receive_files(
        cls,
        port_path: str,
        baudrate: int,
        destination_dir: str | Path,
        *,
        trigger_command: str | None = None,
        serial_fd: int | None = None,
        timeout: float = 120.0,
    ) -> Path:
        """Принять файл(ы) по протоколу ZMODEM с использованием утилиты ``rz``."""
        if not cls.is_available():
            raise CapabilityNotSupportedError(
                "ZMODEM requires 'sz' and 'rz' binaries from lrzsz package. "
                "Install it: sudo apt install lrzsz (Linux) or brew install lrzsz (macOS).",
                host=port_path,
            )

        dest = Path(destination_dir)
        dest.mkdir(parents=True, exist_ok=True)
        _ = (baudrate, trigger_command)
        rz_bin = shutil.which("rz") or "rz"

        with _open_serial_fd(port_path, serial_fd) as fd:
            stdin_arg: Any = fd if fd is not None else asyncio.subprocess.DEVNULL
            stdout_arg: Any = fd if fd is not None else asyncio.subprocess.PIPE

            proc = await asyncio.create_subprocess_exec(
                rz_bin,
                "--zmodem",
                cwd=str(dest),
                stdin=stdin_arg,
                stdout=stdout_arg,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except TimeoutError as exc:
                proc.kill()
                await proc.wait()
                raise ModemTransferError(
                    f"ZMODEM receive timed out after {timeout:.1f}s",
                    host=port_path,
                ) from exc

        if proc.returncode != 0:
            err_text = stderr.decode("utf-8", errors="replace").strip()
            raise ModemTransferError(
                f"ZMODEM receive failed (exit code {proc.returncode}): {err_text}",
                exit_code=proc.returncode,
                stderr=err_text,
                host=port_path,
            )

        return dest


__all__ = [
    "ZmodemSubprocessAdapter",
]
