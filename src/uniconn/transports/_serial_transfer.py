# src/uniconn/transports/_serial_transfer.py
"""Миксин передачи файлов по модемным протоколам XMODEM/YMODEM/ZMODEM для SerialTransport."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..exceptions import ConnectionError
from .serial_protocols import (
    AsyncXmodemReceiver,
    AsyncXmodemSender,
    AsyncYmodemReceiver,
    AsyncYmodemSender,
    ModemProtocolError,
    XmodemMode,
    ZmodemSubprocessAdapter,
)


class _SerialTransferMixin:
    """Миксин с методами загрузки и скачивания файлов по XMODEM/YMODEM/ZMODEM."""

    DEFAULT_BAUDRATE: int
    config: Any
    _connected: bool
    _reader: asyncio.StreamReader | None
    _writer: asyncio.StreamWriter | None
    _device: str

    @property
    def serial_instance(self) -> Any | None:  # pragma: no cover - overridden in SerialTransport
        return None

    def _flush_input_buffer(self) -> None:  # pragma: no cover - overridden in SerialTransport
        return None

    async def _prepare_modem_transfer(
        self,
        trigger_command: str | None = None,
        trigger_delay: float = 0.5,
    ) -> None:
        """Сбросить входной буфер порта и опционально отправить команду инициализации загрузчика."""
        if not self._connected or not self._reader or not self._writer:
            raise ConnectionError("Serial transport is not connected", host=self._device)

        self._flush_input_buffer()

        if trigger_command:
            cmd_str = trigger_command
            if not cmd_str.endswith(("\r", "\n")):
                cmd_str += "\r"
            encoding = self.config.options.get("encoding", "utf-8")
            self._writer.write(cmd_str.encode(encoding, errors="replace"))
            drain_fn = getattr(self._writer, "drain", None)
            if callable(drain_fn):
                res = drain_fn()
                if inspect.isawaitable(res):
                    await res
            if trigger_delay > 0:
                await asyncio.sleep(trigger_delay)

    async def upload_xmodem(
        self,
        local_path: str | Path,
        *,
        mode: XmodemMode = "1k",
        trigger_command: str | None = None,
        trigger_delay: float = 0.5,
        progress_callback: Callable[[int, int], None] | None = None,
        timeout: float = 60.0,
        max_retries: int = 10,
        packet_timeout: float = 10.0,
        cancel_event: asyncio.Event | None = None,
    ) -> int:
        """Загрузить файл на устройство по протоколу XMODEM (checksum, crc или 1k)."""
        await self._prepare_modem_transfer(trigger_command, trigger_delay=trigger_delay)
        if self._reader is None or self._writer is None:
            raise ConnectionError("Serial transport is not connected", host=self._device)

        path = Path(local_path)
        if not path.is_file():
            raise FileNotFoundError(f"Local file does not exist: {path}")

        total_size = int(path.stat().st_size)
        sender = AsyncXmodemSender(
            self._reader,
            self._writer,
            max_retries=max_retries,
            packet_timeout=packet_timeout,
            handshake_timeout=timeout,
        )
        with path.open("rb") as fp:
            return await sender.send(
                fp,
                total_size=total_size,
                mode=mode,
                progress_callback=progress_callback,
                cancel_event=cancel_event,
            )

    async def upload_ymodem(
        self,
        local_path: str | Path,
        *,
        trigger_command: str | None = None,
        trigger_delay: float = 0.5,
        progress_callback: Callable[[int, int], None] | None = None,
        timeout: float = 60.0,
        max_retries: int = 10,
        packet_timeout: float = 10.0,
        cancel_event: asyncio.Event | None = None,
    ) -> int:
        """Загрузить файл на устройство по протоколу YMODEM (с сохранением имени и точного размера)."""
        await self._prepare_modem_transfer(trigger_command, trigger_delay=trigger_delay)
        if self._reader is None or self._writer is None:
            raise ConnectionError("Serial transport is not connected", host=self._device)

        sender = AsyncYmodemSender(
            self._reader,
            self._writer,
            max_retries=max_retries,
            packet_timeout=packet_timeout,
            handshake_timeout=timeout,
        )
        return await sender.send_file(
            local_path,
            progress_callback=progress_callback,
            cancel_event=cancel_event,
        )

    async def download_xmodem(
        self,
        local_path: str | Path,
        *,
        mode: XmodemMode = "crc",
        trigger_command: str | None = None,
        trigger_delay: float = 0.5,
        progress_callback: Callable[[int, int], None] | None = None,
        timeout: float = 60.0,
        max_retries: int = 10,
        strip_padding: bool = True,
        cancel_event: asyncio.Event | None = None,
    ) -> int:
        """Скачать файл с устройства по протоколу XMODEM."""
        await self._prepare_modem_transfer(trigger_command, trigger_delay=trigger_delay)
        if self._reader is None or self._writer is None:
            raise ConnectionError("Serial transport is not connected", host=self._device)

        path = Path(local_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        receiver = AsyncXmodemReceiver(
            self._reader,
            self._writer,
            max_retries=max_retries,
            packet_timeout=min(timeout, 10.0),
        )
        with path.open("wb") as fp:
            return await receiver.receive(
                fp,
                mode=mode,
                strip_padding=strip_padding,
                progress_callback=progress_callback,
                cancel_event=cancel_event,
            )

    async def download_ymodem(
        self,
        destination_dir: str | Path,
        *,
        trigger_command: str | None = None,
        trigger_delay: float = 0.5,
        progress_callback: Callable[[int, int, str], None] | None = None,
        timeout: float = 60.0,
        max_retries: int = 10,
        cancel_event: asyncio.Event | None = None,
    ) -> list[Path]:
        """Скачать файлы с устройства по протоколу YMODEM-Batch в целевую директорию."""
        await self._prepare_modem_transfer(trigger_command, trigger_delay=trigger_delay)
        if self._reader is None or self._writer is None:
            raise ConnectionError("Serial transport is not connected", host=self._device)

        receiver = AsyncYmodemReceiver(
            self._reader,
            self._writer,
            max_retries=max_retries,
            packet_timeout=min(timeout, 10.0),
        )
        return await receiver.receive_batch(
            destination_dir,
            progress_callback=progress_callback,
            cancel_event=cancel_event,
        )

    async def upload(
        self,
        local_path: str,
        remote_path: str = "",
        *,
        protocol: str = "auto",
        trigger_command: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Универсальная загрузка файла по Serial/UART (по умолчанию YMODEM)."""
        _ = remote_path
        kwargs.pop("recurse", None)
        xmodem_mode: XmodemMode = kwargs.pop("xmodem_mode", kwargs.pop("mode", "1k"))
        proto = (protocol or "auto").lower().strip()

        if proto in ("auto", "ymodem"):
            await self.upload_ymodem(
                local_path,
                trigger_command=trigger_command,
                **kwargs,
            )
            return
        if proto == "xmodem":
            await self.upload_xmodem(
                local_path,
                mode=xmodem_mode,
                trigger_command=trigger_command,
                **kwargs,
            )
            return
        if proto == "zmodem":
            await self._prepare_modem_transfer(
                trigger_command,
                trigger_delay=float(kwargs.get("trigger_delay", 0.5)),
            )
            baud = int(self.config.options.get("baudrate", self.DEFAULT_BAUDRATE))
            ser = self.serial_instance
            fd = ser.fileno() if ser is not None and hasattr(ser, "fileno") else None
            await ZmodemSubprocessAdapter.send_file(
                self._device,
                baud,
                local_path,
                trigger_command=trigger_command,
                serial_fd=fd,
                timeout=float(kwargs.get("timeout", 120.0)),
            )
            return

        raise ModemProtocolError(
            f"Unsupported serial file transfer protocol: {protocol!r}. "
            "Expected 'auto', 'ymodem', 'xmodem', or 'zmodem'."
        )

    async def download(
        self,
        remote_path: str,
        local_path: str,
        *,
        protocol: str = "auto",
        trigger_command: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Универсальное скачивание файла по Serial/UART."""
        _ = remote_path
        kwargs.pop("recurse", None)
        xmodem_mode: XmodemMode = kwargs.pop("xmodem_mode", kwargs.pop("mode", "crc"))
        proto = (protocol or "auto").lower().strip()

        if proto in ("auto", "ymodem"):
            dest_p = Path(local_path)
            target_dir = dest_p if dest_p.is_dir() else (dest_p.parent or Path("."))
            cb = kwargs.pop("progress_callback", None)

            def _wrap_cb(sent: int, total: int, _name: str) -> None:
                if cb is not None:
                    cb(sent, total)

            files = await self.download_ymodem(
                target_dir,
                trigger_command=trigger_command,
                progress_callback=_wrap_cb if cb is not None else None,
                **kwargs,
            )
            if files and not dest_p.is_dir() and files[0] != dest_p:
                files[0].replace(dest_p)
            return
        if proto == "xmodem":
            await self.download_xmodem(
                local_path,
                mode=xmodem_mode,
                trigger_command=trigger_command,
                **kwargs,
            )
            return
        if proto == "zmodem":
            await self._prepare_modem_transfer(
                trigger_command,
                trigger_delay=float(kwargs.get("trigger_delay", 0.5)),
            )
            baud = int(self.config.options.get("baudrate", self.DEFAULT_BAUDRATE))
            ser = self.serial_instance
            fd = ser.fileno() if ser is not None and hasattr(ser, "fileno") else None
            dest_p = Path(local_path)
            target_dir = dest_p if dest_p.is_dir() else (dest_p.parent or Path("."))
            await ZmodemSubprocessAdapter.receive_files(
                self._device,
                baud,
                target_dir,
                trigger_command=trigger_command,
                serial_fd=fd,
                timeout=float(kwargs.get("timeout", 120.0)),
            )
            return

        raise ModemProtocolError(
            f"Unsupported serial file transfer protocol: {protocol!r}. "
            "Expected 'auto', 'ymodem', 'xmodem', or 'zmodem'."
        )


__all__ = ["_SerialTransferMixin"]
