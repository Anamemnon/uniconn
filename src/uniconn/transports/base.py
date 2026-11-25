# src/uniconn/transports/base.py
"""Базовые абстракции и Capability-протоколы транспортов (Interface Segregation Principle)."""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import os
import shlex
import uuid
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Callable, Iterable
from contextlib import AbstractAsyncContextManager
from pathlib import Path
from typing import Any, Protocol, Self, TypedDict, TypeVar, runtime_checkable

from ..config.models import ConnectionConfig
from ..exceptions import CapabilityNotSupportedError
from ..result import Result

CapT = TypeVar("CapT")


class FileStat(TypedDict, total=False):
    """Типизированный словарь метаданных файла, возвращаемый методом ``stat()``."""

    size: int
    uid: int | None
    gid: int | None
    permissions: str | None
    mode: int | None
    atime: float | None
    mtime: float | None
    is_file: bool
    is_dir: bool
    is_symlink: bool


class ShellStdinProtocol(Protocol):
    """Протокол входного потока (stdin) процесса интерактивной оболочки."""

    def write(self, data: Any) -> Any:
        """Записать данные в поток ввода оболочки."""
        ...

    async def drain(self) -> None:
        """Дождаться сброса буфера записи."""
        ...


class ShellStdoutProtocol(Protocol):
    """Протокол выходного потока (stdout) процесса интерактивной оболочки."""

    async def read(self, n: int = -1) -> Any:
        """Прочитать порцию данных из потока вывода оболочки."""
        ...


@runtime_checkable
class ShellProcessProtocol(Protocol):
    """Структурный протокол процесса интерактивной PTY-оболочки."""

    stdin: ShellStdinProtocol
    stdout: ShellStdoutProtocol

    def change_terminal_size(self, width: int, height: int) -> Any:
        """Изменить размер терминала PTY."""
        ...

    def close(self) -> Any:
        """Закрыть процесс оболочки."""
        ...

    def is_closing(self) -> bool:
        """Проверить, закрывается ли процесс оболочки."""
        ...


@runtime_checkable
class CommandTransport(Protocol):
    """Базовый протокол транспорта, поддерживающего выполнение команд и потоковый вывод."""

    @property
    def name(self) -> str:
        """Название транспорта."""
        ...

    @property
    def is_connected(self) -> bool:
        """Статус подключения."""
        ...

    async def connect(self) -> None:
        """Установить подключение."""
        ...

    async def disconnect(self) -> None:
        """Закрыть подключение."""
        ...

    async def run(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> Result:
        """Выполнить команду и вернуть ``Result``."""
        ...

    def stream(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Потоковое чтение вывода команды."""
        ...

    async def ping(self, timeout: float | None = None) -> bool:
        """Проверить доступность транспорта."""
        ...


@runtime_checkable
class FileCapableTransport(Protocol):
    """Протокол транспорта с поддержкой файловых и SFTP-операций."""

    async def upload(self, local_path: str, remote_path: str, **kwargs: Any) -> None:
        """Загрузить файл или директорию на хост."""
        ...

    async def download(self, remote_path: str, local_path: str, **kwargs: Any) -> None:
        """Скачать файл или директорию с хоста."""
        ...

    async def read_file(self, remote_path: str) -> bytes:
        """Прочитать файл в память."""
        ...

    async def write_file(
        self,
        remote_path: str,
        data: bytes,
        mode: int | None = None,
    ) -> None:
        """Записать байты в файл на хосте."""
        ...

    async def chmod(self, remote_path: str, mode: int) -> None:
        """Изменить права доступа к файлу."""
        ...

    async def stat(self, remote_path: str) -> FileStat:
        """Получить метаданные файла."""
        ...

    async def listdir(self, remote_path: str = ".") -> list[str]:
        """Получить список элементов директории."""
        ...

    async def remove_file(self, remote_path: str) -> None:
        """Удалить файл на хосте."""
        ...

    async def exists(self, remote_path: str) -> bool:
        """Проверить существование пути."""
        ...

    async def mkdir(
        self,
        remote_path: str,
        parents: bool = True,
        exist_ok: bool = True,
        mode: int | None = None,
    ) -> None:
        """Создать директорию."""
        ...


@runtime_checkable
class ShellCapableTransport(Protocol):
    """Протокол транспорта с поддержкой интерактивной PTY/shell-сессии."""

    async def open_shell(
        self,
        term_type: str = "xterm",
        term_size: tuple[int, int] = (80, 24),
        **kwargs: Any,
    ) -> Any:
        """Открыть интерактивный процесс оболочки."""
        ...


@runtime_checkable
class TunnelCapableTransport(Protocol):
    """Протокол транспорта с поддержкой сетевого проброса портов (Local/Remote Forwarding)."""

    def forward_local_port(
        self,
        remote_host: str = "127.0.0.1",
        remote_port: int = 80,
        local_host: str = "127.0.0.1",
        local_port: int = 0,
    ) -> AbstractAsyncContextManager[int]:
        """Открыть прямой проброс порта."""
        ...

    def forward_remote_port(
        self,
        remote_host: str = "127.0.0.1",
        remote_port: int = 0,
        local_host: str = "127.0.0.1",
        local_port: int = 80,
    ) -> AbstractAsyncContextManager[int]:
        """Открыть обратный проброс порта."""
        ...


_PROTOCOL_PRIMARY_METHODS: dict[type[Any], str] = {
    FileCapableTransport: "stat",
    ShellCapableTransport: "open_shell",
    TunnelCapableTransport: "forward_local_port",
}


def supports_capability(transport: Any, protocol: type[Any]) -> bool:
    """Проверить, поддерживает ли транспорт указанный протокол возможностей."""
    custom_check = getattr(type(transport), "_supports_capability", None)
    if callable(custom_check):
        return bool(custom_check(transport, protocol))
    if not isinstance(transport, protocol):
        return False
    primary_method = _PROTOCOL_PRIMARY_METHODS.get(protocol)
    if primary_method is not None and isinstance(transport, BaseTransport):
        cls_method = getattr(type(transport), primary_method, None)
        base_method = getattr(BaseTransport, primary_method, None)
        if cls_method is base_method:
            return False
    return True


def require_capability(
    transport: Any,
    protocol: type[CapT],
    capability_name: str,
) -> CapT:
    """Проверить поддержку протокола возможностей транспортом."""
    if not supports_capability(transport, protocol):
        cfg = getattr(transport, "config", None)
        host = getattr(cfg, "host", None)
        name = getattr(transport, "name", type(transport).__name__)
        raise CapabilityNotSupportedError(
            f"{capability_name} not supported for {name} transport",
            host=host,
        )
    return transport


class BaseTransport(ABC):
    """Базовый абстрактный класс для всех транспортов."""

    def __init__(self, config: ConnectionConfig) -> None:
        self.config = config
        self._connected = False

    @property
    @abstractmethod
    def name(self) -> str:
        """Название транспорта (ssh, local, telnet, serial, ipmi)."""

    @abstractmethod
    async def connect(self) -> None:
        """Установить подключение."""

    @abstractmethod
    async def disconnect(self) -> None:
        """Закрыть подключение."""

    @abstractmethod
    async def run(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> Result:
        """Выполнить команду и вернуть результат."""

    @abstractmethod
    async def stream(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Потоковое выполнение с yield строк вывода."""
        raise CapabilityNotSupportedError(
            f"stream not supported for {self.name} transport",
            host=self.config.host,
        )
        yield ""  # pragma: no cover

    async def __aenter__(self) -> Self:
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.disconnect()

    @property
    def is_connected(self) -> bool:
        """Установлено ли соединение."""
        return self._connected

    async def ping(self, timeout: float | None = None) -> bool:
        """Проверить живость подключения."""
        if not self._connected:
            return False
        try:
            result = await self.run("echo ping", timeout=timeout or 5.0)
            return result.ok
        except Exception:
            return False

    async def run_bytes(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> bytes:
        """Выполнить команду и вернуть сырой байтовый вывод (stdout)."""
        result = await self.run(command, timeout=timeout, **kwargs)
        return result.stdout.encode("utf-8")

    async def upload(
        self,
        local_path: str,
        remote_path: str,
        **kwargs: Any,
    ) -> None:
        """Загрузить файл на удалённый хост."""
        raise CapabilityNotSupportedError(
            f"Upload not supported for {self.name} transport",
            host=self.config.host,
        )

    async def download(
        self,
        remote_path: str,
        local_path: str,
        **kwargs: Any,
    ) -> None:
        """Скачать файл с удалённого хоста."""
        raise CapabilityNotSupportedError(
            f"Download not supported for {self.name} transport",
            host=self.config.host,
        )

    async def chmod(
        self,
        remote_path: str,
        mode: int,
    ) -> None:
        """Изменить права доступа к файлу."""
        raise CapabilityNotSupportedError(
            f"chmod not supported for {self.name} transport",
            host=self.config.host,
        )

    async def stat(
        self,
        remote_path: str,
    ) -> FileStat:
        """Получить информацию о файле."""
        raise CapabilityNotSupportedError(
            f"stat not supported for {self.name} transport",
            host=self.config.host,
        )

    async def listdir(
        self,
        remote_path: str = ".",
    ) -> list[str]:
        """Список файлов в директории."""
        raise CapabilityNotSupportedError(
            f"listdir not supported for {self.name} transport",
            host=self.config.host,
        )

    async def read_file(self, remote_path: str) -> bytes:
        """Прочитать содержимое файла в память (в виде ``bytes``)."""
        raise CapabilityNotSupportedError(
            f"read_file not supported for {self.name} transport",
            host=self.config.host,
        )

    async def iter_file_chunks(
        self,
        remote_path: str,
        chunk_size: int = 65536,
    ) -> AsyncIterator[bytes]:
        """Потоково читать содержимое файла чанками (fallback поверх ``read_file``)."""
        if chunk_size <= 0:
            raise ValueError(f"chunk_size must be positive, got {chunk_size}")
        data = await self.read_file(remote_path)
        for offset in range(0, len(data), chunk_size):
            yield data[offset : offset + chunk_size]

    async def write_file(
        self,
        remote_path: str,
        data: bytes,
        mode: int | None = None,
    ) -> None:
        """Записать байты из памяти в файл (с опциональной установкой прав ``mode``)."""
        raise CapabilityNotSupportedError(
            f"write_file not supported for {self.name} transport",
            host=self.config.host,
        )

    async def exists(self, remote_path: str) -> bool:
        """Проверить существование файла или директории на хосте."""
        res = await self.run(f"test -e {shlex.quote(remote_path)}")
        return res.ok

    async def mkdir(
        self,
        remote_path: str,
        parents: bool = True,
        exist_ok: bool = True,
        mode: int | None = None,
    ) -> None:
        """Создать директорию на хосте."""
        flags = "-p " if (parents or exist_ok) else ""
        res = await self.run(f"mkdir {flags}{shlex.quote(remote_path)}")
        res.raise_for_status()
        if mode is not None:
            chmod_res = await self.run(
                f"chmod {oct(mode)[2:]} {shlex.quote(remote_path)}"
            )
            chmod_res.raise_for_status()

    async def open_shell(
        self,
        term_type: str = "xterm",
        term_size: tuple[int, int] = (80, 24),
        **kwargs: Any,
    ) -> Any:
        """Открыть интерактивную PTY shell-сессию."""
        raise CapabilityNotSupportedError(
            f"open_shell not supported for {self.name} transport",
            host=self.config.host,
        )

    async def remove_file(self, remote_path: str) -> None:
        """Удалить файл на хосте."""
        raise CapabilityNotSupportedError(
            f"remove_file not supported for {self.name} transport",
            host=self.config.host,
        )

    def forward_local_port(
        self,
        remote_host: str = "127.0.0.1",
        remote_port: int = 80,
        local_host: str = "127.0.0.1",
        local_port: int = 0,
    ) -> AbstractAsyncContextManager[int]:
        """Открыть локальный проброс порта (SSH Local Port Forwarding)."""
        raise CapabilityNotSupportedError(
            f"forward_local_port not supported for {self.name} transport",
            host=self.config.host,
        )

    def forward_remote_port(
        self,
        remote_host: str = "127.0.0.1",
        remote_port: int = 0,
        local_host: str = "127.0.0.1",
        local_port: int = 80,
    ) -> AbstractAsyncContextManager[int]:
        """Открыть удалённый проброс порта (SSH Remote Port Forwarding)."""
        raise CapabilityNotSupportedError(
            f"forward_remote_port not supported for {self.name} transport",
            host=self.config.host,
        )


@contextlib.asynccontextmanager
async def _maybe_aclosing(stream: Any) -> AsyncIterator[None]:
    """Гарантировать вызов ``aclose()`` у асинхронного генератора при выходе или исключении."""
    try:
        yield
    finally:
        aclose = getattr(stream, "aclose", None)
        if callable(aclose):
            res = aclose()
            if inspect.isawaitable(res):
                await res


async def _iter_async_bytes(
    chunks: AsyncIterator[bytes] | Iterable[bytes],
) -> AsyncIterator[bytes]:
    """Унифицировать синхронный или асинхронный поток байтовых чанков в ``AsyncIterator``."""
    if isinstance(chunks, AsyncIterator):
        async with _maybe_aclosing(chunks):
            async for chunk in chunks:
                yield bytes(chunk)
    else:
        for chunk in chunks:
            yield bytes(chunk)


async def _iter_local_file_chunks(
    src: Path,
    chunk_size: int,
) -> AsyncIterator[bytes]:
    """Потоково читать локальный файл чанками в отдельном потоке с гарантированным закрытием."""
    with src.open("rb") as fp:
        while True:
            chunk = await asyncio.to_thread(fp.read, chunk_size)
            if not chunk:
                break
            yield chunk


async def _save_chunk_stream_to_file(
    dst: Path,
    chunk_stream: AsyncIterator[tuple[bytes, int | None]],
    *,
    progress_callback: Callable[[int, int], None] | None = None,
    empty_total: int = 0,
) -> None:
    """Атомарно записать поток ``(chunk, total_hint)`` во временный файл и заменить ``dst``."""
    transferred = 0
    saw_item = False
    tmp_dst: Path | None = None
    fp: Any = None
    try:
        async with _maybe_aclosing(chunk_stream):
            async for chunk, total_hint in chunk_stream:
                if not saw_item:
                    saw_item = True
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    tmp_dst = dst.parent / f".{dst.name}.part_{uuid.uuid4().hex[:8]}"
                    fp = tmp_dst.open("wb")
                if chunk:
                    await asyncio.to_thread(fp.write, chunk)
                    transferred += len(chunk)
                if callable(progress_callback):
                    progress_callback(
                        transferred,
                        total_hint if total_hint is not None else transferred,
                    )
        if not saw_item:
            dst.parent.mkdir(parents=True, exist_ok=True)
            tmp_dst = dst.parent / f".{dst.name}.part_{uuid.uuid4().hex[:8]}"
            tmp_dst.write_bytes(b"")
            if callable(progress_callback):
                progress_callback(0, empty_total)
        if fp is not None:
            fp.close()
            fp = None
        if tmp_dst is not None:
            os.replace(tmp_dst, dst)
            tmp_dst = None
    finally:
        if fp is not None:
            with contextlib.suppress(Exception):
                fp.close()
        if tmp_dst is not None:
            with contextlib.suppress(OSError):
                tmp_dst.unlink(missing_ok=True)


__all__ = [
    "BaseTransport",
    "CommandTransport",
    "FileCapableTransport",
    "FileStat",
    "ShellCapableTransport",
    "ShellProcessProtocol",
    "ShellStdinProtocol",
    "ShellStdoutProtocol",
    "TunnelCapableTransport",
    "require_capability",
    "supports_capability",
]
