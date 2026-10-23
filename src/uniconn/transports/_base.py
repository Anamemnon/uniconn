# src/uniconn/transports/_base.py
"""Базовые абстракции и Capability-протоколы транспортов (Interface Segregation Principle)."""

from __future__ import annotations

import shlex
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager
from typing import Any, Protocol, Self, TypeVar, runtime_checkable

from .._config import ConnectionConfig
from ..exceptions import CapabilityNotSupportedError
from ..result import Result

CapT = TypeVar("CapT")


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

    async def stat(self, remote_path: str) -> dict[str, Any]:
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
    FileCapableTransport: "upload",
    ShellCapableTransport: "open_shell",
    TunnelCapableTransport: "forward_local_port",
}


def supports_capability(transport: Any, protocol: type[Any]) -> bool:
    """Проверить, поддерживает ли транспорт указанный протокол возможностей."""
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
    ) -> dict[str, Any]:
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
    ) -> Any:
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
    ) -> Any:
        """Открыть удалённый проброс порта (SSH Remote Port Forwarding)."""
        raise CapabilityNotSupportedError(
            f"forward_remote_port not supported for {self.name} transport",
            host=self.config.host,
        )
