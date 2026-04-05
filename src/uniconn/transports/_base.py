# src/uniconn/transports/_base.py
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from typing import Self

from .._config import ConnectionConfig
from ..result import Result


class BaseTransport(ABC):
    """Базовый класс для всех транспортов."""

    def __init__(self, config: ConnectionConfig):
        self.config = config
        self._connected = False

    @property
    @abstractmethod
    def name(self) -> str:
        """Название транспорта (ssh, uart, ipmi, etc.)."""
        pass

    @abstractmethod
    async def connect(self) -> None:
        """Установить подключение."""
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """Закрыть подключение."""
        pass

    @abstractmethod
    async def run(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs
    ) -> Result:
        """Выполнить команду и вернуть результат."""
        pass

    @abstractmethod
    async def stream(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs
    ) -> AsyncIterator[str]:
        """Потоковое выполнение с yield строк вывода."""
        pass

    async def __aenter__(self) -> Self:
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.disconnect()

    @property
    def is_connected(self) -> bool:
        return self._connected
