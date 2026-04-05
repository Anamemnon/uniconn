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

    async def ping(self, timeout: float | None = None) -> bool:
        """Проверить живость подключения.

        Базовая реализация: выполняет команду ``echo`` и проверяет ответ.
        Переопределяется в транспортах для более эффективной проверки.

        Args:
            timeout: Таймаут проверки в секундах

        Returns:
            True если подключение живо
        """
        if not self._connected:
            return False
        try:
            result = await self.run("echo ping", timeout=timeout or 5.0)
            return result.ok
        except Exception:
            return False

    async def upload(
        self,
        local_path: str,
        remote_path: str,
        **kwargs
    ) -> None:
        """Загрузить файл на удалённый хост.

        Базовая реализация вызывает NotImplementedError.
        Переопределяется в транспортах с поддержкой файловых операций.

        Raises:
            NotImplementedError: Если транспорт не поддерживает файловые операции
        """
        raise NotImplementedError(
            f"Upload not supported for {self.name} transport"
        )

    async def download(
        self,
        remote_path: str,
        local_path: str,
        **kwargs
    ) -> None:
        """Скачать файл с удалённого хоста.

        Базовая реализация вызывает NotImplementedError.
        Переопределяется в транспортах с поддержкой файловых операций.

        Raises:
            NotImplementedError: Если транспорт не поддерживает файловые операции
        """
        raise NotImplementedError(
            f"Download not supported for {self.name} transport"
        )

    async def chmod(
        self,
        remote_path: str,
        mode: int,
    ) -> None:
        """Изменить права доступа к файлу."""
        raise NotImplementedError(
            f"chmod not supported for {self.name} transport"
        )

    async def stat(
        self,
        remote_path: str,
    ) -> dict:
        """Получить информацию о файле."""
        raise NotImplementedError(
            f"stat not supported for {self.name} transport"
        )

    async def listdir(
        self,
        remote_path: str = ".",
    ) -> list[str]:
        """Список файлов в директории."""
        raise NotImplementedError(
            f"listdir not supported for {self.name} transport"
        )
