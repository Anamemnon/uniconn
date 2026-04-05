# src/uniconn/_connection.py
import logging
from typing import Self

from tenacity import (
    AsyncRetrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

from ._config import ConnectionConfig
from .exceptions import ConnectionError, TimeoutError
from .plugins._loader import TransportLoader
from .result import Result
from .transports._base import BaseTransport

logger = logging.getLogger(__name__)

class Connection:
    """Основной класс для работы с удалёнными хостами.

    Пример использования:
        async with Connection.from_uri("ssh://user@host") as conn:
            result = await conn.run("uptime")
            print(result.stdout)
    """

    def __init__(
        self,
        transport: BaseTransport,
        config: ConnectionConfig,
        retry_attempts: int = 3,
        logger: logging.Logger | None = None
    ):
        self._transport = transport
        self._config = config
        self._retry_attempts = retry_attempts
        self._logger = logger or logging.getLogger(__name__)

    @classmethod
    def from_uri(
        cls,
        uri: str,
        retry_attempts: int = 3,
        logger: logging.Logger | None = None
    ) -> Self:
        """Создать подключение из URI строки."""
        config = ConnectionConfig.from_uri(uri)
        transport_class = TransportLoader.get(config.transport)
        transport = transport_class(config)
        return cls(transport, config, retry_attempts, logger)

    @classmethod
    def from_config(
        cls,
        config: ConnectionConfig,
        retry_attempts: int = 3,
        logger: logging.Logger | None = None
    ) -> Self:
        """Создать подключение из конфигурации."""
        transport_class = TransportLoader.get(config.transport)
        transport = transport_class(config)
        return cls(transport, config, retry_attempts, logger)

    async def run(
        self,
        command: str,
        timeout: float | None = None,
        raise_on_error: bool = False,
        **kwargs
    ) -> Result:
        """Выполнить команду на удалённом хосте.

        Автоматически повторяет попытку при ConnectionError/TimeoutError
        с экспоненциальным backoff (до retry_attempts раз).

        Args:
            command: Команда для выполнения
            timeout: Таймаут в секундах
            raise_on_error: Raise ExecutionError если exit_code != 0
            **kwargs: Дополнительные аргументы для транспорта

        Returns:
            Result объект с stdout, stderr, exit_code

        Raises:
            ConnectionError: При ошибке подключения после всех retry попыток
            TimeoutError: При таймауте после всех retry попыток

        """
        if not self._transport.is_connected:
            await self._transport.connect()

        timeout = timeout or self._config.timeout
        self._logger.debug(
            f"Running command: {command!r} on {self._config.uri_safe}"
        )

        # Динамический retry с использованием self._retry_attempts
        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(self._retry_attempts),
            wait=wait_exponential_jitter(initial=1, max=10),
            retry=retry_if_exception_type((ConnectionError, TimeoutError)),
            reraise=True,
        ):
            with attempt:
                result = await self._transport.run(
                    command, timeout=timeout, **kwargs
                )

        if raise_on_error:
            result.raise_for_status()

        return result

    async def stream(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs
    ):
        """Потоковое получение вывода команды."""
        if not self._transport.is_connected:
            await self._transport.connect()

        timeout = timeout or self._config.timeout
        async for line in self._transport.stream(command, timeout=timeout, **kwargs):
            yield line

    async def close(self) -> None:
        """Закрыть подключение."""
        await self._transport.disconnect()

    async def __aenter__(self) -> Self:
        await self._transport.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self._transport.disconnect()

    def to_sync(self) -> "SyncConnection":
        """Конвертировать в синхронную версию."""
        from ._sync import SyncConnection
        return SyncConnection(self)

    @property
    def config(self) -> ConnectionConfig:
        return self._config

    @property
    def transport_name(self) -> str:
        return self._transport.name
