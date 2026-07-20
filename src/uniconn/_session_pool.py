# src/uniconn/_session_pool.py
"""Пул SSH-сессий для одного хоста.

Позволяет выполнять множество команд через ограниченное число
SSH-соединений, каждое из которых мультиплексирует каналы.

Пример:
    async with SSHSessionPool(
        "ssh://admin@server",
        max_sessions_per_conn=6,
        max_connections=4
    ) as pool:
        results = await pool.map(["lshw", "dmidecode", "nvme list"])
"""

import asyncio
import logging
from collections.abc import Sequence
from typing import Self

from ._connection import Connection
from .result import Result


class SSHSessionPool:
    """Пул SSH-соединений с ограничением на число каналов.

    Создаёт дополнительные SSH-соединения, когда количество
    параллельных команд превышает `max_sessions_per_conn`.
    """

    def __init__(
        self,
        uri: str,
        max_sessions_per_conn: int = 6,
        max_connections: int = 6,
        retry_attempts: int = 3,
        logger: logging.Logger | None = None,
    ):
        self._uri = uri
        self._max_sessions = max_sessions_per_conn
        self._max_connections = max_connections
        self._retry_attempts = retry_attempts
        self._logger = logger or logging.getLogger(__name__)

        self._connections: list[Connection] = []
        self._semaphores: list[asyncio.Semaphore] = []
        self._lock = asyncio.Lock()

    async def _execute(self, command: str, **kwargs) -> Result:
        """Выполнить команду через один из доступных слотов."""
        # 1. Ищем соединение со свободным слотом без блокировки
        for conn, sem in zip(self._connections, self._semaphores, strict=True):
            if getattr(sem, "_value", 0) > 0:
                async with sem:
                    return await conn.run(command, **kwargs)

        # 2. Все слоты заняты — пробуем получить слот под локом
        conn_to_use: Connection | None = None
        sem_to_use: asyncio.Semaphore | None = None

        async with self._lock:
            # Double-check после взятия лока
            for conn, sem in zip(self._connections, self._semaphores, strict=True):
                if getattr(sem, "_value", 0) > 0:
                    conn_to_use = conn
                    sem_to_use = sem
                    await sem_to_use.acquire()
                    break
            else:
                # Ни одного свободного слота — создаём новое соединение
                if len(self._connections) < self._max_connections:
                    self._logger.debug(
                        f"Creating SSH connection #{len(self._connections) + 1} "
                        f"for {self._uri}"
                    )
                    conn_to_use = Connection.from_uri(
                        self._uri,
                        retry_attempts=self._retry_attempts,
                        logger=self._logger,
                    )
                    sem_to_use = asyncio.Semaphore(self._max_sessions)
                    self._connections.append(conn_to_use)
                    self._semaphores.append(sem_to_use)
                    await sem_to_use.acquire()

        if conn_to_use is not None and sem_to_use is not None:
            # Выполняем команду без удержания lock,
            # чтобы другие задачи могли параллельно создавать соединения
            try:
                return await conn_to_use.run(command, **kwargs)
            finally:
                sem_to_use.release()

        # 3. Лимит соединений исчерпан — ждём на первом доступном
        for conn, sem in zip(self._connections, self._semaphores, strict=True):
            async with sem:
                return await conn.run(command, **kwargs)

        # Fallback — никогда не должен сюда дойти
        raise RuntimeError("No available SSH connection")

    async def run(self, command: str, **kwargs) -> Result:
        """Выполнить одну команду через пул.

        Args:
            command: Команда для выполнения
            **kwargs: Дополнительные аргументы (timeout, raise_on_error и т.д.)

        Returns:
            Result объект с результатом выполнения

        """
        return await self._execute(command, **kwargs)

    async def map(
        self,
        commands: Sequence[str],
        timeout: float | None = None,
        raise_on_error: bool = False,
    ) -> list[Result]:
        """Выполнить несколько команд параллельно.

        Args:
            commands: Список команд для выполнения
            timeout: Таймаут для каждой команды
            raise_on_error: Выбрасывать ExecutionError при ненулевом exit_code

        Returns:
            Список Result в том же порядке, что и команды

        """
        async with asyncio.TaskGroup() as tg:
            tasks = [
                tg.create_task(
                    self._execute(
                        cmd,
                        timeout=timeout,
                        raise_on_error=raise_on_error,
                    )
                )
                for cmd in commands
            ]
        return [t.result() for t in tasks]

    async def close(self) -> None:
        """Закрыть все соединения в пуле."""
        for conn in self._connections:
            await conn.close()
        self._connections.clear()
        self._semaphores.clear()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()
