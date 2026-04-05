"""
Создание кастомного транспорта.

Демонстрирует:
- Наследование от BaseTransport
- Реализация абстрактных методов
- Регистрация через entry-points
"""

import asyncio
import time
from collections.abc import AsyncIterator
from typing import Any

from uniconn._config import ConnectionConfig
from uniconn.exceptions import ConnectionError
from uniconn.result import Result
from uniconn.transports._base import BaseTransport


class WebSocketTransport(BaseTransport):
    """Пример кастомного транспорта — WebSocket.

    Этот транспорт показывает минимальную реализацию:
    - connect / disconnect
    - run (выполнение "команды" как отправка сообщения)
    - stream (потоковый приём сообщений)
    - is_alive (ping через WebSocket)
    """

    def __init__(self, config: ConnectionConfig):
        super().__init__(config)
        # Здесь был бы реальный WebSocket клиент
        self._ws: Any = None

    @property
    def name(self) -> str:
        return "websocket"

    async def connect(self) -> None:
        """Подключение к WebSocket серверу."""
        # import websockets
        # self._ws = await websockets.connect(
        #     f"wss://{self.config.host}:{self.config.port or 443}"
        # )
        self._connected = True

    async def disconnect(self) -> None:
        """Закрытие WebSocket соединения."""
        # if self._ws:
        #     await self._ws.close()
        self._connected = False

    async def run(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs
    ) -> Result:
        """Отправить команду как WebSocket сообщение и ждать ответ."""
        start = time.monotonic()

        # await self._ws.send(command)
        # response = await asyncio.wait_for(
        #     self._ws.recv(), timeout=timeout
        # )

        response = f"Echo: {command}"  # mock

        return Result(
            exit_code=0,
            stdout=response,
            stderr="",
            duration=time.monotonic() - start,
            command=command,
            host=self.config.host,
        )

    async def stream(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs
    ) -> AsyncIterator[str]:
        """Потоковый приём WebSocket сообщений."""
        # await self._ws.send(command)
        # while True:
        #     msg = await asyncio.wait_for(
        #         self._ws.recv(), timeout=timeout
        #     )
        #     yield msg

        yield f"Stream echo: {command}"


# ─── Регистрация через entry-points ─────────────────────────────────
#
# В pyproject.toml добавьте:
#
#   [project.entry-points."uniconn.transports"]
#   websocket = "your_package.websocket_transport:WebSocketTransport"
#
# После установки пакета транспорт станет доступен:
#
#   conn = Connection.from_uri("ws://myserver?port=8080")
#
# ────────────────────────────────────────────────────────────────────


async def main():
    """Пример использования кастомного транспорта напрямую."""
    config = ConnectionConfig(
        transport="websocket",
        host="localhost",
        port=8080,
    )
    transport = WebSocketTransport(config)

    async with transport:
        # Выполнение "команды"
        result = await transport.run("Hello, WebSocket!")
        print(result.stdout)

        # Проверка alive
        alive = await transport.ping()
        print(f"Ping: {alive}")


if __name__ == "__main__":
    asyncio.run(main())
