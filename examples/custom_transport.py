"""Создание кастомного транспорта на базе публичного API uniconn.

Демонстрирует:
- Наследование от публичного класса BaseTransport (from uniconn import BaseTransport)
- Реализацию методов connect(), disconnect(), run(), stream() и ping()
- Использование кастомного транспорта и регистрацию через entry-points
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from typing import Any

from uniconn import BaseTransport, ConnectionConfig, Result


class WebSocketTransport(BaseTransport):
    """Пример кастомного транспорта (WebSocket RPC)."""

    def __init__(self, config: ConnectionConfig, logger: Any = None) -> None:
        super().__init__(config)
        self._logger = logger
        self._ws: Any = None

    @property
    def name(self) -> str:
        return "websocket"

    async def connect(self) -> None:
        """Установить соединение с сервером."""
        self._connected = True

    async def disconnect(self) -> None:
        """Закрыть соединение с сервером."""
        self._connected = False

    async def run(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> Result:
        """Отправить команду как сообщение и вернуть типизированный Result."""
        start = time.monotonic()
        _ = timeout, kwargs
        response = f"Echo from {self.config.host}:{self.config.port}: {command}"
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
        command: str | None = None,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Потоковый приём сообщений от транспорта."""
        _ = timeout, kwargs
        yield f"[frame-1] {command or 'passive'}\n"
        yield f"[frame-2] {command or 'passive'}\n"


# ─── Регистрация через entry-points в pyproject.toml ────────────────
#
# [project.entry-points."uniconn.transports"]
# websocket = "your_package.websocket_transport:WebSocketTransport"
# ────────────────────────────────────────────────────────────────────


async def main() -> None:
    """Локальная демонстрация работы кастомного транспорта."""
    config = ConnectionConfig(
        transport="websocket",
        host="ws.internal.local",
        port=8443,
    )
    transport = WebSocketTransport(config)

    async with transport:
        result = await transport.run("status --json")
        print(f"Run output: {result.text}")

        frames = [line.strip() async for line in transport.stream("subscribe metrics")]
        print(f"Stream frames: {frames}")

        alive = await transport.ping()
        print(f"Transport ping alive: {alive}")


if __name__ == "__main__":
    asyncio.run(main())
