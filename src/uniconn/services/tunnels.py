# src/uniconn/services/tunnels.py
"""Доменный сервис сетевого проброса портов (SSH Local / Remote Port Forwarding)."""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

from ..transports.base import TunnelCapableTransport, require_capability

if TYPE_CHECKING:
    from ..core.connection import Connection


class TunnelService:
    """Доменный сервис управления туннелями (``conn.tunnels``)."""

    def __init__(self, conn: Connection) -> None:
        """Инициализировать сервис управления туннелями."""
        self._conn = conn

    async def _get_ready_transport(self, capability_name: str) -> TunnelCapableTransport:
        """Проверить поддержку туннелей и при необходимости подключить транспорт."""
        transport = require_capability(
            self._conn.transport,
            TunnelCapableTransport,
            capability_name,
        )
        if not self._conn.transport.is_connected:
            await self._conn.transport.connect()
        return transport

    @contextlib.asynccontextmanager
    async def forward_local_port(
        self,
        remote_host: str = "127.0.0.1",
        remote_port: int = 80,
        local_host: str = "127.0.0.1",
        local_port: int = 0,
    ) -> AsyncIterator[int]:
        """Асинхронный контекстный менеджер прямого SSH-туннеля (Local Port Forwarding)."""
        transport = await self._get_ready_transport("forward_local_port")

        async with transport.forward_local_port(
            remote_host=remote_host,
            remote_port=remote_port,
            local_host=local_host,
            local_port=local_port,
        ) as bound_port:
            yield bound_port

    @contextlib.asynccontextmanager
    async def forward_remote_port(
        self,
        remote_host: str = "127.0.0.1",
        remote_port: int = 0,
        local_host: str = "127.0.0.1",
        local_port: int = 80,
    ) -> AsyncIterator[int]:
        """Асинхронный контекстный менеджер обратного SSH-туннеля (Remote Port Forwarding)."""
        transport = await self._get_ready_transport("forward_remote_port")

        async with transport.forward_remote_port(
            remote_host=remote_host,
            remote_port=remote_port,
            local_host=local_host,
            local_port=local_port,
        ) as bound_port:
            yield bound_port
