# src/uniconn/services/tunnels.py
"""Доменный сервис сетевого проброса портов (SSH Local / Remote Port Forwarding)."""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..core.connection import Connection


class TunnelService:
    """Доменный сервис управления туннелями (``conn.tunnels``)."""

    def __init__(self, conn: Connection) -> None:
        """Инициализировать сервис управления туннелями."""
        self._conn = conn

    @contextlib.asynccontextmanager
    async def forward_local_port(
        self,
        remote_host: str = "127.0.0.1",
        remote_port: int = 80,
        local_host: str = "127.0.0.1",
        local_port: int = 0,
    ) -> AsyncIterator[int]:
        """Асинхронный контекстный менеджер прямого SSH-туннеля (Local Port Forwarding)."""
        if not self._conn.transport.is_connected:
            await self._conn.transport.connect()

        async with self._conn.transport.forward_local_port(
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
        if not self._conn.transport.is_connected:
            await self._conn.transport.connect()

        async with self._conn.transport.forward_remote_port(
            remote_host=remote_host,
            remote_port=remote_port,
            local_host=local_host,
            local_port=local_port,
        ) as bound_port:
            yield bound_port
