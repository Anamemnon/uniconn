# tests/unit/test_is_alive.py
"""Тесты для is_alive() / ping()"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import patch, MagicMock, AsyncMock

from pydantic import SecretStr
from uniconn._config import ConnectionConfig
from uniconn._connection import Connection
from uniconn.result import Result


@pytest.fixture
def mock_transport_class(mocker):
    """Фикстура мок транспорта"""
    transport = mocker.AsyncMock()
    transport.name = "ssh"
    transport.is_connected = True
    transport.run = mocker.AsyncMock(
        return_value=Result(
            exit_code=0, stdout="ok", stderr="",
            duration=0.1, command="test",
            timestamp=datetime.now(), host="testhost",
        )
    )
    transport.ping = mocker.AsyncMock(return_value=True)
    transport.connect = mocker.AsyncMock()
    transport.disconnect = mocker.AsyncMock()
    transport.stream = mocker.AsyncMock()
    transport.stream.return_value.__aiter__.return_value = iter(["line1"])

    transport_cls = MagicMock(return_value=transport)
    with patch(
        "uniconn.plugins._loader.TransportLoader.get",
        return_value=transport_cls,
    ):
        yield transport_cls, transport


class TestConnectionIsAlive:
    """Тесты Connection.is_alive()"""

    @pytest.mark.asyncio
    async def test_is_alive_true(self, mock_transport_class):
        """is_alive возвращает True"""
        _, mock_transport = mock_transport_class
        mock_transport.ping = AsyncMock(return_value=True)

        conn = Connection.from_uri("ssh://user@host")
        result = await conn.is_alive()

        assert result is True
        mock_transport.ping.assert_called_once()

    @pytest.mark.asyncio
    async def test_is_alive_false(self, mock_transport_class):
        """is_alive возвращает False"""
        _, mock_transport = mock_transport_class
        mock_transport.ping = AsyncMock(return_value=False)

        conn = Connection.from_uri("ssh://user@host")
        result = await conn.is_alive()

        assert result is False

    @pytest.mark.asyncio
    async def test_is_alive_with_timeout(self, mock_transport_class):
        """is_alive передаёт timeout"""
        _, mock_transport = mock_transport_class
        mock_transport.ping = AsyncMock(return_value=True)

        conn = Connection.from_uri("ssh://user@host")
        await conn.is_alive(timeout=30.0)

        mock_transport.ping.assert_called_once_with(timeout=30.0)


class TestSyncIsAlive:
    """Тесты синхронного is_alive()"""

    def test_sync_is_alive(self, mocker):
        """Синхронный is_alive"""
        mock_async_conn = mocker.AsyncMock()
        mock_async_conn.is_alive = mocker.AsyncMock(return_value=True)
        mock_async_conn.close = mocker.AsyncMock()
        mock_async_conn._transport = mocker.AsyncMock()
        mock_async_conn._transport.connect = mocker.AsyncMock()
        mock_async_conn._transport.disconnect = mocker.AsyncMock()

        from uniconn._sync import SyncConnection
        sync_conn = SyncConnection(mock_async_conn)

        result = sync_conn.is_alive()

        assert result is True
        mock_async_conn.is_alive.assert_called_once()


class TestLocalPing:
    """Тесты LocalTransport.ping()"""

    @pytest.mark.asyncio
    async def test_local_ping_connected(self):
        """Local ping всегда True если подключён"""
        from uniconn.transports._local import LocalTransport
        config = ConnectionConfig(transport="local", host="localhost")
        transport = LocalTransport(config)
        await transport.connect()

        result = await transport.ping()

        assert result is True

    @pytest.mark.asyncio
    async def test_local_ping_disconnected(self):
        """Local ping False если не подключён"""
        from uniconn.transports._local import LocalTransport
        config = ConnectionConfig(transport="local", host="localhost")
        transport = LocalTransport(config)
        transport._connected = False

        result = await transport.ping()

        assert result is False


class TestBasePing:
    """Тесты BaseTransport.ping()"""

    @pytest.mark.asyncio
    async def test_base_ping_not_connected(self, mocker):
        """ping возвращает False если не подключён"""
        from uniconn.transports._base import BaseTransport

        class MockTransport(BaseTransport):
            @property
            def name(self):
                return "mock"

            async def connect(self):
                pass

            async def disconnect(self):
                pass

            async def run(self, command, timeout=None, **kwargs):
                return Result(
                    exit_code=0, stdout="", stderr="",
                    duration=0, command=command,
                    timestamp=datetime.now(), host="mock"
                )

            async def stream(self, command, timeout=None, **kwargs):
                yield ""

        config = ConnectionConfig(transport="mock", host="mock")
        transport = MockTransport(config)

        result = await transport.ping()

        assert result is False
