# tests/unit/test_telnet_transport.py
"""Тесты для TelnetTransport"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, patch, MagicMock

from uniconn.transports._telnet import TelnetTransport
from uniconn._config import ConnectionConfig
from uniconn.exceptions import ConnectionError, AuthenticationError


@pytest.fixture
def telnet_config():
    """Фикстура конфигурации для Telnet"""
    return ConnectionConfig(
        transport="telnet",
        host="localhost",
        port=23,
        username=None,
        password=None,
        timeout=5.0
    )


@pytest.fixture
def telnet_config_with_auth():
    """Фикстура конфигурации с аутентификацией"""
    from pydantic import SecretStr
    return ConnectionConfig(
        transport="telnet",
        host="localhost",
        port=23,
        username="admin",
        password=SecretStr("password"),
        timeout=5.0
    )


@pytest.fixture
def mock_telnetlib(mocker):
    """Мок telnetlib3"""
    telnetlib3_mock = mocker.MagicMock()

    # Создаём моки reader/writer
    reader = mocker.AsyncMock()
    writer = mocker.AsyncMock()
    writer.drain = mocker.AsyncMock()

    telnetlib3_mock.open_connection = mocker.AsyncMock(
        return_value=(reader, writer)
    )

    return telnetlib3_mock, reader, writer


class TestTelnetTransportCreation:
    """Тесты создания транспорта"""

    def test_telnet_transport_without_telnetlib(self):
        """Ошибка при отсутствии telnetlib3"""
        with patch("uniconn.transports._telnet.telnetlib3", None):
            config = ConnectionConfig(transport="telnet", host="localhost")
            with pytest.raises(ImportError, match="telnetlib3 not installed"):
                TelnetTransport(config)

    def test_telnet_transport_name(self, telnet_config):
        """Название транспорта"""
        with patch("uniconn.transports._telnet.telnetlib3", MagicMock()):
            transport = TelnetTransport(telnet_config)
            assert transport.name == "telnet"


class TestTelnetConnect:
    """Тесты подключения"""

    @pytest.mark.asyncio
    async def test_connect_basic(self, telnet_config, mock_telnetlib):
        """Базовое подключение"""
        telnetlib3_mock, reader, writer = mock_telnetlib

        with patch("uniconn.transports._telnet.telnetlib3", telnetlib3_mock):
            transport = TelnetTransport(telnet_config)
            await transport.connect()

            assert transport.is_connected is True
            telnetlib3_mock.open_connection.assert_called_once()

    @pytest.mark.asyncio
    async def test_connect_warns_unencrypted(self, telnet_config, mock_telnetlib, caplog):
        """Предупреждение о незашифрованном протоколе при подключении."""
        import logging

        telnetlib3_mock, _, _ = mock_telnetlib

        with (
            patch("uniconn.transports._telnet.telnetlib3", telnetlib3_mock),
            caplog.at_level(logging.WARNING, logger="uniconn"),
        ):
            transport = TelnetTransport(telnet_config)
            await transport.connect()

            assert any(
                "незашифрованный" in record.message for record in caplog.records
            )

    @pytest.mark.asyncio
    async def test_connect_with_auth(self, telnet_config_with_auth, mock_telnetlib, mocker):
        """Подключение с аутентификацией"""
        telnetlib3_mock, reader, writer = mock_telnetlib

        # Имитируем prompts
        reader.read = mocker.AsyncMock(side_effect=[
            b"login: ",
            b"Password: ",
            b"Welcome!\n$ ",
        ])

        with patch("uniconn.transports._telnet.telnetlib3", telnetlib3_mock):
            transport = TelnetTransport(telnet_config_with_auth)
            await transport.connect()

            assert transport.is_connected is True
            writer.write.assert_called()

    @pytest.mark.asyncio
    async def test_connect_timeout(self, telnet_config, mock_telnetlib, mocker):
        """Таймаут подключения"""
        telnetlib3_mock, _, _ = mock_telnetlib
        telnetlib3_mock.open_connection = mocker.AsyncMock(
            side_effect=asyncio.TimeoutError
        )

        with patch("uniconn.transports._telnet.telnetlib3", telnetlib3_mock):
            transport = TelnetTransport(telnet_config)

            with pytest.raises(ConnectionError, match="timeout"):
                await transport.connect()

    @pytest.mark.asyncio
    async def test_connect_refused(self, telnet_config, mock_telnetlib, mocker):
        """Отказ подключения"""
        telnetlib3_mock, _, _ = mock_telnetlib
        telnetlib3_mock.open_connection = mocker.AsyncMock(
            side_effect=ConnectionRefusedError("Connection refused")
        )

        with patch("uniconn.transports._telnet.telnetlib3", telnetlib3_mock):
            transport = TelnetTransport(telnet_config)

            with pytest.raises(ConnectionError, match="failed"):
                await transport.connect()


class TestTelnetDisconnect:
    """Тесты отключения"""

    @pytest.mark.asyncio
    async def test_disconnect(self, telnet_config, mock_telnetlib):
        """Отключение"""
        telnetlib3_mock, reader, writer = mock_telnetlib

        with patch("uniconn.transports._telnet.telnetlib3", telnetlib3_mock):
            transport = TelnetTransport(telnet_config)
            await transport.connect()
            await transport.disconnect()

            assert transport.is_connected is False
            writer.close.assert_called()


class TestTelnetRun:
    """Тесты выполнения команд"""

    @pytest.mark.asyncio
    async def test_run_basic_command(self, telnet_config, mock_telnetlib, mocker):
        """Выполнение базовой команды"""
        telnetlib3_mock, reader, writer = mock_telnetlib

        # readline должен возвращать строки, пока не вернёт пустой
        lines_to_return = [b"$ ", b"hello\n", b"$ "]
        call_idx = 0

        async def fake_readline():
            nonlocal call_idx
            if call_idx < len(lines_to_return):
                line = lines_to_return[call_idx]
                call_idx += 1
                return line
            return b""

        reader.readline = fake_readline

        with patch("uniconn.transports._telnet.telnetlib3", telnetlib3_mock):
            transport = TelnetTransport(telnet_config)
            await transport.connect()

            result = await transport.run("echo hello")

            assert result.exit_code == 0
            assert result.command == "echo hello"
            assert result.host == "localhost"
            assert result.duration >= 0

    @pytest.mark.asyncio
    async def test_run_not_connected(self, telnet_config):
        """Выполнение без подключения"""
        with patch("uniconn.transports._telnet.telnetlib3", MagicMock()):
            transport = TelnetTransport(telnet_config)

            with pytest.raises(ConnectionError, match="Not connected"):
                await transport.run("echo test")

    @pytest.mark.asyncio
    async def test_run_timeout(self, telnet_config, mock_telnetlib, mocker):
        """Таймаут выполнения"""
        telnetlib3_mock, reader, writer = mock_telnetlib

        reader.readline = mocker.AsyncMock(
            side_effect=asyncio.TimeoutError
        )

        with patch("uniconn.transports._telnet.telnetlib3", telnetlib3_mock):
            transport = TelnetTransport(telnet_config)
            await transport.connect()

            # Не должен выбрасывать исключение — просто вернёт что прочитал
            result = await transport.run("slow_command", timeout=0.1)
            assert result.exit_code == 0  # Telnet не возвращает реальный exit code


class TestTelnetStream:
    """Тесты потокового выполнения"""

    @pytest.mark.asyncio
    async def test_stream_basic(self, telnet_config, mock_telnetlib, mocker):
        """Базовый стриминг"""
        telnetlib3_mock, reader, writer = mock_telnetlib

        lines_to_return = [b"line1\n", b"line2\n", b"$ "]
        call_idx = 0

        async def fake_readline():
            nonlocal call_idx
            if call_idx < len(lines_to_return):
                line = lines_to_return[call_idx]
                call_idx += 1
                return line
            return b""

        reader.readline = fake_readline

        with patch("uniconn.transports._telnet.telnetlib3", telnetlib3_mock):
            transport = TelnetTransport(telnet_config)
            await transport.connect()

            lines = []
            async for line in transport.stream("cat file"):
                lines.append(line)

            assert len(lines) >= 1

    @pytest.mark.asyncio
    async def test_stream_not_connected(self, telnet_config):
        """Стриминг без подключения"""
        with patch("uniconn.transports._telnet.telnetlib3", MagicMock()):
            transport = TelnetTransport(telnet_config)

            with pytest.raises(ConnectionError, match="Not connected"):
                async for _ in transport.stream("test"):
                    pass


class TestTelnetContextManager:
    """Тесты контекстного менеджера"""

    @pytest.mark.asyncio
    async def test_context_manager(self, telnet_config, mock_telnetlib):
        """Контекстный менеджер"""
        telnetlib3_mock, reader, writer = mock_telnetlib

        with patch("uniconn.transports._telnet.telnetlib3", telnetlib3_mock):
            transport = TelnetTransport(telnet_config)

            async with transport as t:
                assert t.is_connected is True

            assert transport.is_connected is False
