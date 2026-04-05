# tests/unit/test_serial_transport.py
"""Тесты для SerialTransport"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import patch, MagicMock, AsyncMock

from uniconn._config import ConnectionConfig
from uniconn.exceptions import ConnectionError


@pytest.fixture
def serial_config():
    """Фикстура конфигурации для Serial"""
    return ConnectionConfig(
        transport="serial",
        host=None,
        port=None,
        username=None,
        password=None,
        timeout=5.0,
        options={"device": "/dev/ttyUSB0", "baudrate": 9600},
    )


@pytest.fixture
def mock_serial_asyncio(mocker):
    """Мок serial_asyncio"""
    serial_asyncio_mock = MagicMock()

    reader = mocker.AsyncMock()
    writer = mocker.AsyncMock()
    writer.drain = mocker.AsyncMock()
    writer.close = MagicMock()
    writer.wait_closed = mocker.AsyncMock()

    serial_asyncio_mock.open_serial_connection = mocker.AsyncMock(
        return_value=(reader, writer)
    )

    return serial_asyncio_mock, reader, writer


class TestSerialTransportCreation:
    """Тесты создания транспорта"""

    def test_serial_without_pyserial(self):
        """Ошибка при отсутствии pyserial_asyncio"""
        with patch(
            "uniconn.transports._serial.serial_asyncio", None
        ):
            config = ConnectionConfig(
                transport="serial",
                options={"device": "/dev/ttyUSB0"},
            )
            with pytest.raises(ImportError, match="pyserial"):
                from uniconn.transports._serial import SerialTransport
                SerialTransport(config)

    def test_serial_name(self, serial_config):
        """Название транспорта"""
        with patch(
            "uniconn.transports._serial.serial_asyncio", MagicMock()
        ):
            from uniconn.transports._serial import SerialTransport
            transport = SerialTransport(serial_config)
            assert transport.name == "serial"


class TestSerialDeviceDetection:
    """Тесты определения устройства"""

    def test_device_from_options(self, serial_config):
        """Устройство из options"""
        with patch(
            "uniconn.transports._serial.serial_asyncio", MagicMock()
        ):
            from uniconn.transports._serial import SerialTransport
            transport = SerialTransport(serial_config)
            assert transport._get_device() == "/dev/ttyUSB0"

    def test_device_from_host(self):
        """Устройство из host"""
        config = ConnectionConfig(
            transport="serial",
            host="COM3",
            options={},
        )
        with patch(
            "uniconn.transports._serial.serial_asyncio", MagicMock()
        ):
            from uniconn.transports._serial import SerialTransport
            transport = SerialTransport(config)
            assert transport._get_device() == "COM3"

    def test_device_default(self):
        """Устройство по умолчанию"""
        config = ConnectionConfig(
            transport="serial",
            host=None,
            options={},
        )
        with patch(
            "uniconn.transports._serial.serial_asyncio", MagicMock()
        ):
            import sys
            from uniconn.transports._serial import SerialTransport
            transport = SerialTransport(config)
            device = transport._get_device()
            if sys.platform == "win32":
                assert device == "COM1"
            else:
                assert device == "/dev/ttyUSB0"


class TestSerialConnect:
    """Тесты подключения"""

    @pytest.mark.asyncio
    async def test_connect_basic(self, serial_config, mock_serial_asyncio):
        """Базовое подключение"""
        serial_mock, reader, writer = mock_serial_asyncio

        with patch(
            "uniconn.transports._serial.serial_asyncio", serial_mock
        ):
            from uniconn.transports._serial import SerialTransport
            transport = SerialTransport(serial_config)
            await transport.connect()

            assert transport.is_connected is True
            serial_mock.open_serial_connection.assert_called_once()

    @pytest.mark.asyncio
    async def test_connect_failure(self, serial_config, mock_serial_asyncio):
        """Ошибка подключения"""
        serial_mock, _, _ = mock_serial_asyncio
        serial_mock.open_serial_connection = AsyncMock(
            side_effect=OSError("Device not found")
        )

        with patch(
            "uniconn.transports._serial.serial_asyncio", serial_mock
        ):
            from uniconn.transports._serial import SerialTransport
            transport = SerialTransport(serial_config)

            with pytest.raises(ConnectionError, match="Device not found"):
                await transport.connect()


class TestSerialDisconnect:
    """Тесты отключения"""

    @pytest.mark.asyncio
    async def test_disconnect(self, serial_config, mock_serial_asyncio):
        """Отключение"""
        serial_mock, reader, writer = mock_serial_asyncio

        with patch(
            "uniconn.transports._serial.serial_asyncio", serial_mock
        ):
            from uniconn.transports._serial import SerialTransport
            transport = SerialTransport(serial_config)
            await transport.connect()
            await transport.disconnect()

            assert transport.is_connected is False
            writer.close.assert_called_once()


class TestSerialRun:
    """Тесты выполнения команд"""

    @pytest.mark.asyncio
    async def test_run_basic(self, serial_config, mock_serial_asyncio, mocker):
        """Базовое выполнение команды"""
        serial_mock, reader, writer = mock_serial_asyncio

        lines = [b"OK\r\n", b"\r\n"]
        call_idx = 0

        async def fake_readline():
            nonlocal call_idx
            if call_idx < len(lines):
                line = lines[call_idx]
                call_idx += 1
                return line
            return b""

        reader.readline = fake_readline

        with patch(
            "uniconn.transports._serial.serial_asyncio", serial_mock
        ):
            from uniconn.transports._serial import SerialTransport
            transport = SerialTransport(serial_config)
            await transport.connect()

            result = await transport.run("AT")

            assert result.exit_code == 0
            assert result.command == "AT"
            assert result.host == "/dev/ttyUSB0"

    @pytest.mark.asyncio
    async def test_run_not_connected(self, serial_config):
        """Выполнение без подключения"""
        with patch(
            "uniconn.transports._serial.serial_asyncio", MagicMock()
        ):
            from uniconn.transports._serial import SerialTransport
            transport = SerialTransport(serial_config)

            with pytest.raises(ConnectionError, match="Not connected"):
                await transport.run("AT")

    @pytest.mark.asyncio
    async def test_run_with_line_ending(self, serial_config, mock_serial_asyncio, mocker):
        """Команда с кастомным разделителем"""
        serial_mock, reader, writer = mock_serial_asyncio

        reader.readline = mocker.AsyncMock(side_effect=[b"OK\r\n", b""])

        with patch(
            "uniconn.transports._serial.serial_asyncio", serial_mock
        ):
            from uniconn.transports._serial import SerialTransport
            transport = SerialTransport(serial_config)
            await transport.connect()

            await transport.run("AT", line_ending="\r")

            writer.write.assert_called()
            call_args = writer.write.call_args
            assert call_args[0][0].endswith(b"\r")


class TestSerialStream:
    """Тесты потокового выполнения"""

    @pytest.mark.asyncio
    async def test_stream_basic(self, serial_config, mock_serial_asyncio, mocker):
        """Базовый стриминг"""
        serial_mock, reader, writer = mock_serial_asyncio

        lines = [b"line1\r\n", b"line2\r\n", b""]
        call_idx = 0

        async def fake_readline():
            nonlocal call_idx
            if call_idx < len(lines):
                line = lines[call_idx]
                call_idx += 1
                return line
            return b""

        reader.readline = fake_readline

        with patch(
            "uniconn.transports._serial.serial_asyncio", serial_mock
        ):
            from uniconn.transports._serial import SerialTransport
            transport = SerialTransport(serial_config)
            await transport.connect()

            collected = []
            async for line in transport.stream("AT"):
                collected.append(line)

            assert len(collected) >= 1

    @pytest.mark.asyncio
    async def test_stream_not_connected(self, serial_config):
        """Стриминг без подключения"""
        with patch(
            "uniconn.transports._serial.serial_asyncio", MagicMock()
        ):
            from uniconn.transports._serial import SerialTransport
            transport = SerialTransport(serial_config)

            with pytest.raises(ConnectionError, match="Not connected"):
                async for _ in transport.stream("AT"):
                    pass


class TestSerialContextManager:
    """Тесты контекстного менеджера"""

    @pytest.mark.asyncio
    async def test_context_manager(self, serial_config, mock_serial_asyncio):
        """Контекстный менеджер"""
        serial_mock, reader, writer = mock_serial_asyncio

        with patch(
            "uniconn.transports._serial.serial_asyncio", serial_mock
        ):
            from uniconn.transports._serial import SerialTransport
            transport = SerialTransport(serial_config)

            async with transport as t:
                assert t.is_connected is True

            assert transport.is_connected is False
