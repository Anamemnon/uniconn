# tests/unit/test_redfish_transport.py
"""Тесты для RedfishTransport"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import patch, MagicMock, AsyncMock

from pydantic import SecretStr
from uniconn._config import ConnectionConfig
from uniconn.exceptions import BMCCapabilityError


@pytest.fixture
def redfish_config():
    """Фикстура конфигурации для Redfish"""
    return ConnectionConfig(
        transport="redfish",
        host="bmc.local",
        port=443,
        username="admin",
        password=SecretStr("password"),
        timeout=10.0,
        options={"verify_ssl": False},
    )


class TestRedfishCreation:
    """Тесты создания транспорта"""

    def test_redfish_without_aiohttp(self, redfish_config):
        """Ошибка при отсутствии aiohttp"""
        with patch(
            "uniconn.transports.bmc._redfish.aiohttp", None
        ):
            with pytest.raises(ImportError, match="aiohttp"):
                from uniconn.transports.bmc._redfish import RedfishTransport
                RedfishTransport(redfish_config)

    def test_redfish_name(self, redfish_config):
        """Название транспорта"""
        with patch(
            "uniconn.transports.bmc._redfish.aiohttp", MagicMock()
        ):
            from uniconn.transports.bmc._redfish import RedfishTransport
            transport = RedfishTransport(redfish_config)
            assert transport.name == "redfish"


class TestRedfishBaseUrl:
    """Тесты базового URL"""

    def test_base_url_default_port(self, redfish_config):
        """URL с портом по умолчанию"""
        with patch(
            "uniconn.transports.bmc._redfish.aiohttp", MagicMock()
        ):
            from uniconn.transports.bmc._redfish import RedfishTransport
            transport = RedfishTransport(redfish_config)
            url = transport._get_base_url()
            assert url == "https://bmc.local"

    def test_base_url_custom_port(self):
        """URL с кастомным портом"""
        config = ConnectionConfig(
            transport="redfish",
            host="bmc.local",
            port=8443,
            username="admin",
            password=SecretStr("pass"),
        )
        with patch(
            "uniconn.transports.bmc._redfish.aiohttp", MagicMock()
        ):
            from uniconn.transports.bmc._redfish import RedfishTransport
            transport = RedfishTransport(config)
            url = transport._get_base_url()
            assert url == "https://bmc.local:8443"

    def test_base_url_with_path(self):
        """URL с путём"""
        config = ConnectionConfig(
            transport="redfish",
            host="bmc.local",
            username="admin",
            password=SecretStr("pass"),
            options={"base_path": "/redfish/v1"},
        )
        with patch(
            "uniconn.transports.bmc._redfish.aiohttp", MagicMock()
        ):
            from uniconn.transports.bmc._redfish import RedfishTransport
            transport = RedfishTransport(config)
            url = transport._get_base_url()
            assert url == "https://bmc.local/redfish/v1"


class TestRedfishConnect:
    """Тесты подключения"""

    @pytest.mark.asyncio
    async def test_connect_stateless(self, redfish_config):
        """Connect помечает как подключённый"""
        with patch(
            "uniconn.transports.bmc._redfish.aiohttp", MagicMock()
        ):
            from uniconn.transports.bmc._redfish import RedfishTransport
            transport = RedfishTransport(redfish_config)

            # Мокаем _discover_system чтобы избежать HTTP вызовов
            transport._discover_system = AsyncMock()

            await transport.connect()
            assert transport.is_connected is True

    @pytest.mark.asyncio
    async def test_disconnect(self, redfish_config):
        """Отключение"""
        with patch(
            "uniconn.transports.bmc._redfish.aiohttp", MagicMock()
        ):
            from uniconn.transports.bmc._redfish import RedfishTransport
            transport = RedfishTransport(redfish_config)
            transport._discover_system = AsyncMock()

            # Устанавливаем mock сессию
            mock_session = AsyncMock()
            transport._session = mock_session
            transport._connected = True

            await transport.disconnect()

            assert transport.is_connected is False
            mock_session.close.assert_called_once()


class TestRedfishRun:
    """Тесты выполнения команд"""

    @pytest.mark.asyncio
    async def test_run_power_status(self, redfish_config):
        """Статус питания"""
        with patch(
            "uniconn.transports.bmc._redfish.aiohttp", MagicMock()
        ):
            from uniconn.transports.bmc._redfish import RedfishTransport
            transport = RedfishTransport(redfish_config)
            transport._discover_system = AsyncMock()

            # Мокаем _get_power_status
            transport._get_power_status = AsyncMock(
                return_value="Power State: On"
            )

            await transport.connect()
            result = await transport.run("power status")

            assert result.exit_code == 0
            assert "Power State" in result.stdout

    @pytest.mark.asyncio
    async def test_run_power_on(self, redfish_config):
        """Включение питания"""
        with patch(
            "uniconn.transports.bmc._redfish.aiohttp", MagicMock()
        ):
            from uniconn.transports.bmc._redfish import RedfishTransport
            transport = RedfishTransport(redfish_config)
            transport._discover_system = AsyncMock()
            transport._do_power_action = AsyncMock(
                return_value="Power action 'PowerOn' initiated"
            )

            await transport.connect()
            result = await transport.run("power on")

            assert result.exit_code == 0
            assert "initiated" in result.stdout

    @pytest.mark.asyncio
    async def test_run_info(self, redfish_config):
        """Информация о системе"""
        with patch(
            "uniconn.transports.bmc._redfish.aiohttp", MagicMock()
        ):
            from uniconn.transports.bmc._redfish import RedfishTransport
            transport = RedfishTransport(redfish_config)
            transport._discover_system = AsyncMock()
            transport._get_system_info = AsyncMock(
                return_value="Model: Server X\nManufacturer: Dell"
            )

            await transport.connect()
            result = await transport.run("info")

            assert result.exit_code == 0
            assert "Server X" in result.stdout

    @pytest.mark.asyncio
    async def test_run_sensors(self, redfish_config):
        """Сенсоры"""
        with patch(
            "uniconn.transports.bmc._redfish.aiohttp", MagicMock()
        ):
            from uniconn.transports.bmc._redfish import RedfishTransport
            transport = RedfishTransport(redfish_config)
            transport._discover_system = AsyncMock()
            transport._get_sensors = AsyncMock(
                return_value="Sensors: Thermal: Available"
            )

            await transport.connect()
            result = await transport.run("sensors")

            assert result.exit_code == 0

    @pytest.mark.asyncio
    async def test_run_unknown_command(self, redfish_config):
        """Неизвестная команда"""
        with patch(
            "uniconn.transports.bmc._redfish.aiohttp", MagicMock()
        ):
            from uniconn.transports.bmc._redfish import RedfishTransport
            transport = RedfishTransport(redfish_config)
            transport._discover_system = AsyncMock()

            await transport.connect()

            with pytest.raises(BMCCapabilityError, match="Unknown Redfish command"):
                await transport.run("unknown cmd")

    @pytest.mark.asyncio
    async def test_run_boot_device(self, redfish_config):
        """Boot устройство"""
        with patch(
            "uniconn.transports.bmc._redfish.aiohttp", MagicMock()
        ):
            from uniconn.transports.bmc._redfish import RedfishTransport
            transport = RedfishTransport(redfish_config)
            transport._discover_system = AsyncMock()
            transport._get_boot_device = AsyncMock(
                return_value="Boot Device: pxe"
            )

            await transport.connect()
            result = await transport.run("boot device")

            assert result.exit_code == 0
            assert "Boot Device" in result.stdout


class TestRedfishStream:
    """Тесты потокового выполнения"""

    @pytest.mark.asyncio
    async def test_stream_falls_back_to_run(self, redfish_config):
        """Stream использует run"""
        with patch(
            "uniconn.transports.bmc._redfish.aiohttp", MagicMock()
        ):
            from uniconn.transports.bmc._redfish import RedfishTransport
            transport = RedfishTransport(redfish_config)
            transport._discover_system = AsyncMock()
            transport._get_power_status = AsyncMock(
                return_value="Power State: Off"
            )

            await transport.connect()

            lines = []
            async for line in transport.stream("power status"):
                lines.append(line)

            assert len(lines) >= 1
            assert "Power State" in lines[0]
