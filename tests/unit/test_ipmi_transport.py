# tests/unit/test_ipmi_transport.py
"""Тесты для IPMITransport"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import patch, MagicMock, AsyncMock

from pydantic import SecretStr
from uniconn._config import ConnectionConfig
from uniconn.exceptions import BMCCapabilityError


@pytest.fixture
def ipmi_config():
    """Фикстура конфигурации для IPMI"""
    return ConnectionConfig(
        transport="ipmi",
        host="bmc.local",
        port=623,
        username="admin",
        password=SecretStr("password"),
        timeout=10.0,
    )


class TestIPMICreation:
    """Тесты создания транспорта"""

    def test_ipmi_without_pyghmi(self, ipmi_config):
        """Ошибка при отсутствии pyghmi"""
        with patch(
            "uniconn.transports.bmc._ipmi.ipmi_cmd", None
        ):
            with pytest.raises(ImportError, match="pyghmi"):
                from uniconn.transports.bmc._ipmi import IPMITransport
                IPMITransport(ipmi_config)

    def test_ipmi_name(self, ipmi_config):
        """Название транспорта"""
        with patch(
            "uniconn.transports.bmc._ipmi.ipmi_cmd", MagicMock()
        ):
            from uniconn.transports.bmc._ipmi import IPMITransport
            transport = IPMITransport(ipmi_config)
            assert transport.name == "ipmi"


class TestIPMIConnect:
    """Тесты подключения"""

    @pytest.mark.asyncio
    async def test_connect_stateless(self, ipmi_config):
        """IPMI не требует явного подключения"""
        with patch(
            "uniconn.transports.bmc._ipmi.ipmi_cmd", MagicMock()
        ):
            from uniconn.transports.bmc._ipmi import IPMITransport
            transport = IPMITransport(ipmi_config)
            await transport.connect()

            assert transport.is_connected is True

    @pytest.mark.asyncio
    async def test_disconnect(self, ipmi_config):
        """Отключение"""
        with patch(
            "uniconn.transports.bmc._ipmi.ipmi_cmd", MagicMock()
        ):
            from uniconn.transports.bmc._ipmi import IPMITransport
            transport = IPMITransport(ipmi_config)
            await transport.connect()
            await transport.disconnect()

            assert transport.is_connected is False


class TestIPMIRun:
    """Тесты выполнения команд"""

    @pytest.mark.asyncio
    async def test_run_power_on(self, ipmi_config, mocker):
        """Включение питания"""
        mock_cmd = MagicMock()
        mock_cmd.set_power = MagicMock(return_value={"powerstate": "on"})

        mock_ipmi_module = MagicMock()
        mock_ipmi_module.Command = MagicMock(return_value=mock_cmd)

        with patch(
            "uniconn.transports.bmc._ipmi.ipmi_cmd", mock_ipmi_module
        ):
            from uniconn.transports.bmc._ipmi import IPMITransport
            transport = IPMITransport(ipmi_config)
            await transport.connect()

            result = await transport.run("power on")

            assert result.exit_code == 0
            assert result.command == "power on"
            assert result.host == "bmc.local"
            mock_cmd.set_power.assert_called_once_with("on")

    @pytest.mark.asyncio
    async def test_run_power_off(self, ipmi_config, mocker):
        """Выключение питания"""
        mock_cmd = MagicMock()
        mock_cmd.set_power = MagicMock(return_value={"powerstate": "off"})

        mock_ipmi_module = MagicMock()
        mock_ipmi_module.Command = MagicMock(return_value=mock_cmd)

        with patch(
            "uniconn.transports.bmc._ipmi.ipmi_cmd", mock_ipmi_module
        ):
            from uniconn.transports.bmc._ipmi import IPMITransport
            transport = IPMITransport(ipmi_config)

            result = await transport.run("power off")

            assert result.exit_code == 0
            mock_cmd.set_power.assert_called_once_with("off")

    @pytest.mark.asyncio
    async def test_run_power_status(self, ipmi_config, mocker):
        """Статус питания"""
        mock_cmd = MagicMock()
        mock_cmd.get_power = MagicMock(
            return_value={"powerstate": "on"}
        )

        mock_ipmi_module = MagicMock()
        mock_ipmi_module.Command = MagicMock(return_value=mock_cmd)

        with patch(
            "uniconn.transports.bmc._ipmi.ipmi_cmd", mock_ipmi_module
        ):
            from uniconn.transports.bmc._ipmi import IPMITransport
            transport = IPMITransport(ipmi_config)

            result = await transport.run("power status")

            assert result.exit_code == 0
            mock_cmd.get_power.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_sensors(self, ipmi_config, mocker):
        """Получение данных сенсоров"""
        mock_cmd = MagicMock()
        mock_cmd.get_health = MagicMock(
            return_value={"temperatures": [], "fans": []}
        )

        mock_ipmi_module = MagicMock()
        mock_ipmi_module.Command = MagicMock(return_value=mock_cmd)

        with patch(
            "uniconn.transports.bmc._ipmi.ipmi_cmd", mock_ipmi_module
        ):
            from uniconn.transports.bmc._ipmi import IPMITransport
            transport = IPMITransport(ipmi_config)

            result = await transport.run("sensors")

            assert result.exit_code == 0
            mock_cmd.get_health.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_boot_device(self, ipmi_config, mocker):
        """Получение boot устройства"""
        mock_cmd = MagicMock()
        mock_cmd.get_bootdev = MagicMock(
            return_value={"bootdev": "pxe"}
        )

        mock_ipmi_module = MagicMock()
        mock_ipmi_module.Command = MagicMock(return_value=mock_cmd)

        with patch(
            "uniconn.transports.bmc._ipmi.ipmi_cmd", mock_ipmi_module
        ):
            from uniconn.transports.bmc._ipmi import IPMITransport
            transport = IPMITransport(ipmi_config)

            result = await transport.run("boot device")

            assert result.exit_code == 0
            mock_cmd.get_bootdev.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_unknown_command(self, ipmi_config):
        """Неизвестная команда"""
        with patch(
            "uniconn.transports.bmc._ipmi.ipmi_cmd", MagicMock()
        ):
            from uniconn.transports.bmc._ipmi import IPMITransport
            transport = IPMITransport(ipmi_config)

            with pytest.raises(BMCCapabilityError, match="Unknown IPMI command"):
                await transport.run("reboot custom")


class TestIPMIStream:
    """Тесты потокового выполнения"""

    @pytest.mark.asyncio
    async def test_stream_falls_back_to_run(self, ipmi_config, mocker):
        """Stream использует run"""
        mock_cmd = MagicMock()
        mock_cmd.get_power = MagicMock(return_value={"powerstate": "on"})

        mock_ipmi_module = MagicMock()
        mock_ipmi_module.Command = MagicMock(return_value=mock_cmd)

        with patch(
            "uniconn.transports.bmc._ipmi.ipmi_cmd", mock_ipmi_module
        ):
            from uniconn.transports.bmc._ipmi import IPMITransport
            transport = IPMITransport(ipmi_config)

            lines = []
            async for line in transport.stream("power status"):
                lines.append(line)

            assert len(lines) >= 1
