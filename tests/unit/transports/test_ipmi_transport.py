# tests/unit/transports/test_ipmi_transport.py
"""Тесты для IPMITransport (питание, SEL, raw IPMI, boot override и детальные датчики SDR)."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from pydantic import SecretStr

from uniconn.config.models import ConnectionConfig
from uniconn.exceptions import BMCCapabilityError


@pytest.fixture
def ipmi_config() -> ConnectionConfig:
    """Фикстура конфигурации для IPMI."""
    return ConnectionConfig(
        transport="ipmi",
        host="bmc.local",
        port=623,
        username="admin",
        password=SecretStr("password"),
        timeout=10.0,
    )


class TestIPMICreation:
    """Тесты создания транспорта."""

    def test_ipmi_without_pyghmi(self, ipmi_config: ConnectionConfig) -> None:
        """Ошибка при отсутствии pyghmi."""
        with patch("uniconn.transports.bmc._ipmi.ipmi_cmd", None):
            with pytest.raises(ImportError, match="pyghmi"):
                from uniconn.transports.bmc._ipmi import IPMITransport

                IPMITransport(ipmi_config)

    def test_ipmi_name(self, ipmi_config: ConnectionConfig) -> None:
        """Название транспорта."""
        with patch("uniconn.transports.bmc._ipmi.ipmi_cmd", MagicMock()):
            from uniconn.transports.bmc._ipmi import IPMITransport

            transport = IPMITransport(ipmi_config)
            assert transport.name == "ipmi"


class TestIPMIConnect:
    """Тесты подключения."""

    @pytest.mark.asyncio
    async def test_connect_stateless(self, ipmi_config: ConnectionConfig) -> None:
        """IPMI не требует явного подключения."""
        with patch("uniconn.transports.bmc._ipmi.ipmi_cmd", MagicMock()):
            from uniconn.transports.bmc._ipmi import IPMITransport

            transport = IPMITransport(ipmi_config)
            await transport.connect()

            assert transport.is_connected is True

    @pytest.mark.asyncio
    async def test_disconnect(self, ipmi_config: ConnectionConfig) -> None:
        """Отключение."""
        with patch("uniconn.transports.bmc._ipmi.ipmi_cmd", MagicMock()):
            from uniconn.transports.bmc._ipmi import IPMITransport

            transport = IPMITransport(ipmi_config)
            await transport.connect()
            await transport.disconnect()

            assert transport.is_connected is False


class TestIPMIRun:
    """Тесты выполнения команд IPMITransport."""

    @pytest.mark.asyncio
    async def test_run_power_on(self, ipmi_config: ConnectionConfig) -> None:
        """Включение питания и проверка JSON-ответа."""
        mock_cmd = MagicMock()
        mock_cmd.set_power = MagicMock(return_value={"powerstate": "on"})

        mock_ipmi_module = MagicMock()
        mock_ipmi_module.Command = MagicMock(return_value=mock_cmd)

        with patch("uniconn.transports.bmc._ipmi.ipmi_cmd", mock_ipmi_module):
            from uniconn.transports.bmc._ipmi import IPMITransport

            transport = IPMITransport(ipmi_config)
            await transport.connect()

            result = await transport.run("power on")

            assert result.exit_code == 0
            assert result.command == "power on"
            assert result.host == "bmc.local"
            assert result.json() == {"powerstate": "on"}
            mock_cmd.set_power.assert_called_once_with("on")

    @pytest.mark.asyncio
    async def test_run_power_off(self, ipmi_config: ConnectionConfig) -> None:
        """Выключение питания."""
        mock_cmd = MagicMock()
        mock_cmd.set_power = MagicMock(return_value={"powerstate": "off"})

        mock_ipmi_module = MagicMock()
        mock_ipmi_module.Command = MagicMock(return_value=mock_cmd)

        with patch("uniconn.transports.bmc._ipmi.ipmi_cmd", mock_ipmi_module):
            from uniconn.transports.bmc._ipmi import IPMITransport

            transport = IPMITransport(ipmi_config)
            result = await transport.run("power off")

            assert result.exit_code == 0
            assert result.json() == {"powerstate": "off"}
            mock_cmd.set_power.assert_called_once_with("off")

    @pytest.mark.asyncio
    async def test_run_power_status(self, ipmi_config: ConnectionConfig) -> None:
        """Статус питания."""
        mock_cmd = MagicMock()
        mock_cmd.get_power = MagicMock(return_value={"powerstate": "on"})

        mock_ipmi_module = MagicMock()
        mock_ipmi_module.Command = MagicMock(return_value=mock_cmd)

        with patch("uniconn.transports.bmc._ipmi.ipmi_cmd", mock_ipmi_module):
            from uniconn.transports.bmc._ipmi import IPMITransport

            transport = IPMITransport(ipmi_config)
            result = await transport.run("power status")

            assert result.exit_code == 0
            assert result.json() == {"powerstate": "on"}
            mock_cmd.get_power.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_sensors(self, ipmi_config: ConnectionConfig) -> None:
        """Получение данных сенсоров с откатом на get_health()."""
        mock_cmd = MagicMock()
        mock_cmd.get_health = MagicMock(
            return_value={"temperatures": [], "fans": []}
        )

        mock_ipmi_module = MagicMock()
        mock_ipmi_module.Command = MagicMock(return_value=mock_cmd)

        with patch("uniconn.transports.bmc._ipmi.ipmi_cmd", mock_ipmi_module):
            from uniconn.transports.bmc._ipmi import IPMITransport

            transport = IPMITransport(ipmi_config)
            result = await transport.run("sensors")

            assert result.exit_code == 0
            payload = result.json()
            assert "temperatures" in payload
            assert "fans" in payload
            assert "sensors" in payload
            mock_cmd.get_health.assert_called_once()

    @pytest.mark.asyncio
    async def test_run_sensors_detailed_with_units_and_thresholds(
        self, ipmi_config: ConnectionConfig
    ) -> None:
        """Детальный вывод sensors через get_sensor_data() и get_sensor_descriptions() с порогами."""
        mock_cmd = MagicMock()
        mock_cmd.get_sensor_data = MagicMock(
            return_value=[
                SimpleNamespace(
                    name="CPU1 Temp",
                    type="Temperature",
                    value=88.0,
                    units="°C",
                    health=0,
                    states=[],
                    imprecision=0.5,
                ),
                SimpleNamespace(
                    name="BBU PA Temp",
                    type="Temperature",
                    value=94.0,
                    units="°C",
                    health=2,
                    states=["Upper Critical - going high"],
                    imprecision=None,
                    upper_critical=92.0,
                    upper_non_recoverable=98.0,
                ),
                SimpleNamespace(
                    name="SYS Fan 1",
                    type="Fan",
                    value=7200,
                    units="RPM",
                    health=0,
                    states=[],
                    imprecision=50,
                    lower_critical=1200,
                ),
                SimpleNamespace(
                    name="12V Rail",
                    type="Voltage",
                    value=12.1,
                    units="V",
                    health=0,
                    states=[],
                    imprecision=0.05,
                ),
                SimpleNamespace(
                    name="PSU1 Input",
                    type="Power",
                    value=420,
                    units="W",
                    health=0,
                    states=[],
                    imprecision=None,
                ),
            ]
        )
        mock_cmd.get_sensor_descriptions = MagicMock(
            return_value=[
                {
                    "name": "CPU1 Temp",
                    "type": "Temperature",
                    "upper_non_critical": 85.0,
                    "upper_critical": 95.0,
                    "upper_non_recoverable": 100.0,
                }
            ]
        )

        mock_ipmi_module = MagicMock()
        mock_ipmi_module.Command = MagicMock(return_value=mock_cmd)

        with patch("uniconn.transports.bmc._ipmi.ipmi_cmd", mock_ipmi_module):
            from uniconn.transports.bmc._ipmi import IPMITransport

            transport = IPMITransport(ipmi_config)
            res = await transport.run("sensors")
            data = res.json()

            assert len(data["sensors"]) == 5
            assert len(data["temperatures"]) == 2
            assert len(data["fans"]) == 1
            assert len(data["voltages"]) == 1
            assert len(data["power"]) == 1

            cpu_temp = next(s for s in data["sensors"] if s["name"] == "CPU1 Temp")
            assert cpu_temp["units"] == "°C"
            assert cpu_temp["value"] == 88.0
            assert cpu_temp["status"] == "Warning"  # 88.0 >= upper_non_critical (85.0)
            assert cpu_temp["thresholds"]["upper_non_critical"] == 85.0
            assert cpu_temp["thresholds"]["upper_critical"] == 95.0
            assert cpu_temp["upper_threshold_critical"] == 95.0

            pa_temp = next(s for s in data["sensors"] if s["name"] == "BBU PA Temp")
            assert pa_temp["status"] == "Critical"
            assert pa_temp["thresholds"]["upper_critical"] == 92.0
            assert pa_temp["thresholds"]["upper_non_recoverable"] == 98.0

            fan1 = data["fans"][0]
            assert fan1["name"] == "SYS Fan 1"
            assert fan1["reading"] == 7200
            assert fan1["units"] == "RPM"
            assert fan1["lower_threshold_critical"] == 1200

    @pytest.mark.asyncio
    async def test_run_sel_list_and_clear(self, ipmi_config: ConnectionConfig) -> None:
        """Чтение (sel / sel list) и очистка (sel clear) журнала аппаратных событий IPMI SEL."""
        sample_events = [
            {
                "record_id": 1,
                "timestamp": "2026-11-06T01:00:00Z",
                "severity": 2,
                "component": "FPGA_VDD",
                "event": "Voltage Droop asserted",
            },
            SimpleNamespace(
                record_id=2,
                time="2026-11-06T01:02:10Z",
                severity="Warning",
                sensor="FAN_TACH_2",
                event="Lower Non-criticalgoing low",
            ),
        ]
        mock_cmd = MagicMock()
        mock_cmd.get_event_log = MagicMock(return_value=sample_events)

        mock_ipmi_module = MagicMock()
        mock_ipmi_module.Command = MagicMock(return_value=mock_cmd)

        with patch("uniconn.transports.bmc._ipmi.ipmi_cmd", mock_ipmi_module):
            from uniconn.transports.bmc._ipmi import IPMITransport

            transport = IPMITransport(ipmi_config)

            res_sel = await transport.run("sel")
            sel_data = res_sel.json()
            assert sel_data["count"] == 2
            assert sel_data["cleared"] is False
            assert sel_data["entries"][0]["sensor"] == "FPGA_VDD"
            assert sel_data["entries"][0]["severity"] == "Critical"
            assert sel_data["entries"][1]["sensor"] == "FAN_TACH_2"
            mock_cmd.get_event_log.assert_called_with(clear=False)

            res_list = await transport.run("sel list")
            assert res_list.json()["count"] == 2
            mock_cmd.get_event_log.assert_called_with(clear=False)

            res_clear = await transport.run("sel clear")
            clear_data = res_clear.json()
            assert clear_data["cleared"] is True
            assert clear_data["count"] == 2
            mock_cmd.get_event_log.assert_called_with(clear=True)

    @pytest.mark.asyncio
    async def test_run_raw_command_pwm_and_flash_bank(
        self, ipmi_config: ConnectionConfig
    ) -> None:
        """Отправка сырых байтовых команд raw <netfn> <cmd> [data...] (управление ШИМ и флеш-банком)."""
        mock_cmd = MagicMock()
        mock_cmd.raw_command = MagicMock(
            return_value={"code": 0, "data": bytearray([0x01, 0x50, 0xFF])}
        )

        mock_ipmi_module = MagicMock()
        mock_ipmi_module.Command = MagicMock(return_value=mock_cmd)

        with patch("uniconn.transports.bmc._ipmi.ipmi_cmd", mock_ipmi_module):
            from uniconn.transports.bmc._ipmi import IPMITransport

            transport = IPMITransport(ipmi_config)

            # Установка ШИМ вентиляторов 80% (0x50): NetFn=0x30, Cmd=0x30, Data=[0x02, 0xff, 80]
            res = await transport.run("raw 0x30 30h 0x02 0xff 80")
            payload = res.json()

            assert payload["netfn"] == 0x30
            assert payload["command"] == 0x30
            assert payload["request_data"] == [0x02, 0xFF, 80]
            assert payload["code"] == 0
            assert payload["data"] == [1, 80, 255]
            assert payload["hex"] == "01 50 ff"
            mock_cmd.raw_command.assert_called_once_with(
                netfn=0x30, command=0x30, data=[0x02, 0xFF, 80]
            )

            # Валидация ошибок синтаксиса raw
            with pytest.raises(BMCCapabilityError, match="requires at least"):
                await transport.run("raw 0x30")

            with pytest.raises(BMCCapabilityError, match="out of range"):
                await transport.run("raw 0x30 0x30 0x1ff")

            with pytest.raises(BMCCapabilityError, match="Invalid IPMI"):
                await transport.run("raw 0x30 0xZZ")

            # Ошибка от самого BMC в raw_command (с ключом error и без него по коду != 0)
            mock_cmd.raw_command.return_value = {
                "error": "Invalid command",
                "code": 0xC1,
            }
            with pytest.raises(BMCCapabilityError, match="Invalid command"):
                await transport.run("raw 0x06 0x01")

            mock_cmd.raw_command.return_value = {
                "code": 0xD5,
                "data": b"",
            }
            with pytest.raises(BMCCapabilityError, match="0xd5"):
                await transport.run("raw 0x30 0x30 0x01")

    @pytest.mark.asyncio
    async def test_run_boot_device_and_boot_override(
        self, ipmi_config: ConnectionConfig
    ) -> None:
        """Чтение (boot device) и установка (boot pxe|disk|bios|cdrom с флагами) загрузочного устройства."""
        mock_cmd = MagicMock()
        mock_cmd.get_bootdev = MagicMock(return_value={"bootdev": "pxe"})
        mock_cmd.set_bootdev = MagicMock(return_value={"bootdev": "network"})

        mock_ipmi_module = MagicMock()
        mock_ipmi_module.Command = MagicMock(return_value=mock_cmd)

        with patch("uniconn.transports.bmc._ipmi.ipmi_cmd", mock_ipmi_module):
            from uniconn.transports.bmc._ipmi import IPMITransport

            transport = IPMITransport(ipmi_config)

            result = await transport.run("boot device")
            assert result.exit_code == 0
            assert result.json() == {"bootdev": "pxe"}
            mock_cmd.get_bootdev.assert_called_once()

            # Базовые целевые устройства: pxe, disk, bios, cdrom
            r_pxe = await transport.run("boot pxe")
            assert r_pxe.json()["bootdev"] == "pxe"
            mock_cmd.set_bootdev.assert_called_with("network")

            r_disk = await transport.run("boot disk")
            assert r_disk.json()["pyghmi_bootdev"] == "hd"
            mock_cmd.set_bootdev.assert_called_with("hd")

            r_bios = await transport.run("boot bios")
            assert r_bios.json()["pyghmi_bootdev"] == "setup"
            mock_cmd.set_bootdev.assert_called_with("setup")

            r_cdrom = await transport.run("boot cdrom")
            assert r_cdrom.json()["pyghmi_bootdev"] == "optical"
            mock_cmd.set_bootdev.assert_called_with("optical")

            # С опциональными модификаторами once/continuous и uefi/legacy
            r_opts = await transport.run("boot pxe continuous uefi")
            opts_json = r_opts.json()
            assert opts_json["bootdev"] == "pxe"
            assert opts_json["persist"] is True
            assert opts_json["uefiboot"] is True
            mock_cmd.set_bootdev.assert_called_with(
                "network", persist=True, uefiboot=True
            )

            with pytest.raises(BMCCapabilityError, match="Unsupported IPMI boot target"):
                await transport.run("boot tape")

            with pytest.raises(BMCCapabilityError, match="Unsupported boot modifier"):
                await transport.run("boot pxe invalid_flag")

    @pytest.mark.asyncio
    async def test_run_error_dict_and_edge_cases(
        self, ipmi_config: ConnectionConfig
    ) -> None:
        """Проверка перехвата словаря {'error': ...}, булевого health и неизвестной подкоманды sel."""
        from uniconn.transports.bmc._ipmi import _normalize_health_status

        assert _normalize_health_status(True) == "OK"
        assert _normalize_health_status(False) == "OK"
        assert _normalize_health_status(1) == "Warning"

        mock_cmd = MagicMock()
        mock_cmd.set_power = MagicMock(return_value={"error": "Node busy"})

        mock_ipmi_module = MagicMock()
        mock_ipmi_module.Command = MagicMock(return_value=mock_cmd)

        with patch("uniconn.transports.bmc._ipmi.ipmi_cmd", mock_ipmi_module):
            from uniconn.transports.bmc._ipmi import IPMITransport

            transport = IPMITransport(ipmi_config)

            with pytest.raises(BMCCapabilityError, match="Node busy"):
                await transport.run("power on")

            with pytest.raises(
                BMCCapabilityError, match="Unsupported IPMI SEL subcommand"
            ):
                await transport.run("sel unknown_sub")

    @pytest.mark.asyncio
    async def test_run_unknown_command(self, ipmi_config: ConnectionConfig) -> None:
        """Неизвестная команда."""
        with patch("uniconn.transports.bmc._ipmi.ipmi_cmd", MagicMock()):
            from uniconn.transports.bmc._ipmi import IPMITransport

            transport = IPMITransport(ipmi_config)

            with pytest.raises(BMCCapabilityError, match="Unknown IPMI command"):
                await transport.run("reboot custom")


class TestIPMIStream:
    """Тесты потокового выполнения."""

    @pytest.mark.asyncio
    async def test_stream_falls_back_to_run(self, ipmi_config: ConnectionConfig) -> None:
        """Stream использует run."""
        mock_cmd = MagicMock()
        mock_cmd.get_power = MagicMock(return_value={"powerstate": "on"})

        mock_ipmi_module = MagicMock()
        mock_ipmi_module.Command = MagicMock(return_value=mock_cmd)

        with patch("uniconn.transports.bmc._ipmi.ipmi_cmd", mock_ipmi_module):
            from uniconn.transports.bmc._ipmi import IPMITransport

            transport = IPMITransport(ipmi_config)

            lines = []
            async for line in transport.stream("power status"):
                lines.append(line)

            assert len(lines) >= 1

