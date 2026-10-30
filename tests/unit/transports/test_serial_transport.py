# tests/unit/test_serial_transport.py
"""Тесты для SerialTransport"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

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
    writer.write = MagicMock()
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
        serial_mock, _reader, _writer = mock_serial_asyncio

        with patch(
            "uniconn.transports._serial.serial_asyncio", serial_mock
        ):
            from uniconn.transports._serial import SerialTransport
            transport = SerialTransport(serial_config)
            await transport.connect()

            assert transport.is_connected is True
            serial_mock.open_serial_connection.assert_called_once()

    @pytest.mark.asyncio
    async def test_connect_warns_unencrypted(self, serial_config, mock_serial_asyncio, caplog):
        """Предупреждение о незашифрованном соединении при подключении."""
        import logging

        serial_mock, _, _ = mock_serial_asyncio

        with (
            patch(
                "uniconn.transports._serial.serial_asyncio", serial_mock
            ),
            caplog.at_level(logging.WARNING, logger="uniconn"),
        ):
            from uniconn.transports._serial import SerialTransport
            transport = SerialTransport(serial_config)
            await transport.connect()

            assert any(
                "незашифрованное" in record.message for record in caplog.records
            )

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
        serial_mock, _reader, writer = mock_serial_asyncio

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
        serial_mock, reader, _writer = mock_serial_asyncio

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
        serial_mock, reader, _writer = mock_serial_asyncio

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
        serial_mock, _reader, _writer = mock_serial_asyncio

        with patch(
            "uniconn.transports._serial.serial_asyncio", serial_mock
        ):
            from uniconn.transports._serial import SerialTransport
            transport = SerialTransport(serial_config)

            async with transport as t:
                assert t.is_connected is True

            assert transport.is_connected is False



class TestSerialFramingAndBugs:
    """Тесты на устранение критических багов кадрирования и чтения."""

    @pytest.mark.asyncio
    async def test_run_prompt_without_newline(self, serial_config, mock_serial_asyncio):
        """Промпт без символа перевода строки не теряется и возвращается в stdout."""
        serial_mock, _, writer = mock_serial_asyncio
        reader = asyncio.StreamReader()
        reader.feed_data(b"Switch# ")

        with patch("uniconn.transports._serial.serial_asyncio", serial_mock):
            from uniconn.transports._serial import SerialTransport

            serial_mock.open_serial_connection = AsyncMock(return_value=(reader, writer))
            transport = SerialTransport(serial_config)
            await transport.connect()

            res = await transport.run("show version", timeout=1.0, inter_byte_timeout=0.05)
            assert "Switch#" in res.stdout
            assert res.ok

    @pytest.mark.asyncio
    async def test_run_no_artificial_one_second_delay(self, serial_config, mock_serial_asyncio):
        """Быстрый ответ с read_until завершается немедленно без ожидания 1.0 с."""
        serial_mock, _, writer = mock_serial_asyncio
        reader = asyncio.StreamReader()
        reader.feed_data(b"OK\r\n")

        with patch("uniconn.transports._serial.serial_asyncio", serial_mock):
            from uniconn.transports._serial import SerialTransport

            serial_mock.open_serial_connection = AsyncMock(return_value=(reader, writer))
            transport = SerialTransport(serial_config)
            await transport.connect()

            t0 = asyncio.get_running_loop().time()
            res = await transport.run("AT", timeout=2.0, read_until="OK")
            duration = asyncio.get_running_loop().time() - t0

            assert res.stdout == "OK"
            assert duration < 0.2  # Намного быстрее 1.0 с

    @pytest.mark.asyncio
    async def test_run_read_until_timeout_raises(self, serial_config, mock_serial_asyncio):
        """Если read_until не получен, выбрасывается UniconnTimeoutError, а не фиктивный успех."""
        serial_mock, _, writer = mock_serial_asyncio
        reader = asyncio.StreamReader()
        reader.feed_data(b"SOME OTHER OUTPUT\r\n")

        with patch("uniconn.transports._serial.serial_asyncio", serial_mock):
            from uniconn.exceptions import TimeoutError as UniconnTimeoutError
            from uniconn.transports._serial import SerialTransport

            serial_mock.open_serial_connection = AsyncMock(return_value=(reader, writer))
            transport = SerialTransport(serial_config)
            await transport.connect()

            with pytest.raises(UniconnTimeoutError, match="waiting for b'EXPECTED_PROMPT'"):
                await transport.run("cmd", timeout=0.2, read_until="EXPECTED_PROMPT")

    @pytest.mark.asyncio
    async def test_run_prompt_regex(self, serial_config, mock_serial_asyncio):
        """Остановка чтения по regex-промпту."""
        serial_mock, _, writer = mock_serial_asyncio
        reader = asyncio.StreamReader()
        reader.feed_data(b"booting...\r\nlogin: ")

        with patch("uniconn.transports._serial.serial_asyncio", serial_mock):
            from uniconn.transports._serial import SerialTransport

            serial_mock.open_serial_connection = AsyncMock(return_value=(reader, writer))
            transport = SerialTransport(serial_config)
            await transport.connect()

            res = await transport.run("init", timeout=1.0, prompt_pattern=r"login:\s*$")
            assert "login:" in res.stdout

    @pytest.mark.asyncio
    async def test_run_preserves_indentation_and_spaces(self, serial_config, mock_serial_asyncio):
        """Пробелы и отступы не срезаются слепым rstrip()."""
        serial_mock, _, writer = mock_serial_asyncio
        reader = asyncio.StreamReader()
        reader.feed_data(b"    config_key: value  \r\n        nested: true\r\n")

        with patch("uniconn.transports._serial.serial_asyncio", serial_mock):
            from uniconn.transports._serial import SerialTransport

            serial_mock.open_serial_connection = AsyncMock(return_value=(reader, writer))
            transport = SerialTransport(serial_config)
            await transport.connect()

            res = await transport.run("get_config", timeout=1.0, inter_byte_timeout=0.05)
            assert "    config_key: value  " in res.stdout
            assert "        nested: true" in res.stdout

    @pytest.mark.asyncio
    async def test_run_connection_lost_raises_connection_error(self, serial_config, mock_serial_asyncio):
        """Обрыв USB-соединения транслируется в ConnectionError и сбрасывает is_connected."""
        serial_mock, _, writer = mock_serial_asyncio
        reader = asyncio.StreamReader()

        with patch("uniconn.transports._serial.serial_asyncio", serial_mock):
            from uniconn.exceptions import ConnectionError
            from uniconn.transports._serial import SerialTransport

            serial_mock.open_serial_connection = AsyncMock(return_value=(reader, writer))
            transport = SerialTransport(serial_config)
            await transport.connect()

            writer.drain = AsyncMock(side_effect=OSError("Device disconnected"))

            with pytest.raises(ConnectionError, match="connection lost"):
                await transport.run("test")

            assert transport.is_connected is False


class TestSerialBinaryAndListen:
    """Тесты бинарного режима и пассивного прослушивания."""

    @pytest.mark.asyncio
    async def test_run_bytes_round_trip(self, serial_config, mock_serial_asyncio):
        """run_bytes отправляет и принимает сырые байты без UTF-8 подмены."""
        serial_mock, _, writer = mock_serial_asyncio
        reader = asyncio.StreamReader()
        # Бинарный ответ Modbus RTU с байтами > 0x7F
        raw_response = b"\x01\x03\x04\x00\x01\x00\x02\xc4\x0b"
        reader.feed_data(raw_response)

        with patch("uniconn.transports._serial.serial_asyncio", serial_mock):
            from uniconn.transports._serial import SerialTransport

            serial_mock.open_serial_connection = AsyncMock(return_value=(reader, writer))
            transport = SerialTransport(serial_config)
            await transport.connect()

            raw_req = b"\x01\x03\x00\x00\x00\x02\xc4\x0b"
            out = await transport.run_bytes(raw_req, timeout=1.0, inter_byte_timeout=0.05)
            assert out == raw_response
            writer.write.assert_called_with(raw_req)

    @pytest.mark.asyncio
    async def test_passive_listen_stream(self, serial_config, mock_serial_asyncio):
        """stream(command=None) работает в режиме пассивного прослушивания (Sniffer/Monitor)."""
        serial_mock, _, writer = mock_serial_asyncio
        reader = asyncio.StreamReader()
        reader.feed_data(b"$GPGGA,123519,4807.038,N\r\n$GPRMC,123519,A,4807.038,N\r\n")

        with patch("uniconn.transports._serial.serial_asyncio", serial_mock):
            from uniconn.transports._serial import SerialTransport

            serial_mock.open_serial_connection = AsyncMock(return_value=(reader, writer))
            transport = SerialTransport(serial_config)
            await transport.connect()

            lines = []
            async for line in transport.stream(command=None, timeout=0.1):
                lines.append(line)

            assert len(lines) == 2
            assert "$GPGGA" in lines[0]
            assert "$GPRMC" in lines[1]
            writer.write.assert_not_called()

    @pytest.mark.asyncio
    async def test_stream_bytes(self, serial_config, mock_serial_asyncio):
        """stream_bytes читает поток сырыми порциями."""
        serial_mock, _, writer = mock_serial_asyncio
        reader = asyncio.StreamReader()
        reader.feed_data(b"\xAA\xBB\xCC\xDD")

        with patch("uniconn.transports._serial.serial_asyncio", serial_mock):
            from uniconn.transports._serial import SerialTransport

            serial_mock.open_serial_connection = AsyncMock(return_value=(reader, writer))
            transport = SerialTransport(serial_config)
            await transport.connect()

            chunks = []
            async for chunk in transport.stream_bytes(timeout=0.1):
                chunks.append(chunk)

            assert chunks == [b"\xAA\xBB\xCC\xDD"]


class TestSerialHardwareSignals:
    """Тесты аппаратного управления DTR/RTS/BREAK."""

    @pytest.mark.asyncio
    async def test_dtr_and_rts_control(self, serial_config, mock_serial_asyncio):
        """Управление линиями DTR и RTS."""
        serial_mock, reader, writer = mock_serial_asyncio
        mock_raw_serial = MagicMock()
        mock_raw_serial.dtr = False
        mock_raw_serial.rts = False
        mock_raw_serial.cts = True
        mock_raw_serial.dsr = True
        mock_raw_serial.ri = False
        mock_raw_serial.cd = True

        writer.get_extra_info = MagicMock(side_effect=lambda key: mock_raw_serial if key == "serial" else None)

        with patch("uniconn.transports._serial.serial_asyncio", serial_mock):
            from uniconn.transports._serial import SerialTransport

            serial_mock.open_serial_connection = AsyncMock(return_value=(reader, writer))
            transport = SerialTransport(serial_config)
            await transport.connect()

            transport.set_dtr(True)
            assert mock_raw_serial.dtr is True

            transport.set_rts(True)
            assert mock_raw_serial.rts is True

            assert transport.get_cts() is True
            assert transport.get_dsr() is True
            assert transport.get_ri() is False
            assert transport.get_cd() is True

            transport.send_break(0.1)
            mock_raw_serial.send_break.assert_called_once_with(duration=0.1)

    @pytest.mark.asyncio
    async def test_pulse_dtr_rts(self, serial_config, mock_serial_asyncio):
        """Импульс аппаратного сброса pulse_dtr_rts."""
        serial_mock, reader, writer = mock_serial_asyncio
        mock_raw_serial = MagicMock()
        writer.get_extra_info = MagicMock(side_effect=lambda key: mock_raw_serial if key == "serial" else None)

        with patch("uniconn.transports._serial.serial_asyncio", serial_mock):
            from uniconn.transports._serial import SerialTransport

            serial_mock.open_serial_connection = AsyncMock(return_value=(reader, writer))
            transport = SerialTransport(serial_config)
            await transport.connect()

            await transport.pulse_dtr_rts(dtr=False, rts=True, duration=0.01)
            assert mock_raw_serial.dtr is True
            assert mock_raw_serial.rts is False

    @pytest.mark.asyncio
    async def test_safe_ping(self, serial_config, mock_serial_asyncio):
        """ping() не отправляет echo ping в линию, а проверяет дескриптор."""
        serial_mock, reader, writer = mock_serial_asyncio
        mock_raw_serial = MagicMock()
        mock_raw_serial.is_open = True
        writer.get_extra_info = MagicMock(side_effect=lambda key: mock_raw_serial if key == "serial" else None)

        with patch("uniconn.transports._serial.serial_asyncio", serial_mock):
            from uniconn.transports._serial import SerialTransport

            serial_mock.open_serial_connection = AsyncMock(return_value=(reader, writer))
            transport = SerialTransport(serial_config)
            await transport.connect()

            ok = await transport.ping()
            assert ok is True
            writer.write.assert_not_called()


class TestSerialProcessProtocolAndShell:
    """Тесты соответствия ShellProcessProtocol."""

    @pytest.mark.asyncio
    async def test_shell_process_implements_protocol(self, serial_config, mock_serial_asyncio):
        """_SerialShellProcess удовлетворяет ShellProcessProtocol (включая is_closing)."""
        serial_mock, reader, writer = mock_serial_asyncio

        with patch("uniconn.transports._serial.serial_asyncio", serial_mock):
            from uniconn.transports._serial import SerialTransport
            from uniconn.transports.base import ShellProcessProtocol

            serial_mock.open_serial_connection = AsyncMock(return_value=(reader, writer))
            transport = SerialTransport(serial_config)
            await transport.connect()

            proc = await transport.open_shell()
            assert isinstance(proc, ShellProcessProtocol)
            assert proc.is_closing() is False
            proc.close()
            assert proc.is_closing() is True


class TestSerialURIAndConfiguration:
    """Тесты парсинга URI, схем и параметров связи."""

    def test_uart_scheme_parsing(self):
        """Схема uart:// парсится наравне с serial://."""
        from uniconn.config.uri import URIParser

        cfg = URIParser.parse("uart:///dev/ttyUSB0?baudrate=115200")
        assert cfg.transport == "uart"
        assert cfg.host == "/dev/ttyUSB0"
        assert cfg.options["device"] == "/dev/ttyUSB0"
        assert cfg.options["baudrate"] == 115200
        assert "uart:///dev/ttyUSB0:115200" in cfg.uri_safe

    def test_uri_port_as_baudrate(self):
        """Задание скорости в поле порта serial://COM3:115200."""
        from uniconn.config.uri import URIParser

        cfg = URIParser.parse("serial://COM3:115200")
        assert cfg.host == "COM3"
        assert cfg.options["device"] == "COM3"
        assert cfg.options["baudrate"] == 115200
        assert "COM3:115200" in cfg.uri_safe

    def test_windows_com_path_normalization(self):
        """Нормализация пути Windows serial:///COM3 -> COM3."""
        from uniconn.config.uri import URIParser

        cfg = URIParser.parse("serial:///COM3?baudrate=9600")
        assert cfg.host == "COM3"
        assert cfg.options["device"] == "COM3"

    def test_parity_comprehensive(self):
        """Поддержка строковых обозначений четности (even, odd, none)."""
        from uniconn._config import ConnectionConfig
        from uniconn.transports._serial import SerialTransport

        with patch("uniconn.transports._serial.serial_asyncio", MagicMock()):
            import serial

            for val, expected in [
                ("even", serial.PARITY_EVEN),
                ("ODD", serial.PARITY_ODD),
                ("none", serial.PARITY_NONE),
                ("E", serial.PARITY_EVEN),
                ("N", serial.PARITY_NONE),
            ]:
                cfg = ConnectionConfig(transport="serial", options={"device": "COM1", "parity": val})
                t = SerialTransport(cfg)
                kwargs = t._get_serial_kwargs()
                assert kwargs["parity"] == expected

    def test_stopbits_comprehensive(self):
        """Поддержка стоп-битов 1, 1.5, 2 в виде float, int и str."""
        from uniconn._config import ConnectionConfig
        from uniconn.transports._serial import SerialTransport

        with patch("uniconn.transports._serial.serial_asyncio", MagicMock()):
            import serial

            for val, expected in [
                (1, serial.STOPBITS_ONE),
                (1.5, serial.STOPBITS_ONE_POINT_FIVE),
                ("1.5", serial.STOPBITS_ONE_POINT_FIVE),
                (2, serial.STOPBITS_TWO),
                ("2", serial.STOPBITS_TWO),
            ]:
                cfg = ConnectionConfig(transport="serial", options={"device": "COM1", "stopbits": val})
                t = SerialTransport(cfg)
                kwargs = t._get_serial_kwargs()
                assert kwargs["stopbits"] == expected

    def test_invalid_parity_raises(self):
        """Невалидная четность вызывает ConfigurationError."""
        from uniconn._config import ConnectionConfig
        from uniconn.exceptions import ConfigurationError
        from uniconn.transports._serial import SerialTransport

        with patch("uniconn.transports._serial.serial_asyncio", MagicMock()):
            cfg = ConnectionConfig(transport="serial", options={"device": "COM1", "parity": "invalid"})
            t = SerialTransport(cfg)
            with pytest.raises(ConfigurationError, match="Unsupported serial parity"):
                t._get_serial_kwargs()


class TestSerialPortDiscovery:
    """Тесты перечисления портов."""

    def test_list_serial_ports(self):
        """Функция list_serial_ports возвращает структурированный список."""
        mock_port = MagicMock()
        mock_port.device = "COM3"
        mock_port.name = "COM3"
        mock_port.description = "Silicon Labs CP210x"
        mock_port.hwid = "USB VID:PID=10C4:EA60"
        mock_port.vid = 0x10C4
        mock_port.pid = 0xEA60
        mock_port.serial_number = "0001"
        mock_port.manufacturer = "Silicon Labs"
        mock_port.product = "CP210x"
        mock_port.interface = None

        with patch("serial.tools.list_ports.comports", return_value=[mock_port]):
            from uniconn.transports._serial import list_serial_ports

            ports = list_serial_ports()
            assert len(ports) == 1
            assert ports[0].device == "COM3"
            assert ports[0].vid_pid_hex == "10C4:EA60"

    def test_auto_device_detection_by_vid_pid(self):
        """Авто-определение устройства по VID/PID."""
        mock_port = MagicMock()
        mock_port.device = "/dev/ttyUSB1"
        mock_port.hwid = "VID:PID=10C4:EA60"
        mock_port.vid = 0x10C4
        mock_port.pid = 0xEA60
        mock_port.description = "CP2102"
        mock_port.manufacturer = "Silicon Labs"

        with (
            patch("uniconn.transports._serial.serial_asyncio", MagicMock()),
            patch("serial.tools.list_ports.comports", return_value=[mock_port]),
        ):
            from uniconn._config import ConnectionConfig
            from uniconn.transports._serial import SerialTransport

            cfg = ConnectionConfig(transport="serial", options={"vid": "0x10c4", "pid": "0xea60"})
            t = SerialTransport(cfg)
            assert t._device == "/dev/ttyUSB1"

    def test_auto_device_detection_by_vid_pid_without_0x_prefix(self):
        """Авто-определение по VID/PID без префикса 0x (например, 10c4:ea60)."""
        mock_port = MagicMock()
        mock_port.device = "/dev/ttyUSB2"
        mock_port.hwid = "VID:PID=10C4:EA60"
        mock_port.vid = 0x10C4
        mock_port.pid = 0xEA60
        mock_port.description = "CP2102"
        mock_port.manufacturer = "Silicon Labs"

        with (
            patch("uniconn.transports._serial.serial_asyncio", MagicMock()),
            patch("serial.tools.list_ports.comports", return_value=[mock_port]),
        ):
            from uniconn._config import ConnectionConfig
            from uniconn.transports._serial import SerialTransport

            cfg = ConnectionConfig(transport="serial", options={"vid": "10c4", "pid": "ea60"})
            t = SerialTransport(cfg)
            assert t._device == "/dev/ttyUSB2"

    def test_auto_device_detection_by_vid_pid_combined(self):
        """Авто-определение по объединённой опции vid_pid='10c4:ea60'."""
        mock_port = MagicMock()
        mock_port.device = "/dev/ttyUSB3"
        mock_port.hwid = "VID:PID=10C4:EA60"
        mock_port.vid = 0x10C4
        mock_port.pid = 0xEA60
        mock_port.description = "CP2102"
        mock_port.manufacturer = "Silicon Labs"

        with (
            patch("uniconn.transports._serial.serial_asyncio", MagicMock()),
            patch("serial.tools.list_ports.comports", return_value=[mock_port]),
        ):
            from uniconn._config import ConnectionConfig
            from uniconn.transports._serial import SerialTransport

            cfg = ConnectionConfig(transport="serial", options={"vid_pid": "10c4:ea60"})
            t = SerialTransport(cfg)
            assert t._device == "/dev/ttyUSB3"

    def test_filter_not_found_raises_connection_error(self):
        """Если фильтр VID/PID/pattern не найден, выбрасывается ConnectionError, а не COM1."""
        with (
            patch("uniconn.transports._serial.serial_asyncio", MagicMock()),
            patch("serial.tools.list_ports.comports", return_value=[]),
        ):
            from uniconn._config import ConnectionConfig
            from uniconn.exceptions import ConnectionError
            from uniconn.transports._serial import SerialTransport

            cfg = ConnectionConfig(transport="serial", options={"vid": "ffff", "pid": "0000"})
            with pytest.raises(ConnectionError, match="No serial port matching filter"):
                SerialTransport(cfg)

    @pytest.mark.asyncio
    async def test_read_lines_timeout_raises(self, serial_config):
        """Если запрошено N строк, но пришло меньше до таймаута, выбрасывается UniconnTimeoutError."""
        reader = asyncio.StreamReader()
        reader.feed_data(b"only one line\n")
        writer = MagicMock()
        writer.drain = AsyncMock()

        serial_mock = MagicMock()
        serial_mock.open_serial_connection = AsyncMock(return_value=(reader, writer))

        with patch("uniconn.transports._serial.serial_asyncio", serial_mock):
            from uniconn.exceptions import TimeoutError as UniconnTimeoutError
            from uniconn.transports._serial import SerialTransport

            t = SerialTransport(serial_config)
            await t.connect()

            with pytest.raises(UniconnTimeoutError, match="waiting for 3 lines"):
                await t.run("cmd", timeout=0.1, read_lines=3)

    @pytest.mark.asyncio
    async def test_is_connected_reflects_serial_instance_open_state(self, serial_config):
        """is_connected отражает физическое состояние порта (serial_instance.is_open)."""
        reader = asyncio.StreamReader()
        writer = MagicMock()
        writer.drain = AsyncMock()

        mock_hw_serial = MagicMock()
        mock_hw_serial.is_open = True
        writer.get_extra_info.return_value = mock_hw_serial

        serial_mock = MagicMock()
        serial_mock.open_serial_connection = AsyncMock(return_value=(reader, writer))

        with patch("uniconn.transports._serial.serial_asyncio", serial_mock):
            from uniconn.transports._serial import SerialTransport

            t = SerialTransport(serial_config)
            await t.connect()
            assert t.is_connected is True

            # Порт физически закрылся
            mock_hw_serial.is_open = False
            assert t.is_connected is False

    @pytest.mark.asyncio
    async def test_uart_scheme_skips_posix_initialization(self):
        """Для схемы uart:// не запускается POSIX initialize (stty, export PS1)."""
        from uniconn import Connection
        from uniconn.transports._serial import _SerialShellProcess

        reader = asyncio.StreamReader()
        writer = MagicMock()
        writer.drain = AsyncMock()
        writer.is_closing.return_value = False

        mock_proc = _SerialShellProcess(reader, writer)
        mock_transport = MagicMock()
        mock_transport.is_connected = True
        mock_transport.name = "uart"
        mock_transport.open_shell = AsyncMock(return_value=mock_proc)

        conn = Connection.from_uri("uart://COM3:115200")
        conn._transport = mock_transport

        with patch("uniconn.core.shell_facade.ShellSession.initialize", new_callable=AsyncMock) as mock_init:
            session = await conn.open_shell()
            assert session is not None
            mock_init.assert_not_called()

    @pytest.mark.asyncio
    async def test_flush_input_buffer_resets_hardware_buffer(self, serial_config):
        """_flush_input_buffer вызывает reset_input_buffer на аппаратном дескрипторе."""
        reader = asyncio.StreamReader()
        writer = MagicMock()
        writer.drain = AsyncMock()

        mock_hw_serial = MagicMock()
        writer.get_extra_info.return_value = mock_hw_serial

        serial_mock = MagicMock()
        serial_mock.open_serial_connection = AsyncMock(return_value=(reader, writer))

        with patch("uniconn.transports._serial.serial_asyncio", serial_mock):
            from uniconn.transports._serial import SerialTransport

            t = SerialTransport(serial_config)
            await t.connect()

            t._flush_input_buffer()
            mock_hw_serial.reset_input_buffer.assert_called_once()

    @pytest.mark.asyncio
    async def test_connection_passive_stream_without_command(self):
        """Connection.stream() без передачи command запускает пассивный режим прослушивания."""
        from uniconn import Connection

        mock_transport = MagicMock()
        mock_transport.is_connected = True
        mock_transport.name = "serial"

        async def fake_stream(cmd=None, **kwargs):
            assert cmd is None
            yield "NMEA sentence 1"
            yield "NMEA sentence 2"

        mock_transport.stream = fake_stream

        conn = Connection.from_uri("serial:///dev/ttyUSB0")
        conn._transport = mock_transport

        lines = []
        async for line in conn.stream():
            lines.append(line)

        assert lines == ["NMEA sentence 1", "NMEA sentence 2"]

