# tests/unit/test_uri.py
"""Тесты для URIParser"""

import pytest
from uniconn._uri import URIParser


class TestNetworkURIParsing:
    """Тесты парсинга сетевых URI"""

    def test_basic_ssh_uri(self):
        """Парсинг базового SSH URI"""
        config = URIParser.parse("ssh://user:pass@host:22")
        assert config.transport == "ssh"
        assert config.host == "host"
        assert config.port == 22
        assert config.username == "user"
        assert config.password.get_secret_value() == "pass"

    def test_ssh_uri_without_port(self):
        """SSH URI без порта — должен подставить 22"""
        config = URIParser.parse("ssh://user@host")
        assert config.port == 22

    def test_ssh_uri_with_custom_port(self):
        """SSH URI с кастомным портом"""
        config = URIParser.parse("ssh://admin@server.example.com:2222")
        assert config.host == "server.example.com"
        assert config.port == 2222
        assert config.username == "admin"

    def test_telnet_uri(self):
        """Парсинг Telnet URI"""
        config = URIParser.parse("telnet://user:secret@router:23")
        assert config.transport == "telnet"
        assert config.host == "router"
        assert config.port == 23
        assert config.username == "user"
        assert config.password.get_secret_value() == "secret"

    def test_telnet_uri_default_port(self):
        """Telnet URI без порта — должен подставить 23"""
        config = URIParser.parse("telnet://host")
        assert config.port == 23

    def test_ipmi_uri(self):
        """Парсинг IPMI URI"""
        config = URIParser.parse("ipmi://admin:password@bmc.local:623")
        assert config.transport == "ipmi"
        assert config.host == "bmc.local"
        assert config.port == 623
        assert config.username == "admin"

    def test_ipmi_uri_default_port(self):
        """IPMI URI без порта — должен подставить 623"""
        config = URIParser.parse("ipmi://user@bmc")
        assert config.port == 623


class TestSerialURIParsing:
    """Тесты парсинга Serial URI"""

    def test_serial_uri_linux(self):
        """Serial URI для Linux"""
        config = URIParser.parse("serial:///dev/ttyUSB0?baudrate=9600")
        assert config.transport == "serial"
        # Ведущий / сохраняется — это часть пути устройства
        assert config.options["device"] == "/dev/ttyUSB0"
        assert config.options["baudrate"] == 9600

    def test_serial_uri_windows(self):
        """Serial URI для Windows"""
        config = URIParser.parse("serial://COM3?baudrate=115200")
        assert config.transport == "serial"
        assert config.options["device"] == "COM3"
        assert config.options["baudrate"] == 115200

    def test_serial_uri_with_full_options(self):
        """Serial URI с полным набором опций"""
        config = URIParser.parse(
            "serial:///dev/ttyUSB0?baudrate=9600&parity=N&stopbits=1"
        )
        assert config.options["baudrate"] == 9600
        assert config.options["parity"] == "N"
        assert config.options["stopbits"] == 1

    def test_serial_uri_no_options(self):
        """Serial URI без опций"""
        config = URIParser.parse("serial:///dev/ttyS0")
        assert config.transport == "serial"
        # device извлекается из path
        assert config.options["device"] == "/dev/ttyS0"


class TestLocalURIParsing:
    """Тесты парсинга Local URI"""

    def test_local_uri_basic(self):
        """Базовый Local URI"""
        config = URIParser.parse("local://")
        assert config.transport == "local"
        assert config.host == "localhost"

    def test_local_uri_with_options(self):
        """Local URI с опциями"""
        config = URIParser.parse("local://?timeout=60")
        assert config.options["timeout"] == 60


class TestURIOptions:
    """Тесты обработки опций"""

    def test_int_option(self):
        """Целочисленные опции"""
        config = URIParser.parse("ssh://host?timeout=30")
        assert config.options["timeout"] == 30
        assert isinstance(config.options["timeout"], int)

    def test_float_option(self):
        """Опции с плавающей точкой"""
        config = URIParser.parse("ssh://host?threshold=3.14")
        assert config.options["threshold"] == 3.14
        assert isinstance(config.options["threshold"], float)

    def test_bool_option_true(self):
        """Булевы опции — True"""
        for value in ("true", "True", "TRUE", "yes"):
            config = URIParser.parse(f"ssh://host?flag={value}")
            assert config.options["flag"] is True, f"Failed for {value}"

    def test_bool_option_false(self):
        """Булевы опции — False"""
        for value in ("false", "False", "FALSE", "no"):
            config = URIParser.parse(f"ssh://host?flag={value}")
            assert config.options["flag"] is False, f"Failed for {value}"

    def test_string_option(self):
        """Строковые опции"""
        config = URIParser.parse("ssh://host?encoding=utf-8")
        assert config.options["encoding"] == "utf-8"

    def test_multiple_options(self):
        """Несколько опций"""
        config = URIParser.parse(
            "ssh://host?timeout=60&compress=true&encoding=utf-8"
        )
        assert config.options["timeout"] == 60
        assert config.options["compress"] is True
        assert config.options["encoding"] == "utf-8"


class TestURIBuilder:
    """Тесты сборки URI"""

    def test_build_ssh_uri(self):
        """Сборка SSH URI"""
        uri = URIParser.build(
            "ssh", host="example.com", port=22,
            username="admin", password="secret"
        )
        assert uri == "ssh://admin:secret@example.com:22"

    def test_build_ssh_uri_no_auth(self):
        """Сборка SSH URI без аутентификации"""
        uri = URIParser.build("ssh", host="example.com", port=22)
        assert uri == "ssh://example.com:22"

    def test_build_local_uri(self):
        """Сборка Local URI"""
        uri = URIParser.build("local")
        assert uri == "local://"

    def test_build_local_uri_with_options(self):
        """Сборка Local URI с опциями"""
        uri = URIParser.build("local", options={"timeout": 60})
        assert uri == "local://?timeout=60"

    def test_build_serial_uri(self):
        """Сборка Serial URI"""
        uri = URIParser.build(
            "serial", host="/dev/ttyUSB0",
            options={"baudrate": 9600}
        )
        assert uri == "serial:///dev/ttyUSB0?baudrate=9600"

    def test_build_uri_with_options(self):
        """Сборка URI с опциями"""
        uri = URIParser.build(
            "ssh", host="host", username="user",
            options={"timeout": "30", "compress": "true"}
        )
        assert "?timeout=30&compress=true" in uri


class TestURIErrorHandling:
    """Тесты обработки ошибок"""

    def test_invalid_uri_no_scheme(self):
        """URI без схемы"""
        with pytest.raises(ValueError, match="схему"):
            URIParser.parse("user@host")

    def test_invalid_uri_empty(self):
        """Пустая строка"""
        with pytest.raises(ValueError):
            URIParser.parse("")


class TestPercentEncoding:
    """Тесты percent-decoding креденшелов и экранирования в build()"""

    def test_parse_decodes_username_and_password(self):
        """Percent-encoded логин/пароль декодируются при парсинге"""
        config = URIParser.parse("ssh://user%40corp:p%40ss%3Aw%2Frd@host")
        assert config.username == "user@corp"
        assert config.password.get_secret_value() == "p@ss:w/rd"

    def test_build_quotes_credentials(self):
        """build() экранирует спецсимволы в логине/пароле"""
        uri = URIParser.build(
            "ssh", host="host", username="user@corp", password="p@ss:w/rd"
        )
        assert uri == "ssh://user%40corp:p%40ss%3Aw%2Frd@host"

    def test_round_trip_special_chars(self):
        """parse → build → parse сохраняет креденшелы со спецсимволами"""
        config1 = URIParser.parse("ssh://user%40corp:p%40ss%3Aw%2Frd@host:2222")
        uri = URIParser.build(
            config1.transport,
            host=config1.host,
            port=config1.port,
            username=config1.username,
            password=config1.password.get_secret_value(),
        )
        config2 = URIParser.parse(uri)
        assert config2.username == config1.username
        assert (
            config2.password.get_secret_value()
            == config1.password.get_secret_value()
        )
        assert config2.host == config1.host
        assert config2.port == config1.port


class TestRepeatedQueryParams:
    """Тесты повторяющихся query-параметров"""

    def test_repeated_param_last_wins(self):
        """?opt=1&opt=2 — побеждает последнее значение, без исключения"""
        config = URIParser.parse("ssh://host?opt=1&opt=2")
        assert config.options["opt"] == 2

    def test_repeated_param_mixed_types(self):
        """Повторяющийся параметр с разными значениями"""
        config = URIParser.parse("ssh://host?timeout=10&timeout=60")
        assert config.options["timeout"] == 60
