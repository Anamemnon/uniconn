# tests/unit/test_connection_methods.py
"""Тесты для новых методов Connection: copy, from_dict, from_file, with_overrides"""

import json
import tempfile
import pytest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch, MagicMock

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
            exit_code=0,
            stdout="ok",
            stderr="",
            duration=1.0,
            command="test",
            timestamp=datetime.now(),
            host="testhost",
        )
    )
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


class TestFromDict:
    """Тесты from_dict"""

    def test_from_dict_basic(self, mock_transport_class):
        """Создание из словаря"""
        _, transport = mock_transport_class

        conn = Connection.from_dict({
            "transport": "ssh",
            "host": "example.com",
            "username": "admin",
            "timeout": 60,
        })

        assert conn.config.transport == "ssh"
        assert conn.config.host == "example.com"
        assert conn.config.username == "admin"
        assert conn.config.timeout == 60

    def test_from_dict_with_password(self, mock_transport_class):
        """Создание с паролем"""
        _, transport = mock_transport_class

        conn = Connection.from_dict({
            "transport": "ssh",
            "host": "example.com",
            "username": "admin",
            "password": SecretStr("secret123"),
        })

        assert conn.config.password.get_secret_value() == "secret123"

    def test_from_dict_with_retry(self, mock_transport_class):
        """Создание с кастомным retry_attempts"""
        _, transport = mock_transport_class

        conn = Connection.from_dict(
            {"transport": "ssh", "host": "example.com"},
            retry_attempts=5,
        )

        assert conn._retry_attempts == 5

    def test_from_dict_with_logger(self, mock_transport_class):
        """Создание с кастомным логером"""
        import logging
        _, transport = mock_transport_class

        my_logger = logging.getLogger("my_test")
        conn = Connection.from_dict(
            {"transport": "ssh", "host": "example.com"},
            logger=my_logger,
        )

        assert conn._logger is my_logger


class TestFromFile:
    """Тесты from_file"""

    def test_from_json_file(self, mock_transport_class):
        """Загрузка из JSON файла"""
        _, transport = mock_transport_class

        data = [
            {"transport": "ssh", "host": "node1"},
            {"transport": "ssh", "host": "node2", "username": "admin"},
        ]

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(data, f)
            f.flush()
            conns = Connection.from_file(f.name)

        assert len(conns) == 2
        assert conns[0].config.host == "node1"
        assert conns[1].config.host == "node2"

    def test_from_yaml_file(self, mock_transport_class):
        """Загрузка из YAML файла"""
        _, transport = mock_transport_class

        try:
            import yaml
        except ImportError:
            pytest.skip("PyYAML not installed")

        content = """
- transport: ssh
  host: node1
- transport: ssh
  host: node2
  username: admin
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as f:
            f.write(content)
            f.flush()
            conns = Connection.from_file(f.name)

        assert len(conns) == 2
        assert conns[0].config.host == "node1"

    def test_from_yml_file(self, mock_transport_class):
        """Загрузка из .yml файла"""
        _, transport = mock_transport_class

        try:
            import yaml
        except ImportError:
            pytest.skip("PyYAML not installed")

        content = "- transport: ssh\n  host: server1\n"
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False, encoding="utf-8"
        ) as f:
            f.write(content)
            f.flush()
            conns = Connection.from_file(f.name)

        assert len(conns) == 1
        assert conns[0].config.host == "server1"

    def test_from_single_object_json(self, mock_transport_class):
        """Загрузка одиночного объекта из JSON"""
        _, transport = mock_transport_class

        data = {"transport": "ssh", "host": "single"}

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(data, f)
            f.flush()
            conns = Connection.from_file(f.name)

        assert len(conns) == 1
        assert conns[0].config.host == "single"

    def test_from_unsupported_format(self, mock_transport_class):
        """Неподдерживаемый формат файла"""
        _, _ = mock_transport_class

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".xml", delete=False
        ) as f:
            f.write("<data/>")
            f.flush()

            with pytest.raises(ValueError, match="Unsupported file format"):
                Connection.from_file(f.name)


class TestCopy:
    """Тесты copy"""

    def test_copy_basic(self, mock_transport_class):
        """Базовое копирование"""
        _, _ = mock_transport_class

        original = Connection.from_uri("ssh://admin@original-host")
        copied = original.copy()

        assert copied.config.host == "original-host"
        assert copied.config.transport == original.config.transport
        assert copied._retry_attempts == original._retry_attempts

    def test_copy_change_host(self, mock_transport_class):
        """Копирование с изменением хоста"""
        _, _ = mock_transport_class

        original = Connection.from_uri("ssh://admin@prod-server")
        dev = original.copy(host="dev-server")

        assert dev.config.host == "dev-server"
        assert dev.config.username == "admin"

    def test_copy_change_username(self, mock_transport_class):
        """Копирование с изменением username"""
        _, _ = mock_transport_class

        original = Connection.from_uri("ssh://admin@server")
        copied = original.copy(username="root")

        assert copied.config.username == "root"
        assert copied.config.host == "server"

    def test_copy_change_timeout(self, mock_transport_class):
        """Копирование с изменением таймаута"""
        _, _ = mock_transport_class

        original = Connection.from_uri("ssh://admin@server")
        copied = original.copy(timeout=120)

        assert copied.config.timeout == 120
        assert original.config.timeout == 30  # оригинал не изменён

    def test_copy_with_password_string(self, mock_transport_class):
        """Копирование с паролем как строка"""
        _, _ = mock_transport_class

        original = Connection.from_uri("ssh://admin@server")
        copied = original.copy(password="newpass")

        assert copied.config.password.get_secret_value() == "newpass"

    def test_copy_with_secretstr_password(self, mock_transport_class):
        """Копирование с паролем как SecretStr"""
        _, _ = mock_transport_class

        original = Connection.from_uri("ssh://admin@server")
        copied = original.copy(password=SecretStr("secret"))

        assert copied.config.password.get_secret_value() == "secret"

    def test_copy_preserves_original(self, mock_transport_class):
        """Оригинал не изменяется при копировании"""
        _, _ = mock_transport_class

        original = Connection.from_uri("ssh://admin@original")
        _ = original.copy(host="changed", timeout=100)

        assert original.config.host == "original"
        assert original.config.timeout == 30

    def test_copy_change_retry_attempts(self, mock_transport_class):
        """Копирование с изменением retry_attempts"""
        _, _ = mock_transport_class

        original = Connection.from_uri(
            "ssh://admin@server", retry_attempts=3
        )
        copied = original.copy(retry_attempts=10)

        assert copied._retry_attempts == 10
        assert original._retry_attempts == 3

    def test_copy_with_options(self, mock_transport_class):
        """Копирование с изменением options"""
        _, _ = mock_transport_class

        original = Connection.from_uri("ssh://admin@server")
        copied = original.copy(options={"compress": True})

        assert copied.config.options == {"compress": True}

    def test_copy_with_port(self, mock_transport_class):
        """Копирование с изменением порта"""
        _, _ = mock_transport_class

        original = Connection.from_uri("ssh://admin@server:22")
        copied = original.copy(port=2222)

        assert copied.config.port == 2222
        assert original.config.port == 22


class TestWithOverrides:
    """Тесты with_overrides"""

    def test_overrides_host(self, mock_transport_class):
        """Переопределение хоста"""
        _, _ = mock_transport_class

        original = Connection.from_uri("ssh://admin@prod")
        overridden = original.with_overrides(host="staging")

        assert overridden.config.host == "staging"

    def test_overrides_multiple(self, mock_transport_class):
        """Переопределение нескольких параметров"""
        _, _ = mock_transport_class

        original = Connection.from_uri("ssh://admin@prod:22")
        overridden = original.with_overrides(
            host="dev",
            timeout=120,
            options={"compress": True},
        )

        assert overridden.config.host == "dev"
        assert overridden.config.timeout == 120
        assert overridden.config.options == {"compress": True}

    def test_overrides_preserves_original(self, mock_transport_class):
        """Оригинал не изменяется"""
        _, _ = mock_transport_class

        original = Connection.from_uri("ssh://admin@prod")
        _ = original.with_overrides(host="other")

        assert original.config.host == "prod"

    def test_overrides_empty(self, mock_transport_class):
        """Переопределение без параметров"""
        _, _ = mock_transport_class

        original = Connection.from_uri("ssh://admin@prod")
        cloned = original.with_overrides()

        assert cloned.config.host == "prod"
