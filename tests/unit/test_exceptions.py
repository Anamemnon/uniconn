# tests/unit/test_exceptions.py
"""Тесты для иерархии исключений"""

import pytest

from uniconn.exceptions import (
    UniconnError,
    ConnectionError,
    AuthenticationError,
    ExecutionError,
    TimeoutError,
    TransportNotFoundError,
    BMCCapabilityError,
)


class TestUniconnError:
    """Тесты базового исключения"""

    def test_basic_message(self):
        """Базовое сообщение об ошибке"""
        exc = UniconnError("Something went wrong")
        assert str(exc) == "Something went wrong"

    def test_with_context(self):
        """Ошибка с контекстом (command, host)"""
        exc = UniconnError(
            "Failed",
            command="uptime",
            host="example.com",
            exit_code=1,
            stdout="output",
            stderr="error"
        )
        assert "command='uptime'" in str(exc)
        assert "host=example.com" in str(exc)

    def test_with_partial_context(self):
        """Ошибка с частичным контекстом"""
        exc = UniconnError("Failed", command="test")
        assert "command='test'" in str(exc)
        assert "host=" not in str(exc)

    def test_inheritance(self):
        """UniconnError наследует Exception"""
        assert issubclass(UniconnError, Exception)


class TestConnectionError:
    """Тесты ConnectionError"""

    def test_connection_error_inheritance(self):
        """ConnectionError наследует UniconnError"""
        assert issubclass(ConnectionError, UniconnError)

    def test_connection_error_with_host(self):
        """ConnectionError с хостом"""
        exc = ConnectionError("Connection refused", host="bad-host")
        assert "host=bad-host" in str(exc)
        assert "Connection refused" in str(exc)


class TestAuthenticationError:
    """Тесты AuthenticationError"""

    def test_auth_error_inheritance(self):
        """AuthenticationError наследует ConnectionError"""
        assert issubclass(AuthenticationError, ConnectionError)

    def test_auth_error_message(self):
        """AuthenticationError сообщение"""
        exc = AuthenticationError("Invalid password", host="server")
        assert "Invalid password" in str(exc)
        assert "host=server" in str(exc)


class TestExecutionError:
    """Тесты ExecutionError"""

    def test_execution_error_inheritance(self):
        """ExecutionError наследует UniconnError"""
        assert issubclass(ExecutionError, UniconnError)

    def test_execution_error_full_context(self):
        """ExecutionError с полным контекстом"""
        exc = ExecutionError(
            "Command failed",
            command="rm -rf /",
            exit_code=127,
            stdout="",
            stderr="permission denied",
            host="prod-server"
        )
        error_str = str(exc)
        assert "command='rm -rf /'" in error_str
        assert "host=prod-server" in error_str


class TestTimeoutError:
    """Тесты TimeoutError"""

    def test_timeout_error_inheritance(self):
        """TimeoutError наследует UniconnError"""
        assert issubclass(TimeoutError, UniconnError)

    def test_timeout_error_not_builtin(self):
        """uniconn.TimeoutError — это не builtins.TimeoutError"""
        # Важно: наше исключение не путать с встроенным
        exc = TimeoutError("Operation timed out", command="slow_cmd")
        assert isinstance(exc, UniconnError)


class TestTransportNotFoundError:
    """Тесты TransportNotFoundError"""

    def test_transport_not_found_inheritance(self):
        """TransportNotFoundError наследует UniconnError"""
        assert issubclass(TransportNotFoundError, UniconnError)

    def test_transport_not_found_message(self):
        """Сообщение о ненайденном транспорте"""
        exc = TransportNotFoundError("Transport 'ftp' not found")
        assert "Transport 'ftp' not found" in str(exc)


class TestBMCCapabilityError:
    """Тесты BMCCapabilityError"""

    def test_bmc_capability_inheritance(self):
        """BMCCapabilityError наследует UniconnError"""
        assert issubclass(BMCCapabilityError, UniconnError)

    def test_bmc_capability_message(self):
        """BMCCapabilityError сообщение"""
        exc = BMCCapabilityError(
            "Unknown command",
            command="power reset",
            host="bmc.local"
        )
        assert "Unknown command" in str(exc)
        assert "command='power reset'" in str(exc)


class TestExceptionHierarchy:
    """Тесты иерархии исключений"""

    def test_catch_by_base_class(self):
        """Дочерние исключения ловятся базовым классом"""
        for exc_class in (
            ConnectionError, AuthenticationError, ExecutionError,
            TimeoutError, TransportNotFoundError, BMCCapabilityError
        ):
            exc = exc_class("test")
            assert isinstance(exc, UniconnError)

    def test_authentication_is_connection_error(self):
        """AuthenticationError — это подтип ConnectionError"""
        exc = AuthenticationError("auth failed")
        assert isinstance(exc, ConnectionError)
