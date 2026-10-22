# tests/unit/test_result.py
"""Тесты для Result dataclass"""

from datetime import datetime
import pytest

from uniconn.result import Result
from uniconn.exceptions import ExecutionError


class TestResult:
    """Тесты Result"""

    def test_result_ok(self):
        """Result с exit_code=0 — ok"""
        result = Result(
            exit_code=0, stdout="", stderr="",
            duration=1.0, command="test", timestamp=datetime.now()
        )
        assert result.ok is True

    def test_result_not_ok(self):
        """Result с exit_code!=0 — not ok"""
        result = Result(
            exit_code=1, stdout="", stderr="",
            duration=1.0, command="test", timestamp=datetime.now()
        )
        assert result.ok is False

    def test_result_timestamp_default(self):
        """timestamp по умолчанию — текущее время"""
        result = Result(
            exit_code=0, stdout="", stderr="",
            duration=1.0, command="test"
        )
        assert isinstance(result.timestamp, datetime)
        # Не старше 1 секунды
        assert (datetime.now() - result.timestamp).total_seconds() < 1

    def test_result_str(self):
        """Строковое представление"""
        result = Result(
            exit_code=0, stdout="", stderr="",
            duration=1.234, command="uptime", timestamp=datetime.now()
        )
        repr_str = str(result)
        assert "exit_code=0" in repr_str
        assert "1.23s" in repr_str or "1.23" in repr_str

    def test_result_frozen(self):
        """Result неизменяемый"""
        result = Result(
            exit_code=0, stdout="", stderr="",
            duration=1.0, command="test", timestamp=datetime.now()
        )
        with pytest.raises((TypeError, AttributeError)):
            result.exit_code = 1  # type: ignore[misc]

    def test_result_host_optional(self):
        """host может быть None"""
        result = Result(
            exit_code=0, stdout="", stderr="",
            duration=1.0, command="test", timestamp=datetime.now()
        )
        assert result.host is None

    def test_result_with_host(self):
        """host устанавливается"""
        result = Result(
            exit_code=0, stdout="", stderr="",
            duration=1.0, command="test",
            timestamp=datetime.now(), host="example.com"
        )
        assert result.host == "example.com"


class TestRaiseForStatus:
    """Тесты raise_for_status"""

    def test_raise_for_status_ok(self):
        """raise_for_status не выбрасывает для ok"""
        result = Result(
            exit_code=0, stdout="", stderr="",
            duration=1.0, command="test", timestamp=datetime.now()
        )
        # Не должно выбрасывать исключение
        result.raise_for_status()

    def test_raise_for_status_error(self):
        """raise_for_status выбрасывает ExecutionError"""
        result = Result(
            exit_code=1, stdout="output", stderr="error output",
            duration=1.0, command="false_cmd", timestamp=datetime.now()
        )
        with pytest.raises(ExecutionError) as exc_info:
            result.raise_for_status()

        exc = exc_info.value
        assert exc.exit_code == 1
        assert exc.command == "false_cmd"
        assert exc.stdout == "output"
        assert exc.stderr == "error output"

    def test_raise_for_status_different_codes(self):
        """raise_for_status для разных кодов ошибки"""
        for code in (1, 2, 127, 255):
            result = Result(
                exit_code=code, stdout="", stderr="",
                duration=1.0, command="test", timestamp=datetime.now()
            )
            with pytest.raises(ExecutionError):
                result.raise_for_status()
