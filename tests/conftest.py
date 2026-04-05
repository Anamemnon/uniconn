# tests/conftest.py
import pytest
from unittest.mock import AsyncMock, MagicMock
from uniconn.result import Result
from datetime import datetime

# pytest-mock фикстура 'mocker' предоставляется автоматически плагином pytest-mock

@pytest.fixture
def mock_result():
    """Фикстура для создания mock Result"""
    def _create_result(
        exit_code: int = 0,
        stdout: str = "",
        stderr: str = "",
        duration: float = 1.0
    ) -> Result:
        return Result(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration=duration,
            command="test_command",
            timestamp=datetime.now()
        )
    return _create_result

@pytest.fixture
def mock_transport(mocker):
    """Фикстура для мока транспорта"""
    transport = mocker.AsyncMock()
    transport.name = "mock"
    transport.is_connected = True
    transport.run = mocker.AsyncMock(
        return_value=Result(
            exit_code=0,
            stdout="ok",
            stderr="",
            duration=1.0,
            command="test",
            timestamp=datetime.now()
        )
    )
    transport.stream = mocker.AsyncMock()
    transport.stream.return_value.__aiter__.return_value = iter(["line1", "line2"])
    transport.connect = mocker.AsyncMock()
    transport.disconnect = mocker.AsyncMock()
    return transport

@pytest.fixture
def event_loop():
    """Event loop для async тестов"""
    import asyncio
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()