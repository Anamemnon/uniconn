import sys
from datetime import datetime

import pytest

from uniconn.result import Result

posix_only = pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX filesystem or environment capabilities required",
)
windows_only = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Windows environment capabilities required",
)


def pytest_runtest_setup(item: pytest.Item) -> None:
    """Автоматический skip тестов с маркерами posix_only и windows_only."""
    if item.get_closest_marker("posix_only") and sys.platform == "win32":
        pytest.skip("POSIX filesystem or environment capabilities required")
    if item.get_closest_marker("windows_only") and sys.platform != "win32":
        pytest.skip("Windows environment capabilities required")

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
