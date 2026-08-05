# tests/unit/test_base_transport.py
"""Тесты BaseTransport: ping() и NotImplementedError-ветки файловых операций."""

import pytest

from uniconn._config import ConnectionConfig
from uniconn.result import Result
from uniconn.transports._base import BaseTransport


class DummyTransport(BaseTransport):
    """Минимальная конкретная реализация для тестов базового класса."""

    def __init__(self, config, run_result: Result | None = None, run_error=None):
        """Инициализировать транспорт с заготовленным результатом/ошибкой run."""
        super().__init__(config)
        self._run_result = run_result
        self._run_error = run_error
        self.connected_calls = 0
        self.disconnected_calls = 0

    @property
    def name(self) -> str:
        """Название транспорта."""
        return "dummy"

    async def connect(self) -> None:
        """Установить подключение (счётчик вызовов)."""
        self.connected_calls += 1
        self._connected = True

    async def disconnect(self) -> None:
        """Закрыть подключение (счётчик вызовов)."""
        self.disconnected_calls += 1
        self._connected = False

    async def run(self, command, timeout=None, **kwargs):
        """Вернуть заготовленный Result или бросить заготовленную ошибку."""
        if self._run_error is not None:
            raise self._run_error
        return self._run_result

    async def stream(self, command, timeout=None, **kwargs):
        """Потоковое выполнение (одна строка)."""
        yield "line"


@pytest.fixture
def config():
    """Конфигурация для DummyTransport."""
    return ConnectionConfig(transport="dummy", host="example.com")


def _ok_result() -> Result:
    return Result(
        exit_code=0, stdout="ok", stderr="", duration=0.1, command="echo ping"
    )


class TestBaseTransportPing:
    """Тесты BaseTransport.ping()."""

    @pytest.mark.asyncio
    async def test_ping_not_connected(self, config):
        """Без подключения ping → False (run не вызывается)."""
        transport = DummyTransport(config, run_result=_ok_result())
        assert await transport.ping() is False

    @pytest.mark.asyncio
    async def test_ping_ok(self, config):
        """Подключён и команда успешна → True."""
        transport = DummyTransport(config, run_result=_ok_result())
        await transport.connect()
        assert await transport.ping() is True

    @pytest.mark.asyncio
    async def test_ping_nonzero_exit(self, config):
        """Ненулевой exit_code → False."""
        result = Result(
            exit_code=1, stdout="", stderr="", duration=0.1, command="echo ping"
        )
        transport = DummyTransport(config, run_result=result)
        await transport.connect()
        assert await transport.ping() is False

    @pytest.mark.asyncio
    async def test_ping_exception(self, config):
        """Исключение в run → False (не пробрасывается)."""
        transport = DummyTransport(config, run_error=OSError("boom"))
        await transport.connect()
        assert await transport.ping() is False


class TestBaseTransportNotImplemented:
    """Файловые операции базового класса бросают NotImplementedError."""

    @pytest.mark.asyncio
    async def test_upload_not_implemented(self, config):
        """Upload → NotImplementedError."""
        transport = DummyTransport(config)
        with pytest.raises(NotImplementedError, match="Upload not supported"):
            await transport.upload("/a", "/b")

    @pytest.mark.asyncio
    async def test_download_not_implemented(self, config):
        """Download → NotImplementedError."""
        transport = DummyTransport(config)
        with pytest.raises(NotImplementedError, match="Download not supported"):
            await transport.download("/a", "/b")

    @pytest.mark.asyncio
    async def test_chmod_not_implemented(self, config):
        """Chmod → NotImplementedError."""
        transport = DummyTransport(config)
        with pytest.raises(NotImplementedError, match="chmod not supported"):
            await transport.chmod("/a", 0o755)

    @pytest.mark.asyncio
    async def test_stat_not_implemented(self, config):
        """Stat → NotImplementedError."""
        transport = DummyTransport(config)
        with pytest.raises(NotImplementedError, match="stat not supported"):
            await transport.stat("/a")

    @pytest.mark.asyncio
    async def test_listdir_not_implemented(self, config):
        """Listdir → NotImplementedError."""
        transport = DummyTransport(config)
        with pytest.raises(NotImplementedError, match="listdir not supported"):
            await transport.listdir("/a")


class TestBaseTransportContextManager:
    """Async context manager вызывает connect/disconnect."""

    @pytest.mark.asyncio
    async def test_async_with(self, config):
        """Вход/выход из `async with` вызывают connect/disconnect."""
        transport = DummyTransport(config)
        async with transport as t:
            assert t is transport
            assert transport.is_connected
            assert transport.connected_calls == 1
        assert transport.disconnected_calls == 1
        assert not transport.is_connected
