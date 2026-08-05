# tests/unit/test_sync.py
"""Тесты SyncConnection: stream (инкрементальность), close, context manager."""

import asyncio
import threading
import time
from unittest.mock import AsyncMock

import pytest

from uniconn._config import ConnectionConfig
from uniconn._connection import Connection
from uniconn._sync import SyncConnection
from uniconn.result import Result


def _make_transport(stream_lines: list[str] | None = None, stream_delay: float = 0.0):
    """Мок транспорта для Connection."""
    transport = AsyncMock()
    transport.name = "mock"
    transport.is_connected = True
    transport.run = AsyncMock(
        return_value=Result(
            exit_code=0, stdout="ok", stderr="", duration=0.1, command="cmd"
        )
    )

    lines = stream_lines or []

    def _stream(command, timeout=None, **kwargs):
        async def _gen():
            for line in lines:
                if stream_delay:
                    await asyncio.sleep(stream_delay)
                yield line

        return _gen()

    transport.stream = _stream
    transport.connect = AsyncMock()
    transport.disconnect = AsyncMock()
    return transport


def _make_sync(transport) -> SyncConnection:
    config = ConnectionConfig(transport="mock", host="example.com")
    return SyncConnection(Connection(transport, config, retry_attempts=1))


class TestSyncRun:
    """Базовый синхронный запуск."""

    def test_run(self):
        """run() возвращает Result."""
        transport = _make_transport()
        sync = _make_sync(transport)
        try:
            result = sync.run("uptime")
            assert result.exit_code == 0
            assert result.stdout == "ok"
        finally:
            sync.close()

    def test_run_after_close_raises(self):
        """Вызов после close() → RuntimeError."""
        sync = _make_sync(_make_transport())
        sync.close()
        with pytest.raises(RuntimeError, match="закрыт"):
            sync.run("uptime")


class TestSyncStream:
    """Стриминг: инкрементальная отдача строк."""

    def test_stream_all_lines(self):
        """Все строки async-генератора отдаются синхронному итератору."""
        transport = _make_transport(stream_lines=["a", "b", "c"])
        sync = _make_sync(transport)
        try:
            assert list(sync.stream("tail -f /var/log")) == ["a", "b", "c"]
        finally:
            sync.close()

    def test_stream_is_incremental(self):
        """Первая строка отдаётся до завершения команды (нет буферизации)."""
        # Задержка перед КАЖДОЙ строкой: при старом поведении (сбор всего
        # вывода до первого yield) первая строка пришла бы через 2 * delay
        delay = 0.3
        transport = _make_transport(stream_lines=["first", "second"],
                                    stream_delay=delay)
        sync = _make_sync(transport)
        try:
            start = time.monotonic()
            iterator = sync.stream("cmd")
            first = next(iterator)
            elapsed = time.monotonic() - start
            assert first == "first"
            assert elapsed < 2 * delay
            assert list(iterator) == ["second"]
        finally:
            sync.close()

    def test_stream_error_propagates(self):
        """Исключение из async-генератора пробрасывается потребителю."""
        transport = _make_transport()

        def _stream(command, timeout=None, **kwargs):
            async def _gen():
                yield "ok"
                raise ValueError("stream failed")

            return _gen()

        transport.stream = _stream
        sync = _make_sync(transport)
        try:
            iterator = sync.stream("cmd")
            assert next(iterator) == "ok"
            with pytest.raises(ValueError, match="stream failed"):
                next(iterator)
        finally:
            sync.close()


class TestSyncClose:
    """close() и context manager."""

    def test_close_disconnects_transport(self):
        """close() закрывает async-подключение (disconnect транспорта)."""
        transport = _make_transport()
        sync = _make_sync(transport)
        sync.run("uptime")  # инициализирует loop
        sync.close()
        transport.disconnect.assert_awaited_once()

    def test_close_is_idempotent(self):
        """Повторный close() не падает."""
        sync = _make_sync(_make_transport())
        sync.close()
        sync.close()  # повторный вызов не падает

    def test_close_terminates_promptly(self):
        """close() не зависает: loop.stop вызывается до shutdown executor'а."""
        sync = _make_sync(_make_transport())
        sync.run("uptime")  # инициализирует loop

        done = threading.Thread(target=sync.close)
        done.start()
        done.join(timeout=10.0)
        assert not done.is_alive(), "close() завис в executor.shutdown()"

    def test_context_manager(self):
        """`with` подключает транспорт и закрывает всё на выходе."""
        transport = _make_transport()
        sync = _make_sync(transport)
        with sync as conn:
            assert conn is sync
            result = conn.run("uptime")
            assert result.ok
        transport.connect.assert_awaited_once()
        transport.disconnect.assert_awaited_once()
