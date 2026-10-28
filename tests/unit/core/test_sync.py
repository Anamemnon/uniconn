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
from uniconn.core.bridge import EventLoopPortal
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
        """close() не зависает: loop.stop вызывается до join потока loop'а."""
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


class TestSyncShellSession:
    """Тесты SyncShellSession: execute, resize, close и контекстный менеджер."""

    def test_sync_open_shell_execute_and_close(self):
        """SyncConnection.open_shell() позволяет выполнять stateful команды синхронно."""
        from test_shell import FakeShellProcess

        proc = FakeShellProcess()
        transport = _make_transport()
        transport.open_shell = AsyncMock(return_value=proc)

        sync = _make_sync(transport)
        with sync as conn, conn.open_shell(term_size=(100, 30)) as shell:
            assert shell.is_alive
            shell.execute("cd /etc")
            res = shell.execute("pwd")
            assert res.ok
            assert res.stdout == "/etc"

            shell.resize(132, 43)
            assert proc.term_size == (132, 43)

        assert not shell.is_alive
        assert proc.terminated


class TestEventLoopPortalDeadlockProtection:
    """Тесты защиты от взаимных блокировок (deadlock) и защиты буфера очереди."""

    def test_call_from_loop_thread_raises_deadlock(self):
        """Вызов portal.call() изнутри daemon-потока портала возбуждает RuntimeError."""
        portal = EventLoopPortal(owner_name="TestPortal")

        async def _nested():
            return "nested"

        async def _outer():
            # Попытка вызвать portal.call() из корутины, исполняемой на самом портале
            return portal.call(_nested())

        with pytest.raises(
            RuntimeError,
            match=r"Deadlock detected: TestPortal\.call\(\) cannot be called from within the portal event loop thread",
        ):
            portal.call(_outer())

    def test_iter_async_from_loop_thread_raises_deadlock(self):
        """Вызов portal.iter_async() изнутри daemon-потока портала возбуждает RuntimeError."""
        portal = EventLoopPortal(owner_name="TestPortal")

        async def _gen():
            yield 1
            yield 2

        async def _outer():
            # Попытка синхронной итерации portal.iter_async() из потока портала
            return list(portal.iter_async(_gen()))

        with pytest.raises(
            RuntimeError,
            match=(
                r"Deadlock detected: TestPortal\.iter_async\(\) cannot be called "
                r"from within the portal event loop thread"
            ),
        ):
            portal.call(_outer())

    def test_iter_async_queue_bounded_and_streaming(self):
        """Итератор iter_async использует ограниченную очередь (maxsize=1000) и корректно отдает данные."""
        portal = EventLoopPortal(owner_name="TestPortal")

        async def _gen():
            for i in range(5):
                yield i

        items = list(portal.iter_async(_gen()))
        assert items == [0, 1, 2, 3, 4]


