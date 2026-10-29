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


class TestEventLoopPortalStabilityAndResilience:
    """Расширенные тесты устойчивости EventLoopPortal: таймауты, aclose, shutdown и многопоточность."""

    def test_call_timeout_cancels_task_and_raises_domain_timeout(self):
        """portal.call() с timeout выбрасывает uniconn.exceptions.TimeoutError и отменяет корутину."""
        from uniconn.exceptions import TimeoutError as UniconnTimeoutError

        portal = EventLoopPortal(owner_name="TimeoutTestPortal")
        cancelled = False

        async def _hanging_task():
            nonlocal cancelled
            try:
                await asyncio.sleep(10.0)
            except asyncio.CancelledError:
                cancelled = True
                raise

        with pytest.raises(UniconnTimeoutError, match=r"timed out after 0\.05s"):
            portal.call(_hanging_task(), timeout=0.05)

        time.sleep(0.05)
        assert cancelled, "Зависшая корутина не была отменена при таймауте portal.call"

    def test_iter_async_timeout_raises_domain_timeout(self):
        """portal.iter_async() с timeout выбрасывает TimeoutError при задержке следующего элемента."""
        from uniconn.exceptions import TimeoutError as UniconnTimeoutError

        portal = EventLoopPortal(owner_name="IterTimeoutPortal")

        async def _slow_generator():
            yield 1
            await asyncio.sleep(10.0)
            yield 2

        it = portal.iter_async(_slow_generator(), timeout=0.05)
        assert next(it) == 1
        with pytest.raises(UniconnTimeoutError, match=r"timed out waiting for next item"):
            next(it)

    def test_iter_async_early_break_triggers_aclose(self):
        """При досрочном выходе из синхронного цикла вызывается aclose() асинхронного генератора."""
        portal = EventLoopPortal(owner_name="AclosePortal")
        aclose_called = False

        class TrackedGen:
            def __aiter__(self):
                self.i = 0
                return self

            async def __anext__(self):
                self.i += 1
                if self.i > 10:
                    raise StopAsyncIteration
                await asyncio.sleep(0.01)
                return self.i

            async def aclose(self):
                nonlocal aclose_called
                aclose_called = True

        for item in portal.iter_async(TrackedGen(), buffer_size=5):
            if item == 3:
                break

        time.sleep(0.05)
        assert aclose_called, "aclose() не был вызван при досрочном прерывании iter_async"

    def test_concurrent_threads_deterministic_loop_initialization(self):
        """Множество потоков ОС одновременно вызывают get_loop() — цикл стартует без race condition."""
        from concurrent.futures import ThreadPoolExecutor

        loops: list[asyncio.AbstractEventLoop] = []
        errors: list[Exception] = []

        def _worker():
            try:
                p = EventLoopPortal("ThreadWorker")
                loops.append(p.get_loop())
            except Exception as e:
                errors.append(e)

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(_worker) for _ in range(20)]
            for f in futures:
                f.result()

        assert not errors
        assert len(loops) == 20
        assert all(loop is loops[0] for loop in loops)

    def test_sync_connection_50_threads_stress(self):
        """Стресс-тест: 50 параллельных потоков ОС выполняют команды через SyncConnection."""
        from concurrent.futures import ThreadPoolExecutor

        sync_conn = _make_sync(_make_transport())
        results: list[int] = []

        def _task(thread_id: int) -> int:
            res = sync_conn.run(f"echo thread_{thread_id}")
            assert res.ok
            return thread_id

        try:
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = [executor.submit(_task, i) for i in range(50)]
                for f in futures:
                    results.append(f.result())

            assert sorted(results) == list(range(50))
        finally:
            sync_conn.close()

    def test_shutdown_all_and_restart_cleanly(self):
        """EventLoopPortal.shutdown_all() корректно завершает поток, и следующий вызов создаёт свежий цикл."""
        portal1 = EventLoopPortal("BeforeShutdown")
        loop1 = portal1.get_loop()
        assert loop1.is_running()

        EventLoopPortal.shutdown_all(timeout=2.0)
        assert loop1.is_closed()

        portal2 = EventLoopPortal("AfterShutdown")
        loop2 = portal2.get_loop()
        assert loop2.is_running()
        assert loop2 is not loop1
        assert portal2.call(asyncio.sleep(0.01, result="fresh_ok")) == "fresh_ok"
