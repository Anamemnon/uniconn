# tests/unit/screen/test_screen_pool.py
"""Тесты BackgroundPool — оркестрация множества фоновых сессий (мок Connection)."""

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from uniconn.background import BackgroundPool, BackgroundPoolConfig, LogConfig
from uniconn.background._models import BackgroundResult
from uniconn.exceptions import BackgroundError, BackgroundPoolFullError
from uniconn.result import Result


def make_result(stdout: str = "", exit_code: int = 0, command: str = "") -> Result:
    """Создать Result для мока."""
    return Result(
        exit_code=exit_code,
        stdout=stdout,
        stderr="",
        duration=0.1,
        command=command,
        timestamp=datetime.now(),
    )


def make_connection(handler) -> MagicMock:
    """Мок Connection с маршрутизацией команд в handler."""
    conn = MagicMock()
    conn.run = AsyncMock(side_effect=handler)
    conn.close = AsyncMock()
    return conn


def default_handler(command: str, **kwargs) -> Result:
    """Стандартный хост: auto-probe возвращает screen, сессий нет, логи пустые."""
    if "if command -v tmux" in command:
        return make_result("screen\n", command=command)
    if "command -v screen" in command:
        return make_result("", command=command)
    if command == "screen -ls":
        return make_result("No Sockets found in /run/screen/S-user.\n", exit_code=1)
    return make_result("", command=command)


def make_pool(handler=default_handler, **kwargs) -> BackgroundPool:
    """BackgroundPool с подменённым подключением."""
    conn = make_connection(handler)
    with patch("uniconn.background._pool.Connection") as mock_cls:
        mock_cls.from_uri.return_value = conn
        pool = BackgroundPool("ssh://user@host", **kwargs)
    pool._connection = conn
    return pool


def detach_hooks(pool: BackgroundPool) -> None:
    """Снять atexit/signal хуки, установленные при регистрации сессий."""
    pool._cleanup_manager.uninstall()


class TestStart:
    """Тесты запуска сессий."""

    async def test_start_creates_session(self):
        """Start создаёт сессию с именем {prefix}_{idx} и регистрирует её."""
        pool = make_pool()
        session = await pool.start("stress-ng --cpu 4")
        try:
            assert session.session_id.startswith("uniconn_")
            assert session.session_id.endswith("_0")
            assert session.remote_log_path == f"/tmp/{session.session_id}.log"
            assert session.session_id in pool.sessions
            assert pool.resolved_backend is not None
            assert pool.resolved_backend.name == "screen"
            calls = [c.args[0] for c in pool._connection.run.call_args_list]
            assert any(pool._cleanup_manager.sentinel_path in c for c in calls)
            assert any(pool._cleanup_manager.cleanup_script_path in c for c in calls)
        finally:
            detach_hooks(pool)

    async def test_start_custom_name(self):
        """Start с явным именем использует его как session_id."""
        pool = make_pool()
        session = await pool.start("uptime", name="mysess")
        try:
            assert session.session_id == "mysess"
            assert session.remote_log_path == "/tmp/mysess.log"
        finally:
            detach_hooks(pool)

    async def test_start_max_sessions_exceeded(self):
        """Превышение max_sessions приводит к BackgroundPoolFullError."""
        pool = make_pool(max_sessions=1)
        await pool.start("cmd1")
        try:
            with pytest.raises(BackgroundPoolFullError):
                await pool.start("cmd2")
        finally:
            detach_hooks(pool)

    async def test_start_with_nohup_fallback(self):
        """При отсутствии tmux и screen пул автоматически использует nohup."""
        state = {"alive": False}

        def handler(command: str, **kwargs) -> Result:
            if "if command -v tmux" in command:
                return make_result("nohup\n", command=command)
            if "kill -0 $(cat" in command:
                return make_result(
                    "", exit_code=0 if state["alive"] else 1, command=command
                )
            return make_result("", command=command)

        pool = make_pool(handler)
        session = await pool.start("python3 job.py", name="nohup_job")
        try:
            assert session.backend_name == "nohup"
            assert pool.resolved_backend is not None
            assert pool.resolved_backend.name == "nohup"
        finally:
            detach_hooks(pool)


class TestStop:
    """Тесты остановки сессий."""

    async def test_stop_kills_and_removes_session(self):
        """Stop убивает сессию (graceful → Ctrl+C) и снимает её с учёта."""
        state = {"alive": False}

        def handler(command: str, **kwargs) -> Result:
            if "if command -v tmux" in command:
                return make_result("screen\n", command=command)
            if command == "screen -ls":
                if state["alive"]:
                    return make_result("\t12345.mysess\t(Detached)\n", command=command)
                return make_result("", exit_code=1, command=command)
            if "stuff" in command:
                state["alive"] = False
            return make_result("", command=command)

        pool = make_pool(handler)
        session = await pool.start("uptime", name="mysess")
        state["alive"] = True

        result = await pool.stop(session.session_id)
        try:
            assert isinstance(result, BackgroundResult)
            assert result.backend == "screen"
            assert session.session_id not in pool.sessions
            calls = [c.args[0] for c in pool._connection.run.call_args_list]
            assert any("stuff" in c for c in calls)
        finally:
            detach_hooks(pool)

    async def test_stop_unknown_session(self):
        """Stop для неизвестной сессии падает с BackgroundError."""
        pool = make_pool()
        with pytest.raises(BackgroundError):
            await pool.stop("no_such_session")

    async def test_stop_all(self):
        """stop_all останавливает все активные сессии."""
        state = {"alive": False}

        def handler(command: str, **kwargs) -> Result:
            if "if command -v tmux" in command:
                return make_result("screen\n", command=command)
            if command == "screen -ls":
                if state["alive"]:
                    return make_result("\t1.a\t(Detached)\n\t2.b\t(Detached)\n")
                return make_result("", exit_code=1, command=command)
            return make_result("", command=command)

        pool = make_pool(handler)
        s1 = await pool.start("cmd1", name="a")
        await pool.start("cmd2", name="b")
        state["alive"] = True
        await pool.stop_all(graceful=False)
        try:
            assert pool.sessions == {}
            calls = [c.args[0] for c in pool._connection.run.call_args_list]
            kills = [
                c for c in calls if c.startswith("screen -S") and "-X kill" in c
            ]
            assert len(kills) == 2
            assert s1.session_id == "a"
        finally:
            detach_hooks(pool)


class TestWaitAll:
    """Тесты ожидания завершения сессий."""

    async def test_wait_all_collects_results(self):
        """wait_all возвращает BackgroundResult с exit code из exit-файла."""

        def handler(command: str, **kwargs) -> Result:
            if "if command -v tmux" in command:
                return make_result("screen\n", command=command)
            if command == "screen -ls":
                return make_result("", exit_code=1, command=command)
            if command.startswith("cat /tmp/"):
                return make_result("0\n", command=command)
            return make_result("", command=command)

        pool = make_pool(handler, poll_interval=0.01)
        session = await pool.start("true", name="done")
        results = await pool.wait_all()
        try:
            assert session.session_id in results
            assert results[session.session_id].exit_code == 0
            assert results[session.session_id].backend == "screen"
            assert pool.sessions == {}
        finally:
            detach_hooks(pool)

    async def test_wait_all_timeout_force_kills(self):
        """wait_all с timeout: оставшиеся сессии force kill, exit code -1."""
        state = {"alive": False}

        def handler(command: str, **kwargs) -> Result:
            if "if command -v tmux" in command:
                return make_result("screen\n", command=command)
            if command == "screen -ls":
                if state["alive"]:
                    return make_result(
                        "\t12345.stuck\t(Detached)\n", command=command
                    )
                return make_result("", exit_code=1, command=command)
            if command.startswith("cat /tmp/"):
                return make_result("", exit_code=1, command=command)
            return make_result("", command=command)

        pool = make_pool(handler, poll_interval=0.01)
        session = await pool.start("sleep 1000", name="stuck")
        state["alive"] = True
        results = await pool.wait_all(timeout=0.05)
        try:
            assert results[session.session_id].exit_code == -1
            calls = [c.args[0] for c in pool._connection.run.call_args_list]
            assert any("-X kill" in c for c in calls)
        finally:
            detach_hooks(pool)


class TestPoll:
    """Тесты опроса логов и статуса."""

    async def test_poll_logs_yields_events(self, tmp_path):
        """poll_logs читает порции через tail и отдаёт LogEvent."""
        data = "line1\nline2\n"

        def handler(command: str, **kwargs) -> Result:
            if "if command -v tmux" in command:
                return make_result("screen\n", command=command)
            if command == "screen -ls":
                return make_result("", exit_code=1, command=command)
            if command.startswith("stat -c %s"):
                return make_result(f"{len(data.encode())}\n", command=command)
            if command.startswith("tail -c"):
                return make_result(data, command=command)
            return make_result("", command=command)

        pool = make_pool(handler, log_config=LogConfig(local_dir=str(tmp_path)))
        session = await pool.start("cmd", name="logged")
        try:
            events = []
            async for event in pool.poll_logs(interval=0.01):
                events.append(event)
                if len(events) >= 2:
                    break
            assert [e.line for e in events] == ["line1\n", "line2\n"]
            assert all(e.session_id == session.session_id for e in events)
        finally:
            detach_hooks(pool)

    async def test_poll_status_yields_events(self):
        """poll_status отдаёт StatusEvent с alive/pid живой сессии."""
        state = {"alive": False}

        def handler(command: str, **kwargs) -> Result:
            if "if command -v tmux" in command:
                return make_result("screen\n", command=command)
            if command == "screen -ls":
                if state["alive"]:
                    return make_result("\t12345.mon\t(Detached)\n", command=command)
                return make_result("", exit_code=1, command=command)
            return make_result("", command=command)

        pool = make_pool(handler)
        await pool.start("cmd", name="mon")
        state["alive"] = True
        try:
            agen = pool.poll_status(interval=0.01)
            event = await agen.__anext__()
            await agen.aclose()
            assert event.session_id == "mon"
            assert event.alive is True
            assert event.pid == 12345
        finally:
            detach_hooks(pool)

    async def test_monitor_semaphore_limits_concurrency(self):
        """Число одновременных SSH-запросов мониторинга ≤ max_monitors."""
        state = {"alive": False, "current": 0, "peak": 0}

        async def run(command: str, **kwargs) -> Result:
            state["current"] += 1
            state["peak"] = max(state["peak"], state["current"])
            await asyncio.sleep(0.01)
            state["current"] -= 1
            if "if command -v tmux" in command:
                return make_result("screen\n", command=command)
            if command == "screen -ls":
                if state["alive"]:
                    return make_result("\t1.x\t(Detached)\n", command=command)
                return make_result("", exit_code=1, command=command)
            return make_result("", command=command)

        pool = make_pool(run, max_monitors=1)
        for i in range(3):
            await pool.start(f"cmd{i}", name=f"s{i}")
        state["alive"] = True
        state["peak"] = 0
        try:
            agen = pool.poll_status(interval=0.01)
            await agen.__anext__()
            await agen.aclose()
            assert state["peak"] == 1
        finally:
            detach_hooks(pool)


class TestFactories:
    """Тесты фабричных методов."""

    def test_from_config(self):
        """from_config переносит все поля BackgroundPoolConfig."""
        config = BackgroundPoolConfig(
            uri="ssh://admin@server",
            backend="tmux",
            max_sessions=8,
            max_monitors=2,
            poll_interval=1.5,
            log_config=LogConfig(local_dir="/tmp/logs"),
        )
        pool = BackgroundPool.from_config(config)
        assert pool._uri == "ssh://admin@server"
        assert pool.backend == "tmux"
        assert pool._max_sessions == 8
        assert pool._max_monitors == 2
        assert pool._poll_interval == 1.5
        assert pool._log_config.local_dir == "/tmp/logs"

    def test_from_file(self, tmp_path):
        """from_file загружает конфигурацию из JSON."""
        path = tmp_path / "pool.json"
        path.write_text(
            '{"uri": "ssh://admin@server", "backend": "nohup", "max_sessions": 4, "max_monitors": 1}',
            encoding="utf-8",
        )
        pool = BackgroundPool.from_file(path)
        assert pool._uri == "ssh://admin@server"
        assert pool.backend == "nohup"
        assert pool._max_sessions == 4
        assert pool._max_monitors == 1


class TestCleanup:
    """Тесты очистки пула и контекстного менеджера."""

    async def test_cleanup_removes_server_artifacts(self):
        """Cleanup останавливает сессии, удаляет sentinel/script, закрывает conn."""
        pool = make_pool()
        conn = pool._connection
        await pool.start("cmd", name="c1")
        await pool.cleanup()
        calls = [c.args[0] for c in conn.run.call_args_list]
        rm_calls = [c for c in calls if c.startswith("rm -f")]
        assert any(pool._cleanup_manager.sentinel_path in c for c in rm_calls)
        assert any(pool._cleanup_manager.cleanup_script_path in c for c in rm_calls)
        conn.close.assert_awaited_once()
        assert pool.sessions == {}
        assert pool._cleanup_manager._installed is False

    async def test_context_manager(self):
        """Async with: выход из блока вызывает cleanup."""
        pool = make_pool()
        conn = pool._connection
        async with pool:
            await pool.start("cmd", name="ctx")
            assert pool.sessions != {}
        assert pool.sessions == {}
        conn.close.assert_awaited_once()
        assert pool._cleanup_manager._installed is False
