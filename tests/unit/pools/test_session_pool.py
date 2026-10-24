# tests/unit/test_session_pool.py
"""Тесты для SSHSessionPool."""

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, patch

import pytest

from uniconn._session_pool import SSHSessionPool
from uniconn.result import Result


def make_mock_connection(sleep_time: float = 0.0):
    """Создаёт мок Connection с поддержкой задержки."""
    result = Result(
        exit_code=0,
        stdout="ok",
        stderr="",
        duration=1.0,
        command="test",
        timestamp=datetime.now(),
        host="testhost",
    )

    conn = AsyncMock()

    async def _run(*args, **kwargs):
        if sleep_time:
            await asyncio.sleep(sleep_time)
        return result

    conn.run = _run
    conn.close = AsyncMock()
    conn.__aenter__ = AsyncMock(return_value=conn)
    conn.__aexit__ = AsyncMock(return_value=None)

    return conn


@pytest.fixture
def patch_connection_factory(mocker):
    """Фикстура для патчинга Connection.from_uri с фабрикой моков."""
    created = []

    def _create(sleep_time: float = 0.0):
        def side_effect(uri, *args, **kwargs):
            conn = make_mock_connection(sleep_time)
            created.append(conn)
            return conn

        patcher = patch(
            "uniconn._session_pool.Connection.from_uri",
            side_effect=side_effect,
        )
        return patcher, created

    return _create


@pytest.mark.asyncio
async def test_session_pool_map_basic(patch_connection_factory):
    """Базовый тест map с несколькими командами."""
    patcher, created = patch_connection_factory(sleep_time=0.0)

    with patcher:
        pool = SSHSessionPool("ssh://user@host", max_sessions_per_conn=6)
        results = await pool.map(["cmd1", "cmd2", "cmd3"])

    assert len(results) == 3
    for res in results:
        assert res.exit_code == 0
        assert res.stdout == "ok"

    # Все команды уместились в одно соединение
    assert len(created) == 1


@pytest.mark.asyncio
async def test_session_pool_creates_additional_connection(patch_connection_factory):
    """При превышении max_sessions_per_conn создаётся новое соединение."""
    # sleep_time > 0, чтобы семафоры реально блокировались на время выполнения
    patcher, created = patch_connection_factory(sleep_time=0.05)

    with patcher:
        pool = SSHSessionPool(
            "ssh://user@host",
            max_sessions_per_conn=2,
            max_connections=10,
        )
        results = await pool.map(["cmd1", "cmd2", "cmd3", "cmd4"])

    assert len(results) == 4
    # 4 команды с max_sessions=2 и задержкой → минимум 2 соединения
    assert len(created) >= 2


@pytest.mark.asyncio
async def test_session_pool_respects_max_connections(patch_connection_factory):
    """Не создаёт больше соединений, чем max_connections."""
    patcher, created = patch_connection_factory(sleep_time=0.05)

    with patcher:
        pool = SSHSessionPool(
            "ssh://user@host",
            max_sessions_per_conn=1,
            max_connections=2,
        )
        results = await pool.map(["cmd1", "cmd2", "cmd3", "cmd4"])

    assert len(results) == 4
    # max_connections=2 ограничивает число соединений
    assert len(created) == 2


@pytest.mark.asyncio
async def test_session_pool_run_single_command(patch_connection_factory):
    """Тест метода run для одиночной команды."""
    patcher, created = patch_connection_factory(sleep_time=0.0)

    with patcher:
        pool = SSHSessionPool("ssh://user@host")
        result = await pool.run("whoami")

    assert result.exit_code == 0
    assert result.stdout == "ok"
    assert len(created) == 1


@pytest.mark.asyncio
async def test_session_pool_close_all_connections(patch_connection_factory):
    """close() закрывает все соединения."""
    # sleep_time > 0, чтобы гарантировать создание нескольких соединений
    patcher, created = patch_connection_factory(sleep_time=0.05)

    with patcher:
        pool = SSHSessionPool(
            "ssh://user@host",
            max_sessions_per_conn=1,
            max_connections=3,
        )
        await pool.map(["cmd1", "cmd2", "cmd3"])
        assert len(created) == 3

        await pool.close()

    for conn in created:
        conn.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_session_pool_context_manager(patch_connection_factory):
    """Тест async context manager."""
    patcher, created = patch_connection_factory(sleep_time=0.0)

    with patcher:
        async with SSHSessionPool("ssh://user@host") as pool:
            result = await pool.run("uptime")
            assert result.exit_code == 0

    # При выходе из контекста все соединения закрыты
    for conn in created:
        conn.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_session_pool_passes_timeout_and_raise_on_error():
    """Проверка проброса timeout и raise_on_error в Connection.run."""
    calls = []

    async def tracking_run(command, **kwargs):
        calls.append((command, kwargs))
        return Result(
            exit_code=0,
            stdout="ok",
            stderr="",
            duration=1.0,
            command=command,
            timestamp=datetime.now(),
            host="testhost",
        )

    def side_effect(uri, *args, **kwargs):
        conn = make_mock_connection(sleep_time=0.0)
        conn.run = tracking_run
        return conn

    with patch(
        "uniconn._session_pool.Connection.from_uri",
        side_effect=side_effect,
    ):
        pool = SSHSessionPool("ssh://user@host")
        await pool.map(
            ["cmd1", "cmd2"],
            timeout=30.0,
            raise_on_error=True,
        )

    assert len(calls) == 2
    for _, kwargs in calls:
        assert kwargs.get("timeout") == 30.0
        assert kwargs.get("raise_on_error") is True


@pytest.mark.asyncio
async def test_session_pool_empty_commands():
    """Тест map с пустым списком команд."""
    pool = SSHSessionPool("ssh://user@host")
    results = await pool.map([])
    assert results == []


@pytest.mark.asyncio
async def test_session_pool_adaptive_channel_limit_scale_down():
    """При превышении серверного MaxSessions пул автоматически снижает max_sessions_per_conn и повторяет команды."""
    server_max_sessions = 2

    def make_limited_conn(*_args, **_kwargs):
        conn = make_mock_connection(sleep_time=0.02)
        active_on_conn = 0

        async def _limited_run(command, **_kw):
            nonlocal active_on_conn
            active_on_conn += 1
            try:
                if active_on_conn > server_max_sessions:
                    from uniconn.exceptions import ConnectionError as UniconnConnError

                    raise UniconnConnError(
                        "Channel open failed: Administratively prohibited (MaxSessions=2)"
                    )
                await asyncio.sleep(0.02)
                return Result(
                    exit_code=0,
                    stdout=f"ok:{command}",
                    stderr="",
                    duration=0.02,
                    command=command,
                    timestamp=datetime.now(),
                    host="testhost",
                )
            finally:
                active_on_conn -= 1

        conn.run = _limited_run
        conn.is_alive = AsyncMock(return_value=True)
        return conn

    with patch(
        "uniconn._session_pool.Connection.from_uri",
        side_effect=make_limited_conn,
    ):
        async with SSHSessionPool(
            "ssh://user@host",
            max_sessions_per_conn=6,
            max_connections=2,
            adaptive=True,
        ) as pool:
            assert pool.max_sessions_per_conn == 6
            results = await pool.map([f"cmd-{i}" for i in range(6)])
            assert len(results) == 6
            assert all(r.ok for r in results)
            # Лимит автоматически снизился до серверного потолка 2 и зафиксировался
            assert pool.max_sessions_per_conn == 2
            assert pool.scale_down_events >= 1


@pytest.mark.asyncio
async def test_session_pool_adaptive_max_connections_scale_down():
    """При отказе открытия новых TCP-соединений (MaxStartups) пул фиксирует рабочий max_connections."""
    created_conns = []
    server_max_conns = 2

    def make_conn_with_startup_limit(*_args, **_kwargs):
        idx = len(created_conns) + 1
        conn = make_mock_connection(sleep_time=0.02)
        if idx > server_max_conns:
            from uniconn.exceptions import ConnectionError as UniconnConnError

            conn.run = AsyncMock(
                side_effect=UniconnConnError("Connection reset by peer (MaxStartups)")
            )
        created_conns.append(conn)
        return conn

    with patch(
        "uniconn._session_pool.Connection.from_uri",
        side_effect=make_conn_with_startup_limit,
    ):
        async with SSHSessionPool(
            "ssh://user@host",
            max_sessions_per_conn=1,
            max_connections=4,
            adaptive=True,
        ) as pool:
            results = await pool.map(["c1", "c2", "c3", "c4"])
            assert len(results) == 4
            assert all(r.ok for r in results)
            assert pool.max_connections == 2
            assert pool.active_connections == 2
            assert pool.scale_down_events >= 1
            # Отклонённые 3-е и 4-е соединения должны быть закрыты при дренаже
            for rejected in created_conns[2:]:
                rejected.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_session_pool_adaptive_disabled_propagates_error():
    """При adaptive=False ошибка превышения каналов пробрасывается без авто-снижения."""
    def make_failing_second_channel(*_args, **_kwargs):
        conn = make_mock_connection(sleep_time=0.02)
        active = 0

        async def _run(command, **_kw):
            nonlocal active
            active += 1
            try:
                if active > 1:
                    from uniconn.exceptions import ConnectionError as UniconnConnError

                    raise UniconnConnError("Channel open failed")
                await asyncio.sleep(0.02)
                return Result(
                    exit_code=0,
                    stdout="ok",
                    stderr="",
                    duration=0.02,
                    command=command,
                    timestamp=datetime.now(),
                    host="testhost",
                )
            finally:
                active -= 1

        conn.run = _run
        return conn

    with patch(
        "uniconn._session_pool.Connection.from_uri",
        side_effect=make_failing_second_channel,
    ):
        pool = SSHSessionPool(
            "ssh://user@host",
            max_sessions_per_conn=4,
            max_connections=1,
            adaptive=False,
        )
        with pytest.raises(ExceptionGroup):
            await pool.map(["c1", "c2"])
        assert pool.max_sessions_per_conn == 4
        assert pool.scale_down_events == 0
        await pool.close()


@pytest.mark.asyncio
async def test_session_pool_resize_graceful_drain():
    """resize() мягко дренирует лишние активные соединения после завершения текущих команд."""
    gate = asyncio.Event()
    started = asyncio.Event()
    in_flight_counter = 0
    created: list[AsyncMock] = []

    def make_gated_conn(*_args, **_kwargs):
        conn = make_mock_connection(sleep_time=0.0)

        async def _gated_run(command, **_kw):
            nonlocal in_flight_counter
            in_flight_counter += 1
            if in_flight_counter >= 3:
                started.set()
            await gate.wait()
            return Result(
                exit_code=0,
                stdout=command,
                stderr="",
                duration=0.01,
                command=command,
                timestamp=datetime.now(),
                host="testhost",
            )

        conn.run = _gated_run
        created.append(conn)
        return conn

    with patch(
        "uniconn._session_pool.Connection.from_uri",
        side_effect=make_gated_conn,
    ):
        pool = SSHSessionPool(
            "ssh://user@host",
            max_sessions_per_conn=1,
            max_connections=3,
        )
        task = asyncio.create_task(pool.map(["cmd1", "cmd2", "cmd3"]))
        await asyncio.wait_for(started.wait(), timeout=2.0)
        assert len(created) == 3
        assert pool.in_flight_sessions == 3

        # Уменьшаем max_connections с 3 до 1 во время выполнения команд
        snap = await pool.resize(max_sessions_per_conn=2, max_connections=1)
        assert snap["max_sessions_per_conn"] == 2
        assert snap["max_connections"] == 1
        assert snap["active_connections"] == 1
        assert snap["draining_connections"] == 2
        # Пока команды выполняются, ни одно соединение ещё не закрыто
        for c in created:
            c.close.assert_not_awaited()

        # Отпускаем барьер — команды завершаются, а 2 лишних соединения автоматически закрываются
        gate.set()
        results = await task
        assert len(results) == 3
        assert pool.active_connections == 1
        assert pool.draining_connections == 0
        closed_count = sum(1 for c in created if c.close.await_count == 1)
        assert closed_count == 2

        await pool.close()


def test_session_pool_validation_and_stats():
    """Проверка валидации параметров SSHSessionPool и метода stats()."""
    with pytest.raises(ValueError):
        SSHSessionPool("ssh://user@host", max_sessions_per_conn=0)
    with pytest.raises(ValueError):
        SSHSessionPool("ssh://user@host", max_connections=0)
    with pytest.raises(ValueError):
        SSHSessionPool("ssh://user@host", min_sessions_per_conn=0)

    pool = SSHSessionPool("ssh://user@host", max_sessions_per_conn=4, max_connections=2)
    st = pool.stats()
    assert st["max_sessions_per_conn"] == 4
    assert st["max_connections"] == 2
    assert st["adaptive"] is True
    assert st["scale_down_events"] == 0

