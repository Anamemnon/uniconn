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
