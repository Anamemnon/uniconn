# tests/unit/test_pool.py
"""Тесты для ConnectionPool"""

import asyncio
import pytest
from datetime import datetime
from unittest.mock import patch, AsyncMock

from uniconn._pool import ConnectionPool
from uniconn.result import Result
from uniconn.exceptions import ConnectionError


def make_mock_connection():
    """Создаёт мок Connection с правильным aenter/aexit"""
    result = Result(
        exit_code=0,
        stdout="ok",
        stderr="",
        duration=1.0,
        command="test",
        timestamp=datetime.now(),
        host="testhost"
    )

    conn = AsyncMock()
    conn.run = AsyncMock(return_value=result)
    conn.close = AsyncMock()

    # Настраиваем контекстный менеджер
    conn.__aenter__ = AsyncMock(return_value=conn)
    conn.__aexit__ = AsyncMock(return_value=None)

    return conn


def make_failing_connection(error_msg="Connection refused"):
    """Создаёт мок Connection, который падает при run"""
    conn = AsyncMock()
    conn.run = AsyncMock(
        side_effect=ConnectionError(error_msg, host="host")
    )
    conn.close = AsyncMock()
    conn.__aenter__ = AsyncMock(return_value=conn)
    conn.__aexit__ = AsyncMock(return_value=None)
    return conn


@pytest.fixture
def patch_connection(mocker):
    """Патчит Connection.from_uri"""
    mock_conn = make_mock_connection()

    with patch(
        "uniconn._pool.Connection.from_uri",
        return_value=mock_conn
    ) as mock_from_uri:
        yield mock_from_uri, mock_conn


@pytest.fixture
def patch_connection_factory():
    """Фабрика для патчинга Connection.from_uri"""
    def _patch(return_value=None):
        mock_conn = return_value or make_mock_connection()
        return patch(
            "uniconn._pool.Connection.from_uri",
            return_value=mock_conn
        )
    return _patch


@pytest.mark.asyncio
async def test_pool_map_basic(patch_connection):
    """Тест map с успешным выполнением на всех хостах"""
    mock_from_uri, mock_conn = patch_connection

    uris = ["ssh://host1", "ssh://host2", "ssh://host3"]
    pool = ConnectionPool(uris, max_concurrent=3)

    results = await pool.map("uptime")

    assert len(results) == 3
    for result in results:
        assert result.exit_code == 0
        assert result.stdout == "ok"

    # Connection.from_uri вызвался для каждого хоста
    assert mock_from_uri.call_count == 3


@pytest.mark.asyncio
async def test_pool_map_with_timeout(patch_connection):
    """Тест map с таймаутом"""
    mock_from_uri, mock_conn = patch_connection

    pool = ConnectionPool(["ssh://host1"])
    await pool.map("sleep 100", timeout=5.0)

    mock_conn.run.assert_called_once()
    call_kwargs = mock_conn.run.call_args[1]
    assert call_kwargs["timeout"] == 5.0


@pytest.mark.asyncio
async def test_pool_map_with_raise_on_error(patch_connection):
    """Тест map с raise_on_error=True"""
    mock_from_uri, mock_conn = patch_connection

    pool = ConnectionPool(["ssh://host1"])
    await pool.map("false_cmd", raise_on_error=True)

    call_kwargs = mock_conn.run.call_args[1]
    assert call_kwargs["raise_on_error"] is True


@pytest.mark.asyncio
async def test_pool_map_with_retry_attempts(patch_connection):
    """Тест что retry_attempts передаётся в Connection"""
    mock_from_uri, _ = patch_connection

    pool = ConnectionPool(["ssh://host1"], retry_attempts=5)
    await pool.map("uptime")

    mock_from_uri.assert_called_once()
    call_kwargs = mock_from_uri.call_args[1]
    assert call_kwargs["retry_attempts"] == 5


@pytest.mark.asyncio
async def test_pool_map_safe_success(patch_connection):
    """Тест map_safe с успешным выполнением"""
    mock_from_uri, mock_conn = patch_connection

    pool = ConnectionPool(["ssh://host1", "ssh://host2"])
    results = await pool.map_safe("uptime")

    assert isinstance(results, dict)
    assert "ssh://host1" in results
    assert "ssh://host2" in results
    assert isinstance(results["ssh://host1"], Result)


@pytest.mark.asyncio
async def test_pool_map_safe_with_error():
    """Тест map_safe с ошибкой на одном хосте"""
    call_count = 0

    def side_effect(uri, *args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 2:  # Второй хост — ошибка
            return make_failing_connection()
        return make_mock_connection()

    with patch(
        "uniconn._pool.Connection.from_uri",
        side_effect=side_effect
    ):
        pool = ConnectionPool(["ssh://host1", "ssh://host2"])
        results = await pool.map_safe("uptime")

        assert isinstance(results["ssh://host1"], Result)
        assert isinstance(results["ssh://host2"], Exception)


@pytest.mark.asyncio
async def test_pool_map_callback(patch_connection):
    """Тест map_with_callback"""
    mock_from_uri, mock_conn = patch_connection

    callbacks_received = []

    def my_callback(uri: str, result: Result):
        callbacks_received.append((uri, result))

    pool = ConnectionPool(["ssh://host1", "ssh://host2"])
    await pool.map_with_callback("uptime", my_callback)

    assert len(callbacks_received) == 2
    assert callbacks_received[0][0] == "ssh://host1"
    assert isinstance(callbacks_received[0][1], Result)


@pytest.mark.asyncio
async def test_pool_max_concurrent(patch_connection):
    """Тест ограничения параллелизма"""
    mock_from_uri, mock_conn = patch_connection

    concurrent_count = 0
    max_concurrent_seen = 0

    async def track_concurrency(*args, **kwargs):
        nonlocal concurrent_count, max_concurrent_seen
        concurrent_count += 1
        max_concurrent_seen = max(max_concurrent_seen, concurrent_count)
        await asyncio.sleep(0.05)
        concurrent_count -= 1
        return Result(
            exit_code=0, stdout="ok", stderr="",
            duration=1.0, command="test", timestamp=datetime.now(),
            host="testhost"
        )

    mock_conn.run = track_concurrency

    pool = ConnectionPool(
        [f"ssh://host{i}" for i in range(10)],
        max_concurrent=3
    )
    await pool.map("uptime")

    assert max_concurrent_seen <= 3


@pytest.mark.asyncio
async def test_pool_empty_uris():
    """Тест с пустым списком хостов"""
    pool = ConnectionPool([])
    results = await pool.map("uptime")
    assert results == []


@pytest.mark.asyncio
async def test_pool_logger(patch_connection):
    """Тест что логер используется"""
    mock_from_uri, _ = patch_connection
    import logging
    test_logger = logging.getLogger("test_pool")

    pool = ConnectionPool(["ssh://host1"], logger=test_logger)
    await pool.map("uptime")

    # Проверяем что Connection.from_uri вызвался с правильным логером
    call_kwargs = mock_from_uri.call_args[1]
    assert call_kwargs["logger"] is test_logger
