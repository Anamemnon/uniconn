# tests/unit/test_pool.py
"""Тесты для ConnectionPool"""

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, patch

import pytest

from uniconn.exceptions import ConnectionError
from uniconn.pool.connection_pool import ConnectionPool
from uniconn.result import Result


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
        "uniconn.pool.connection_pool.Connection.from_uri",
        return_value=mock_conn
    ) as mock_from_uri:
        yield mock_from_uri, mock_conn


@pytest.fixture
def patch_connection_factory():
    """Фабрика для патчинга Connection.from_uri"""
    def _patch(return_value=None):
        mock_conn = return_value or make_mock_connection()
        return patch(
            "uniconn.pool.connection_pool.Connection.from_uri",
            return_value=mock_conn
        )
    return _patch


@pytest.mark.asyncio
async def test_pool_map_basic(patch_connection):
    """Тест map с успешным выполнением на всех хостах"""
    mock_from_uri, _mock_conn = patch_connection

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
    _mock_from_uri, mock_conn = patch_connection

    pool = ConnectionPool(["ssh://host1"])
    await pool.map("sleep 100", timeout=5.0)

    mock_conn.run.assert_called_once()
    call_kwargs = mock_conn.run.call_args[1]
    assert call_kwargs["timeout"] == 5.0


@pytest.mark.asyncio
async def test_pool_map_with_raise_on_error(patch_connection):
    """Тест map с raise_on_error=True"""
    _mock_from_uri, mock_conn = patch_connection

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
    _mock_from_uri, _mock_conn = patch_connection

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
        "uniconn.pool.connection_pool.Connection.from_uri",
        side_effect=side_effect
    ):
        pool = ConnectionPool(["ssh://host1", "ssh://host2"])
        results = await pool.map_safe("uptime")

        assert isinstance(results["ssh://host1"], Result)
        assert isinstance(results["ssh://host2"], Exception)


@pytest.mark.asyncio
async def test_pool_map_callback(patch_connection):
    """Тест map_with_callback"""
    _mock_from_uri, _mock_conn = patch_connection

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
    _mock_from_uri, mock_conn = patch_connection

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


@pytest.mark.asyncio
async def test_pool_expect_and_sync_pool_expect() -> None:
    """Групповой метод pool.expect() и sync_pool.expect() параллельно выполняют интерактивный диалог."""
    from uniconn.core.connection import Connection

    c1 = Connection.from_uri("local://").with_overrides(host="node-1")
    c2 = Connection.from_uri("local://").with_overrides(host="node-2")

    async def fake_expect(command, patterns=None, **kwargs):
        return Result(
            exit_code=0,
            stdout=f"expected:{command}",
            stderr="",
            duration=0.01,
            command=str(command),
            timestamp=datetime.now(),
        )

    c1.expect = AsyncMock(side_effect=fake_expect)  # type: ignore[method-assign]
    c2.expect = AsyncMock(side_effect=fake_expect)  # type: ignore[method-assign]

    pool = ConnectionPool([c1, c2])
    res_map = await pool.expect("passwd", patterns={"New password:": "secret\n"})
    assert set(res_map.keys()) == {"node-1", "node-2"}
    assert res_map["node-1"].stdout == "expected:passwd"

    with pool.to_sync() as sync_pool:
        sync_map = sync_pool.expect("confirm", patterns={"Continue?": "y\n"})
        assert set(sync_map.keys()) == {"node-1", "node-2"}
        assert sync_map["node-2"].stdout == "expected:confirm"


def test_pool_from_file_propagates_dry_run_and_auto_diagnostics(tmp_path) -> None:
    """ConnectionPool.from_file и SyncConnectionPool.from_file пробрасывают dry_run и auto_diagnostics."""
    from uniconn.sync.pool import SyncConnectionPool

    inv_file = tmp_path / "hosts.yaml"
    inv_file.write_text(
        "hosts:\n  web1:\n    uri: local://\n  web2:\n    uri: local://\n",
        encoding="utf-8",
    )

    pool = ConnectionPool.from_file(
        inv_file,
        dry_run=True,
        auto_diagnostics=True,
    )
    assert pool.dry_run is True
    assert pool.auto_diagnostics is True
    assert len(pool.targets) == 2
    for target in pool.targets:
        assert getattr(target, "dry_run", False) is True
        assert getattr(target, "auto_diagnostics", False) is True

    sub_pool = pool.select(["web1"])
    assert sub_pool.dry_run is True
    assert sub_pool.auto_diagnostics is True

    sync_pool = SyncConnectionPool.from_file(
        inv_file,
        dry_run=True,
        auto_diagnostics=True,
    )
    assert sync_pool.dry_run is True
    assert sync_pool.auto_diagnostics is True
    assert len(sync_pool.targets) == 2
    for target in sync_pool.targets:
        assert getattr(target, "dry_run", False) is True
        assert getattr(target, "auto_diagnostics", False) is True


@pytest.mark.asyncio
async def test_pool_map_safe_and_callback_propagate_retry_and_dry_run(patch_connection) -> None:
    """map_safe и map_with_callback передают retry_attempts и logger в Connection.from_uri и применяют dry_run."""
    import logging

    mock_from_uri, mock_conn = patch_connection
    custom_logger = logging.getLogger("pool_safe_cb")

    pool = ConnectionPool(
        ["ssh://host1"],
        retry_attempts=7,
        logger=custom_logger,
        dry_run=True,
        auto_diagnostics=True,
    )
    await pool.map_safe("uptime")
    assert mock_from_uri.call_args.kwargs["retry_attempts"] == 7
    assert mock_from_uri.call_args.kwargs["logger"] is custom_logger
    assert mock_conn._dry_run is True
    assert mock_conn.auto_diagnostics is True

    mock_from_uri.reset_mock()
    seen: list[str] = []
    await pool.map_with_callback("uptime", lambda h, _r: seen.append(h))
    assert seen == ["ssh://host1"]
    assert mock_from_uri.call_args.kwargs["retry_attempts"] == 7
    assert mock_from_uri.call_args.kwargs["logger"] is custom_logger


@pytest.mark.asyncio
async def test_pool_disambiguates_same_host_different_ports_and_supports_run() -> None:
    """ConnectionPool.run() и SyncConnectionPool.run() не перезаписывают одинаковые host на разных портах."""
    from uniconn.core.connection import Connection

    c1 = Connection.from_uri("ssh://localhost:2201")
    c2 = Connection.from_uri("ssh://localhost:2202")
    c1._transport._connected = True
    c2._transport._connected = True

    c1.run = AsyncMock(  # type: ignore[method-assign]
        return_value=Result(exit_code=0, stdout="from-2201", stderr="", duration=0.01, command="id", host="localhost")
    )
    c2.run = AsyncMock(  # type: ignore[method-assign]
        return_value=Result(exit_code=0, stdout="from-2202", stderr="", duration=0.01, command="id", host="localhost")
    )

    pool = ConnectionPool([c1, c2])
    out = await pool.run("id")
    assert len(out) == 2
    assert out["ssh://localhost:2201"].stdout == "from-2201"
    assert out["ssh://localhost:2202"].stdout == "from-2202"

    sync_pool = pool.to_sync()
    try:
        sync_out = sync_pool.run("id")
        assert len(sync_out) == 2
        assert sync_out["ssh://localhost:2201"].stdout == "from-2201"
        assert sync_out["ssh://localhost:2202"].stdout == "from-2202"
    finally:
        sync_pool.close()



