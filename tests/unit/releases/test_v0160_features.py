# tests/unit/releases/test_v0160_features.py
"""Приёмочные тесты релиза v0.16.0: примитивы wait_for_*, батчевая раскатка и pool.select()."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

import uniconn
from uniconn import (
    BatchAbortedError,
    Connection,
    ConnectionPool,
    PingResult,
    Result,
    SyncConnection,
    TimeoutError,
)

# ─── Unit 1: Примитивы ожидания (wait_for_connection, wait_for_port, wait_for_path) ───


@pytest.mark.asyncio
async def test_wait_for_connection_recovers_after_retries(mocker: pytest.MonkeyPatch) -> None:
    """wait_for_connection повторяет ping с интервалом и возвращает PingResult при успехе."""
    conn = Connection.from_uri("local://localhost")
    attempts = 0

    async def fake_ping(timeout: float | None = None) -> PingResult:
        nonlocal attempts
        attempts += 1
        alive = attempts >= 3
        return PingResult(
            host="localhost",
            alive=alive,
            latency_ms=1.2 if alive else 0.0,
            transport="local",
            error=None if alive else "Connection refused",
        )

    mocker.patch.object(conn, "ping", side_effect=fake_ping)
    res = await conn.wait_for_connection(timeout=2.0, interval=0.01)
    assert res.alive is True
    assert attempts == 3


@pytest.mark.asyncio
async def test_wait_for_connection_timeout(mocker: pytest.MonkeyPatch) -> None:
    """wait_for_connection выбрасывает TimeoutError при истечении таймаута."""
    conn = Connection.from_uri("local://localhost")
    mocker.patch.object(
        conn,
        "ping",
        new=AsyncMock(
            return_value=PingResult(
                host="localhost",
                alive=False,
                latency_ms=5.0,
                transport="local",
                error="Host down",
            )
        ),
    )
    with pytest.raises(TimeoutError, match="wait_for_connection"):
        await conn.wait_for_connection(timeout=0.05, interval=0.01)


@pytest.mark.asyncio
async def test_wait_for_port_remote_and_local(mocker: pytest.MonkeyPatch) -> None:
    """wait_for_port поддерживает check_from='local' и check_from='remote', а также state='open'|'closed'."""
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    try:
        async with Connection.from_uri("local://127.0.0.1") as conn:
            # 1. check_from="local", state="open"
            elapsed_local = await conn.wait_for_port(
                port,
                host="127.0.0.1",
                state="open",
                check_from="local",
                timeout=2.0,
                interval=0.02,
            )
            assert elapsed_local >= 0.0

            # 2. check_from="remote", state="open" (через команду на целевом хосте)
            calls = 0

            async def fake_run(cmd: str, **kw: object) -> Result:
                nonlocal calls
                calls += 1
                code = 0 if calls >= 2 else 1
                return Result(exit_code=code, stdout="", stderr="", duration=0.01, command=cmd)

            mocker.patch.object(conn, "run", side_effect=fake_run)
            elapsed_remote = await conn.wait_for_port(
                port,
                host="127.0.0.1",
                state="open",
                check_from="remote",
                timeout=2.0,
                interval=0.01,
            )
            assert elapsed_remote >= 0.0
            assert calls == 2
    finally:
        server.close()
        await server.wait_closed()

    # 3. После закрытия сервера state="closed" с check_from="local" завершается успешно
    async with Connection.from_uri("local://127.0.0.1") as conn2:
        elapsed_closed = await conn2.wait_for_port(
            port,
            host="127.0.0.1",
            state="closed",
            check_from="local",
            timeout=2.0,
            interval=0.01,
        )
        assert elapsed_closed >= 0.0

        # А ожидание state="open" на закрытом порту выбрасывает TimeoutError
        with pytest.raises(TimeoutError, match="wait_for_port"):
            await conn2.wait_for_port(
                port,
                host="127.0.0.1",
                state="open",
                check_from="local",
                timeout=0.05,
                interval=0.01,
            )


@pytest.mark.asyncio
async def test_wait_for_path_present_absent_and_regex(tmp_path: Path) -> None:
    """wait_for_path ожидает появления файла, совпадения content_regex и удаления файла."""
    target = tmp_path / "status.txt"

    async with Connection.from_uri("local://localhost") as conn:
        async def _delayed_writer() -> None:
            await asyncio.sleep(0.03)
            target.write_text("STARTING...\n", encoding="utf-8")
            await asyncio.sleep(0.03)
            target.write_text("READY: 42\n", encoding="utf-8")

        task = asyncio.create_task(_delayed_writer())
        elapsed = await conn.wait_for_path(
            target,
            state="present",
            content_regex=r"READY:\s+\d+",
            timeout=2.0,
            interval=0.01,
        )
        await task
        assert elapsed >= 0.02

        # Удаление файла
        target.unlink()
        elapsed_abs = await conn.wait_for_path(
            target,
            state="absent",
            timeout=1.0,
            interval=0.01,
        )
        assert elapsed_abs >= 0.0

        # Таймаут при ожидании несуществующего файла
        with pytest.raises(TimeoutError, match="wait_for_path"):
            await conn.wait_for_path(
                tmp_path / "never_created.sock",
                state="present",
                timeout=0.05,
                interval=0.01,
            )


# ─── Unit 2: Батчевая раскатка (batch_size, max_fail_ratio, BatchAbortedError) и pool.select() ───


@pytest.mark.asyncio
async def test_pool_batch_rollout_success(mocker: pytest.MonkeyPatch) -> None:
    """ConnectionPool выполняет задачи последовательными волнами размера batch_size."""
    uris = [f"local://host-{i}" for i in range(5)]
    pool = ConnectionPool(uris, batch_size=2, max_fail_ratio=0.0)

    active_now = 0
    max_observed = 0

    async def fake_run(self_conn: Connection, cmd: str, **kw: object) -> Result:
        nonlocal active_now, max_observed
        active_now += 1
        max_observed = max(max_observed, active_now)
        await asyncio.sleep(0.02)
        active_now -= 1
        return Result(
            exit_code=0,
            stdout="ok\n",
            stderr="",
            duration=0.02,
            command=cmd,
            host=self_conn.config.host,
        )

    mocker.patch.object(Connection, "run", fake_run)
    results = await pool.map("echo ok")
    assert len(results) == 5
    assert max_observed <= 2


@pytest.mark.asyncio
async def test_pool_batch_aborted_on_result_failure(mocker: pytest.MonkeyPatch) -> None:
    """При превышении max_fail_ratio в текущем батче выбрасывается BatchAbortedError, следующие батчи не запускаются."""
    uris = [f"local://node-{i}" for i in range(6)]
    pool = ConnectionPool(uris)
    executed_hosts: list[str] = []

    async def fake_run(self_conn: Connection, cmd: str, **kw: object) -> Result:
        host = self_conn.config.host or "unknown"
        executed_hosts.append(host)
        # Во втором батче (node-2, node-3) оба хоста возвращают ошибку (fail_ratio = 1.0 > 0.25)
        exit_code = 1 if host in ("node-2", "node-3") else 0
        return Result(
            exit_code=exit_code,
            stdout="",
            stderr="boom" if exit_code else "",
            duration=0.01,
            command=cmd,
            host=host,
        )

    mocker.patch.object(Connection, "run", fake_run)

    with pytest.raises(BatchAbortedError) as exc_info:
        await pool.map("deploy.sh", batch_size=2, max_fail_ratio=0.25)

    err = exc_info.value
    assert err.batch_index == 1
    assert err.fail_ratio == 1.0
    assert err.max_fail_ratio == 0.25
    assert set(err.failed_hosts.keys()) == {"local://node-2", "local://node-3"}
    # Первые 2 батча (node-0..node-3) выполнились, а 3-й батч (node-4, node-5) не запускался!
    assert set(err.completed_results.keys()) == {
        "local://node-0",
        "local://node-1",
        "local://node-2",
        "local://node-3",
    }
    assert "node-4" not in executed_hosts
    assert "node-5" not in executed_hosts


@pytest.mark.asyncio
async def test_pool_batch_aborted_on_exception(mocker: pytest.MonkeyPatch) -> None:
    """Неперехваченное исключение в батче также учитывается в fail_ratio и вызывает BatchAbortedError."""
    uris = ["local://h1", "local://h2", "local://h3", "local://h4"]
    pool = ConnectionPool(uris)
    called: list[str] = []

    async def fake_checksum(
        self_conn: Connection,
        remote_path: str | Path,
        algorithm: str = "sha256",
        *,
        sudo: bool = False,
    ) -> str:
        host = self_conn.config.host or ""
        called.append(host)
        if host == "h1":
            raise RuntimeError("disk I/O error")
        return "deadbeef"

    mocker.patch.object(Connection, "checksum", fake_checksum)

    with pytest.raises(BatchAbortedError) as exc_info:
        await pool.checksum("/etc/hosts", batch_size=2, max_fail_ratio=0.2)

    err = exc_info.value
    assert err.batch_index == 0
    assert err.fail_ratio == 0.5
    assert "local://h1" in err.failed_hosts
    assert err.completed_results.get("local://h2") == "deadbeef"
    assert "h3" not in called
    assert "h4" not in called


@pytest.mark.asyncio
async def test_pool_select_by_hosts_and_predicate() -> None:
    """pool.select() фильтрует хосты по списку или предикату и переиспользует открытые соединения."""
    uris = ["local://web-1", "local://web-2", "local://db-1"]
    async with ConnectionPool(uris) as pool:
        web_pool = pool.select(predicate=lambda key, _conn: "web-" in key)
        assert len(web_pool._uris) == 2

        # Проверяем, что активные соединения переиспользуются
        pings = await web_pool.ping()
        assert set(pings.keys()) == {"local://web-1", "local://web-2"}

        # Фильтрация по списку коротких имён или полных URI
        db_pool = pool.select(["db-1"])
        db_pings = await db_pool.ping()
        assert list(db_pings.keys()) == ["local://db-1"]

        # Закрытие подпула не должно закрывать родительский пул
        await db_pool.close()
        assert pool._is_entered is True
        all_pings = await pool.ping()
        assert len(all_pings) == 3


# ─── Unit 3: Паритет SyncConnection, SyncConnectionPool, CLI и версия v0.16.0 ───


def test_sync_connection_and_sync_pool_v0160_parity(tmp_path: Path) -> None:
    """SyncConnection и SyncConnectionPool поддерживают wait_for_*, select() и батчинг."""
    assert uniconn.__version__ == "0.16.0"

    marker = tmp_path / "sync_ready.txt"
    marker.write_text("OK: 200\n", encoding="utf-8")

    with SyncConnection.from_uri("local://localhost") as sconn:
        pr = sconn.wait_for_connection(timeout=2.0, interval=0.05)
        assert pr.alive is True

        elapsed = sconn.wait_for_path(marker, state="present", content_regex=r"OK:\s+200", timeout=1.0)
        assert elapsed >= 0.0

    spool = ConnectionPool(["local://localhost", "local://127.0.0.1"], batch_size=1).to_sync()
    try:
        sub_spool = spool.select(["localhost"])
        ping_map = sub_spool.wait_for_connection(timeout=2.0, interval=0.05)
        assert "local://localhost" in ping_map
        assert ping_map["local://localhost"].alive is True

        path_map = sub_spool.wait_for_path(marker, state="present", timeout=1.0)
        assert path_map["local://localhost"] >= 0.0
    finally:
        spool.close()


def test_cli_v0160_wait_for_and_batch_flags(tmp_path: Path) -> None:
    """CLI поддерживает команду wait-for (connection, port, path) и флаги --batch-size / --max-fail-ratio."""
    from uniconn.cli import CliRunner, create_cli_app

    cli_app = create_cli_app()
    runner = CliRunner()

    f_path = tmp_path / "cli_wait.txt"
    f_path.write_text("READY_TOKEN\n", encoding="utf-8")

    res_conn = runner.invoke(
        cli_app,
        [
            "wait-for",
            "connection",
            "local://localhost",
            "--timeout",
            "2",
            "--interval",
            "0.05",
            "--format",
            "json",
        ],
    )
    assert res_conn.exit_code == 0
    assert '"alive": true' in res_conn.output.lower()

    res_path = runner.invoke(
        cli_app,
        [
            "wait-for",
            "path",
            str(f_path),
            "local://localhost",
            "--state",
            "present",
            "--regex",
            "READY_TOKEN",
            "--timeout",
            "2",
            "--format",
            "json",
        ],
    )
    assert res_path.exit_code == 0
    assert "local://localhost" in res_path.output

    res_exec = runner.invoke(
        cli_app,
        [
            "run-multi",
            "local://localhost",
            "-c",
            "echo batch-ok",
            "--batch-size",
            "1",
            "--max-fail-ratio",
            "0.5",
            "--format",
            "json",
        ],
    )
    assert res_exec.exit_code == 0
    assert "batch-ok" in res_exec.output

