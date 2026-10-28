# tests/unit/pools/test_batch_rollout_and_select.py
"""Unit-тесты батчевой раскатки (batch_size, max_fail_ratio, BatchAbortedError) и pool.select()."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from uniconn import (
    BatchAbortedError,
    Connection,
    ConnectionPool,
    Result,
)


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
    """При превышении max_fail_ratio в текущем батче выбрасывается BatchAbortedError."""
    uris = [f"local://node-{i}" for i in range(6)]
    pool = ConnectionPool(uris)
    executed_hosts: list[str] = []

    async def fake_run(self_conn: Connection, cmd: str, **kw: object) -> Result:
        host = self_conn.config.host or "unknown"
        executed_hosts.append(host)
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

    from uniconn.services.files import FileOperationsService

    async def fake_checksum(
        self_files: FileOperationsService,
        remote_path: str | Path,
        algorithm: str = "sha256",
        *,
        sudo: bool = False,
    ) -> str:
        host = self_files._conn.config.host or ""
        called.append(host)
        if host == "h1":
            raise RuntimeError("disk I/O error")
        return "deadbeef"

    mocker.patch.object(FileOperationsService, "checksum", fake_checksum)

    with pytest.raises(BatchAbortedError) as exc_info:
        await pool.files.checksum("/etc/hosts", batch_size=2, max_fail_ratio=0.2)

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

        pings = await web_pool.ping()
        assert set(pings.keys()) == {"local://web-1", "local://web-2"}

        db_pool = pool.select(["db-1"])
        db_pings = await db_pool.ping()
        assert list(db_pings.keys()) == ["local://db-1"]

        await db_pool.close()
        assert pool._is_entered is True
        all_pings = await pool.ping()
        assert len(all_pings) == 3


def test_sync_pool_select_and_wait_for(tmp_path: Path) -> None:
    """SyncConnectionPool поддерживает select(), батчинг и методы wait_for_*."""
    marker = tmp_path / "sync_ready.txt"
    marker.write_text("OK: 200\n", encoding="utf-8")

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


def test_cli_wait_for_and_batch_flags(tmp_path: Path) -> None:
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
