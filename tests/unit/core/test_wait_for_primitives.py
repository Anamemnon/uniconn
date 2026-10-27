# tests/unit/core/test_wait_for_primitives.py
"""Unit-тесты примитивов ожидания: wait_for_connection, wait_for_port, wait_for_path."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from uniconn import (
    Connection,
    PingResult,
    Result,
    SyncConnection,
    TimeoutError,
)


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
            elapsed_local = await conn.wait_for_port(
                port,
                host="127.0.0.1",
                state="open",
                check_from="local",
                timeout=2.0,
                interval=0.02,
            )
            assert elapsed_local >= 0.0

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

        target.unlink()
        elapsed_abs = await conn.wait_for_path(
            target,
            state="absent",
            timeout=1.0,
            interval=0.01,
        )
        assert elapsed_abs >= 0.0

        with pytest.raises(TimeoutError, match="wait_for_path"):
            await conn.wait_for_path(
                tmp_path / "never_created.sock",
                state="present",
                timeout=0.05,
                interval=0.01,
            )


def test_sync_connection_wait_for_primitives(tmp_path: Path) -> None:
    """SyncConnection поддерживает wait_for_connection и wait_for_path."""
    marker = tmp_path / "sync_ready.txt"
    marker.write_text("OK: 200\n", encoding="utf-8")

    with SyncConnection.from_uri("local://localhost") as sconn:
        pr = sconn.wait_for_connection(timeout=2.0, interval=0.05)
        assert pr.alive is True

        elapsed = sconn.wait_for_path(
            marker, state="present", content_regex=r"OK:\s+200", timeout=1.0
        )
        assert elapsed >= 0.0
