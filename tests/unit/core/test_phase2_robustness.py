# tests/unit/core/test_phase2_robustness.py
"""Регрессионные unit-тесты этапа 2: гонки пулов, timeout=0, Telnet/Shell, пути и sync_dir."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from uniconn import (
    BatchAbortedError,
    Connection,
    ConnectionConfig,
    ConnectionError,
    ConnectionPool,
    ExecutionError,
    Result,
    TimeoutError,
)
from uniconn.core.context import ExecutionContext
from uniconn.pool.session_pool import SSHSessionPool
from uniconn.shell.session import ShellSession
from uniconn.transports._telnet import TelnetTransport


@pytest.mark.asyncio
async def test_batch_rollout_tolerates_exceptions_within_max_fail_ratio(
    mocker: pytest.MonkeyPatch,
) -> None:
    """Если исключений <= max_fail_ratio, батчевая раскатка не падает на первом сбое и идёт дальше."""
    uris = [f"local://node-{i}" for i in range(4)]
    pool = ConnectionPool(uris, batch_size=2, max_fail_ratio=0.5)
    visited: list[str] = []

    async def fake_run(self_conn: Connection, cmd: str, **kw: object) -> Result:
        host = self_conn.config.host or ""
        visited.append(host)
        if host == "node-0":
            raise ConnectionError("transient node-0 error", host=host)
        return Result(exit_code=0, stdout=f"ok:{host}", stderr="", duration=0.01, command=cmd, host=host)

    mocker.patch.object(Connection, "run", fake_run)
    results = await pool.map("echo hi")
    # Все 4 узла были обработаны (батч 0 имел 1/2 = 0.5 <= 0.5, батч 1 тоже прошёл)
    assert visited == ["node-0", "node-1", "node-2", "node-3"]
    assert [r.stdout for r in results] == ["ok:node-1", "ok:node-2", "ok:node-3"]

    # А при max_fail_ratio=0.2 тот же 1/2 сбой корректно вызывает BatchAbortedError
    with pytest.raises(BatchAbortedError):
        await pool.map("echo hi", batch_size=2, max_fail_ratio=0.2)


@pytest.mark.asyncio
async def test_session_pool_check_health_does_not_block_acquire_and_execute_exhaustion() -> None:
    """check_health() не удерживает условие пула во время I/O, а исчерпание retry бросает ConnectionError."""
    spool = SSHSessionPool("local://localhost", max_connections=2, max_sessions_per_conn=2)
    slow_probe_started = asyncio.Event()
    release_probe = asyncio.Event()

    async def slow_is_alive(timeout: float | None = None) -> bool:
        slow_probe_started.set()
        await release_probe.wait()
        return True

    slot, _ = await spool._acquire_slot()
    slot.conn.is_alive = slow_is_alive  # type: ignore[method-assign]
    await spool._release_slot(slot)

    health_task = asyncio.create_task(spool.check_health(timeout=1.0))
    await slow_probe_started.wait()

    # Пока check_health ждёт сеть, другой корутине должен сразу выдаваться свободный слот без дедлока
    acquired = await asyncio.wait_for(spool._acquire_slot(), timeout=0.5)
    await spool._release_slot(acquired[0])

    release_probe.set()
    assert await health_task >= 1
    await spool.close()

    # Проверка отсутствия AssertionError при исчерпании адаптивных повторов в _execute
    spool2 = SSHSessionPool("local://localhost", max_connections=1)
    spool2._run_on_slot = AsyncMock(return_value=(None, True))  # type: ignore[method-assign]
    with pytest.raises(ConnectionError, match="exhausted adaptive recovery"):
        await spool2.run("uname -a")
    await spool2.close()


@pytest.mark.asyncio
async def test_zero_timeout_and_cancelled_error_and_retry_order() -> None:
    """Явный timeout=0.0 сохраняется, CancelledError не вызывает on_error, а Retry коннектится после backoff."""
    seen_timeouts: list[float | None] = []
    hook_errors: list[str] = []
    lifecycle_events: list[str] = []

    transport = MagicMock()
    transport.name = "mock"
    transport.is_connected = True

    async def mock_connect() -> None:
        lifecycle_events.append("connect")
        transport.is_connected = True

    async def mock_disconnect() -> None:
        lifecycle_events.append("disconnect")
        transport.is_connected = False

    async def mock_run(cmd: str, timeout: float | None = None, **kw: object) -> Result:
        seen_timeouts.append(timeout)
        if cmd == "cancel_me":
            raise asyncio.CancelledError()
        if len(lifecycle_events) == 0:
            lifecycle_events.append("fail_run")
            raise ConnectionError("drop once", host="h1")
        lifecycle_events.append("ok_run")
        return Result(exit_code=0, stdout="ok", stderr="", duration=0.01, command=cmd, host="h1")

    transport.connect = AsyncMock(side_effect=mock_connect)
    transport.disconnect = AsyncMock(side_effect=mock_disconnect)
    transport.run = AsyncMock(side_effect=mock_run)

    conn = Connection(transport, ConnectionConfig(transport="ssh", host="h1", timeout=30.0), retry_attempts=2)
    conn.add_hook("on_error", lambda exc, cmd, host: hook_errors.append(cmd))

    # 1. Explicit timeout=0.0 не должен подменяться на 30.0, а reconnect происходит во 2-й попытке после disconnect
    res = await conn.run("zero_to", timeout=0.0)
    assert res.ok
    assert seen_timeouts[0] == 0.0
    assert lifecycle_events == ["fail_run", "disconnect", "connect", "ok_run"]

    # 2. CancelledError не должен вызывать on_error хук
    with pytest.raises(asyncio.CancelledError):
        await conn.run("cancel_me")
    assert hook_errors == []


@pytest.mark.asyncio
async def test_shell_session_non_posix_and_resync_after_timeout() -> None:
    """ShellSession с shell_type='network' не шлёт export PS1, а после таймаута сбрасывает устаревший буфер."""
    proc = MagicMock()
    proc.returncode = None
    proc.exit_status = None
    written: list[str] = []
    proc.stdin = MagicMock()
    proc.stdin.write = MagicMock(side_effect=lambda s: written.append(s))
    proc.stdin.drain = AsyncMock()
    proc.close = MagicMock()
    proc.terminate = MagicMock()
    proc.wait_closed = AsyncMock()

    net_session = ShellSession(proc, host="sw1", shell_type="cisco_ios")
    await net_session.initialize()
    assert not any("export PS1" in w for w in written)

    # Тест resync после timeout на POSIX сессии
    posix_session = ShellSession(proc, host="srv1", session_uuid="sync1234", default_timeout=0.05)

    call_idx = 0

    async def fake_read(_n: int = 4096) -> str:
        nonlocal call_idx
        call_idx += 1
        if call_idx == 1:
            await asyncio.sleep(0.3)
            return "stale slow output\n"
        if call_idx == 2:
            # Ответ на resync ':'
            return "stale residual chunk\n__UNICONN_sync1234__0\n"
        return "fresh_ok\n__UNICONN_sync1234__0\n"

    proc.stdout = MagicMock()
    proc.stdout.read = AsyncMock(side_effect=fake_read)

    with pytest.raises(TimeoutError):
        await posix_session.execute("slow_cmd", timeout=0.05)
    assert posix_session._needs_resync is True

    res2 = await posix_session.execute("echo fresh_ok", timeout=1.0)
    assert res2.stdout == "fresh_ok"
    assert "stale residual chunk" not in res2.stdout


@pytest.mark.asyncio
async def test_telnet_eol_prompt_matching_stream_timeout_and_disconnect_cleanup() -> None:
    """TelnetTransport не прерывается на '$ '/'# '/'> ' в середине строки, пробрасывает TimeoutError в stream и чистится."""
    transport = TelnetTransport(ConnectionConfig(transport="telnet", host="10.0.0.8", timeout=10.0))
    transport._connected = True

    lines = [
        b"show balance\r\n",
        b"Price: $ 100 and a > b and # comment\r\n",
        b"router# ",
    ]
    line_iter = iter(lines)
    reader = MagicMock()

    async def fake_readline() -> bytes:
        return next(line_iter, b"")

    reader.readline = AsyncMock(side_effect=fake_readline)
    writer = MagicMock()
    writer.write = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock(side_effect=RuntimeError("close boom"))
    transport._reader = reader
    transport._writer = writer

    res = await transport.run("show balance")
    assert "Price: $ 100 and a > b and # comment" in res.stdout

    # В stream TimeoutError пробрасывается как UniconnTimeoutError (а не тихий break)
    reader.readline = AsyncMock(side_effect=TimeoutError("read timed out"))
    with pytest.raises(TimeoutError, match="Telnet stream timeout"):
        async for _ in transport.stream("tail -f /var/log/messages", timeout=0.1):
            pass

    # disconnect() обязан обнулить состояние несмотря на сбой wait_closed()
    await transport.disconnect()
    assert transport.is_connected is False
    assert transport._reader is None
    assert transport._writer is None


def test_execution_context_uses_target_path_semantics() -> None:
    """ExecutionContext.resolve_path использует posixpath/ntpath без примеси локальной ОС."""
    ctx = ExecutionContext()
    with ctx.cd("/var/log"):
        assert ctx.resolve_path("nginx/error.log") == "/var/log/nginx/error.log"
    with ctx.cd(r"C:\ProgramData\App"):
        assert ctx.resolve_path("logs/app.log") == r"C:\ProgramData\App\logs\app.log"


@pytest.mark.asyncio
async def test_sync_dir_delete_prunes_stale_empty_directories(tmp_path: Path) -> None:
    """sync_dir(delete=True) удаляет устаревшие пустые поддиректории на удалённой стороне."""
    src_dir = tmp_path / "src"
    dst_dir = tmp_path / "dst"
    src_dir.mkdir()
    dst_dir.mkdir()
    (src_dir / "keep.txt").write_text("ok", encoding="utf-8")
    (dst_dir / "keep.txt").write_text("ok", encoding="utf-8")
    stale_dir = dst_dir / "old_nested" / "sub"
    stale_dir.mkdir(parents=True)
    (stale_dir / "dead.txt").write_text("dead", encoding="utf-8")

    async with Connection.from_uri("local://") as conn:
        res = await conn.files.sync_dir(src_dir, dst_dir, delete=True)
        assert "old_nested/sub/dead.txt" in res.deleted
        assert not (dst_dir / "old_nested" / "sub").exists()
        assert not (dst_dir / "old_nested").exists()


@pytest.mark.asyncio
async def test_python_worker_windows_quoting_and_malformed_json_frame() -> None:
    """RemotePythonWorker использует безопасное экранирование под WinRM и корректно оборачивает битый JSON."""
    win_conn = Connection(
        transport=MagicMock(name="winrm"),
        config=ConnectionConfig(
            transport="winrm",
            host="win01",
            options={"python_interpreter": r"C:\Program Files\Python312\python.exe"},
        ),
    )
    win_conn._transport.name = "winrm"
    boot = win_conn.python_worker._build_bootstrap_command()
    assert '& "C:\\Program Files\\Python312\\python.exe"' in boot
    assert "'C:" not in boot

    # Битый JSON-RPC фрейм в oneshot-ответе -> ExecutionError, а не необработанный JSONDecodeError
    local_conn = Connection.from_uri("local://")
    local_conn.run = AsyncMock(  # type: ignore[method-assign]
        return_value=Result(
            exit_code=0,
            stdout="__UNICONN_PYRPC__:{not-valid-json",
            stderr="",
            duration=0.01,
            command="mock",
        )
    )
    with pytest.raises(ExecutionError, match="Malformed JSON-RPC frame"):
        await local_conn.python_worker._execute_oneshot_via_run({"id": 1, "op": "ping"})
