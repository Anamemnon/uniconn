# tests/unit/architecture/test_post_refactoring_audit.py
"""Приёмочные архитектурные тесты по результатам повторного аудита (v0.11.1)."""

from __future__ import annotations

import sys
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from uniconn import (
    Connection,
    ConnectionConfig,
    FactSpec,
    FileSourceSpec,
    InMemoryTracer,
    Result,
    SyncConnection,
    SyncResult,
    TimeoutError,
    blocklist_hook,
    otel_tracing_hook,
)
from uniconn.core.pipeline import CommandRequest, NextHandler
from uniconn.transports._local import LocalTransport
from uniconn.transports._ssh import SSHTransport


class _DummyObserver:
    """Тестовый наблюдатель сквозных операций для проверки цепочки вызовов."""

    def __init__(self, tag: str, log: list[str]) -> None:
        self.tag = tag
        self.log = log

    async def observe_stream(
        self,
        conn: Any,
        command: Any,
        raw_gen: AsyncIterator[str],
    ) -> AsyncIterator[str]:
        self.log.append(f"{self.tag}:stream:start")
        async for line in raw_gen:
            yield line
        self.log.append(f"{self.tag}:stream:end")

    async def observe_open_shell(
        self,
        conn: Any,
        raw_fn: Callable[..., Awaitable[Any]],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        self.log.append(f"{self.tag}:open_shell:before")
        res = await raw_fn(*args, **kwargs)
        self.log.append(f"{self.tag}:open_shell:after")
        return res

    async def observe_upload(
        self,
        conn: Any,
        raw_fn: Callable[..., Awaitable[None]],
        local_path: str | Path,
        remote_path: str | Path,
        recurse: bool = False,
        **kwargs: Any,
    ) -> None:
        self.log.append(f"{self.tag}:upload:before")
        await raw_fn(local_path, remote_path, recurse=recurse, **kwargs)
        self.log.append(f"{self.tag}:upload:after")

    async def observe_download(
        self,
        conn: Any,
        raw_fn: Callable[..., Awaitable[None]],
        remote_path: str | Path,
        local_path: str | Path,
        recurse: bool = False,
        **kwargs: Any,
    ) -> None:
        self.log.append(f"{self.tag}:download:before")
        await raw_fn(remote_path, local_path, recurse=recurse, **kwargs)
        self.log.append(f"{self.tag}:download:after")

    async def observe_read_file(
        self,
        conn: Any,
        raw_fn: Callable[..., Awaitable[str | bytes]],
        remote_path: str | Path,
        encoding: str | None = "utf-8",
    ) -> str | bytes:
        self.log.append(f"{self.tag}:read_file:before")
        res = await raw_fn(remote_path, encoding=encoding)
        self.log.append(f"{self.tag}:read_file:after")
        return res

    async def observe_write_file(
        self,
        conn: Any,
        raw_fn: Callable[..., Awaitable[None]],
        remote_path: str | Path,
        content: str | bytes,
        mode: int | None = None,
        encoding: str = "utf-8",
    ) -> None:
        self.log.append(f"{self.tag}:write_file:before")
        await raw_fn(remote_path, content, mode=mode, encoding=encoding)
        self.log.append(f"{self.tag}:write_file:after")

    async def observe_sync_dir(
        self,
        conn: Any,
        raw_fn: Callable[..., Awaitable[SyncResult]],
        **kwargs: Any,
    ) -> SyncResult:
        self.log.append(f"{self.tag}:sync_dir:before")
        res = await raw_fn(**kwargs)
        self.log.append(f"{self.tag}:sync_dir:after")
        return res

    async def observe_shell_execute(
        self,
        conn: Any,
        raw_fn: Callable[..., Awaitable[Result]],
        command: Any,
        timeout: float | None = None,
    ) -> Result:
        self.log.append(f"{self.tag}:shell_execute:before")
        res = await raw_fn(command, timeout=timeout)
        self.log.append(f"{self.tag}:shell_execute:after")
        return res

    async def observe_shell_expect(
        self,
        conn: Any,
        raw_fn: Callable[..., Awaitable[Result]],
        **kwargs: Any,
    ) -> Result:
        self.log.append(f"{self.tag}:shell_expect:before")
        res = await raw_fn(**kwargs)
        self.log.append(f"{self.tag}:shell_expect:after")
        return res


@pytest.mark.asyncio
async def test_multiple_operation_observers_are_chained(tmp_path: Path) -> None:
    """Все зарегистрированные OperationObserver вызываются последовательно по цепочке."""
    events: list[str] = []
    obs1 = _DummyObserver("obs1", events)
    obs2 = _DummyObserver("obs2", events)

    conn = Connection.from_uri("local://")
    conn.add_operation_observer(obs1)
    conn.add_operation_observer(obs2)

    f = tmp_path / "chained.txt"
    await conn.write_file(f, "hello")
    content = await conn.read_file(f)
    assert content == "hello"

    assert events == [
        "obs1:write_file:before",
        "obs2:write_file:before",
        "obs2:write_file:after",
        "obs1:write_file:after",
        "obs1:read_file:before",
        "obs2:read_file:before",
        "obs2:read_file:after",
        "obs1:read_file:after",
    ]
    await conn.close()


@pytest.mark.asyncio
async def test_file_operations_respect_cd_dry_run_and_auto_connect(tmp_path: Path) -> None:
    """upload, download, chmod, stat и listdir учитывают conn.cd(), dry_run и ленивое подключение."""
    src_file = tmp_path / "source.txt"
    src_file.write_text("payload", encoding="utf-8")
    work_dir = tmp_path / "work"
    work_dir.mkdir()

    # Dry-run не должен создавать целевой файл при upload и менять права при chmod
    dry_conn = Connection.from_uri("local://", dry_run=True)
    with dry_conn.cd(work_dir):
        await dry_conn.upload(src_file, "dest.txt")
        await dry_conn.chmod(src_file, 0o600)
    assert not (work_dir / "dest.txt").exists()

    # Обычный режим без явного async with (проверка автоподключения и разрешения cd)
    conn = Connection.from_uri("local://")
    assert not conn.transport.is_connected
    with conn.cd(work_dir):
        await conn.upload(src_file, "uploaded.txt")
        assert conn.transport.is_connected
        entries = await conn.listdir(".")
        assert "uploaded.txt" in entries
        st = await conn.stat("uploaded.txt")
        assert st["size"] == 7
        dl_target = tmp_path / "downloaded.txt"
        await conn.download("uploaded.txt", dl_target)
        assert dl_target.read_text(encoding="utf-8") == "payload"
    await conn.close()


@pytest.mark.asyncio
async def test_run_bytes_executes_through_command_pipeline_and_cassette(tmp_path: Path) -> None:
    """run_bytes проходит через CommandPipeline (хуки, OTel-трассировка) и записывается в кассету."""
    tracer = InMemoryTracer()
    hook = otel_tracing_hook(tracer=tracer)
    before_called: list[str] = []

    conn = Connection.from_uri("local://")
    hook.attach(conn)
    conn.add_hook("before_run", lambda cmd, host, kw: before_called.append(cmd))
    conn.add_hook("before_run", blocklist_hook(["rm -rf *"]))

    with pytest.raises(PermissionError):
        await conn.run_bytes("rm -rf /tmp/forbidden")

    cassette_file = tmp_path / "bytes_cassette.yaml"
    async with conn.use_cassette(cassette_file, mode="all"):
        out = await conn.run_bytes(["python3", "-c", "import sys; sys.stdout.buffer.write(b'\\x00\\xffok')"])
        assert out == b"\x00\xffok"

    assert any("sys.stdout.buffer.write" in c for c in before_called)
    assert any(s.name == "uniconn.run" for s in tracer.spans)

    # Воспроизведение из кассеты в режиме none без обращения к реальному процессу
    async with conn.use_cassette(cassette_file, mode="none"):
        replayed = await conn.run_bytes(["python3", "-c", "import sys; sys.stdout.buffer.write(b'\\x00\\xffok')"])
        assert replayed == b"\x00\xffok"

    await conn.close()


@pytest.mark.asyncio
async def test_connection_copy_preserves_observers_retry_zero_and_middlewares() -> None:
    """Connection.copy() сохраняет retry_attempts=0, OtelTracingHook и пользовательские Middleware."""
    tracer = InMemoryTracer()
    hook = otel_tracing_hook(tracer=tracer)
    custom_mw_calls: list[str] = []

    class _CustomMiddleware:
        async def __call__(self, request: CommandRequest, call_next: NextHandler) -> Result:
            custom_mw_calls.append(request.command)
            return await call_next(request)

    conn = Connection.from_uri("local://", retry_attempts=3)
    hook.attach(conn)
    conn.pipeline.add_middleware(_CustomMiddleware())

    cloned = conn.copy(retry_attempts=0)
    assert cloned.retry_attempts == 0
    assert hook in cloned.operation_observers

    res = await cloned.run("echo copy_ok")
    assert res.ok
    assert custom_mw_calls == ["echo copy_ok"]
    assert any(s.name == "uniconn.run" for s in tracer.spans)
    await cloned.close()


@pytest.mark.posix_only
@pytest.mark.asyncio
async def test_gather_facts_custom_only_does_not_pollute_builtin_cache(tmp_path: Path) -> None:
    """Вызов gather_facts с include_builtin=False не затирает кэш встроенных системных фактов."""
    marker_file = tmp_path / "release.txt"
    marker_file.write_text("custom-1.0\n", encoding="utf-8")

    async with Connection.from_uri("local://") as conn:
        partial = await conn.gather_facts(
            spec=FactSpec(
                include_builtin=False,
                files=[FileSourceSpec(name="rel", path=str(marker_file))],
            )
        )
        assert partial.kernel == "Unknown"
        assert str(partial.custom["rel"]).strip() == "custom-1.0"
        assert conn._cached_facts is None

        full = await conn.gather_facts()
        assert full.kernel != "Unknown"
        assert conn._cached_facts is full


def test_sync_connection_factories_shared_loop_and_reentrant_context(tmp_path: Path) -> None:
    """SyncConnection поддерживает все фабрики, общий daemon-поток и повторный вход в with."""
    c1 = SyncConnection.from_uri("local://")
    c2 = SyncConnection.from_dict({"transport": "local"})
    c3 = c1.copy(dry_run=True)

    with c1:
        r1 = c1.run("echo first")
        assert r1.text == "first"

    # Повторный вход в контекстный менеджер после закрытия
    with c1:
        r2 = c1.run("echo second")
        assert r2.text == "second"

    with c2:
        assert c2.run("echo dict_conn").text == "dict_conn"
        assert c1._portal.get_loop() is c2._portal.get_loop()

    with c3:
        assert c3.is_dry_run is True
        assert c3.run("echo dry").text == ""


@pytest.mark.asyncio
async def test_ssh_and_local_timeout_wrapped_in_domain_timeout_error() -> None:
    """Таймаут выполнения в LocalTransport и SSHTransport выбрасывает uniconn.exceptions.TimeoutError."""
    local_t = LocalTransport(ConnectionConfig(transport="local"))
    await local_t.connect()
    with pytest.raises(TimeoutError):
        await local_t.run([sys.executable, "-c", "import time; time.sleep(2)"], timeout=0.05)
    await local_t.disconnect()

    ssh_t = SSHTransport(ConnectionConfig(transport="ssh", host="127.0.0.1"))
    ssh_t._connected = True
    mock_conn = MagicMock()
    mock_proc_cm = MagicMock()
    mock_proc_cm.__aenter__ = AsyncMock(side_effect=TimeoutError("simulated") if False else __import__("builtins").TimeoutError("raw timeout"))
    mock_proc_cm.__aexit__ = AsyncMock(return_value=None)
    mock_conn.create_process = MagicMock(return_value=mock_proc_cm)
    ssh_t._conn = mock_conn

    with pytest.raises(TimeoutError):
        await ssh_t.run("hostname", timeout=0.1)


def test_no_internal_imports_from_deprecated_private_shims() -> None:
    """Внутри src/uniconn/ нет внутренних импортов из устаревших модулей-заглушек _*.py."""
    src_root = Path(__file__).resolve().parents[3] / "src" / "uniconn"
    shim_files = {
        "_base.py",
        "_config.py",
        "_connection.py",
        "_facts.py",
        "_pool.py",
        "_session_pool.py",
        "_shell.py",
        "_sync.py",
    }
    forbidden_patterns = (
        "from ._base import",
        "from .._base import",
        "from .._config import",
        "from ._connection import",
        "from .._connection import",
        "from ._facts import",
        "from .._facts import",
        "from ._shell import",
        "from .._shell import",
        "from ._sync import",
        "from .._sync import",
    )
    violations: list[str] = []
    for py_file in src_root.rglob("*.py"):
        if py_file.name in shim_files:
            continue
        text = py_file.read_text(encoding="utf-8")
        for pat in forbidden_patterns:
            if pat in text:
                violations.append(f"{py_file.relative_to(src_root)}: {pat}")
    assert not violations, f"Found internal shim imports: {violations}"
