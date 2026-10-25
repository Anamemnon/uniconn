# tests/unit/core/test_otel_tracing.py
"""Unit-тесты для интеграции с OpenTelemetry (OtelTracingHook, TracingMiddleware, InMemoryTracer)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from uniconn import (
    Connection,
    ConnectionError,
    ConnectionPool,
    ExecutionError,
    InMemoryTracer,
    Result,
    otel_tracing_hook,
)


class TestOtelTracingHook:
    """Проверка автоматического создания span'ов для операций Connection и ConnectionPool."""

    @pytest.mark.asyncio
    async def test_run_creates_span_with_attributes_and_masks_sensitive(self) -> None:
        """Вызовы run() создают span uniconn.run с атрибутами и маскируют sensitive-команды."""
        tracer = InMemoryTracer(service_name="test-svc")
        hook = otel_tracing_hook(tracer=tracer, service_name="test-svc", record_output=True)
        conn = Connection.from_uri("local://")
        hook.attach(conn)

        res = await conn.run("echo hello_otel")
        assert res.ok

        await conn.run("echo secret_password_value", sensitive=True)

        assert len(tracer.spans) == 2
        span1 = tracer.spans[0]
        assert span1.name == "uniconn.run"
        assert span1.attributes["rpc.system"] == "uniconn"
        assert span1.attributes["uniconn.transport"] == "local"
        assert span1.attributes["process.command_line"] == "echo hello_otel"
        assert span1.attributes["process.exit_code"] == 0
        assert span1.attributes["uniconn.ok"] is True
        assert span1.attributes["process.stdout"].strip() == "hello_otel"
        assert span1.status_code == "OK"

        span2 = tracer.spans[1]
        assert span2.attributes["process.command_line"] == "***REDACTED***"
        assert span2.attributes["process.stdout"] == "***REDACTED***"
        assert span2.attributes["uniconn.sensitive"] is True

    @pytest.mark.asyncio
    async def test_run_records_exception_and_closes_span_on_raise_on_error(self) -> None:
        """При raise_on_error=True span фиксирует ExecutionError, код выхода и статус ERROR."""
        tracer = InMemoryTracer()
        conn = Connection.from_uri("local://")
        otel_tracing_hook(tracer=tracer).attach(conn)

        with pytest.raises(ExecutionError):
            await conn.run("exit 42", raise_on_error=True)

        assert len(tracer.spans) == 1
        span = tracer.spans[0]
        assert span.name == "uniconn.run"
        assert span.attributes["process.exit_code"] == 42
        assert span.attributes["uniconn.ok"] is False
        assert span.status_code == "ERROR"
        assert span.end_time is not None
        assert any("ExecutionError" in exc for exc in span.exceptions)

    @pytest.mark.asyncio
    async def test_retry_middleware_adds_retry_events_to_active_span(self) -> None:
        """При сбоях сети RetryMiddleware добавляет события command.retry в активный span."""
        tracer = InMemoryTracer()
        conn = Connection.from_uri("local://", retry_attempts=2)
        otel_tracing_hook(tracer=tracer).attach(conn)

        call_count = 0

        async def flaky_run(command: str, timeout: float | None = None, **kwargs: object) -> Result:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ConnectionError("Temporary link drop", host="localhost")
            return Result(exit_code=0, stdout="recovered\n", stderr="", duration=0.01, command=command)

        conn._transport.run = AsyncMock(side_effect=flaky_run)
        res = await conn.run("uptime")
        assert res.text == "recovered"

        assert len(tracer.spans) == 1
        span = tracer.spans[0]
        event_names = [ev[0] for ev in span.events]
        assert "command.retry" in event_names

    @pytest.mark.asyncio
    async def test_file_operations_shell_and_stream_create_spans(
        self,
        tmp_path: Path,
    ) -> None:
        """Файловые операции (write_file, read_file, upload, download, sync_dir), open_shell и stream создают span'ы."""
        tracer = InMemoryTracer()
        conn = Connection.from_uri("local://")
        otel_tracing_hook(tracer=tracer).attach(conn)

        target_file = tmp_path / "sample.txt"
        copy_file = tmp_path / "copy.txt"
        dl_file = tmp_path / "downloaded.txt"

        await conn.write_file(str(target_file), "telemetry-data")
        content = await conn.read_file(str(target_file))
        assert content == "telemetry-data"

        await conn.upload(str(target_file), str(copy_file))
        await conn.download(str(copy_file), str(dl_file))

        src_dir = tmp_path / "src_sync"
        dst_dir = tmp_path / "dst_sync"
        src_dir.mkdir()
        (src_dir / "a.txt").write_text("123", encoding="utf-8")
        await conn.sync_dir(src_dir, dst_dir)

        lines = [line async for line in conn.stream("printf 'a\\nb\\n'")]
        assert lines == ["a", "b"]

        async with await conn.open_shell(init_posix=False) as shell:
            sh_res = await shell.execute("echo in_shell")
            assert sh_res.text == "in_shell"

        span_names = [s.name for s in tracer.spans]
        assert "uniconn.write_file" in span_names
        assert "uniconn.read_file" in span_names
        assert "uniconn.upload" in span_names
        assert "uniconn.download" in span_names
        assert "uniconn.sync_dir" in span_names
        assert "uniconn.stream" in span_names
        assert "uniconn.open_shell" in span_names
        assert "uniconn.shell.execute" in span_names

    def test_sync_connection_preserves_parent_span_across_event_loop_portal(self) -> None:
        """SyncConnection сохраняет родительский span из вызывающего потока через EventLoopPortal."""
        tracer = InMemoryTracer()
        conn = Connection.from_uri("local://")
        otel_tracing_hook(tracer=tracer).attach(conn)

        with conn.to_sync() as sync_conn:
            with tracer.start_as_current_span("parent_http_request") as parent_span:
                res = sync_conn.run("echo child_op")
                assert res.text == "child_op"

        run_spans = [s for s in tracer.spans if s.name == "uniconn.run"]
        assert len(run_spans) == 1
        assert run_spans[0].parent_name == "parent_http_request"
        assert run_spans[0].parent_span_id == parent_span.span_id

    @pytest.mark.asyncio
    async def test_concurrent_pool_execution_isolates_span_contexts(self) -> None:
        """При параллельном выполнении в ConnectionPool контексты span'ов не смешиваются между корутинами."""
        tracer = InMemoryTracer()
        pool = ConnectionPool(["local://?host=node-1", "local://?host=node-2", "local://?host=node-3"])
        otel_tracing_hook(tracer=tracer).attach(pool)

        with tracer.start_as_current_span("fleet_batch") as batch_span:
            results = await asyncio.gather(
                pool.map("echo fleet_ping"),
            )
            assert len(results[0]) == 3

        run_spans = [s for s in tracer.spans if s.name == "uniconn.run"]
        assert len(run_spans) == 3
        for sp in run_spans:
            assert sp.parent_span_id == batch_span.span_id
