# tests/unit/test_screen_log_pipeline.py
"""Тесты LogPipeline, обработчиков логов и BackgroundLogCollector."""

import logging
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from uniconn.background._log_collector import BackgroundLogCollector
from uniconn.background._log_pipeline import (
    ForwardHandler,
    LocalFileHandler,
    LogPipeline,
    NullHandler,
    StreamHandler,
)
from uniconn.result import Result


def make_result(stdout: str = "", exit_code: int = 0, command: str = "") -> Result:
    """Создать Result для мока."""
    return Result(
        exit_code=exit_code,
        stdout=stdout,
        stderr="",
        duration=0.1,
        command=command,
        timestamp=datetime.now(),
    )


def make_connection(handler) -> MagicMock:
    """Мок Connection с маршрутизацией команд в handler."""
    conn = MagicMock()
    conn.run = AsyncMock(side_effect=handler)
    return conn


def make_session(session_id: str = "s1", log_path: str = "/tmp/s1.log") -> MagicMock:
    """Мок ScreenSession с нужными атрибутами для коллектора."""
    session = MagicMock()
    session.session_id = session_id
    session.remote_log_path = log_path
    return session


class TestNullHandler:
    """Тесты NullHandler."""

    async def test_handle_is_noop(self):
        """Handle ничего не делает и возвращает None."""
        assert await NullHandler().handle("s1", ["line\n"]) is None


class TestLocalFileHandler:
    """Тесты LocalFileHandler: шаблоны имён и стратегии записи."""

    async def test_default_template(self, tmp_path: Path):
        """Шаблон по умолчанию — {session_id}.log."""
        handler = LocalFileHandler(str(tmp_path))
        assert handler.local_path("s1") == tmp_path / "s1.log"

    async def test_full_template_with_format_spec(self, tmp_path: Path):
        """Шаблон подставляет pool_id, idx, host, command и timestamp с format spec."""
        handler = LocalFileHandler(
            str(tmp_path),
            name_template="{pool_id}/{host}_{command}_{idx}_{timestamp:%Y%m%d}.log",
            pool_id="pool1",
            idx=3,
            host="node1",
            command="stress",
        )
        path = handler.local_path("s1")
        assert path.parent == tmp_path / "pool1"
        assert path.name.startswith("node1_stress_3_")
        assert path.suffix == ".log"

    async def test_realtime_writes_immediately(self, tmp_path: Path):
        """Стратегия realtime пишет каждую порцию сразу в файл."""
        handler = LocalFileHandler(str(tmp_path), strategy="realtime")
        await handler.handle("s1", ["one\n"])
        assert (tmp_path / "s1.log").read_text(encoding="utf-8") == "one\n"

    async def test_periodic_buffers_until_interval(self, tmp_path: Path):
        """Стратегия periodic буферизует, пока не истечёт интервал."""
        handler = LocalFileHandler(
            str(tmp_path), strategy="periodic", periodic_interval=1e12
        )
        await handler.handle("s1", ["one\n", "two\n"])
        assert not (tmp_path / "s1.log").exists()

    async def test_periodic_flushes_after_interval(self, tmp_path: Path):
        """Стратегия periodic сбрасывает буфер при нулевом интервале."""
        handler = LocalFileHandler(str(tmp_path), strategy="periodic", periodic_interval=0.0)
        await handler.handle("s1", ["one\n"])
        await handler.handle("s1", ["two\n"])
        assert (tmp_path / "s1.log").read_text(encoding="utf-8") == "one\ntwo\n"

    async def test_on_complete_writes_only_after_finalize(self, tmp_path: Path):
        """Стратегия on_complete пишет файл только после finalize()."""
        handler = LocalFileHandler(str(tmp_path), strategy="on_complete")
        await handler.handle("s1", ["one\n"])
        assert not (tmp_path / "s1.log").exists()

        path = await handler.finalize("s1")
        assert path == tmp_path / "s1.log"
        assert path.read_text(encoding="utf-8") == "one\n"

    async def test_finalize_resets_buffer(self, tmp_path: Path):
        """finalize() возвращает путь и очищает буфер — повторный вызов не дублирует."""
        handler = LocalFileHandler(str(tmp_path), strategy="on_complete")
        await handler.handle("s1", ["one\n"])
        await handler.finalize("s1")
        await handler.finalize("s1")
        assert (tmp_path / "s1.log").read_text(encoding="utf-8") == "one\n"


class TestForwardHandler:
    """Тесты ForwardHandler."""

    async def test_handle_runs_printf_append(self):
        """Handle дописывает chunk в удалённый файл через printf >>."""
        conn = make_connection(lambda command, **kwargs: make_result("", command=command))
        handler = ForwardHandler(conn, "/var/log/remote.log")
        await handler.handle("s1", ["line one\n", "line two\n"])

        cmd = conn.run.call_args.args[0]
        assert cmd.startswith("printf '%s'")
        assert "line one" in cmd
        assert cmd.endswith(">> /var/log/remote.log")

    async def test_handle_error_does_not_raise(self, caplog):
        """Ошибка пересылки логируется warning и не роняет обработчик."""
        conn = make_connection(None)
        conn.run = AsyncMock(side_effect=Exception("ssh down"))
        handler = ForwardHandler(conn, "/var/log/remote.log")

        with caplog.at_level(logging.WARNING):
            await handler.handle("s1", ["line\n"])
        assert "не удался" in caplog.text


class TestStreamHandler:
    """Тесты StreamHandler."""

    async def test_handle_queues_events(self):
        """Handle кладёт каждую строку как LogEvent, events() их отдаёт."""
        handler = StreamHandler()
        await handler.handle("s1", ["one\n", "two\n"])

        events = handler.events()
        first = await events.__anext__()
        second = await events.__anext__()
        assert (first.session_id, first.line) == ("s1", "one\n")
        assert (second.session_id, second.line) == ("s1", "two\n")


class TestLogPipeline:
    """Тесты LogPipeline."""

    async def test_emit_broadcasts_to_all_handlers(self):
        """Emit рассылает chunk всем зарегистрированным обработчикам."""
        h1, h2 = MagicMock(), MagicMock()
        h1.handle = AsyncMock()
        h2.handle = AsyncMock()
        pipeline = LogPipeline([h1, h2])

        await pipeline.emit("s1", ["line\n"])
        h1.handle.assert_awaited_once_with("s1", ["line\n"])
        h2.handle.assert_awaited_once_with("s1", ["line\n"])


class TestBackgroundLogCollector:
    """Тесты BackgroundLogCollector.read_chunk — offset-логика."""

    async def test_first_read_uses_tail_from_start(self):
        """Первый вызов читает tail -c +1 и возвращает строки с новым offset."""
        def handler(command: str, **kwargs) -> Result:
            if command == "stat -c %s /tmp/s1.log":
                return make_result("12\n", command=command)
            if command == "tail -c +1 /tmp/s1.log":
                return make_result("line one\nli", command=command)
            return make_result("", command=command)

        collector = BackgroundLogCollector(make_connection(handler))
        lines, offset = await collector.read_chunk(make_session())
        assert lines == ["line one\n", "li"]
        assert offset == len(b"line one\nli")

    async def test_second_read_continues_from_offset(self):
        """Второй вызов читает tail -c +{offset+1}."""
        size = {"value": 11}

        def handler(command: str, **kwargs) -> Result:
            if command == "stat -c %s /tmp/s1.log":
                return make_result(f"{size['value']}\n", command=command)
            if command == "tail -c +1 /tmp/s1.log":
                return make_result("first line\n", command=command)
            if command == "tail -c +12 /tmp/s1.log":
                return make_result("second", command=command)
            return make_result("", command=command)

        conn = make_connection(handler)
        collector = BackgroundLogCollector(conn)
        session = make_session()

        _, offset1 = await collector.read_chunk(session)
        assert offset1 == 11

        size["value"] = 17
        _, offset2 = await collector.read_chunk(session)
        tail_calls = [c.args[0] for c in conn.run.call_args_list if "tail" in c.args[0]]
        assert tail_calls == ["tail -c +1 /tmp/s1.log", "tail -c +12 /tmp/s1.log"]
        assert offset2 == 17

    async def test_truncated_log_resets_offset(self):
        """Размер меньше offset — лог усечён, offset сбрасывается в 0 и читаем с начала."""
        size = {"value": 10}

        def handler(command: str, **kwargs) -> Result:
            if command == "stat -c %s /tmp/s1.log":
                return make_result(f"{size['value']}\n", command=command)
            if command.startswith("tail"):
                return make_result("x" * size["value"], command=command)
            return make_result("", command=command)

        conn = make_connection(handler)
        collector = BackgroundLogCollector(conn)
        session = make_session()

        _, offset = await collector.read_chunk(session)
        assert offset == 10

        size["value"] = 4
        lines, offset = await collector.read_chunk(session)
        tail_calls = [c.args[0] for c in conn.run.call_args_list if "tail" in c.args[0]]
        assert tail_calls[-1] == "tail -c +1 /tmp/s1.log"
        assert offset == 4
        assert lines == ["xxxx"]

    async def test_no_new_data_returns_empty(self):
        """Размер равен offset — ([], offset) без вызова tail."""
        def handler(command: str, **kwargs) -> Result:
            if command == "stat -c %s /tmp/s1.log":
                return make_result("5\n", command=command)
            return make_result("12345", command=command)

        conn = make_connection(handler)
        collector = BackgroundLogCollector(conn)
        session = make_session()

        await collector.read_chunk(session)
        conn.run.reset_mock()

        lines, offset = await collector.read_chunk(session)
        assert lines == []
        assert offset == 5
        assert not any("tail" in c.args[0] for c in conn.run.call_args_list)

    async def test_stat_error_returns_empty(self):
        """Stat вернул ошибку — ([], 0), tail не вызывается."""
        conn = make_connection(
            lambda command, **kwargs: make_result("", exit_code=1, command=command)
        )
        collector = BackgroundLogCollector(conn)
        lines, offset = await collector.read_chunk(make_session())
        assert lines == []
        assert offset == 0
        assert not any("tail" in c.args[0] for c in conn.run.call_args_list)


class TestLocalFileHandlerRotationAndWindowsJobBackend:
    """Тесты ротации локальных логов LocalFileHandler и стратегии WindowsJobBackend."""

    async def test_local_file_handler_rotates_backups(self, tmp_path) -> None:
        from uniconn.background import LocalFileHandler

        handler = LocalFileHandler(
            local_dir=tmp_path,
            strategy="realtime",
            max_bytes=20,
            backup_count=2,
        )
        # 1-я запись: 15 байт <= 20
        await handler.handle("sess1", ["12345678901234\n"])
        log_file = tmp_path / "sess1.log"
        assert log_file.read_text(encoding="utf-8") == "12345678901234\n"
        assert not (tmp_path / "sess1.log.1").exists()

        # 2-я запись: 15 + 15 > 20 -> ротация в sess1.log.1
        await handler.handle("sess1", ["abcdefghijklmn\n"])
        assert (tmp_path / "sess1.log.1").read_text(encoding="utf-8") == "12345678901234\n"
        assert log_file.read_text(encoding="utf-8") == "abcdefghijklmn\n"

        # 3-я запись: ротация в sess1.log.2 и sess1.log.1
        await handler.handle("sess1", ["ABCDEFGHIJKLMN\n"])
        assert (tmp_path / "sess1.log.2").read_text(encoding="utf-8") == "12345678901234\n"
        assert (tmp_path / "sess1.log.1").read_text(encoding="utf-8") == "abcdefghijklmn\n"
        assert log_file.read_text(encoding="utf-8") == "ABCDEFGHIJKLMN\n"

    async def test_windows_job_backend_lifecycle(self) -> None:
        import base64

        from uniconn.background import WindowsJobBackend, get_backend_by_name

        backend = get_backend_by_name("windows_job")
        assert isinstance(backend, WindowsJobBackend)
        assert backend.name == "windows_job"

        def _decode(cmd: str) -> str:
            if "-EncodedCommand " in cmd:
                b64 = cmd.split("-EncodedCommand ", 1)[1].strip().split()[0]
                return base64.b64decode(b64).decode("utf-16-le")
            return cmd

        def _handler(cmd: str, **kw: object) -> object:
            ps = _decode(cmd)
            assert ' -Command "' not in cmd
            stdout = "5\n" if "PSVersionTable" in ps else ("4321\n" if "Write-Output $procId" in ps else "s1 4321\n")
            return make_result(stdout, exit_code=0, command=cmd)

        conn = make_connection(_handler)
        assert await backend.is_available(conn) is True
        await backend.start_session(
            conn, "s1", "C:\\tmp\\s1.ps1", "C:\\tmp\\s1.log", "C:\\tmp\\s1.exit", "C:\\tmp\\s1.pid"
        )
        assert await backend.is_alive(conn, "s1", "C:\\tmp\\s1.pid", "C:\\tmp\\s1.exit") is True
        assert await backend.get_pid(conn, "s1", "C:\\tmp\\s1.pid", "C:\\tmp\\s1.exit") == 4321
        assert await backend.list_sessions(conn, prefix="s") == {"s1": 4321}
        await backend.send_interrupt(conn, "s1", "C:\\tmp\\s1.pid", "C:\\tmp\\s1.exit")
        await backend.terminate(conn, "s1", "C:\\tmp\\s1.pid")


class TestPatternTriggerAndTimelineAndWatchdog:
    """Тесты PatternTriggerHandler, LogWatchRule, BUILTIN_WATCH_RULES, TimelineHandler и Watchdog."""

    async def test_pattern_trigger_ring_buffer_context_and_abort(
        self, tmp_path: Path
    ) -> None:
        import json

        import pytest

        from uniconn import (
            BUILTIN_WATCH_RULES,
            ConfigurationError,
            HardwareFaultDetectedError,
            LogMatchEvent,
            LogWatchRule,
            PatternTriggerHandler,
            TimelineHandler,
            resolve_watch_rules,
        )

        with pytest.raises(ConfigurationError):
            LogWatchRule(name="bad", pattern="[unclosed")

        preset_rules = resolve_watch_rules(["kernel_panic", "telecom_bs"])
        assert len(preset_rules) == (
            len(BUILTIN_WATCH_RULES["kernel_panic"])
            + len(BUILTIN_WATCH_RULES["telecom_bs"])
        )

        matched_events: list[LogMatchEvent] = []
        timeline = TimelineHandler(tmp_path / "timeline.jsonl", fsync=False)
        trigger = PatternTriggerHandler(
            rules=[
                LogWatchRule(
                    name="aer_fatal",
                    pattern=r"AER:\s*Uncorrected",
                    severity="critical",
                    abort_on_match=True,
                    context_lines=2,
                ),
                {"name": "temp_warn", "pattern": r"temp=\d+C", "severity": "warning"},
            ],
            on_match=lambda ev: matched_events.append(ev),
            timeline=timeline,
            host="bbu-node-01",
        )

        pipeline = LogPipeline([timeline, trigger])
        await pipeline.emit(
            "dmesg",
            [
                "[1.0] pcieport 0000:00:01.0: normal init\n",
                "[2.0] pcieport 0000:00:01.0: link speed 16GT/s\n",
                "[3.0] pcieport 0000:00:01.0: device status check\n",
                "[4.0] pcieport 0000:00:01.0: AER: Uncorrected (Fatal) error received\n",
            ],
        )

        assert len(trigger.matches) == 1
        assert len(matched_events) == 1
        ev = trigger.matches[0]
        assert ev.rule_name == "aer_fatal"
        assert ev.session_id == "dmesg"
        assert ev.abort_triggered is True
        assert list(ev.context_before) == [
            "[2.0] pcieport 0000:00:01.0: link speed 16GT/s",
            "[3.0] pcieport 0000:00:01.0: device status check",
        ]

        with pytest.raises(HardwareFaultDetectedError) as exc_info:
            trigger.check_abort()
        assert exc_info.value.match == ev
        assert exc_info.value.host == "bbu-node-01"

        await pipeline.finalize()
        records = [
            json.loads(ln)
            for ln in (tmp_path / "timeline.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        ]
        assert any(r["kind"] == "match" and r["rule_name"] == "aer_fatal" for r in records)

    async def test_direct_stream_collector_watchdog_silence_stall(
        self, tmp_path: Path
    ) -> None:
        import asyncio
        import json

        from uniconn import (
            Connection,
            DirectStreamCollector,
            StallEvent,
            TimelineHandler,
        )

        conn = Connection.from_uri("local://")

        async def hanging_stream(command: str, timeout=None, **kwargs):
            yield "boot step 1\n"
            yield "boot step 2 (entering FPGA init)\n"
            await asyncio.sleep(10.0)

        conn.stream = hanging_stream  # type: ignore[method-assign]

        stalled_events: list[StallEvent] = []
        timeline = TimelineHandler(tmp_path / "timeline.jsonl")
        pipeline = LogPipeline([timeline])

        collector = DirectStreamCollector(
            connection=conn,
            name="uart_console",
            command="cat /dev/ttyUSB0",
            pipeline=pipeline,
            max_silence_seconds=0.05,
            on_stall=lambda sev: stalled_events.append(sev),
            timeline=timeline,
        )
        task = collector.start()
        await task
        await collector.stop()

        assert collector.lines_collected == 2
        assert collector.stalled is True
        assert collector.stall_event is not None
        assert len(stalled_events) == 1
        assert stalled_events[0].session_id == "uart_console"
        assert "stalled" in (collector.error or "")

        records = [
            json.loads(ln)
            for ln in (tmp_path / "timeline.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        ]
        assert [r["kind"] for r in records] == ["line", "line", "stall"]

    async def test_resolve_watch_rules_variants_and_multiline_chunks(
        self, tmp_path: Path
    ) -> None:
        import pytest

        from uniconn import (
            BUILTIN_WATCH_RULES,
            ConfigurationError,
            Connection,
            DirectStreamCollector,
            LogPipeline,
            PatternTriggerHandler,
            StreamSourceSpec,
            TimelineHandler,
            resolve_watch_rules,
        )

        # Single preset string (not iterated char-by-char)
        single_preset = resolve_watch_rules("kernel_panic")
        assert len(single_preset) == len(BUILTIN_WATCH_RULES["kernel_panic"])

        # Single rule dict with name & pattern
        single_dict = resolve_watch_rules(
            {"name": "custom_err", "pattern": "FATAL_ERR", "abort_on_match": True}
        )
        assert len(single_dict) == 1
        assert single_dict[0].name == "custom_err"
        assert single_dict[0].abort_on_match is True

        # Mapping of {rule_name: pattern_or_dict}
        mapped_rules = resolve_watch_rules(
            {
                "r1": "ERR_1",
                "r2": {"pattern": "ERR_2", "severity": "warning"},
            }
        )
        assert [r.name for r in mapped_rules] == ["r1", "r2"]
        assert mapped_rules[1].severity == "warning"

        # Invalid max_silence_seconds <= 0 raises ConfigurationError
        with pytest.raises(ConfigurationError):
            StreamSourceSpec(name="bad", command="dmesg -w", max_silence_seconds=0)
        with pytest.raises(ConfigurationError):
            DirectStreamCollector(
                connection=Connection.from_uri("local://"),
                name="bad",
                command="dmesg -w",
                pipeline=LogPipeline([]),
                max_silence_seconds=-1.0,
            )

        # Multi-line chunk splitting in TimelineHandler and PatternTriggerHandler
        timeline = TimelineHandler(tmp_path / "multi.jsonl")
        trigger = PatternTriggerHandler(
            rules=[{"name": "panic", "pattern": "Kernel panic", "context_lines": 2}],
            timeline=timeline,
        )
        pipeline = LogPipeline([timeline, trigger])
        await pipeline.emit(
            "uart",
            ["line 1\nline 2\nKernel panic - not syncing: Fatal exception\n"],
        )
        assert len(trigger.matches) == 1
        assert list(trigger.matches[0].context_before) == ["line 1", "line 2"]
        assert timeline.entries_written == 4  # 3 lines + 1 match event

    async def test_windows_job_encoded_command_paths_and_pool_temp_resolution(self) -> None:
        """WindowsJobBackend использует -EncodedCommand, Split-Path -Parent и TEMP вместо хардкода /tmp."""
        import base64

        from uniconn.background import BackgroundPool, BackgroundSession, WindowsJobBackend

        def _decode(cmd: str) -> str:
            if "-EncodedCommand " in cmd:
                b64 = cmd.split("-EncodedCommand ", 1)[1].strip().split()[0]
                return base64.b64decode(b64).decode("utf-16-le")
            return cmd

        recorded_ps: list[str] = []

        def _handler(cmd: str, **kw: object) -> object:
            ps = _decode(cmd)
            recorded_ps.append(ps)
            if "GetTempPath()" in ps:
                return make_result("C:\\Users\\ci\\AppData\\Local\\Temp\r\n", exit_code=0, command=cmd)
            return make_result("", exit_code=0, command=cmd)

        conn = make_connection(_handler)
        conn._transport.config.transport = "winrm"  # type: ignore[attr-defined]
        backend = WindowsJobBackend()

        await backend.start_session(
            conn,
            "s1",
            "C:\\Work\\logs\\uniconn_s1.ps1",
            "C:\\Work\\logs\\s1.log",
            "C:\\Work\\logs\\uniconn_s1.exit",
            "C:\\Work\\logs\\uniconn_s1.pid",
        )
        start_ps = recorded_ps[-1]
        assert "Split-Path -Parent" in start_ps
        assert "'/tmp'" not in start_ps
        assert "'-EncodedCommand'" in start_ps

        await backend.list_sessions(conn, prefix="s")
        list_ps = recorded_ps[-1]
        assert "[System.IO.Path]::GetTempPath()" in list_ps
        assert 'Write-Output "$sid $procId"' in list_ps
        assert '\\"$sid' not in list_ps

        # BackgroundSession на Windows кладёт .exit/.pid/.ps1 рядом с remote_log_path
        sess = BackgroundSession(conn, "job1", "C:\\Work\\logs\\job1.log", backend=backend)
        assert sess.script_path == "C:\\Work\\logs\\uniconn_job1.ps1"
        assert sess.pid_file_path == "C:\\Work\\logs\\uniconn_job1.pid"
        assert sess.exit_file_path == "C:\\Work\\logs\\uniconn_job1.exit"

        # BackgroundPool резолвит %TEMP% через GetTempPath вместо /tmp
        pool = BackgroundPool("winrm://admin:pass@win-host", backend="windows_job")
        orig_handler = _handler

        def _pool_handler(cmd: str, **kw: object) -> object:
            ps = _decode(cmd)
            if "Test-Path" in ps and "exit 1" in ps:
                return make_result("", exit_code=1, command=cmd)
            return orig_handler(cmd, **kw)

        conn2 = make_connection(_pool_handler)
        conn2._transport.config.transport = "winrm"  # type: ignore[attr-defined]
        conn2.files.write_file = AsyncMock()  # type: ignore[method-assign]
        pool._connection = conn2
        pool._resolved_backend = backend
        created = await pool.start("Write-Output 'hi'", name="winjob")
        assert created.remote_log_path == "C:\\Users\\ci\\AppData\\Local\\Temp\\winjob.log"

    async def test_windows_background_components_use_encoded_command(self) -> None:
        """BackgroundSession, BackgroundLogCollector и BackgroundCleanupManager оборачивают PowerShell в -EncodedCommand."""
        import base64

        from uniconn.background import (
            BackgroundCleanupManager,
            BackgroundLogCollector,
            BackgroundSession,
            WindowsJobBackend,
        )

        executed: list[str] = []

        def _decode(cmd: str) -> str:
            assert cmd.startswith("powershell -NoProfile -NonInteractive -EncodedCommand "), cmd
            b64 = cmd.split("-EncodedCommand ", 1)[1].strip().split()[0]
            return base64.b64decode(b64).decode("utf-16-le")

        def _handler(cmd: str, **kw: object) -> object:
            executed.append(cmd)
            ps = _decode(cmd)
            if "if ((Test-Path" in ps and "Get-Process -Id" in ps:
                return make_result("", exit_code=1, command=cmd)
            if "Test-Path" in ps and "(Get-Content -Path" in ps and "-Raw).Trim()" in ps:
                return make_result("0\n", exit_code=0, command=cmd)
            if "Write-Output $procId" in ps:
                return make_result("8888\n", exit_code=0, command=cmd)
            if ".Length" in ps:
                return make_result("6\n", exit_code=0, command=cmd)
            if "StreamReader" in ps or ("Get-Content -Path" in ps and "-Raw" in ps):
                return make_result("hello\n", exit_code=0, command=cmd)
            return make_result("", exit_code=0, command=cmd)

        conn = make_connection(_handler)
        conn.transport_name = "winrm"
        conn.config.transport = "winrm"
        backend = WindowsJobBackend()
        session = BackgroundSession(conn, "win1", "C:\\Work\\logs\\win1.log", backend=backend)

        await session.create("Write-Output 'ok'")
        assert await session.get_exit_code() == 0
        await session.send_signal(9)
        await session.cleanup()

        collector = BackgroundLogCollector(conn)
        lines, offset = await collector.read_chunk(session)
        assert lines == ["hello\n"]
        assert offset == 6
        assert await collector.read_all(session) == "hello\n"

        cleaner = BackgroundCleanupManager("pool_win")
        await cleaner.install_server_side(conn)
        assert await cleaner.cleanup_stale(conn, max_age_seconds=10) == []
        assert len(executed) >= 8




