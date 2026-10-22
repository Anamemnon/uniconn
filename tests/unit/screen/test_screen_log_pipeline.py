# tests/unit/test_screen_log_pipeline.py
"""Тесты LogPipeline, обработчиков логов и ScreenLogCollector."""

import logging
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from uniconn.background._log_collector import ScreenLogCollector
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


class TestScreenLogCollector:
    """Тесты ScreenLogCollector.read_chunk — offset-логика."""

    async def test_first_read_uses_tail_from_start(self):
        """Первый вызов читает tail -c +1 и возвращает строки с новым offset."""
        def handler(command: str, **kwargs) -> Result:
            if command == "stat -c %s /tmp/s1.log":
                return make_result("12\n", command=command)
            if command == "tail -c +1 /tmp/s1.log":
                return make_result("line one\nli", command=command)
            return make_result("", command=command)

        collector = ScreenLogCollector(make_connection(handler))
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
        collector = ScreenLogCollector(conn)
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
        collector = ScreenLogCollector(conn)
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
        collector = ScreenLogCollector(conn)
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
        collector = ScreenLogCollector(conn)
        lines, offset = await collector.read_chunk(make_session())
        assert lines == []
        assert offset == 0
        assert not any("tail" in c.args[0] for c in conn.run.call_args_list)
