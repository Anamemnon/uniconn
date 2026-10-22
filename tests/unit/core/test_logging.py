# tests/unit/test_logging.py
"""Тесты для модуля логирования."""

import logging
import logging.handlers
import tempfile
from pathlib import Path

import pytest

from uniconn._logging import (
    SecretMaskingFilter,
    get_logger,
    setup_file_logging,
    DEFAULT_FORMAT,
    DETAILED_FORMAT,
)


class TestSecretMaskingFilter:
    """Тесты фильтра маскирования секретов."""

    def test_mask_password_in_message(self):
        """Пароль в сообщении маскируется."""
        filter_ = SecretMaskingFilter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="Connecting with password=mysecret123 to host",
            args=(), exc_info=None,
        )
        filter_.filter(record)
        assert "password=***" in record.msg
        assert "mysecret123" not in record.msg

    def test_mask_password_in_args_tuple(self):
        """Пароль в args (tuple) маскируется."""
        filter_ = SecretMaskingFilter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="Auth: %s",
            args=("password=secret",), exc_info=None,
        )
        filter_.filter(record)
        assert "password=***" in record.args[0]
        assert "secret" not in record.args[0]

    def test_mask_password_in_args_dict(self):
        """Пароль в args (dict) маскируется."""
        filter_ = SecretMaskingFilter()
        record = logging.makeLogRecord({
            "name": "test",
            "level": logging.INFO,
            "msg": "Auth: %(cred)s",
            "args": {"cred": "pass=s3cr3t"},
        })
        filter_.filter(record)
        assert "pass=***" in record.args["cred"]

    def test_mask_credentials_in_url(self):
        """Учётные данные в URL маскируются."""
        filter_ = SecretMaskingFilter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="Connecting to ssh://admin:P@ssw0rd@host:22",
            args=(), exc_info=None,
        )
        filter_.filter(record)
        assert "://***:***@" in record.msg
        assert "P@ssw0rd" not in record.msg

    def test_mask_token(self):
        """Токен маскируется."""
        filter_ = SecretMaskingFilter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="Using token=abc123xyz",
            args=(), exc_info=None,
        )
        filter_.filter(record)
        assert "token=***" in record.msg

    def test_mask_secret(self):
        """Секрет маскируется."""
        filter_ = SecretMaskingFilter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="My secret=hidden value",
            args=(), exc_info=None,
        )
        filter_.filter(record)
        assert "secret=***" in record.msg

    def test_filter_disabled(self):
        """Фильтр не маскирует если отключён."""
        filter_ = SecretMaskingFilter()
        filter_._enabled = False
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="password=visible",
            args=(), exc_info=None,
        )
        filter_.filter(record)
        assert "password=visible" in record.msg

    def test_non_string_message(self):
        """Не строковые сообщения не ломают фильтр."""
        filter_ = SecretMaskingFilter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg=12345,
            args=(), exc_info=None,
        )
        filter_.filter(record)
        assert record.msg == 12345


class TestGetLogger:
    """Тесты get_logger."""

    def test_get_logger_basic(self):
        """Базовое создание логгера."""
        logger = get_logger("test_basic", level=logging.DEBUG)
        assert logger.level == logging.DEBUG
        assert len(logger.handlers) > 0

    def test_get_logger_secret_masking(self):
        """Фильтр SecretMaskingFilter висит на handlers логгера."""
        logger = get_logger("test_mask", mask_secrets=True)
        assert logger.handlers
        assert any(
            isinstance(f, SecretMaskingFilter)
            for f in logger.handlers[0].filters
        )

    def test_get_logger_child_masking(self):
        """Маскирование работает и для дочерних логгеров (через propagation).

        Регрессия: фильтр на logger не наследуется дочерними логгерами,
        поэтому фильтр должен висеть на handlers.
        """
        import io

        # Свой handler до вызова get_logger: фильтр должен быть добавлен на него
        parent = logging.getLogger("test_parent_mask")
        parent.handlers.clear()
        stream = io.StringIO()
        parent.addHandler(logging.StreamHandler(stream))

        get_logger("test_parent_mask", mask_secrets=True)
        child = logging.getLogger("test_parent_mask.child")
        child.info("password=supersecret123")

        assert "supersecret123" not in stream.getvalue()
        assert "password=***" in stream.getvalue()
        parent.handlers.clear()

    def test_get_logger_no_masking(self):
        """Логгер без маскирования."""
        logger = get_logger("test_no_mask", mask_secrets=False)
        for handler in logger.handlers:
            assert not any(
                isinstance(f, SecretMaskingFilter) for f in handler.filters
            )

    def test_get_logger_reuse(self):
        """Повторный вызов возвращает тот же логгер."""
        logger1 = get_logger("test_reuse")
        logger2 = get_logger("test_reuse")
        assert logger1 is logger2


def _close_logger_handlers(logger: logging.Logger):
    """Закрыть все handlers логгера (для Windows)."""
    for handler in logger.handlers:
        handler.flush()
        handler.close()
    logger.handlers.clear()


class TestSetupFileLogging:
    """Тесты setup_file_logging."""

    def test_size_rotation_creates_file(self):
        """Size rotation создаёт файл."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "test_size.log"
            logger = setup_file_logging(
                log_path,
                rotation="size",
                max_bytes=1024,
                backup_count=2,
                logger_name="test_size_rotation",
            )
            logger.info("Test message")
            _close_logger_handlers(logger)

            assert log_path.exists()
            assert "Test message" in log_path.read_text()

    def test_time_rotation_creates_file(self):
        """Time rotation создаёт файл."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "test_time.log"
            logger = setup_file_logging(
                log_path,
                rotation="time",
                when="midnight",
                backup_count=3,
                logger_name="test_time_rotation",
            )
            logger.info("Time rotation test")
            _close_logger_handlers(logger)

            assert log_path.exists()
            assert "Time rotation test" in log_path.read_text()

    def test_secret_masking_in_file(self):
        """Секреты маскируются в файле."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "test_mask.log"
            logger = setup_file_logging(
                log_path,
                mask_secrets=True,
                logger_name="test_file_mask",
            )
            logger.info("password=supersecret")
            _close_logger_handlers(logger)

            content = log_path.read_text()
            assert "password=***" in content
            assert "supersecret" not in content

    def test_no_masking_in_file(self):
        """Без маскирования секреты видны."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "test_nomask.log"
            logger = setup_file_logging(
                log_path,
                mask_secrets=False,
                logger_name="test_file_nomask",
            )
            logger.info("password=visible")
            _close_logger_handlers(logger)

            content = log_path.read_text()
            assert "password=visible" in content

    def test_creates_parent_directory(self):
        """Создаёт родительские директории."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "sub" / "dir" / "test.log"
            logger = setup_file_logging(
                log_path,
                logger_name="test_mkdir",
            )
            logger.info("Directory test")
            _close_logger_handlers(logger)

            assert log_path.exists()
            assert log_path.parent.exists()

    def test_also_console(self):
        """also_console добавляет консольный handler."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "test_console.log"
            logger = setup_file_logging(
                log_path,
                also_console=True,
                logger_name="test_also_console",
            )
            # Должно быть 2 handler: файл + консоль
            assert len(logger.handlers) == 2
            _close_logger_handlers(logger)

    def test_detailed_format(self):
        """Detailed формат включает module и line number."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "test_detailed.log"
            logger = setup_file_logging(
                log_path,
                fmt=DETAILED_FORMAT,
                logger_name="test_detailed_fmt",
            )
            logger.info("Detailed test")
            _close_logger_handlers(logger)

            content = log_path.read_text()
            # Должен содержать номер строки
            assert ":" in content

    def test_custom_level(self):
        """Кастомный уровень логирования."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "test_level.log"
            logger = setup_file_logging(
                log_path,
                level=logging.WARNING,
                logger_name="test_custom_level",
            )
            logger.debug("Debug message")
            logger.warning("Warning message")
            _close_logger_handlers(logger)

            content = log_path.read_text()
            assert "Debug message" not in content
            assert "Warning message" in content

    def test_structured_file_logging_jsonl(self):
        """setup_file_logging(structured=True) пишет валидный JSONL."""
        import json

        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "structured.jsonl"
            logger = setup_file_logging(
                log_path,
                level=logging.INFO,
                logger_name="test_struct_file",
                structured=True,
            )
            logger.info("Server connected")
            _close_logger_handlers(logger)

            lines = [
                line for line in log_path.read_text().splitlines() if line.strip()
            ]
            assert len(lines) == 1
            data = json.loads(lines[0])
            assert data["event"] == "Server connected"
            assert data["level"] == "info"
            assert "timestamp" in data


class TestStructuredLogging:
    """Тесты структурированного логирования на базе structlog."""

    def teardown_method(self):
        """Очищать контекст после каждого теста."""
        from uniconn import clear_log_context

        clear_log_context()

    def test_configure_logging_json_and_contextvars(self):
        """configure_logging(fmt='json') выводит JSON с полями contextvars."""
        import io
        import json

        from uniconn import (
            bind_log_context,
            configure_logging,
            get_log_context,
            get_struct_logger,
            log_context,
            unbind_log_context,
        )

        buf = io.StringIO()
        configure_logging(
            level="DEBUG",
            fmt="json",
            stream=buf,
            logger_name="uniconn_test_json",
        )
        bind_log_context(datacenter="eu-central-1", service="inventory")
        assert get_log_context()["datacenter"] == "eu-central-1"

        slog = get_struct_logger("uniconn_test_json")
        with log_context(host="node-01", transport="ssh"):
            slog.info("host.checked", latency_ms=12.4, ok=True)

        # После выхода из log_context поле host удалено, а datacenter остался
        assert "host" not in get_log_context()
        unbind_log_context("datacenter")
        assert "datacenter" not in get_log_context()

        raw_lines = [line for line in buf.getvalue().splitlines() if line.strip()]
        assert len(raw_lines) == 1
        entry = json.loads(raw_lines[0])
        assert entry["event"] == "host.checked"
        assert entry["datacenter"] == "eu-central-1"
        assert entry["service"] == "inventory"
        assert entry["host"] == "node-01"
        assert entry["transport"] == "ssh"
        assert entry["latency_ms"] == 12.4
        assert entry["ok"] is True
        assert entry["level"] == "info"
        assert "timestamp" in entry

    def test_redact_secrets_in_structlog(self):
        """Пароли, SecretStr и sensitive-поля маскируются в JSON-логах."""
        import io
        import json
        from pydantic import SecretStr
        from uniconn import configure_logging, get_struct_logger

        buf = io.StringIO()
        configure_logging(
            level="DEBUG",
            fmt="json",
            stream=buf,
            logger_name="uniconn_test_redact",
        )
        slog = get_struct_logger("uniconn_test_redact")
        slog.info(
            "auth.attempt",
            password="plain_password_123",
            sudo_password=SecretStr("sudo_secret_456"),
            uri="ssh://admin:url_secret_789@10.0.0.1:22",
            command="echo secret_token",
            stdout="secret_token",
            sensitive=True,
        )

        output = buf.getvalue().strip()
        assert "plain_password_123" not in output
        assert "sudo_secret_456" not in output
        assert "url_secret_789" not in output
        assert "secret_token" not in output

        entry = json.loads(output)
        assert entry["password"] == "***REDACTED***"
        assert entry["sudo_password"] == "***REDACTED***"
        assert entry["command"] == "***REDACTED***"
        assert entry["stdout"] == "***REDACTED***"
        assert "://***:***@" in entry["uri"]

    @pytest.mark.asyncio
    async def test_connection_run_emits_structured_json_events(self):
        """Connection.run() генерирует структурированные события command.start и command.finish."""
        import io
        import json
        from uniconn import Connection, configure_logging, log_context

        buf = io.StringIO()
        logger = configure_logging(
            level="DEBUG",
            fmt="json",
            stream=buf,
            logger_name="uniconn_conn_json",
        )

        async with Connection.from_uri("local://", logger=logger) as conn:
            async with log_context(cluster="prod-clickhouse"):
                res = await conn.run(["echo", "hello_structlog"])
                assert res.ok

        records = [
            json.loads(line)
            for line in buf.getvalue().splitlines()
            if line.strip()
        ]
        events = {r["event"]: r for r in records}
        assert "command.start" in events
        assert "command.finish" in events

        finish = events["command.finish"]
        assert finish["transport"] == "local"
        assert finish["cluster"] == "prod-clickhouse"
        assert finish["command"] == "echo hello_structlog"
        assert finish["exit_code"] == 0
        assert finish["ok"] is True
        assert isinstance(finish["duration_ms"], float)

    @pytest.mark.asyncio
    async def test_structured_log_hook_for_telemetry(self):
        """structured_log_hook формирует событие command.executed с метриками для БД/Grafana."""
        import io
        import json
        from uniconn import Connection, configure_logging, structured_log_hook

        buf = io.StringIO()
        logger = configure_logging(
            level="INFO",
            fmt="json",
            stream=buf,
            logger_name="uniconn_telemetry_test",
        )

        async with Connection.from_uri("local://") as conn:
            conn.add_hook(
                "after_run",
                structured_log_hook(
                    logger=logger,
                    include_output=True,
                    tags={"env": "staging", "db_sink": "clickhouse"},
                ),
            )
            await conn.run("echo metrics_payload")

        lines = [line for line in buf.getvalue().splitlines() if line.strip()]
        assert len(lines) == 1
        payload = json.loads(lines[0])
        assert payload["event"] == "command.executed"
        assert payload["env"] == "staging"
        assert payload["db_sink"] == "clickhouse"
        assert payload["exit_code"] == 0
        assert payload["ok"] is True
        assert "duration_ms" in payload
        assert payload["stdout_bytes"] > 0
        assert "metrics_payload" in payload["stdout"]

