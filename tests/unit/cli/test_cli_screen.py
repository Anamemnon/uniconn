# tests/unit/cli/test_cli_screen.py
"""Тесты CLI команд bg-* (bg-run, bg-logs, bg-status, bg-kill)."""

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from uniconn import cli
from uniconn.cli import CliRunner
from uniconn.result import Result


@pytest.fixture
def cli_app():
    """Собрать cyclopts.App из cli.create_cli_app()."""
    return cli.create_cli_app()


@pytest.fixture
def runner():
    """CliRunner для вызова команд."""
    return CliRunner()


def make_result(stdout="", exit_code=0, stderr=""):
    """Создать Result для мока Connection.run."""
    return Result(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        duration=0.1,
        command="test",
        timestamp=datetime.now(),
        host="host",
    )


def make_pool_mock():
    """Создать мок BackgroundPool с async context manager и счётчиком start."""
    pool = MagicMock()
    pool.__aenter__.return_value = pool
    pool.__aexit__.return_value = False

    counter = {"n": 0}

    async def fake_start(command, name=None):
        idx = counter["n"]
        counter["n"] += 1
        session = MagicMock()
        session.session_id = f"uniconn_test_{idx}"
        session.backend_name = "tmux"
        return session

    pool.start = AsyncMock(side_effect=fake_start)
    pool.disconnect = AsyncMock()
    return pool


def make_connection_mock(run_side_effect=None, run_return=None):
    """Создать мок класса Connection: from_uri -> async CM -> conn.run."""
    conn = MagicMock()
    if run_side_effect is not None:
        conn.run = AsyncMock(side_effect=run_side_effect)
    else:
        conn.run = AsyncMock(return_value=run_return or make_result())

    conn_cm = MagicMock()
    conn_cm.__aenter__ = AsyncMock(return_value=conn)
    conn_cm.__aexit__ = AsyncMock(return_value=False)

    conn_cls = MagicMock()
    conn_cls.from_uri.return_value = conn_cm
    return conn_cls, conn


SCREEN_LS_OUTPUT = (
    "There are screens on:\n"
    "\t12345.uniconn_abc123_0\t(Detached)\n"
    "\t12346.uniconn_abc123_1\t(Detached)\n"
    "\t9999.user_session\t(Attached)\n"
    "2 Sockets in /run/screen/S-user.\n"
)


class TestBgRun:
    """Тесты команды bg-run."""

    def test_adhoc_creates_n_sessions(self, cli_app, runner):
        """Ad-hoc запуск создаёт N сессий по --instances."""
        pool = make_pool_mock()
        pool_cls = MagicMock(return_value=pool)

        with patch("uniconn.background.BackgroundPool", pool_cls, create=True):
            result = runner.invoke(
                cli_app,
                [
                    "bg-run",
                    "ssh://host",
                    "--backend",
                    "tmux",
                    "--instances",
                    "4",
                    "-c",
                    "stress-ng --cpu 4",
                ],
            )

        assert result.exit_code == 0, result.output
        pool_cls.assert_called_once()
        assert pool_cls.call_args.args[0] == "ssh://host"
        assert pool_cls.call_args.kwargs["backend"] == "tmux"
        assert pool.start.await_count == 4
        pool.start.assert_awaited_with("stress-ng --cpu 4")

    def test_from_config_reads_file(self, cli_app, runner, tmp_path):
        """Запуск из конфигурационного файла."""
        config_file = tmp_path / "pool.yaml"
        config_file.write_text(
            'uri: "ssh://admin@web-server"\nmax_sessions: 8\n', encoding="utf-8"
        )

        pool = make_pool_mock()
        pool_cls = MagicMock()
        pool_cls.from_file.return_value = pool

        with patch("uniconn.background.BackgroundPool", pool_cls, create=True):
            result = runner.invoke(
                cli_app,
                [
                    "bg-run",
                    "--config",
                    str(config_file),
                    "-c",
                    "tail -f /var/log/syslog",
                ],
            )

        assert result.exit_code == 0, result.output
        pool_cls.from_file.assert_called_once()
        assert pool_cls.from_file.call_args.args[0] == str(config_file)
        pool.start.assert_awaited_once_with("tail -f /var/log/syslog")

    def test_logs_streams_events(self, cli_app, runner):
        """--logs выводит события poll_logs в консоль."""
        from uniconn.background import LogEvent

        async def fake_poll_logs(interval=2.0):
            yield LogEvent(
                session_id="uniconn_test_0",
                line="stress: dispatching hogs\n",
                timestamp=datetime.now(),
            )

        pool = make_pool_mock()
        pool.poll_logs = MagicMock(side_effect=lambda: fake_poll_logs())
        pool_cls = MagicMock(return_value=pool)

        with patch("uniconn.background.BackgroundPool", pool_cls, create=True):
            result = runner.invoke(
                cli_app,
                ["bg-run", "ssh://host", "-c", "stress-ng --cpu 4", "--logs"],
            )

        assert result.exit_code == 0, result.output
        assert "stress: dispatching hogs" in result.output
        pool.poll_logs.assert_called_once()

    def test_requires_command(self, cli_app, runner):
        """Без --command команда завершается с ошибкой."""
        result = runner.invoke(cli_app, ["bg-run", "ssh://host"])
        assert result.exit_code != 0

    def test_requires_uri_or_config(self, cli_app, runner):
        """Без URI и --config команда завершается с ошибкой."""
        result = runner.invoke(cli_app, ["bg-run", "-c", "uptime"])
        assert result.exit_code != 0


class TestBgLogs:
    """Тесты команды bg-logs."""

    def test_oneshot_reads_log(self, cli_app, runner):
        """Без --follow лог читается один раз."""
        conn_cls, conn = make_connection_mock(
            run_return=make_result(stdout="line1\nline2\n")
        )

        with patch("uniconn.cli.Connection", conn_cls):
            result = runner.invoke(
                cli_app,
                ["bg-logs", "ssh://host", "--session-id", "uniconn_abc123_0"],
            )

        assert result.exit_code == 0, result.output
        assert "line1" in result.output
        conn.run.assert_awaited_once_with(
            "cat /tmp/uniconn_abc123_0.log", raise_on_error=False
        )

    def test_follow_stops_when_session_dead(self, cli_app, runner):
        """--follow читает порции и останавливается после завершения сессии."""
        conn_cls, conn = make_connection_mock(
            run_side_effect=[
                make_result(stdout="chunk1\n"),  # tail: новые данные
                make_result(stdout="screen\n"),  # auto-probe -> screen
                make_result(exit_code=1),        # screen -ls: сессии нет
            ]
        )

        with patch("uniconn.cli.Connection", conn_cls):
            result = runner.invoke(
                cli_app,
                ["bg-logs", "ssh://host", "-s", "uniconn_abc123_0", "--follow"],
            )

        assert result.exit_code == 0, result.output
        assert "chunk1" in result.output
        assert conn.run.await_count == 3


class TestBgStatus:
    """Тесты команды bg-status."""

    def test_lists_pool_sessions(self, cli_app, runner):
        """Выводит только сессии с префиксом uniconn_{pool-id}."""
        conn_cls, _conn = make_connection_mock(
            run_side_effect=[
                make_result(stdout="screen\n"),      # resolve_backend('auto')
                make_result(stdout=SCREEN_LS_OUTPUT),  # screen -ls
            ]
        )

        with patch("uniconn.cli.Connection", conn_cls):
            result = runner.invoke(
                cli_app,
                ["bg-status", "ssh://host", "--pool-id", "abc123"],
            )

        assert result.exit_code == 0, result.output
        assert "uniconn_abc123_0" in result.output
        assert "uniconn_abc123_1" in result.output
        assert "user_session" not in result.output


class TestBgKill:
    """Тесты команды bg-kill."""

    def test_kill_session_force(self, cli_app, runner):
        """--force убивает сессию через выбранный бэкенд."""
        conn_cls, conn = make_connection_mock(
            run_side_effect=[
                make_result(stdout="screen\n"),  # resolve_backend('auto')
                make_result(),                   # screen -S ... -X kill
            ]
        )

        with patch("uniconn.cli.Connection", conn_cls):
            result = runner.invoke(
                cli_app,
                ["bg-kill", "ssh://host", "-s", "uniconn_abc123_0", "--force"],
            )

        assert result.exit_code == 0, result.output
        assert conn.run.await_args_list[-1].args[0] == "screen -S uniconn_abc123_0 -X kill"

    def test_kill_pool_all(self, cli_app, runner):
        """--pool-id --all убивает все сессии пула."""
        conn_cls, conn = make_connection_mock(
            run_side_effect=[
                make_result(stdout="screen\n"),      # resolve_backend('auto')
                make_result(stdout=SCREEN_LS_OUTPUT),  # screen -ls
                make_result(),                       # kill первой сессии
                make_result(),                       # kill второй сессии
            ]
        )

        with patch("uniconn.cli.Connection", conn_cls):
            result = runner.invoke(
                cli_app,
                ["bg-kill", "ssh://host", "--pool-id", "abc123", "--all", "--force"],
            )

        assert result.exit_code == 0, result.output
        kill_calls = [c.args[0] for c in conn.run.await_args_list[2:]]
        assert "screen -S uniconn_abc123_0 -X kill" in kill_calls
        assert "screen -S uniconn_abc123_1 -X kill" in kill_calls

    def test_requires_target(self, cli_app, runner):
        """Без --session-id и --pool-id --all команда завершается с ошибкой."""
        result = runner.invoke(cli_app, ["bg-kill", "ssh://host"])
        assert result.exit_code != 0
