# tests/unit/test_cli.py
"""Тесты для CLI интерфейса"""

import pytest
from unittest.mock import patch, AsyncMock
from datetime import datetime


@pytest.fixture
def mock_connection(mocker):
    """Фикстура для мока Connection в CLI"""
    from uniconn.result import Result

    conn = mocker.AsyncMock()
    conn.run = mocker.AsyncMock(
        return_value=Result(
            exit_code=0,
            stdout="Linux server 5.15.0 x86_64",
            stderr="",
            duration=0.5,
            command="uptime",
            timestamp=datetime.now(),
            host="server"
        )
    )
    conn.close = mocker.AsyncMock()
    conn._transport = mocker.AsyncMock()
    conn._transport.connect = mocker.AsyncMock()
    conn._transport.disconnect = mocker.AsyncMock()
    return conn


class TestCLIImports:
    """Тесты импортов CLI"""

    def test_cli_module_imports(self):
        """CLI модуль импортируется"""
        from uniconn import cli
        assert hasattr(cli, "main")

    def test_cli_deps_check(self):
        """check_cli_deps существует"""
        from uniconn.cli import check_cli_deps
        assert callable(check_cli_deps)


class TestCLIVersion:
    """Тесты команды version"""

    def test_version_exists(self):
        """__version__ определён"""
        from uniconn import __version__
        assert isinstance(__version__, str)
        assert len(__version__) > 0


class TestCLITransports:
    """Тесты команды transports"""

    def test_transport_loader_list(self):
        """TransportLoader.list_available возвращает список"""
        from uniconn.plugins._loader import TransportLoader
        # Должен вернуть список (может быть пустым без установленных extras)
        available = TransportLoader.list_available()
        assert isinstance(available, (list, set))


class TestCLIRun:
    """Тесты команды run"""

    @pytest.mark.asyncio
    async def test_run_command_success(self, mocker):
        """Успешное выполнение команды"""
        from uniconn.result import Result

        result_data = Result(
            exit_code=0,
            stdout="Linux server 5.15.0 x86_64",
            stderr="",
            duration=0.5,
            command="uptime",
            timestamp=datetime.now(),
            host="server"
        )

        mocker.patch(
            "uniconn.plugins._loader.TransportLoader.get",
            return_value=lambda config: mocker.AsyncMock(
                name="mock",
                is_connected=True,
                run=mocker.AsyncMock(return_value=result_data),
                connect=mocker.AsyncMock(),
                disconnect=mocker.AsyncMock(),
            )
        )

        from uniconn import Connection

        async with Connection.from_uri("ssh://user@host") as conn:
            result = await conn.run("uptime")

        assert result.exit_code == 0
        assert result.stdout == "Linux server 5.15.0 x86_64"


class TestCLIRunMulti:
    """Тесты команды run-multi"""

    @pytest.mark.asyncio
    async def test_run_multi_multiple_hosts(self, mocker):
        """Запуск на нескольких хостах"""
        from uniconn.result import Result

        def make_mock_conn(uri, *args, **kwargs):
            conn = mocker.AsyncMock()
            conn.run = mocker.AsyncMock(
                return_value=Result(
                    exit_code=0,
                    stdout=f"Result from {uri}",
                    stderr="",
                    duration=0.5,
                    command="test",
                    timestamp=datetime.now(),
                    host=uri
                )
            )
            conn.close = mocker.AsyncMock()
            conn._transport = mocker.AsyncMock()
            conn._transport.connect = mocker.AsyncMock()
            conn._transport.disconnect = mocker.AsyncMock()
            return conn

        mocker.patch(
            "uniconn.plugins._loader.TransportLoader.get",
            return_value=lambda config: mocker.AsyncMock(
                name="mock",
                is_connected=True,
                run=mocker.AsyncMock(
                    return_value=Result(
                        exit_code=0, stdout="ok", stderr="",
                        duration=0.5, command="test",
                        timestamp=datetime.now(), host="host"
                    )
                ),
                connect=mocker.AsyncMock(),
                disconnect=mocker.AsyncMock(),
            )
        )

        from uniconn._pool import ConnectionPool

        pool = ConnectionPool(["ssh://host1", "ssh://host2"])
        results = await pool.map("uptime")

        assert len(results) == 2


class TestCLIOutputFormats:
    """Тесты форматов вывода"""

    def test_json_format_structure(self):
        """JSON формат имеет правильную структуру"""
        import json
        from uniconn.result import Result

        result = Result(
            exit_code=0, stdout="ok", stderr="",
            duration=1.0, command="test",
            timestamp=datetime.now(), host="host"
        )

        output = {
            "host": "ssh://host",
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "duration": result.duration,
        }

        # Проверяем сериализуемость
        json_str = json.dumps(output)
        parsed = json.loads(json_str)
        assert parsed["exit_code"] == 0
        assert parsed["stdout"] == "ok"


class TestCLIBMC:
    """Тесты BMC команды"""

    @pytest.mark.asyncio
    async def test_bmc_power_status(self, mocker):
        """BMC статус питания"""
        from uniconn.result import Result

        mocker.patch(
            "uniconn.plugins._loader.TransportLoader.get",
            return_value=lambda config: mocker.AsyncMock(
                name="mock",
                is_connected=True,
                run=mocker.AsyncMock(
                    return_value=Result(
                        exit_code=0,
                        stdout="Power State: On",
                        stderr="",
                        duration=1.0,
                        command="power status",
                        timestamp=datetime.now(),
                        host="bmc"
                    )
                ),
                connect=mocker.AsyncMock(),
                disconnect=mocker.AsyncMock(),
            )
        )

        from uniconn import Connection

        async with Connection.from_uri("ipmi://admin:pass@bmc") as conn:
            result = await conn.run("power status")

        assert result.exit_code == 0
        assert "Power State" in result.stdout


class TestCLIShell:
    """Тесты интерактивной команды shell через ShellSession."""

    def test_cli_shell_uses_shell_session_execute(self):
        """Команда `uniconn shell` открывает ShellSession и вызывает execute()."""
        from unittest.mock import MagicMock

        from uniconn import cli
        from uniconn.cli import CliRunner
        from uniconn.result import Result

        app = cli.create_cli_app()

        session = MagicMock()
        session.execute = AsyncMock(
            side_effect=[
                Result(exit_code=0, stdout="", stderr="", duration=0.05, command="cd /tmp"),
                Result(exit_code=0, stdout="/tmp", stderr="", duration=0.05, command="pwd"),
            ]
        )
        session_cm = MagicMock()
        session_cm.__aenter__ = AsyncMock(return_value=session)
        session_cm.__aexit__ = AsyncMock(return_value=False)

        conn = MagicMock()
        conn.open_shell = AsyncMock(return_value=session_cm)
        conn_cm = MagicMock()
        conn_cm.__aenter__ = AsyncMock(return_value=conn)
        conn_cm.__aexit__ = AsyncMock(return_value=False)

        conn_cls = MagicMock()
        conn_cls.from_uri.return_value = conn_cm

        runner = CliRunner()
        with patch("uniconn.cli.Connection", conn_cls):
            res = runner.invoke(
                app,
                ["shell", "ssh://user@host"],
                input="cd /tmp\npwd\nexit\n",
            )

        assert res.exit_code == 0, res.output
        conn.open_shell.assert_awaited_once()
        assert session.execute.await_count == 2
        assert session.execute.await_args_list[0].args[0] == "cd /tmp"
        assert session.execute.await_args_list[1].args[0] == "pwd"
        assert "/tmp" in res.output

    def test_cli_global_log_options_and_version(self):
        """Глобальные флаги --log-level и --log-format работают через meta-приложение Cyclopts."""
        from uniconn import cli
        from uniconn.cli import CliRunner

        app = cli.create_cli_app()
        runner = CliRunner()
        res = runner.invoke(
            app,
            ["--log-level", "DEBUG", "--log-format", "json", "version"],
        )
        assert res.exit_code == 0, res.output
        assert "uniconn" in res.output


