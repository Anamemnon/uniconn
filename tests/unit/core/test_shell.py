# tests/unit/test_shell.py
"""Unit-тесты для PTY shell (ShellSession, SSHTransport.open_shell, Connection.open_shell)."""

from __future__ import annotations

import asyncio
import re
from unittest.mock import AsyncMock, MagicMock, patch

try:
    import pytest
except ImportError:
    pytest = None  # type: ignore[assignment]

from uniconn._config import ConnectionConfig
from uniconn._connection import Connection
from uniconn._shell import ShellSession
from uniconn.exceptions import ConnectionError, TimeoutError
from uniconn.result import Result
from uniconn.transports._local import LocalTransport
from uniconn.transports._serial import SerialTransport
from uniconn.transports._ssh import SSHTransport
from uniconn.transports._telnet import TelnetTransport
from uniconn.transports.bmc._ipmi import IPMITransport


class FakeShellProcess:
    """Фейковый asyncssh PTY-процесс с эмуляцией stateful оболочки (cwd и env)."""

    def __init__(self, echo_commands: bool = False) -> None:
        """Инициализировать фейковый процесс оболочки."""
        self.cwd = "/home/user"
        self.env: dict[str, str] = {}
        self.echo_commands = echo_commands
        self.returncode: int | None = None
        self.exit_status: int | None = None
        self.terminated = False
        self.closed = False
        self.term_size = (80, 24)
        self.written_chunks: list[str] = []
        self._out_queue: asyncio.Queue[str] = asyncio.Queue()

        self.stdin = MagicMock()
        self.stdin.write = MagicMock(side_effect=self._on_stdin_write)
        self.stdin.drain = AsyncMock()

        self.stdout = MagicMock()
        self.stdout.read = AsyncMock(side_effect=self._on_stdout_read)

    def _on_stdin_write(self, text: str) -> None:
        self.written_chunks.append(text)
        stripped = text.strip()
        if stripped in ("", "\x03", "exit", "export PS1=''; stty -echo"):
            return

        # Парсим обёрнутую команду вида: {cmd}; echo "\n__UNICONN_{uuid}__$?"
        m = re.match(r'^(.*);\s*echo\s+"\\n(__UNICONN_[a-f0-9]+__)\$\?"$', stripped)
        if not m:
            return
        cmd, marker_prefix = m.group(1).strip(), m.group(2)

        output, exit_code = self._eval_command(cmd)
        prefix = f"{stripped}\r\n" if self.echo_commands else ""
        payload = f"{prefix}{output}\n{marker_prefix}{exit_code}\n"
        self._out_queue.put_nowait(payload)

    def _eval_command(self, cmd: str) -> tuple[str, int]:
        if cmd.startswith("cd "):
            target = cmd[3:].strip()
            self.cwd = target
            return "", 0
        if cmd == "pwd":
            return self.cwd, 0
        if cmd.startswith("export "):
            assignment = cmd[7:].strip()
            if "=" in assignment:
                k, v = assignment.split("=", 1)
                self.env[k.strip()] = v.strip().strip("'\"")
            return "", 0
        if cmd.startswith("echo $"):
            var_name = cmd[6:].strip()
            return self.env.get(var_name, ""), 0
        if cmd.startswith("echo "):
            return cmd[5:].strip().strip("'\""), 0
        if cmd == "false":
            return "error occurred", 127
        return f"ran:{cmd}", 0

    async def _on_stdout_read(self, _n: int = 4096) -> str:
        if self.returncode is not None:
            return ""
        return await self._out_queue.get()

    def change_terminal_size(self, cols: int, rows: int) -> None:
        """Обновить размер терминала."""
        self.term_size = (cols, rows)

    def terminate(self) -> None:
        """Терминировать процесс."""
        self.terminated = True
        self.returncode = -15

    def close(self) -> None:
        """Закрыть канал процесса."""
        self.closed = True


class TestShellSessionExecute:
    """Тесты выполнения команд и маркерного протокола в ShellSession."""

    @pytest.mark.asyncio
    async def test_execute_returns_result_and_parses_exit_code(self):
        """execute() возвращает корректный Result и парсит exit_code из маркера."""
        proc = FakeShellProcess()
        session = ShellSession(proc, host="node1", session_uuid="abc123def456")

        res_ok = await session.execute("echo hello world")
        assert res_ok.ok
        assert res_ok.exit_code == 0
        assert res_ok.stdout == "hello world"
        assert res_ok.stderr == ""
        assert res_ok.command == "echo hello world"
        assert res_ok.host == "node1"

        res_fail = await session.execute("false")
        assert not res_fail.ok
        assert res_fail.exit_code == 127
        assert res_fail.stdout == "error occurred"

    @pytest.mark.asyncio
    async def test_statefulness_cd_and_export(self):
        """Состояние (cd, export) сохраняется между вызовами execute()."""
        proc = FakeShellProcess()
        session = ShellSession(proc, host="node1")

        await session.execute("cd /tmp")
        pwd_res = await session.execute("pwd")
        assert pwd_res.stdout == "/tmp"

        await session.execute("export X=1")
        env_res = await session.execute("echo $X")
        assert env_res.stdout == "1"

    @pytest.mark.asyncio
    async def test_echo_fallback_strips_echoed_command(self):
        """Если stty -echo не сработал и команда продублировалась, первая строка срезается."""
        proc = FakeShellProcess(echo_commands=True)
        session = ShellSession(proc, host="node1")

        res = await session.execute("pwd")
        assert res.stdout == "/home/user"
        assert res.exit_code == 0

    @pytest.mark.asyncio
    async def test_uuid_marker_does_not_collide_with_similar_output(self):
        """Маркер с UUID не ломается на выводе, содержащем похожий текст с другим UUID."""
        proc = FakeShellProcess()
        session = ShellSession(proc, host="node1", session_uuid="realuuid0001")

        # Переопределяем чтение: сначала приходит фальшивый маркер с другим UUID, затем настоящий
        chunks = [
            "line1\n__UNICONN_fakeuuid9999__99\nline2",
            "\n__UNICONN_realuuid0001__0\n",
        ]
        proc.stdout.read = AsyncMock(side_effect=chunks)

        res = await session.execute("cat tricky.txt")
        assert res.exit_code == 0
        assert "__UNICONN_fakeuuid9999__99" in res.stdout
        assert "line2" in res.stdout

    @pytest.mark.asyncio
    async def test_execute_timeout_sends_ctrl_c_and_raises(self):
        r"""Таймаут execute() отправляет Ctrl-C (\x03) и бросает uniconn.TimeoutError."""
        proc = FakeShellProcess()

        async def slow_read(_n: int = 4096) -> str:
            await asyncio.sleep(5.0)
            return ""

        proc.stdout.read = AsyncMock(side_effect=slow_read)
        session = ShellSession(proc, host="node1", default_timeout=0.05)

        with pytest.raises(TimeoutError, match="timed out"):
            await session.execute("sleep 100", timeout=0.05)

        assert "\x03" in proc.written_chunks

    @pytest.mark.asyncio
    async def test_process_death_raises_connection_error(self):
        """Смерть процесса (EOF или returncode != None) бросает ConnectionError."""
        proc = FakeShellProcess()
        proc.stdout.read = AsyncMock(return_value="")  # EOF
        session = ShellSession(proc, host="node1")

        with pytest.raises(ConnectionError, match="closed stdout unexpectedly"):
            await session.execute("uptime")

        assert not session.is_alive

        # Следующий execute() также бросает ConnectionError
        with pytest.raises(ConnectionError, match="closed or terminated"):
            await session.execute("uptime")

    @pytest.mark.asyncio
    async def test_parallel_execute_serialized_by_lock(self):
        """Параллельные вызовы execute() в одной сессии сериализуются через lock."""
        proc = FakeShellProcess()
        session = ShellSession(proc, host="node1", session_uuid="lockuuid1234")

        order: list[str] = []

        def custom_write(text: str) -> None:
            if "cmd1" in text:
                order.append("write_cmd1")
            elif "cmd2" in text:
                order.append("write_cmd2")

        async def custom_read(_n: int = 4096) -> str:
            await asyncio.sleep(0.03)
            if len(order) == 1:
                order.append("read_cmd1")
                return "out1\n__UNICONN_lockuuid1234__0\n"
            order.append("read_cmd2")
            return "out2\n__UNICONN_lockuuid1234__0\n"

        proc.stdin.write = MagicMock(side_effect=custom_write)
        proc.stdout.read = AsyncMock(side_effect=custom_read)

        r1, r2 = await asyncio.gather(
            session.execute("cmd1"),
            session.execute("cmd2"),
        )
        assert r1.stdout == "out1"
        assert r2.stdout == "out2"
        # cmd2 не должна отправляться в stdin, пока не прочитан маркер cmd1
        assert order == ["write_cmd1", "read_cmd1", "write_cmd2", "read_cmd2"]

    @pytest.mark.asyncio
    async def test_low_level_send_receive_resize_and_close(self):
        """Низкоуровневые методы send(), receive(), resize() и close()."""
        proc = FakeShellProcess()
        proc._out_queue.put_nowait("custom prompt> ")
        session = ShellSession(proc, host="node1")

        async with session as s:
            assert s is session
            assert s.is_alive
            await s.send("raw input\n")
            assert "raw input\n" in proc.written_chunks

            out = await s.receive(timeout=1.0)
            assert out == "custom prompt> "

            await s.resize(120, 40)
            assert proc.term_size == (120, 40)

        assert not session.is_alive
        assert proc.terminated
        assert "\x03" in proc.written_chunks
        assert "exit\n" in proc.written_chunks


class TestTransportsOpenShell:
    """Тесты open_shell() на уровне транспортов и Connection."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "transport_cls,transport_name",
        [
            (IPMITransport, "ipmi"),
        ],
    )
    async def test_unsupported_transports_raise_not_implemented(
        self, transport_cls, transport_name
    ):
        """IPMI бросает NotImplementedError при open_shell()."""
        config = ConnectionConfig(transport=transport_name, host="localhost")
        transport = transport_cls(config)
        with pytest.raises(NotImplementedError, match="open_shell not supported"):
            await transport.open_shell()

    @pytest.mark.asyncio
    async def test_local_and_telnet_open_shell_not_connected_raises(self):
        """LocalTransport, TelnetTransport и SerialTransport без connect() бросают ConnectionError."""
        local_transport = LocalTransport(
            ConnectionConfig(transport="local", host="localhost")
        )
        with pytest.raises(ConnectionError, match="not connected"):
            await local_transport.open_shell()

        telnet_transport = TelnetTransport(
            ConnectionConfig(transport="telnet", host="localhost")
        )
        with pytest.raises(ConnectionError, match="not connected"):
            await telnet_transport.open_shell()

        serial_transport = SerialTransport(
            ConnectionConfig(transport="serial", host="/dev/ttyUSB0")
        )
        with pytest.raises(ConnectionError, match="not connected"):
            await serial_transport.open_shell()

    @pytest.mark.posix_only
    @pytest.mark.asyncio
    async def test_local_open_shell_stateful_session(self, tmp_path):
        """Connection('local://').open_shell() создаёт рабочую stateful сессию."""
        async with Connection.from_uri("local://") as conn:
            async with await conn.open_shell() as shell:
                await shell.execute(f"cd {tmp_path}")
                pwd_res = await shell.execute("pwd")
                from pathlib import Path

                assert Path(pwd_res.text).resolve() == tmp_path.resolve()

                await shell.execute("export LOCAL_SHELL_VAR=hello_v060")
                env_res = await shell.execute("echo $LOCAL_SHELL_VAR")
                assert env_res.text == "hello_v060"

                await shell.resize(132, 43)

    @pytest.mark.asyncio
    async def test_telnet_open_shell_adapter(self):
        """TelnetTransport.open_shell() возвращает адаптер поверх reader/writer."""
        config = ConnectionConfig(transport="telnet", host="10.0.0.5")
        transport = TelnetTransport(config)
        transport._connected = True
        transport._reader = MagicMock()
        transport._writer = MagicMock()

        proc = await transport.open_shell(term_size=(100, 30))
        assert proc.term_size == (100, 30)
        proc.change_terminal_size(120, 40)
        assert proc.term_size == (120, 40)

        await transport.disconnect()
        assert proc.terminated
        assert proc.closed

    @pytest.mark.asyncio
    async def test_ssh_open_shell_not_connected_raises(self):
        """SSHTransport.open_shell() без connect() бросает ConnectionError."""
        config = ConnectionConfig(transport="ssh", host="example.com")
        with patch("uniconn.transports._ssh.asyncssh", MagicMock()):
            transport = SSHTransport(config)
            with pytest.raises(ConnectionError, match="not connected"):
                await transport.open_shell()

    @pytest.mark.asyncio
    async def test_ssh_disconnect_terminates_active_shell_processes(self):
        """SSHTransport.disconnect() терминирует все открытые shell-процессы."""
        mock_asyncssh = MagicMock()
        conn = MagicMock()
        conn.close = MagicMock()
        conn.wait_closed = AsyncMock()
        proc1 = FakeShellProcess()
        proc2 = FakeShellProcess()
        conn.create_process = AsyncMock(side_effect=[proc1, proc2])
        mock_asyncssh.connect = AsyncMock(return_value=conn)

        config = ConnectionConfig(transport="ssh", host="example.com")
        with patch("uniconn.transports._ssh.asyncssh", mock_asyncssh):
            transport = SSHTransport(config)
            await transport.connect()

            p1 = await transport.open_shell()
            p2 = await transport.open_shell(term_type="vt100", term_size=(100, 30))
            assert p1 is proc1
            assert p2 is proc2

            await transport.disconnect()

        assert proc1.terminated
        assert proc2.terminated
        assert proc1.closed
        assert proc2.closed

    @pytest.mark.asyncio
    async def test_connection_open_shell_lazy_connect_and_multiple_sessions(self):
        """Connection.open_shell() делает lazy connect, поддерживает несколько сессий и run()."""
        proc1 = FakeShellProcess()
        proc2 = FakeShellProcess()

        transport = AsyncMock()
        transport.name = "ssh"
        transport.is_connected = False

        async def do_connect():
            transport.is_connected = True

        transport.connect = AsyncMock(side_effect=do_connect)
        transport.disconnect = AsyncMock()
        transport.open_shell = AsyncMock(side_effect=[proc1, proc2])
        transport.run = AsyncMock(
            return_value=Result(
                exit_code=0,
                stdout="from_run",
                stderr="",
                duration=0.05,
                command="uptime",
                host="example.com",
            )
        )

        config = ConnectionConfig(transport="ssh", host="example.com")
        conn = Connection(transport, config)

        # Lazy connect при вызове open_shell без предварительного connect
        s1 = await conn.open_shell()
        transport.connect.assert_awaited_once()
        assert "export PS1=''; stty -echo\n" in proc1.written_chunks

        # Вторая независимая shell-сессия на том же подключении (без реконнекта)
        s2 = await conn.open_shell(term_type="vt100", term_size=(120, 40))
        assert transport.connect.await_count == 1

        await s1.execute("cd /var")
        await s2.execute("cd /opt")

        assert (await s1.execute("pwd")).stdout == "/var"
        assert (await s2.execute("pwd")).stdout == "/opt"

        # Переключение на обычный run() на том же подключении без реконнекта
        run_res = await conn.run("uptime")
        assert run_res.stdout == "from_run"
        assert transport.connect.await_count == 1

        await s1.close()
        await s2.close()
        await conn.close()
