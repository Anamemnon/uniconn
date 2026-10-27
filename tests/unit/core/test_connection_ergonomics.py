# tests/unit/test_v030_features.py
"""Unit-тесты для функциональности этапа v0.3.0.

Охватывают:
- List-based команды (Sequence[str]) с автоэкранированием через shlex.join + uniconn.quote
- Поддержку cwd= в SSHTransport.run() и SSHTransport.stream()
- Поддержку input= (stdin) в LocalTransport.run(), SSHTransport.run(),
  Connection.run(), SyncConnection.run()
- Опции SSHTransport: keepalive/keepalive_interval, keepalive_count_max, ssh_config,
  use_agent/agent_path, client_cert
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from uniconn import Connection, ConnectionConfig, ShellSession, quote
from uniconn.exceptions import ConnectionError
from uniconn.transports._local import LocalTransport
from uniconn.transports._ssh import SSHTransport

# ─── 1. List-based команды и shlex.quote ───────────────────────────────


def test_exported_quote():
    """Функция quote экспортируется из корня пакета uniconn."""
    escaped = quote("hello world; rm -rf /")
    assert escaped == "'hello world; rm -rf /'"


@pytest.mark.asyncio
async def test_connection_run_list_command_local():
    """Connection.run() принимает список аргументов и безопасно экранирует спецсимволы."""
    async with Connection.from_uri("local://") as conn:
        res = await conn.run(
            [sys.executable, "-c", "import sys; print(sys.argv[1])", "arg with spaces & $HOME"]
        )
        assert res.ok
        assert res.stdout.strip() == "arg with spaces & $HOME"


@pytest.mark.asyncio
async def test_connection_run_commands_mixed_str_and_list():
    """Connection.run_commands() поддерживает смешанный список строк и Sequence[str]."""
    async with Connection.from_uri("local://") as conn:
        results = await conn.run_commands([
            ["echo", "first item"],
            "echo second item",
            ("echo", "third item with spaces"),
        ])
        assert len(results) == 3
        assert results[0].stdout.strip() == "first item"
        assert results[1].stdout.strip() == "second item"
        assert results[2].stdout.strip() == "third item with spaces"


@pytest.mark.asyncio
async def test_connection_stream_list_command():
    """Connection.stream() принимает команду в виде списка аргументов."""
    async with Connection.from_uri("local://") as conn:
        lines = []
        async for line in conn.stream([sys.executable, "-c", "print('line 1'); print('line 2')"]):
            lines.append(line.strip())
        assert lines == ["line 1", "line 2"]


@pytest.mark.asyncio
async def test_shell_session_execute_list_command():
    """ShellSession.execute() принимает список аргументов и экранирует их через shlex.join."""
    proc = MagicMock()
    proc.returncode = None
    proc.exit_status = None
    proc.stdin = MagicMock()
    proc.stdout = MagicMock()

    written: list[str] = []
    proc.stdin.write.side_effect = lambda data: written.append(data)
    proc.stdout.read = AsyncMock(
        return_value="hello world\n__UNICONN_fixeduuid__0\n"
    )

    session = ShellSession(proc=proc, host="testhost", session_uuid="fixeduuid")
    result = await session.execute(["echo", "hello world"])

    assert result.ok
    assert result.stdout == "hello world"
    assert result.command == "echo 'hello world'"
    assert written[-1] == "echo 'hello world'; echo \"\\n__UNICONN_fixeduuid__$?\"\n"


def test_sync_connection_run_list_command():
    """SyncConnection.run() поддерживает список аргументов."""
    with Connection.from_uri("local://").to_sync() as conn:
        res = conn.run(["echo", "sync list command"])
        assert res.ok
        assert res.stdout.strip() == "sync list command"


# ─── 2. Поддержка cwd= в SSHTransport ──────────────────────────────────


@pytest.mark.asyncio
async def test_ssh_transport_run_with_cwd():
    """SSHTransport.run() оборачивает команду в cd <quoted_cwd> && <cmd> при передаче cwd."""
    config = ConnectionConfig(transport="ssh", host="example.com", username="root")
    transport = SSHTransport(config)
    transport._connected = True

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout.read = AsyncMock(return_value="/var/log/my app\n")
    mock_proc.stderr.read = AsyncMock(return_value="")
    mock_proc.wait = AsyncMock()

    mock_proc_cm = MagicMock()
    mock_proc_cm.__aenter__ = AsyncMock(return_value=mock_proc)
    mock_proc_cm.__aexit__ = AsyncMock(return_value=None)

    mock_conn = MagicMock()
    mock_conn.create_process = MagicMock(return_value=mock_proc_cm)
    transport._conn = mock_conn

    res = await transport.run("pwd", cwd="/var/log/my app")
    assert res.ok
    assert res.stdout == "/var/log/my app\n"
    mock_conn.create_process.assert_called_once_with(
        "cd '/var/log/my app' && pwd",
        env=None,
    )


@pytest.mark.asyncio
async def test_ssh_transport_stream_with_cwd():
    """SSHTransport.stream() оборачивает команду в cd <quoted_cwd> && <cmd> при передаче cwd."""
    config = ConnectionConfig(transport="ssh", host="example.com", username="root")
    transport = SSHTransport(config)
    transport._connected = True

    class FakeStdout:
        def __init__(self):
            self._lines = ["line1\n", "line2\n"]

        def __aiter__(self):
            return self

        async def __anext__(self):
            if not self._lines:
                raise StopAsyncIteration
            return self._lines.pop(0)

    mock_process = MagicMock()
    mock_process.stdout = FakeStdout()

    mock_process_cm = MagicMock()
    mock_process_cm.__aenter__ = AsyncMock(return_value=mock_process)
    mock_process_cm.__aexit__ = AsyncMock(return_value=None)

    mock_conn = MagicMock()
    mock_conn.create_process = MagicMock(return_value=mock_process_cm)
    transport._conn = mock_conn

    collected = []
    async for line in transport.stream("tail -n 2 app.log", cwd="/srv/app dir"):
        collected.append(line.strip())

    assert collected == ["line1", "line2"]
    mock_conn.create_process.assert_called_once_with(
        "cd '/srv/app dir' && tail -n 2 app.log",
        env=None,
    )


# ─── 3. Поддержка input= (stdin) ───────────────────────────────────────


@pytest.mark.asyncio
async def test_local_transport_run_with_str_and_bytes_input():
    """LocalTransport.run() передаёт строковый и байтовый input в stdin подпроцесса."""
    config = ConnectionConfig(transport="local")
    transport = LocalTransport(config)
    await transport.connect()

    res_str = await transport.run("cat", input="hello from str stdin\n")
    assert res_str.ok
    assert res_str.stdout == "hello from str stdin\n"

    res_bytes = await transport.run("cat", input=b"hello from bytes stdin\n")
    assert res_bytes.ok
    assert res_bytes.stdout == "hello from bytes stdin\n"

    await transport.disconnect()


@pytest.mark.asyncio
async def test_ssh_transport_run_with_input():
    """SSHTransport.run() передаёт input (str и bytes) в stdin процесса asyncssh."""
    config = ConnectionConfig(transport="ssh", host="example.com", username="root")
    transport = SSHTransport(config)
    transport._connected = True

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdin = MagicMock()
    mock_proc.stdout.read = AsyncMock(return_value="received\n")
    mock_proc.stderr.read = AsyncMock(return_value="")
    mock_proc.wait = AsyncMock()

    mock_proc_cm = MagicMock()
    mock_proc_cm.__aenter__ = AsyncMock(return_value=mock_proc)
    mock_proc_cm.__aexit__ = AsyncMock(return_value=None)

    mock_conn = MagicMock()
    mock_conn.create_process = MagicMock(return_value=mock_proc_cm)
    transport._conn = mock_conn

    res = await transport.run("cat > /tmp/out", input=b"payload bytes")
    assert res.ok
    mock_proc.stdin.write.assert_called_once_with("payload bytes")
    mock_proc.stdin.write_eof.assert_called_once_with()


@pytest.mark.asyncio
async def test_connection_and_sync_run_with_input():
    """Connection.run() и SyncConnection.run() пробрасывают input в транспорт."""
    async with Connection.from_uri("local://") as conn:
        res = await conn.run(["cat"], input="async stdin payload")
        assert res.ok
        assert res.stdout == "async stdin payload"

    with Connection.from_uri("local://").to_sync() as sync_conn:
        res_sync = sync_conn.run(["cat"], input="sync stdin payload")
        assert res_sync.ok
        assert res_sync.stdout == "sync stdin payload"


# ─── 4. Новые опции SSHTransport (keepalive, ssh_config, agent, cert) ──


@pytest.mark.asyncio
async def test_ssh_transport_keepalive_options():
    """Опции keepalive / keepalive_interval и keepalive_count_max передаются в asyncssh."""
    config = ConnectionConfig(
        transport="ssh",
        host="example.com",
        username="admin",
        options={
            "known_hosts": "no",
            "keepalive": 25,
            "keepalive_count_max": 4,
        },
    )
    transport = SSHTransport(config)

    with patch("uniconn.transports._ssh.asyncssh.connect", new_callable=AsyncMock) as mock_connect:
        await transport.connect()
        call_kwargs = mock_connect.call_args.kwargs
        assert call_kwargs["keepalive_interval"] == 25.0
        assert call_kwargs["keepalive_count_max"] == 4


@pytest.mark.asyncio
async def test_ssh_transport_ssh_config_custom_file(tmp_path: Path):
    """Опция ssh_config принимает путь к существующему файлу конфигурации OpenSSH."""
    ssh_cfg = tmp_path / "custom_ssh_config"
    ssh_cfg.write_text("Host example.com\n  Port 2222\n", encoding="utf-8")

    config = ConnectionConfig(
        transport="ssh",
        host="example.com",
        options={
            "known_hosts": "no",
            "ssh_config": str(ssh_cfg),
        },
    )
    transport = SSHTransport(config)

    with patch("uniconn.transports._ssh.asyncssh.connect", new_callable=AsyncMock) as mock_connect:
        await transport.connect()
        call_kwargs = mock_connect.call_args.kwargs
        assert call_kwargs["config"] == [str(ssh_cfg)]


@pytest.mark.asyncio
async def test_ssh_transport_ssh_config_missing_file_raises():
    """Если указанный в ssh_config файл не существует, выбрасывается ConnectionError."""
    config = ConnectionConfig(
        transport="ssh",
        host="example.com",
        options={
            "known_hosts": "no",
            "ssh_config": "/nonexistent/path/ssh_config",
        },
    )
    transport = SSHTransport(config)

    with pytest.raises(ConnectionError, match="ssh_config file not found"):
        await transport.connect()


@pytest.mark.asyncio
async def test_ssh_transport_agent_and_client_cert_options(tmp_path: Path):
    """Опции use_agent=False, agent_path и client_cert корректно настраивают asyncssh."""
    cert_file = tmp_path / "id_ed25519-cert.pub"
    cert_file.write_text("ssh-ed25519-cert-v01@openssh.com AAAA...", encoding="utf-8")

    config = ConnectionConfig(
        transport="ssh",
        host="example.com",
        options={
            "known_hosts": "no",
            "use_agent": False,
            "client_cert": str(cert_file),
        },
    )
    transport = SSHTransport(config)

    with patch("uniconn.transports._ssh.asyncssh.connect", new_callable=AsyncMock) as mock_connect:
        await transport.connect()
        call_kwargs = mock_connect.call_args.kwargs
        assert call_kwargs["agent_path"] is None
        assert call_kwargs["client_certs"] == [str(cert_file)]


@pytest.mark.asyncio
async def test_ssh_transport_missing_client_cert_raises():
    """Если указанный client_cert не существует, выбрасывается ConnectionError."""
    config = ConnectionConfig(
        transport="ssh",
        host="example.com",
        options={
            "known_hosts": "no",
            "client_cert": "/nonexistent/id_rsa-cert.pub",
        },
    )
    transport = SSHTransport(config)

    with pytest.raises(ConnectionError, match="client_cert file not found"):
        await transport.connect()
