# tests/unit/test_ssh_transport.py
"""Unit-тесты SSH транспорта с моком asyncssh (без реальных соединений)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from uniconn._config import ConnectionConfig
from uniconn.exceptions import AuthenticationError, ConnectionError
from uniconn.transports._ssh import SSHTransport


@pytest.fixture
def asyncssh_mock():
    """Мок модуля asyncssh с классами исключений."""
    mock = MagicMock()
    mock.PermissionDenied = type("PermissionDenied", (Exception,), {})
    mock.DisconnectError = type("DisconnectError", (Exception,), {})
    with patch("uniconn.transports._ssh.asyncssh", mock):
        yield mock


@pytest.fixture
def ssh_config():
    """Базовая SSH-конфигурация."""
    return ConnectionConfig(
        transport="ssh",
        host="example.com",
        username="admin",
        password="secret",
        timeout=10.0,
    )


def _make_conn() -> MagicMock:
    """Фейковое SSHClientConnection (close синхронный, wait_closed async)."""
    conn = MagicMock()
    conn.close = MagicMock()
    conn.wait_closed = AsyncMock()
    return conn


def _make_proc(stdout: str = "out", stderr: str = "err", returncode: int = 0):
    """Фейковый процесс для create_process (async context manager)."""
    proc = MagicMock()
    proc.stdout = MagicMock()
    proc.stdout.read = AsyncMock(return_value=stdout)
    proc.stderr = MagicMock()
    proc.stderr.read = AsyncMock(return_value=stderr)
    proc.wait = AsyncMock()
    proc.terminate = MagicMock()
    proc.returncode = returncode

    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=proc)
    cm.__aexit__ = AsyncMock(return_value=None)
    return cm, proc


class TestSSHConnect:
    """Тесты подключения."""

    @pytest.mark.asyncio
    async def test_connect_success(self, asyncssh_mock, ssh_config):
        """Успешное подключение с базовыми параметрами."""
        conn = _make_conn()
        asyncssh_mock.connect = AsyncMock(return_value=conn)

        transport = SSHTransport(ssh_config)
        await transport.connect()

        assert transport.is_connected
        asyncssh_mock.connect.assert_awaited_once()
        kwargs = asyncssh_mock.connect.await_args.kwargs
        assert kwargs["host"] == "example.com"
        assert kwargs["port"] == 22
        assert kwargs["username"] == "admin"
        assert kwargs["password"] == "secret"
        assert kwargs["known_hosts"] is None  # режим "no" по умолчанию

    @pytest.mark.asyncio
    async def test_connect_permission_denied(self, asyncssh_mock, ssh_config):
        """Ошибка аутентификации → AuthenticationError."""
        asyncssh_mock.connect = AsyncMock(
            side_effect=asyncssh_mock.PermissionDenied("denied")
        )

        transport = SSHTransport(ssh_config)
        with pytest.raises(AuthenticationError, match="authentication failed"):
            await transport.connect()
        assert not transport.is_connected

    @pytest.mark.asyncio
    async def test_connect_generic_error(self, asyncssh_mock, ssh_config):
        """Прочая ошибка подключения → ConnectionError."""
        asyncssh_mock.connect = AsyncMock(side_effect=OSError("no route"))

        transport = SSHTransport(ssh_config)
        with pytest.raises(ConnectionError, match="connection error"):
            await transport.connect()
        assert not transport.is_connected


class TestSSHKnownHosts:
    """Тесты режимов known_hosts."""

    def test_known_hosts_no(self, asyncssh_mock, ssh_config):
        """Режим "no" — проверка отключена."""
        transport = SSHTransport(ssh_config)
        assert transport._resolve_known_hosts() is None

    def test_known_hosts_explicit_file(self, asyncssh_mock, ssh_config, tmp_path):
        """Явный путь к существующему файлу."""
        kh_file = tmp_path / "known_hosts"
        kh_file.write_text("example.com ssh-ed25519 AAAA\n")
        config = ssh_config.model_copy(
            update={"options": {"known_hosts": str(kh_file)}}
        )
        transport = SSHTransport(config)
        assert transport._resolve_known_hosts() == str(kh_file)

    def test_known_hosts_missing_file(self, asyncssh_mock, ssh_config, tmp_path):
        """Явный путь к несуществующему файлу → ConnectionError."""
        config = ssh_config.model_copy(
            update={"options": {"known_hosts": str(tmp_path / "absent")}}
        )
        transport = SSHTransport(config)
        with pytest.raises(ConnectionError, match="known_hosts file not found"):
            transport._resolve_known_hosts()


class TestSSHProxy:
    """Тесты proxy/jump hosts (в т.ч. multi-hop)."""

    @pytest.mark.asyncio
    async def test_single_jump(self, asyncssh_mock, ssh_config):
        """Один jump-хост: цель подключается через tunnel=proxy."""
        proxy_conn = _make_conn()
        target_conn = _make_conn()
        asyncssh_mock.connect = AsyncMock(side_effect=[proxy_conn, target_conn])

        config = ssh_config.model_copy(update={"options": {"proxy": "jump@h1"}})
        transport = SSHTransport(config)
        await transport.connect()

        assert asyncssh_mock.connect.await_count == 2
        proxy_kwargs = asyncssh_mock.connect.await_args_list[0].kwargs
        target_kwargs = asyncssh_mock.connect.await_args_list[1].kwargs
        assert proxy_kwargs["host"] == "h1"
        assert proxy_kwargs["username"] == "jump"
        assert "tunnel" not in proxy_kwargs
        assert target_kwargs["host"] == "example.com"
        assert target_kwargs["tunnel"] is proxy_conn

    @pytest.mark.asyncio
    async def test_multi_jump_chain(self, asyncssh_mock, ssh_config):
        """Multi-hop: каждый hop идёт через предыдущий (tunnel=)."""
        hop1, hop2, target_conn = _make_conn(), _make_conn(), _make_conn()
        asyncssh_mock.connect = AsyncMock(side_effect=[hop1, hop2, target_conn])

        config = ssh_config.model_copy(
            update={"options": {"proxy": "u1@h1,u2@h2"}}
        )
        transport = SSHTransport(config)
        await transport.connect()

        calls = asyncssh_mock.connect.await_args_list
        assert calls[0].kwargs["host"] == "h1"
        assert "tunnel" not in calls[0].kwargs
        assert calls[1].kwargs["host"] == "h2"
        assert calls[1].kwargs["tunnel"] is hop1
        assert calls[2].kwargs["host"] == "example.com"
        assert calls[2].kwargs["tunnel"] is hop2

    @pytest.mark.asyncio
    async def test_disconnect_closes_all_hops(self, asyncssh_mock, ssh_config):
        """Disconnect закрывает цель и все промежуточные hop'ы."""
        hop1, hop2, target_conn = _make_conn(), _make_conn(), _make_conn()
        asyncssh_mock.connect = AsyncMock(side_effect=[hop1, hop2, target_conn])

        config = ssh_config.model_copy(
            update={"options": {"proxy": "u1@h1,u2@h2"}}
        )
        transport = SSHTransport(config)
        await transport.connect()
        await transport.disconnect()

        target_conn.close.assert_called_once()
        hop1.close.assert_called_once()
        hop2.close.assert_called_once()
        assert not transport.is_connected

    @pytest.mark.asyncio
    async def test_connect_error_closes_hops(self, asyncssh_mock, ssh_config):
        """Ошибка подключения к цели — промежуточные hop'ы закрываются."""
        hop1 = _make_conn()
        asyncssh_mock.connect = AsyncMock(
            side_effect=[hop1, OSError("target unreachable")]
        )

        config = ssh_config.model_copy(update={"options": {"proxy": "u1@h1"}})
        transport = SSHTransport(config)
        with pytest.raises(ConnectionError):
            await transport.connect()

        hop1.close.assert_called_once()


class TestSSHRunStream:
    """Тесты run()/stream()."""

    @pytest.mark.asyncio
    async def test_run_not_connected(self, asyncssh_mock, ssh_config):
        """run() без connect() → ConnectionError, а не AttributeError."""
        transport = SSHTransport(ssh_config)
        with pytest.raises(ConnectionError, match="not connected"):
            await transport.run("uptime")

    @pytest.mark.asyncio
    async def test_stream_not_connected(self, asyncssh_mock, ssh_config):
        """stream() без connect() → ConnectionError, а не AttributeError."""
        transport = SSHTransport(ssh_config)
        with pytest.raises(ConnectionError, match="not connected"):
            async for _ in transport.stream("uptime"):
                pass

    @pytest.mark.asyncio
    async def test_run_success(self, asyncssh_mock, ssh_config):
        """Успешное выполнение команды."""
        conn = _make_conn()
        cm, proc = _make_proc(stdout="hello", stderr="", returncode=0)
        conn.create_process = MagicMock(return_value=cm)
        asyncssh_mock.connect = AsyncMock(return_value=conn)

        transport = SSHTransport(ssh_config)
        await transport.connect()
        result = await transport.run("echo hello", timeout=5.0)

        assert result.exit_code == 0
        assert result.stdout == "hello"
        assert result.stderr == ""
        assert result.command == "echo hello"

    @pytest.mark.asyncio
    async def test_run_timeout_terminates(self, asyncssh_mock, ssh_config):
        """Таймаут чтения — процесс терминируется, TimeoutError пробрасывается."""
        conn = _make_conn()
        cm, proc = _make_proc()
        proc.stdout.read = AsyncMock(side_effect=TimeoutError("slow"))
        conn.create_process = MagicMock(return_value=cm)
        asyncssh_mock.connect = AsyncMock(return_value=conn)

        transport = SSHTransport(ssh_config)
        await transport.connect()
        with pytest.raises(TimeoutError):
            await transport.run("sleep 100", timeout=5.0)
        proc.terminate.assert_called_once()

    @pytest.mark.asyncio
    async def test_stream_lines(self, asyncssh_mock, ssh_config):
        """Стриминг отдаёт строки инкрементально."""

        class _AsyncLines:
            def __init__(self, lines):
                self._lines = lines

            def __aiter__(self):
                async def _gen():
                    for line in self._lines:
                        yield line

                return _gen()

        conn = _make_conn()
        cm, proc = _make_proc()
        proc.stdout = _AsyncLines(["line1\n", "line2\n"])
        conn.create_process = MagicMock(return_value=cm)
        asyncssh_mock.connect = AsyncMock(return_value=conn)

        transport = SSHTransport(ssh_config)
        await transport.connect()

        lines = [line async for line in transport.stream("cat file")]
        assert lines == ["line1", "line2"]


class TestSSHPing:
    """Тесты ping()."""

    @pytest.mark.asyncio
    async def test_ping_not_connected(self, asyncssh_mock, ssh_config):
        """Без подключения ping → False."""
        transport = SSHTransport(ssh_config)
        assert await transport.ping() is False

    @pytest.mark.asyncio
    async def test_ping_success(self, asyncssh_mock, ssh_config):
        """Живое подключение: `true` с exit_status=0 → True."""
        conn = _make_conn()
        conn.run = AsyncMock(return_value=MagicMock(exit_status=0))
        asyncssh_mock.connect = AsyncMock(return_value=conn)

        transport = SSHTransport(ssh_config)
        await transport.connect()
        assert await transport.ping() is True
        conn.run.assert_awaited_once_with("true")

    @pytest.mark.asyncio
    async def test_ping_error_returns_false(self, asyncssh_mock, ssh_config):
        """Ошибка выполнения `true` → False (исключение не пробрасывается)."""
        conn = _make_conn()
        conn.run = AsyncMock(side_effect=OSError("broken pipe"))
        asyncssh_mock.connect = AsyncMock(return_value=conn)

        transport = SSHTransport(ssh_config)
        await transport.connect()
        assert await transport.ping() is False
