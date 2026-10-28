# tests/unit/test_v040_features.py
"""Unit-тесты для функциональности этапа v0.4.0.

Охватывают:
- Безопасное повышение привилегий: sudo=True, sudo_user, sudo_password (через stdin)
- Поддержку passphrase (SecretStr) для зашифрованных SSH-ключей и маскировку в логах
- Режим sensitive=True (маскировка вывода в repr(Result), ExecutionError и логах)
- Контекстные менеджеры conn.cd() и conn.env() (включая вложенные вызовы и sync-обёртку)
- Lifecycle-хуки (before_run, after_run, on_error) и режим dry_run=True
- Файловые операции в памяти (read_file, write_file) и байтовый вывод run_bytes()
"""

from __future__ import annotations

import logging
import stat
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import SecretStr

from uniconn import Connection, ConnectionConfig, SecretMaskingFilter
from uniconn.exceptions import ExecutionError
from uniconn.transports._ssh import SSHTransport

# ─── 1. Безопасность: sudo, passphrase, sensitive ───────────────────────


@pytest.mark.asyncio
async def test_sudo_with_password_via_stdin():
    """При sudo=True пароль передаётся через закрытый stdin, а не в строке команды."""
    config = ConnectionConfig(
        transport="local",
        password=SecretStr("my_sudo_secret"),
    )
    conn = Connection.from_config(config)
    mock_run = AsyncMock(
        return_value=MagicMock(
            exit_code=0,
            stdout="root\n",
            stderr="",
            duration=0.01,
            command="sudo -S -p '' -- sh -c whoami",
            ok=True,
        )
    )
    conn._transport.run = mock_run  # type: ignore[method-assign]
    conn._transport._connected = True

    await conn.run("whoami", sudo=True)

    call_args = mock_run.call_args
    executed_cmd = call_args.args[0]
    passed_input = call_args.kwargs["input"]

    assert "my_sudo_secret" not in executed_cmd
    assert executed_cmd == "sudo -S -p '' -- sh -c whoami"
    assert passed_input == "my_sudo_secret\n"


@pytest.mark.asyncio
async def test_sudo_with_custom_user_and_combined_stdin():
    """sudo_user и sudo_password корректно комбинируются с пользовательским input."""
    conn = Connection.from_uri("local://")
    mock_run = AsyncMock(
        return_value=MagicMock(
            exit_code=0,
            stdout="ok\n",
            stderr="",
            duration=0.01,
            command="replaced",
            ok=True,
        )
    )
    conn._transport.run = mock_run  # type: ignore[method-assign]
    conn._transport._connected = True

    await conn.run(
        ["cat"],
        sudo=True,
        sudo_user="postgres",
        sudo_password="pg_secret",
        input="SELECT 1;\n",
    )

    call_args = mock_run.call_args
    assert call_args.args[0] == "sudo -S -p '' -u postgres -- sh -c cat"
    assert call_args.kwargs["input"] == "pg_secret\nSELECT 1;\n"


@pytest.mark.asyncio
async def test_sudo_passwordless_when_no_password():
    """Если пароль не задан, используется неинтерактивный флаг sudo -n."""
    conn = Connection.from_uri("local://")
    mock_run = AsyncMock(
        return_value=MagicMock(
            exit_code=0,
            stdout="root\n",
            stderr="",
            duration=0.01,
            command="sudo -n -- sh -c id",
            ok=True,
        )
    )
    conn._transport.run = mock_run  # type: ignore[method-assign]
    conn._transport._connected = True

    await conn.run("id", sudo=True)
    assert mock_run.call_args.args[0] == "sudo -n -- sh -c id"
    assert "input" not in mock_run.call_args.kwargs


@pytest.mark.asyncio
async def test_ssh_passphrase_in_config_uri_and_connect():
    """Поле passphrase (SecretStr) парсится из URI, копируется в copy() и передаётся в asyncssh."""
    conn = Connection.from_uri(
        "ssh://admin@example.com?key_file=/tmp/id_ed25519&passphrase=key_secret&known_hosts=no"
    )
    assert conn.config.key_file == "/tmp/id_ed25519"
    assert conn.config.passphrase is not None
    assert conn.config.passphrase.get_secret_value() == "key_secret"
    assert "key_secret" not in repr(conn.config.passphrase)

    cloned = conn.copy(passphrase="new_key_secret")
    assert cloned.config.passphrase is not None
    assert cloned.config.passphrase.get_secret_value() == "new_key_secret"

    transport = SSHTransport(conn.config)
    with patch("uniconn.transports._ssh.asyncssh.connect", new_callable=AsyncMock) as mock_connect:
        await transport.connect()
        kwargs = mock_connect.call_args.kwargs
        assert kwargs["client_keys"] == ["/tmp/id_ed25519"]
        assert kwargs["passphrase"] == "key_secret"


def test_secret_masking_filter_masks_passphrase_and_sudo_password():
    """SecretMaskingFilter маскирует passphrase=... и sudo_password=... в логах."""
    flt = SecretMaskingFilter()
    record = logging.LogRecord(
        name="uniconn",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="Auth with passphrase=my_key_pass and sudo_password:root_pass",
        args=(),
        exc_info=None,
    )
    flt.filter(record)
    assert "my_key_pass" not in record.msg
    assert "root_pass" not in record.msg
    assert "passphrase=***" in record.msg
    assert "sudo_password=***" in record.msg


@pytest.mark.asyncio
async def test_sensitive_mode_redacts_repr_and_exception():
    """При sensitive=True реальный вывод доступен в .stdout, но скрыт в repr() и ExecutionError."""
    async with Connection.from_uri("local://") as conn:
        res = await conn.run("echo super_secret_token", sensitive=True)
        assert res.sensitive is True
        assert res.stdout.strip() == "super_secret_token"
        assert "super_secret_token" not in repr(res)
        assert "***REDACTED***" in repr(res)

        with pytest.raises(ExecutionError) as exc_info:
            await conn.run(
                "echo leaked_secret && exit 1",
                sensitive=True,
                raise_on_error=True,
            )
        err = exc_info.value
        assert "leaked_secret" not in str(err)
        assert err.stdout == "***REDACTED***"
        assert err.stderr == "***REDACTED***"


# ─── 2. Контекстные менеджеры conn.cd() и conn.env() ────────────────────


@pytest.mark.asyncio
async def test_cd_and_env_context_managers_nested(tmp_path: Path):
    """Вложенные conn.cd() и conn.env() корректно разрешают относительные пути и переменные."""
    sub = tmp_path / "level1" / "level2"
    sub.mkdir(parents=True)

    async with Connection.from_uri("local://") as conn:
        async with conn.cd(tmp_path), conn.env(VAR_A="alpha", VAR_B="1"):
            res1 = await conn.run("pwd")
            assert Path(res1.stdout.strip()).resolve() == tmp_path.resolve()

            async with conn.cd("level1/level2"), conn.env(VAR_B="2", VAR_C="gamma"):
                py_code = (
                    "import os; print(os.getcwd(), "
                    "os.environ['VAR_A'], os.environ['VAR_B'], os.environ['VAR_C'])"
                )
                res2 = await conn.run(["python3", "-c", py_code])
                parts = res2.stdout.strip().split()
                assert Path(parts[0]).resolve() == sub.resolve()
                assert parts[1:] == ["alpha", "2", "gamma"]

        assert conn.current_cwd is None
        assert conn.current_env == {}


def test_sync_connection_cd_and_env(tmp_path: Path):
    """SyncConnection поддерживает with conn.cd(...) и with conn.env(...)."""
    with (
        Connection.from_uri("local://").to_sync() as conn,
        conn.cd(tmp_path),
        conn.env(SYNC_KEY="sync_val"),
    ):
        res = conn.run(
            ["python3", "-c", "import os; print(os.getcwd(), os.environ['SYNC_KEY'])"]
        )
        cwd_out, val_out = res.stdout.strip().split()
        assert Path(cwd_out).resolve() == tmp_path.resolve()
        assert val_out == "sync_val"


# ─── 3. Lifecycle Hooks и режим dry_run ────────────────────────────────


@pytest.mark.asyncio
async def test_lifecycle_hooks_before_after_and_on_error():
    """Хуки before_run, after_run и on_error вызываются в правильном порядке (sync и async)."""
    events: list[str] = []

    def on_before(command: str, host: str | None, kwargs: dict) -> None:
        events.append(f"before:{command}:{host}")

    async def on_after(result) -> None:
        events.append(f"after:{result.command}:{result.exit_code}")

    def on_err(exc: BaseException, command: str, host: str | None) -> None:
        events.append(f"error:{command}:{type(exc).__name__}")

    async with Connection.from_uri(
        "local://",
        before_run=[on_before],
        after_run=[on_after],
        on_error=[on_err],
    ) as conn:
        res = await conn.run("echo hello")
        assert res.ok

        with pytest.raises(ExecutionError):
            await conn.run("exit 2", raise_on_error=True)

    assert events == [
        "before:echo hello:localhost",
        "after:echo hello:0",
        "before:exit 2:localhost",
        "error:exit 2:ExecutionError",
    ]


@pytest.mark.asyncio
async def test_dry_run_mode_skips_execution_and_triggers_hooks(tmp_path: Path):
    """В режиме dry_run=True команды и write_file не выполняются реально, но хуки срабатывают."""
    marker_file = tmp_path / "should_not_exist.txt"
    hook_calls: list[str] = []

    async with Connection.from_uri("local://", dry_run=True) as conn:
        conn.add_hook("before_run", lambda cmd, host, kw: hook_calls.append(f"before:{cmd}"))
        conn.add_hook("after_run", lambda res: hook_calls.append(f"after:{res.exit_code}"))

        res = await conn.run(["touch", str(marker_file)])
        assert res.ok
        assert res.stdout == ""
        assert not marker_file.exists()

        await conn.files.write_file(str(marker_file), "data")
        assert not marker_file.exists()

        raw = await conn.run_bytes("echo bytes")
        assert raw == b""

    from uniconn.core.connection import format_command
    expected_cmd = format_command(["touch", str(marker_file)])
    assert hook_calls == [f"before:{expected_cmd}", "after:0"]


# ─── 4. Файловые операции в памяти (read_file, write_file) и run_bytes ──


@pytest.mark.asyncio
async def test_local_read_write_file_and_run_bytes(tmp_path: Path):
    """read_file, write_file (с mode и conn.cd) и run_bytes корректно работают на LocalTransport."""
    async with Connection.from_uri("local://") as conn, conn.cd(tmp_path):
        await conn.files.write_file("config.yaml", "key: value\n", mode=0o600)
        target = tmp_path / "config.yaml"
        assert target.exists()
        if sys.platform != "win32":
            assert stat.S_IMODE(target.stat().st_mode) == 0o600

        text = await conn.files.read_file("config.yaml")
        assert text == "key: value\n"

        raw_bytes = await conn.files.read_file("config.yaml", encoding=None)
        assert raw_bytes == b"key: value\n"

        # Проверка бинарного вывода, не являющегося валидным UTF-8
        out_bytes = await conn.run_bytes(
            ["python3", "-c", "import sys; sys.stdout.buffer.write(b'\\x80\\xfe\\xff\\x00')"]
        )
        assert out_bytes == b"\x80\xfe\xff\x00"


@pytest.mark.asyncio
async def test_ssh_transport_read_write_file_and_run_bytes():
    """SSHTransport реализует read_file, write_file через SFTP и run_bytes без потери байтов."""
    config = ConnectionConfig(transport="ssh", host="example.com", username="root")
    transport = SSHTransport(config)
    transport._connected = True

    mock_file = MagicMock()
    mock_file.read = AsyncMock(return_value=b"remote-binary-content")
    mock_file.write = AsyncMock()

    mock_file_cm = MagicMock()
    mock_file_cm.__aenter__ = AsyncMock(return_value=mock_file)
    mock_file_cm.__aexit__ = AsyncMock(return_value=None)

    mock_sftp = MagicMock()
    mock_sftp.open = MagicMock(return_value=mock_file_cm)
    mock_sftp.chmod = AsyncMock()

    mock_sftp_cm = MagicMock()
    mock_sftp_cm.__aenter__ = AsyncMock(return_value=mock_sftp)
    mock_sftp_cm.__aexit__ = AsyncMock(return_value=None)

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout.read = AsyncMock(return_value=b"\x89PNG\r\n\x1a\n")
    mock_proc.stderr.read = AsyncMock(return_value=b"")
    mock_proc.wait = AsyncMock()

    mock_proc_cm = MagicMock()
    mock_proc_cm.__aenter__ = AsyncMock(return_value=mock_proc)
    mock_proc_cm.__aexit__ = AsyncMock(return_value=None)

    mock_conn = MagicMock()
    mock_conn.start_sftp_client = MagicMock(return_value=mock_sftp_cm)
    mock_conn.create_process = MagicMock(return_value=mock_proc_cm)
    transport._conn = mock_conn

    await transport.write_file("/etc/app.conf", b"secret=1\n", mode=0o600)
    mock_file.write.assert_awaited_once_with(b"secret=1\n")
    mock_sftp.chmod.assert_awaited_once_with("/etc/app.conf", 0o600)

    data = await transport.read_file("/etc/app.conf")
    assert data == b"remote-binary-content"

    png_bytes = await transport.run_bytes("cat /tmp/image.png")
    assert png_bytes == b"\x89PNG\r\n\x1a\n"


def test_sync_connection_read_write_and_run_bytes(tmp_path: Path):
    """SyncConnection поддерживает files.write_file, files.read_file и run_bytes."""
    target = tmp_path / "sync.txt"
    with Connection.from_uri("local://").to_sync() as conn:
        conn.files.write_file(str(target), "sync content")
        assert conn.files.read_file(str(target)) == "sync content"
        raw = conn.run_bytes(["python3", "-c", "import sys; sys.stdout.buffer.write(b'raw_ok')"])
        assert raw == b"raw_ok"
