# tests/unit/security/test_phase1_hardening.py
"""Регрессионные unit-тесты безопасности этапа 1B: инъекции, TLS/SSH strict по умолчанию, HITL, URI и tmpfs."""

from __future__ import annotations

import stat
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from uniconn import (
    ActionRiskTier,
    ApprovalManager,
    ApprovalTamperingError,
    ConnectionConfig,
    ConnectionPool,
)
from uniconn.background._cleanup import BackgroundCleanupManager
from uniconn.background._session import BackgroundSession
from uniconn.exceptions import ConfigurationError
from uniconn.pool.session_pool import SSHSessionPool
from uniconn.result import Result
from uniconn.transports._docker import DockerTransport
from uniconn.transports._kubectl import KubectlTransport
from uniconn.transports._winrm import WinRMTransport
from uniconn.transports.bmc.redfish import RedfishTransport
from uniconn.transports.network.gnmi import GnmiTransport
from uniconn.transports.network.netconf import NetconfTransport
from uniconn.transports.network.restconf import RestconfTransport
from uniconn.transports.ssh.config_parser import OpenSSHConfigParser
from uniconn.transports.virtualization.qga import QgaTransport


def test_proxy_command_expansion_rejects_shell_injection() -> None:
    """OpenSSHConfigParser.expand_proxy_command отклоняет метасимволы оболочки в host/username/port."""
    safe = OpenSSHConfigParser.expand_proxy_command("ssh -W %h:%p %r", "10.0.0.10", 2222, "ops")
    assert safe == "ssh -W 10.0.0.10:2222 ops"

    for bad_host in ("host;rm -rf /", "host$(id)", "host|nc", "host\nwhoami", "host'quoted"):
        with pytest.raises(ConfigurationError, match="Unsafe host"):
            OpenSSHConfigParser.expand_proxy_command("ssh -W %h:%p %r", bad_host, 22, "ops")

    for bad_user in ("user;id", "user`id`", "user name"):
        with pytest.raises(ConfigurationError, match="Unsafe username"):
            OpenSSHConfigParser.expand_proxy_command("ssh -W %h:%p %r", "10.0.0.1", 22, bad_user)

    with pytest.raises(ConfigurationError, match="Invalid port"):
        OpenSSHConfigParser.expand_proxy_command("ssh -W %h:%p %r", "10.0.0.1", 70000, "ops")


def test_docker_and_kubectl_validate_env_keys_and_shell_binary() -> None:
    """DockerTransport и KubectlTransport отклоняют невалидные ключи env и небезопасный параметр shell."""
    cfg_docker_bad_shell = ConnectionConfig(
        transport="docker",
        host="web-ctr",
        options={"shell": "sh; touch /tmp/pwn"},
    )
    with pytest.raises(ConfigurationError, match="Unsafe characters"):
        DockerTransport(cfg_docker_bad_shell)._build_exec_args("id")

    cfg_k8s_bad_shell = ConnectionConfig(
        transport="kubectl",
        host="web-pod",
        options={"shell": "bash && id"},
    )
    with pytest.raises(ConfigurationError, match="Unsafe characters"):
        KubectlTransport(cfg_k8s_bad_shell)._build_exec_args("id")

    docker_ok = DockerTransport(ConnectionConfig(transport="docker", host="web-ctr"))
    with pytest.raises(ValueError, match="Invalid environment variable"):
        docker_ok._build_exec_args("env", env={"BAD=KEY": "1"})
    with pytest.raises(ValueError, match="Invalid environment variable"):
        docker_ok._build_exec_args("env", env={"1STARTS_DIGIT": "1"})

    k8s_ok = KubectlTransport(ConnectionConfig(transport="kubectl", host="web-pod"))
    with pytest.raises(ValueError, match="Invalid environment variable"):
        k8s_ok._build_exec_args("env", env={"BAD;KEY": "1"})


def test_winrm_rejects_cmd_metacharacters_in_cwd() -> None:
    """WinRMTransport в режиме cmd.exe отклоняет метасимволы команды в cwd."""
    cfg = ConnectionConfig(
        transport="winrm",
        host="win-01.internal",
        username="Administrator",
        options={"shell": "cmd"},
    )
    transport = WinRMTransport(cfg)
    assert transport.server_cert_validation == "validate"

    for bad_cwd in (r"C:\Temp & whoami", r"C:\Temp | calc", r"C:\Temp%OS%", "C:\\Temp\ncalc"):
        with pytest.raises(ConfigurationError, match="Unsafe"):
            transport._prepare_execution("dir", shell_mode="cmd", cwd=bad_cwd)


@pytest.mark.asyncio
async def test_transports_enforce_strict_tls_and_known_hosts_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Сетевые и BMC транспорты включают строгую проверку сертификатов и ключей хоста по умолчанию."""
    monkeypatch.setattr(Path, "home", lambda: Path("/nonexistent_home_for_strict_test"))

    # 1. RestconfClient / RestconfTransport
    rc = RestconfTransport(ConnectionConfig(transport="restconf", host="router.local", username="admin"))
    assert rc._client.verify_ssl is True

    # 2. RedfishTransport
    rf = RedfishTransport(ConnectionConfig(transport="redfish", host="bmc.local", username="root"))
    assert rf._verify is True

    # 3. GnmiTransport (при tls=True verify_mode == CERT_REQUIRED по умолчанию)
    gnmi = GnmiTransport(ConnectionConfig(transport="gnmi", host="spine.local", options={"tls": True}))
    assert gnmi._insecure is False
    ssl_ctx = gnmi._build_ssl_context()
    assert ssl_ctx is not None and ssl_ctx.verify_mode.name == "CERT_REQUIRED"

    # 4. QgaTransport (SshUnixSocketChannel получает known_hosts=() вместо None)
    qga = QgaTransport(ConnectionConfig(transport="qga", host="10.0.0.50", username="root", port=22))
    chan = qga._build_channel()
    assert chan.known_hosts == ()

    # 5. NetconfTransport передает known_hosts=() в asyncssh.connect по умолчанию
    fake_ssh_conn = MagicMock()
    fake_ssh_conn.close = MagicMock()
    fake_ssh_conn.wait_closed = AsyncMock()
    fake_proc = MagicMock()
    fake_proc.stdin = MagicMock()
    fake_proc.stdout = MagicMock()
    fake_proc.stdout.read = AsyncMock(
        return_value=b'<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><session-id>1</session-id></hello>]]>]]>'
    )
    fake_ssh_conn.create_process = AsyncMock(return_value=fake_proc)

    with patch("uniconn.transports.network.netconf.asyncssh.connect", new_callable=AsyncMock) as mock_connect:
        mock_connect.return_value = fake_ssh_conn
        nc = NetconfTransport(ConnectionConfig(transport="netconf", host="10.0.0.99", username="admin"))
        await nc.connect()
        try:
            assert mock_connect.await_args is not None
            assert mock_connect.await_args.kwargs["known_hosts"] == ()
        finally:
            await nc.disconnect()


@pytest.mark.asyncio
async def test_background_session_uses_private_0700_dir_and_symlink_checks() -> None:
    """BackgroundSession и CleanupManager используют 0700-директорию, umask 077 и проверки [ ! -L ]."""
    conn = MagicMock()

    async def _fake_run(cmd: str, **kwargs: object) -> Result:
        if "kill -0" in cmd or "tmux has-session" in cmd or "screen -ls" in cmd:
            return Result(exit_code=1, stdout="", stderr="", duration=0.01, command=cmd)
        return Result(exit_code=0, stdout="", stderr="", duration=0.01, command=cmd)

    conn.run = AsyncMock(side_effect=_fake_run)
    mgr = BackgroundCleanupManager("secpool")
    rt_dir = await mgr.ensure_posix_runtime_dir(conn)
    assert rt_dir == "/tmp/uniconn_secpool"
    first_cmd = conn.run.await_args_list[0].args[0]
    assert "umask 077;" in first_cmd
    assert "[ ! -L" in first_cmd
    assert "chmod 0700" in first_cmd

    session = BackgroundSession(conn, "job1", "/tmp/job1.log", backend="nohup")
    await session.create("sleep 1")
    write_cmd = next(c.args[0] for c in conn.run.call_args_list if "printf '%s'" in c.args[0])
    assert "[ ! -L" in write_cmd
    assert "chmod 0700" in write_cmd


@pytest.mark.asyncio
async def test_hitl_key_isolation_and_unmasked_tampering_detection(tmp_path: Path) -> None:
    """Секрет HMAC изолирован в _uniconn_meta SQLite WAL (0600), а подмена замаскированного пароля блокируется."""
    import sqlite3

    store_file = tmp_path / "state.db"
    mgr = ApprovalManager(store_path=store_file)
    mgr2: ApprovalManager | None = None
    try:
        cmd_a = "mysql -u root --password=SecretAlpha -e 'FLUSH PRIVILEGES'"
        cmd_b = "mysql -u root --password=SecretBravo -e 'FLUSH PRIVILEGES'"

        req = await mgr.create_request(
            target_host="prod-db",
            tool_name="uniconn_run",
            risk_tier=ActionRiskTier.TIER_1_MUTATING,
            command=cmd_a,
            parameters={"command": cmd_a},
            diff="--- old\n+++ new_a\n",
        )
        assert store_file.is_file()
        if sys.platform != "win32":
            assert stat.S_IMODE(store_file.stat().st_mode) == 0o600

        with sqlite3.connect(str(store_file)) as conn:
            rows = conn.execute(
                "SELECT value_json FROM state_entries WHERE namespace = 'hitl_approvals'"
            ).fetchall()
            assert len(rows) == 1
            payload_text = str(rows[0][0])
            assert "hmac_secret" not in payload_text
            assert "SecretAlpha" not in payload_text

        # Независимый инстанс без передачи secret читает ключ из _uniconn_meta в SQLite WAL
        mgr2 = ApprovalManager(store_path=store_file)
        await mgr2.approve(req.approval_id, decided_by="sec-admin")

        # Попытка переиграть одобрение с другим паролем (маска идентична!) должна быть отклонена
        with pytest.raises(ApprovalTamperingError):
            await mgr2.verify_and_consume(
                req.approval_id,
                target_host="prod-db",
                tool_name="uniconn_run",
                command=cmd_b,
                parameters={"command": cmd_b},
                diff="--- old\n+++ new_a\n",
            )

        # Попытка подменить diff отклоняется
        with pytest.raises(ApprovalTamperingError):
            await mgr2.verify_and_consume(
                req.approval_id,
                target_host="prod-db",
                tool_name="uniconn_run",
                command=cmd_a,
                parameters={"command": cmd_a},
                diff="--- old\n+++ tampered\n",
            )
    finally:
        await mgr.close()
        if mgr2 is not None:
            await mgr2.close()


def test_session_pool_and_connection_pool_sanitize_uris_and_disambiguate_keys() -> None:
    """SSHSessionPool.stats() и ключи ConnectionPool не содержат секретов и различают дублирующиеся local://."""
    spool = SSHSessionPool("ssh://deploy:UltraSecretPw@10.20.30.40:2222?passphrase=KeySecret")
    stats = spool.stats()
    assert "UltraSecretPw" not in stats["uri"]
    assert "KeySecret" not in stats["uri"]

    cpool = ConnectionPool(
        [
            "local://",
            "local://",
            "ssh://ops:RawPass123@10.0.0.1?token=RawTok999",
        ],
        circuit_breaker=True,
    )
    assert cpool._target_keys[0] == "local://#1"
    assert cpool._target_keys[1] == "local://#2"
    assert cpool._target_keys[2] == "ssh://ops@10.0.0.1"
    for key in cpool.circuit_breakers:
        assert "RawPass123" not in key
        assert "RawTok999" not in key
