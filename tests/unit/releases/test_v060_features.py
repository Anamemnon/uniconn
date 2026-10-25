# tests/unit/test_v060_features.py
"""Unit-тесты возможностей v0.6.0: ProxyCommand, hooks, SSHSessionPool health_check и CLI."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from uniconn import (
    Connection,
    ConnectionConfig,
    MetricsCollector,
    Result,
    SSHSessionPool,
    allowlist_hook,
    audit_log_hook,
    blocklist_hook,
    cli,
    metrics_collector_hook,
)
from uniconn.cli import CliRunner
from uniconn.transports._ssh import SSHTransport


class TestSSHProxyCommand:
    """Тесты ProxyCommand и SOCKS5/HTTP прокси в SSHTransport (§24)."""

    def test_expand_proxy_command_tokens(self):
        """Токены %h, %p, %r и %% корректно подставляются в строку ProxyCommand."""
        expanded = SSHTransport.expand_proxy_command(
            "nc -X 5 -x 127.0.0.1:1080 %h %p --user=%r --literal=%%h",
            host="10.20.30.40",
            port=2222,
            username="deploy",
        )
        assert expanded == (
            "nc -X 5 -x 127.0.0.1:1080 10.20.30.40 2222 --user=deploy --literal=%h"
        )

    def test_parse_openssh_config_proxycommand(self, tmp_path: Path):
        """parse_openssh_config извлекает ProxyCommand для подходящего хоста."""
        cfg_file = tmp_path / "ssh_config"
        cfg_file.write_text(
            "Host corp-*\n"
            "    HostName 10.10.0.5\n"
            "    User root\n"
            "    Port 2202\n"
            "    ProxyCommand nc -X connect -x proxy.corp:8080 %h %p\n",
            encoding="utf-8",
        )
        parsed = SSHTransport.parse_openssh_config(cfg_file, "corp-web1")
        assert parsed["hostname"] == "10.10.0.5"
        assert parsed["user"] == "root"
        assert parsed["port"] == 2202
        assert parsed["proxycommand"] == "nc -X connect -x proxy.corp:8080 %h %p"

    @pytest.mark.asyncio
    async def test_connect_with_proxy_command_option_and_disconnect_cleanup(self):
        """SSHTransport запускает процесс proxy_command, передаёт его в tunnel и закрывает."""
        mock_asyncssh = MagicMock()
        mock_conn = MagicMock()
        mock_conn.close = MagicMock()
        mock_conn.wait_closed = AsyncMock()
        mock_asyncssh.connect = AsyncMock(return_value=mock_conn)

        fake_proxy_proc = MagicMock()
        fake_proxy_proc.terminate = MagicMock()
        fake_proxy_proc.wait = AsyncMock()

        cfg = ConnectionConfig(
            transport="ssh",
            host="target.internal",
            port=2222,
            username="ops",
            options={"proxy_command": "nc -X 5 -x socks.local:1080 %h %p"},
        )
        with (
            patch("uniconn.transports._ssh.asyncssh", mock_asyncssh),
            patch(
                "asyncio.create_subprocess_shell",
                new=AsyncMock(return_value=fake_proxy_proc),
            ) as mock_subproc,
        ):
            transport = SSHTransport(cfg)
            await transport.connect()

            assert transport._active_proxy_command == (
                "nc -X 5 -x socks.local:1080 target.internal 2222"
            )
            mock_subproc.assert_awaited_once()
            connect_kwargs = mock_asyncssh.connect.await_args.kwargs
            assert connect_kwargs["tunnel"] is fake_proxy_proc

            await transport.disconnect()
            fake_proxy_proc.terminate.assert_called_once()
            fake_proxy_proc.wait.assert_awaited_once()
            assert transport._active_proxy_command is None

    @pytest.mark.asyncio
    async def test_connect_with_ssh_config_proxycommand(self, tmp_path: Path):
        """Директива ProxyCommand из ssh_config автоматически запускается при connect()."""
        cfg_file = tmp_path / "config"
        cfg_file.write_text(
            "Host prod-db\n"
            "    HostName 192.168.50.10\n"
            "    User postgres\n"
            "    Port 2222\n"
            "    ProxyCommand socat - SOCKS4A:127.0.0.1:%h:%p,socksport=9050\n",
            encoding="utf-8",
        )
        mock_asyncssh = MagicMock()
        mock_conn = MagicMock()
        mock_conn.close = MagicMock()
        mock_conn.wait_closed = AsyncMock()
        mock_asyncssh.connect = AsyncMock(return_value=mock_conn)

        fake_proxy_proc = MagicMock()
        fake_proxy_proc.terminate = MagicMock()
        fake_proxy_proc.wait = AsyncMock()

        cfg = ConnectionConfig(
            transport="ssh",
            host="prod-db",
            ssh_config=str(cfg_file),
        )
        with (
            patch("uniconn.transports._ssh.asyncssh", mock_asyncssh),
            patch(
                "asyncio.create_subprocess_shell",
                new=AsyncMock(return_value=fake_proxy_proc),
            ) as mock_subproc,
        ):
            transport = SSHTransport(cfg)
            await transport.connect()

            assert transport._active_proxy_command == (
                "socat - SOCKS4A:127.0.0.1:192.168.50.10:2222,socksport=9050"
            )
            mock_subproc.assert_awaited_once()
            await transport.disconnect()


class TestBuiltinHooks:
    """Тесты готовых пресетов хуков (uniconn.hooks)."""

    @pytest.mark.asyncio
    async def test_audit_log_hook_writes_jsonl_and_masks_sensitive(self, tmp_path: Path):
        """audit_log_hook записывает JSONL и маскирует sensitive=True."""
        audit_file = tmp_path / "logs" / "audit.jsonl"
        async with Connection.from_uri("local://") as conn:
            conn.add_hook(
                "after_run",
                audit_log_hook(audit_file, include_output=True),
            )
            await conn.run("echo public_value")
            await conn.run("echo super_secret_token", sensitive=True)

        lines = audit_file.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 2

        entry1 = json.loads(lines[0])
        assert entry1["command"] == "echo public_value"
        assert entry1["ok"] is True
        assert entry1["sensitive"] is False
        assert entry1["stdout"].strip() == "public_value"

        entry2 = json.loads(lines[1])
        assert entry2["command"] == "***REDACTED***"
        assert entry2["sensitive"] is True
        assert entry2["stdout"] == "***REDACTED***"
        assert entry2["stderr"] == "***REDACTED***"

    @pytest.mark.asyncio
    async def test_audit_log_hook_masks_secrets_when_enabled(self, tmp_path: Path):
        """audit_log_hook маскирует токены и пароли при mask_secrets=True даже если sensitive=False."""
        audit_file = tmp_path / "logs" / "audit_masked.jsonl"
        async with Connection.from_uri("local://") as conn:
            conn.add_hook(
                "after_run",
                audit_log_hook(audit_file, include_output=True, mask_secrets=True),
            )
            await conn.run("echo token=ghp_super_secret_123 password=my_db_pass")

        lines = audit_file.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["sensitive"] is False
        assert "token=***" in entry["command"]
        assert "password=***" in entry["command"]
        assert "ghp_super_secret_123" not in entry["command"]
        assert "my_db_pass" not in entry["command"]
        assert "token=***" in entry["stdout"]
        assert "password=***" in entry["stdout"]

    @pytest.mark.asyncio
    async def test_audit_log_hook_does_not_mask_secrets_when_disabled(self, tmp_path: Path):
        """audit_log_hook сохраняет токены без изменений при mask_secrets=False (обратная совместимость)."""
        audit_file = tmp_path / "logs" / "audit_unmasked.jsonl"
        async with Connection.from_uri("local://") as conn:
            conn.add_hook(
                "after_run",
                audit_log_hook(audit_file, include_output=True, mask_secrets=False),
            )
            await conn.run("echo token=public_token_sample")

        lines = audit_file.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["sensitive"] is False
        assert "token=public_token_sample" in entry["command"]
        assert "public_token_sample" in entry["stdout"]

    @pytest.mark.asyncio
    async def test_allowlist_hook_permits_and_blocks(self):
        """allowlist_hook разрешает команды из белого списка и блокирует остальные."""
        async with Connection.from_uri("local://") as conn:
            conn.add_hook("before_run", allowlist_hook(["echo", "uname -s"]))

            res = await conn.run("echo allowed")
            assert res.text == "allowed"

            with pytest.raises(PermissionError, match="not permitted by allowlist"):
                await conn.run("whoami")

    @pytest.mark.asyncio
    async def test_blocklist_hook_blocks_destructive_commands(self):
        """blocklist_hook блокирует опасные команды до обращения к транспорту."""
        async with Connection.from_uri("local://") as conn:
            conn.add_hook("before_run", blocklist_hook())

            res = await conn.run("echo safe")
            assert res.text == "safe"

            with pytest.raises(PermissionError, match="blocked by pattern"):
                await conn.run("rm -rf /")

            with pytest.raises(PermissionError, match="blocked by pattern"):
                await conn.run("mkfs.ext4 /dev/sda1")

    @pytest.mark.asyncio
    async def test_metrics_collector_hook_tracks_runs_and_errors(self):
        """metrics_collector_hook собирает статистику успешных, неуспешных и ошибочных вызовов."""
        metrics = metrics_collector_hook()
        assert isinstance(metrics, MetricsCollector)
        assert metrics.avg_duration == 0.0

        async with Connection.from_uri("local://") as conn:
            metrics.attach(conn)
            await conn.run("echo ok")
            await conn.run("exit 2")
            with pytest.raises( Exception):
                await conn.run("exit 3", raise_on_error=True)

        summary = metrics.to_dict()
        assert summary["total_runs"] == 2
        assert summary["failed_runs"] == 1
        assert summary["errors_count"] == 1
        assert summary["avg_duration"] >= 0.0
        assert "localhost" in summary["by_host"]
        assert summary["by_host"]["localhost"]["runs"] == 2
        assert summary["by_host"]["localhost"]["failed"] == 1
        assert summary["by_host"]["localhost"]["errors"] == 1

        metrics.reset()
        assert metrics.total_runs == 0
        assert metrics.by_host == {}

    def test_result_to_dict_and_sensitive_masking(self):
        """Result.to_dict() возвращает сериализуемый словарь и маскирует секреты."""
        res = Result(
            exit_code=0,
            stdout="visible",
            stderr="",
            duration=0.123,
            command="echo visible",
            host="node1",
        )
        d = res.to_dict()
        assert d["ok"] is True
        assert d["stdout"] == "visible"
        assert d["command"] == "echo visible"

        sec_res = Result(
            exit_code=0,
            stdout="secret_key",
            stderr="secret_err",
            duration=0.1,
            command="cat /etc/secret",
            host="node1",
            sensitive=True,
        )
        sec_d = sec_res.to_dict()
        assert sec_d["stdout"] == "***REDACTED***"
        assert sec_d["stderr"] == "***REDACTED***"
        assert sec_d["command"] == "***REDACTED***"


class TestSSHSessionPoolHealthCheck:
    """Тесты проверки живости соединений в SSHSessionPool."""

    @pytest.mark.asyncio
    async def test_check_health_evicts_dead_connections(self):
        """check_health() закрывает и удаляет мёртвые соединения из пула."""
        pool = SSHSessionPool("ssh://user@host")

        alive_conn = AsyncMock()
        alive_conn.is_alive = AsyncMock(return_value=True)
        alive_conn.close = AsyncMock()

        dead_conn = AsyncMock()
        dead_conn.is_alive = AsyncMock(return_value=False)
        dead_conn.close = AsyncMock()

        import asyncio

        pool._connections = [alive_conn, dead_conn]
        pool._semaphores = [asyncio.Semaphore(2), asyncio.Semaphore(2)]

        remaining = await pool.check_health(timeout=2.0)
        assert remaining == 1
        assert pool._connections == [alive_conn]
        dead_conn.close.assert_awaited_once()
        alive_conn.close.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_health_check_flag_closes_dead_connection_before_run(self):
        """При health_check=True мёртвое соединение закрывается перед выполнением run()."""
        conn = AsyncMock()
        conn._transport = MagicMock(is_connected=True)
        conn.is_alive = AsyncMock(return_value=False)
        conn.close = AsyncMock()
        conn.run = AsyncMock(
            return_value=Result(
                exit_code=0,
                stdout="reconnected",
                stderr="",
                duration=0.1,
                command="uptime",
                host="host",
            )
        )

        with patch("uniconn._session_pool.Connection.from_uri", return_value=conn):
            pool = SSHSessionPool("ssh://user@host", health_check=True)
            res = await pool.run("uptime")

        assert res.text == "reconnected"
        conn.is_alive.assert_awaited_once()
        conn.close.assert_awaited_once()
        conn.run.assert_awaited_once()


def _get_cli_app(monkeypatch=None):
    _ = monkeypatch
    return cli.create_cli_app()


class TestCLIV060:
    """Тесты новых команд и флагов CLI в v0.6.0."""

    def test_cli_run_json_and_sudo(self, monkeypatch):
        """uniconn run поддерживает --format json и --sudo."""
        app = _get_cli_app(monkeypatch)
        runner = CliRunner()

        res = runner.invoke(
            app,
            ["run", "local://", "echo hello_cli_json", "--format", "json"],
        )
        assert res.exit_code == 0, res.output
        data = json.loads(res.output)
        assert data["exit_code"] == 0
        assert data["stdout"].strip() == "hello_cli_json"

    def test_cli_run_multi_with_inventory_and_group(self, monkeypatch, tmp_path: Path):
        """uniconn run-multi работает с --inventory и --group и возвращает JSON."""
        inv_file = tmp_path / "hosts.yaml"
        inv_file.write_text(
            "hosts:\n"
            "  local1:\n"
            "    uri: local://\n"
            "    groups: [local_group]\n"
            "  local2:\n"
            "    uri: local://\n"
            "    groups: [other_group]\n",
            encoding="utf-8",
        )
        app = _get_cli_app(monkeypatch)
        runner = CliRunner()

        res = runner.invoke(
            app,
            [
                "run-multi",
                "--inventory",
                str(inv_file),
                "--group",
                "local_group",
                "-c",
                "echo inv_ok",
                "--format",
                "json",
            ],
        )
        assert res.exit_code == 0, res.output
        parsed = json.loads(res.output)
        assert len(parsed) == 1
        assert parsed[0]["stdout"].strip() == "inv_ok"

    def test_cli_upload_and_download_commands(self, monkeypatch):
        """Команды uniconn upload и uniconn download вызывают методы ConnectionPool."""
        app = _get_cli_app(monkeypatch)
        runner = CliRunner()

        mock_pool = MagicMock()
        mock_pool._uris = ["ssh://node1", "ssh://node2"]
        mock_pool._target_key = lambda x: str(x)
        mock_pool.upload = AsyncMock(return_value=None)
        mock_pool.download = AsyncMock(
            return_value={
                "ssh://node1": "/tmp/node1.log",
                "ssh://node2": "/tmp/node2.log",
            }
        )

        with patch("uniconn.cli.ConnectionPool", return_value=mock_pool):
            up_res = runner.invoke(
                app,
                [
                    "upload",
                    "./local.txt",
                    "/remote.txt",
                    "ssh://node1",
                    "ssh://node2",
                    "--format",
                    "json",
                ],
            )
            assert up_res.exit_code == 0, up_res.output
            up_json = json.loads(up_res.output)
            assert up_json["action"] == "upload"
            assert up_json["ok"] is True
            mock_pool.upload.assert_awaited_once_with(
                "./local.txt", "/remote.txt", recurse=False
            )

            down_res = runner.invoke(
                app,
                [
                    "download",
                    "/var/log/syslog",
                    "/tmp/{host}.log",
                    "ssh://node1",
                    "ssh://node2",
                    "--format",
                    "json",
                ],
            )
            assert down_res.exit_code == 0, down_res.output
            down_json = json.loads(down_res.output)
            assert down_json["action"] == "download"
            assert down_json["saved"]["ssh://node1"] == "/tmp/node1.log"

    def test_cli_bmc_and_screen_status_json_format(self, monkeypatch):
        """Команды bmc и screen-status поддерживают --format json."""
        app = _get_cli_app(monkeypatch)
        runner = CliRunner()

        conn = MagicMock()
        conn.run = AsyncMock(
            return_value=Result(
                exit_code=0,
                stdout="\t1234.uniconn_pool1_0\t(Detached)\n",
                stderr="",
                duration=0.1,
                command="screen -ls",
                timestamp=datetime.now(),
                host="server",
            )
        )
        conn_cm = MagicMock()
        conn_cm.__aenter__ = AsyncMock(return_value=conn)
        conn_cm.__aexit__ = AsyncMock(return_value=False)

        conn_cls = MagicMock()
        conn_cls.from_uri.return_value = conn_cm

        with patch("uniconn.cli.Connection", conn_cls):
            res_status = runner.invoke(
                app,
                ["screen-status", "ssh://user@host", "--format", "json"],
            )
            assert res_status.exit_code == 0, res_status.output
            status_data = json.loads(res_status.output)
            assert status_data == [
                {"session_id": "uniconn_pool1_0", "pid": "1234", "status": "Detached"}
            ]

            res_bmc = runner.invoke(
                app,
                ["bmc", "ipmi://admin:pass@bmc", "power status", "--format", "json"],
            )
            assert res_bmc.exit_code == 0, res_bmc.output
            bmc_data = json.loads(res_bmc.output)
            assert bmc_data["exit_code"] == 0
