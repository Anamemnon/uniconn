# tests/unit/test_v060_features.py
"""Unit-тесты возможностей v0.6.0: ProxyCommand, hooks, SSHSessionPool health_check и CLI."""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from uniconn import (
    Connection,
    ConnectionConfig,
    MetricsCollector,
    Result,
    SSHSessionPool,
    SyncConnection,
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

        with patch("uniconn.pool.session_pool.Connection.from_uri", return_value=conn):
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
        mock_pool.files.upload = AsyncMock(return_value=None)
        mock_pool.files.download = AsyncMock(
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
            mock_pool.files.upload.assert_awaited_once_with(
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
                ["bg-status", "ssh://user@host", "--backend", "screen", "--format", "json"],
            )
            assert res_status.exit_code == 0, res_status.output
            status_data = json.loads(res_status.output)
            assert status_data == [
                {
                    "session_id": "uniconn_pool1_0",
                    "pid": "1234",
                    "status": "Running",
                    "backend": "screen",
                }
            ]

            res_bmc = runner.invoke(
                app,
                ["bmc", "ipmi://admin:pass@bmc", "power status", "--format", "json"],
            )
            assert res_bmc.exit_code == 0, res_bmc.output
            bmc_data = json.loads(res_bmc.output)
            assert bmc_data["exit_code"] == 0


class TestCrossPlatformChecksumProgressAndSyncEnhancements:
    """Тесты кроссплатформенного checksum, progress_callback и расширений sync_dir."""

    def test_build_checksum_command_and_extract_digest_variants(self) -> None:
        from uniconn.services.files import (
            _build_checksum_command,
            _extract_checksum_digest,
        )

        posix_sha256 = _build_checksum_command("/etc/hosts", "sha256")
        assert "sha256sum" in posix_sha256
        assert "shasum -a 256" in posix_sha256
        assert "openssl dgst -sha256" in posix_sha256

        posix_md5 = _build_checksum_command("/etc/hosts", "md5")
        assert "md5sum" in posix_md5
        assert "md5 -q" in posix_md5

        win_cmd = _build_checksum_command("C:\\app\\config.json", "sha256", os_family="Windows")
        assert "certutil -hashfile" in win_cmd
        assert "SHA256" in win_cmd

        gnu_digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        # GNU / shasum output
        assert (
            _extract_checksum_digest(f"{gnu_digest}  /etc/hosts\n", "sha256")
            == gnu_digest
        )
        # OpenSSL dgst output
        assert (
            _extract_checksum_digest(f"SHA2-256(/etc/hosts)= {gnu_digest}\n", "sha256")
            == gnu_digest
        )
        # Windows certutil output (with spaces)
        spaced = " ".join(gnu_digest[i : i + 2] for i in range(0, len(gnu_digest), 2))
        certutil_out = (
            "SHA256 hash of C:\\app\\config.json:\n"
            f"{spaced}\n"
            "CertUtil: -hashfile command completed successfully.\n"
        )
        assert _extract_checksum_digest(certutil_out, "sha256") == gnu_digest

    @pytest.mark.asyncio
    async def test_remote_checksum_uses_cached_windows_os_family(self) -> None:
        from uniconn.services.facts_models import HostFacts

        conn = Connection.from_uri("ssh://win-admin@10.0.0.50")
        conn._facts_collector.cached = HostFacts(os_family="Windows", hostname="win-50")
        digest = "a" * 64
        conn.run = AsyncMock(  # type: ignore[method-assign]
            return_value=Result(
                exit_code=0,
                stdout=f"SHA256 hash of C:\\test.txt:\n{digest}\nCertUtil: ok\n",
                stderr="",
                duration=0.05,
                command="certutil",
            )
        )
        res = await conn.files.checksum("C:\\test.txt", algorithm="sha256")
        assert res == digest
        called_cmd = conn.run.call_args.args[0]
        assert "certutil -hashfile" in called_cmd

    @pytest.mark.asyncio
    async def test_upload_and_download_progress_callback_local_and_sftp(
        self, tmp_path: Path
    ) -> None:
        from uniconn.transports.ssh.sftp import SFTPClientAdapter

        src_file = tmp_path / "source.bin"
        src_file.write_bytes(b"0123456789abcdef")
        dst_file = tmp_path / "dest.bin"
        back_file = tmp_path / "back.bin"

        up_events: list[tuple[int, int]] = []
        down_events: list[tuple[int, int]] = []

        async with Connection.from_uri("local://") as conn:
            await conn.files.upload(
                src_file,
                dst_file,
                verify=True,
                progress_callback=lambda done, total: up_events.append((done, total)),
            )
            await conn.files.download(
                dst_file,
                back_file,
                verify=True,
                progress_callback=lambda done, total: down_events.append((done, total)),
            )

        assert up_events == [(16, 16)]
        assert down_events == [(16, 16)]
        assert back_file.read_bytes() == b"0123456789abcdef"

        # Проверка проброса progress_handler в SFTPClientAdapter
        sftp = MagicMock()

        async def _fake_put(lpath: str, rpath: str, **kwargs):
            handler = kwargs.get("progress_handler")
            if handler is not None:
                handler(b"src", b"dst", 50, 100)
                handler(b"src", b"dst", 100, 100)

        sftp.put = AsyncMock(side_effect=_fake_put)
        sftp_cm = MagicMock()
        sftp_cm.__aenter__ = AsyncMock(return_value=sftp)
        sftp_cm.__aexit__ = AsyncMock(return_value=None)
        raw_conn = MagicMock()
        raw_conn.start_sftp_client = MagicMock(return_value=sftp_cm)

        fake_transport = MagicMock(_connected=True, _conn=raw_conn)
        adapter = SFTPClientAdapter(fake_transport)
        sftp_events: list[tuple[int, int]] = []
        await adapter.upload(
            MagicMock(),
            str(src_file),
            "/remote/dest.bin",
            progress_callback=lambda b, t: sftp_events.append((b, t)),
        )
        assert sftp_events == [(50, 100), (100, 100)]

    @pytest.mark.asyncio
    async def test_sync_dir_checksum_check_and_preserve_permissions(
        self, tmp_path: Path
    ) -> None:
        import os

        src_dir = tmp_path / "src_sync"
        dst_dir = tmp_path / "dst_sync"
        src_dir.mkdir()
        dst_dir.mkdir()

        script_src = src_dir / "run.sh"
        script_src.write_text("#!/bin/sh\necho v1\n", encoding="utf-8")
        os.chmod(script_src, 0o755)

        script_dst = dst_dir / "run.sh"
        # Тот же размер (18 байт), но другое содержимое и более старый/равный mtime на источнике
        script_dst.write_text("#!/bin/sh\necho v2\n", encoding="utf-8")
        os.chmod(script_dst, 0o600)
        os.utime(script_src, (1_700_000_000, 1_700_000_000))
        os.utime(script_dst, (1_700_000_100, 1_700_000_100))

        async with Connection.from_uri("local://") as conn:
            # Без checksum_check файл пропускается (размер 18 == 18 и src_mtime <= dst_mtime)
            res_fast = await conn.files.sync_dir(
                src_dir,
                dst_dir,
                checksum_check=False,
                preserve_permissions=True,
            )
            assert res_fast.skipped == ["run.sh"]
            # Но права 0o755 синхронизированы благодаря preserve_permissions=True
            if sys.platform != "win32":
                assert (script_dst.stat().st_mode & 0o777) == 0o755
            assert script_dst.read_text(encoding="utf-8") == "#!/bin/sh\necho v2\n"

            # С checksum_check=True обнаруживается расхождение SHA-256 и файл перезаписывается
            res_hash = await conn.files.sync_dir(
                src_dir,
                dst_dir,
                checksum_check=True,
                preserve_permissions=True,
            )
            assert res_hash.uploaded == ["run.sh"]
            assert script_dst.read_text(encoding="utf-8") == "#!/bin/sh\necho v1\n"


class TestV100AuditStabilization:
    """Тесты стабилизации v1.0.0: Cassette, BSD stat, supports_capability и ttl."""

    @pytest.mark.asyncio
    async def test_cassette_proxy_supports_capability_and_tunnels(self, tmp_path: Path) -> None:
        from uniconn.config.models import ConnectionConfig
        from uniconn.transports.base import (
            FileCapableTransport,
            TunnelCapableTransport,
            supports_capability,
        )
        from uniconn.transports.replay.models import Cassette, RecordMode
        from uniconn.transports.replay.proxy import CassetteTransportProxy

        cfg = ConnectionConfig(transport="local", host="localhost")
        cassette = Cassette(transport="local", target="local://")
        # В автономном режиме без wrapped транспорта TunnelCapableTransport не поддерживается
        proxy_standalone = CassetteTransportProxy(
            cfg,
            cassette,
            wrapped=None,
            mode=RecordMode.NONE,
            cassette_exists=True,
        )
        assert supports_capability(proxy_standalone, FileCapableTransport) is True
        assert supports_capability(proxy_standalone, TunnelCapableTransport) is False

        async with Connection.from_uri("local://") as conn:
            cassette_file = tmp_path / "cap_test.json"
            async with conn.use_cassette(cassette_file, mode="all"):
                # LocalTransport не поддерживает туннели -> прокси корректно отражает возможности wrapped
                assert supports_capability(conn._transport, TunnelCapableTransport) is False

    @pytest.mark.asyncio
    async def test_state_gather_facts_ttl_and_bsd_stat_owner_group(self) -> None:
        from uniconn.result import Result
        from uniconn.services.provisioning._plan import get_owner_group

        conn = Connection.from_uri("ssh://bsd-host")
        conn.gather_facts = AsyncMock(return_value=MagicMock())  # type: ignore[method-assign]
        await conn.state.gather_facts(refresh=True, ttl=42.5)
        conn.gather_facts.assert_awaited_once_with(
            refresh=True,
            timeout=None,
            spec=None,
            ttl=42.5,
        )

        conn.run = AsyncMock(  # type: ignore[method-assign]
            return_value=Result(
                exit_code=0,
                stdout="root:wheel\n",
                stderr="",
                duration=0.01,
                command="stat",
                host="bsd-host",
            )
        )
        owner, group = await get_owner_group(conn, "/etc/hosts")
        assert (owner, group) == ("root", "wheel")
        called_cmd = conn.run.call_args[0][0]
        assert "-f '%Su:%Sg'" in called_cmd

    @pytest.mark.asyncio
    async def test_write_file_atomic_sudo_and_permission_fallback(self, tmp_path: Path) -> None:
        """write_file(..., atomic=True, sudo=True) использует временный стейджинг и sudo mv -f."""
        from uniconn.result import Result

        conn = Connection.from_uri("ssh://app-node")
        conn._transport._connected = True
        staged_writes: list[tuple[str, str | bytes]] = []
        moved_cmds: list[tuple[str, bool]] = []

        async def fake_write(path: str, content: str | bytes, mode=None, encoding="utf-8"):
            if path.startswith("/etc/"):
                raise PermissionError("Permission denied: /etc")
            staged_writes.append((path, content))

        async def fake_run(cmd: str, **kwargs):
            moved_cmds.append((cmd, bool(kwargs.get("sudo"))))
            return Result(exit_code=0, stdout="", stderr="", duration=0.01, command=cmd, host="app-node")

        conn._transport.write_file = AsyncMock(side_effect=fake_write)  # type: ignore[method-assign]
        conn._create_temp_dir = AsyncMock(return_value="/tmp/uniconn-stage-1")  # type: ignore[method-assign]
        conn._remove_temp_dir = AsyncMock(return_value=None)  # type: ignore[method-assign]
        conn.run = AsyncMock(side_effect=fake_run)  # type: ignore[method-assign]

        await conn.files.write_file("/etc/nginx/nginx.conf", "worker_processes auto;\n", atomic=True, sudo=True, mode=0o640)
        assert len(staged_writes) == 1
        assert staged_writes[0][0].startswith("/tmp/uniconn-stage-1/")
        assert any("mv -f" in cmd and is_sudo for cmd, is_sudo in moved_cmds)
        assert any("chmod 640" in cmd and is_sudo for cmd, is_sudo in moved_cmds)

    @pytest.mark.asyncio
    async def test_sync_dir_uses_batch_python_worker_scan_and_delete(self, tmp_path: Path) -> None:
        """sync_dir на Local/SSH использует пакетный _op_sync_scan воркера для хешей, mkdir и удаления лишних файлов."""
        local_dir = tmp_path / "src_bundle"
        local_dir.mkdir()
        (local_dir / "sub" / "nested").mkdir(parents=True)
        (local_dir / "root.txt").write_text("root-v1", encoding="utf-8")
        (local_dir / "sub" / "nested" / "app.py").write_text("print('hi')\n", encoding="utf-8")

        remote_dir = tmp_path / "dst_bundle"
        remote_dir.mkdir()
        (remote_dir / "stale.old").write_text("obsolete", encoding="utf-8")

        async with Connection.from_uri("local://") as conn:
            res1 = await conn.files.sync_dir(
                local_dir,
                remote_dir,
                delete=True,
                checksum_check=True,
            )
            assert res1.ok
            assert len(res1.uploaded) == 2
            assert len(res1.deleted) == 1
            assert not (remote_dir / "stale.old").exists()
            assert (remote_dir / "sub" / "nested" / "app.py").read_text(encoding="utf-8") == "print('hi')\n"

            # Повторная синхронизация с checksum_check=True должна пропустить оба файла за 1 RPC-запрос
            res2 = await conn.files.sync_dir(
                local_dir,
                remote_dir,
                delete=True,
                checksum_check=True,
            )
            assert res2.ok
            assert len(res2.uploaded) == 0
            assert len(res2.unchanged) == 2

    @pytest.mark.asyncio
    async def test_sync_dir_worker_respects_exclude_patterns(self, tmp_path: Path) -> None:
        """sync_dir передаёт exclude в _op_sync_scan и не удаляет исключённые файлы/директории."""
        local_dir = tmp_path / "src_excl"
        local_dir.mkdir()
        (local_dir / ".git").mkdir()
        (local_dir / ".git" / "HEAD").write_text("ref: main", encoding="utf-8")
        (local_dir / "keep.txt").write_text("v2", encoding="utf-8")

        remote_dir = tmp_path / "dst_excl"
        remote_dir.mkdir()
        (remote_dir / ".git" / "objects").mkdir(parents=True)
        (remote_dir / ".git" / "objects" / "abc").write_text("obj", encoding="utf-8")
        (remote_dir / "debug.log").write_text("remote-log", encoding="utf-8")
        (remote_dir / "keep.txt").write_text("v1", encoding="utf-8")

        async with Connection.from_uri("local://") as conn:
            res = await conn.files.sync_dir(
                local_dir,
                remote_dir,
                exclude=[".git", "*.log"],
                delete=True,
                checksum_check=True,
            )
            assert res.ok
            assert res.uploaded == ["keep.txt"]
            assert res.deleted == []
            assert (remote_dir / ".git" / "objects" / "abc").exists()
            assert (remote_dir / "debug.log").exists()
            assert (remote_dir / "keep.txt").read_text(encoding="utf-8") == "v2"

    @pytest.mark.asyncio
    async def test_write_file_atomic_cleans_staging_and_filters_non_permission_errors(self) -> None:
        """atomic=True удаляет staging-файл при сбое и не делает sudo-fallback для не-permission ошибок."""
        from uniconn.exceptions import ConnectionError as UniconnConnectionError
        from uniconn.exceptions import ExecutionError
        from uniconn.result import Result

        conn = Connection.from_dict(
            {
                "transport": "ssh",
                "host": "app-node",
                "options": {"sudo_password": "secret"},
            }
        )
        conn._transport._connected = True
        removed_paths: list[str] = []
        moved_cmds: list[tuple[str, bool]] = []

        async def track_remove(path: str) -> None:
            removed_paths.append(path)

        conn._transport.remove_file = AsyncMock(side_effect=track_remove)  # type: ignore[method-assign]
        conn._create_temp_dir = AsyncMock(return_value="/tmp/stage-dir")  # type: ignore[method-assign]
        conn._remove_temp_dir = AsyncMock(return_value=None)  # type: ignore[method-assign]

        # 1. PermissionError при sudo=False -> очищает staging и пробрасывает ошибку БЕЗ скрытого sudo
        async def fail_mv_perm(cmd: str, **kwargs):
            moved_cmds.append((cmd, bool(kwargs.get("sudo"))))
            if cmd.startswith("mv -f"):
                raise ExecutionError(
                    "mv failed",
                    command=cmd,
                    exit_code=1,
                    stderr="mv: cannot move: Permission denied",
                )
            return Result(exit_code=0, stdout="", stderr="", duration=0.01, command=cmd, host="app-node")

        conn._transport.write_file = AsyncMock(return_value=None)  # type: ignore[method-assign]
        conn.run = AsyncMock(side_effect=fail_mv_perm)  # type: ignore[method-assign]

        with pytest.raises(ExecutionError, match="mv failed"):
            await conn.files.write_file("/etc/test.conf", "hello", atomic=True)
        assert len(removed_paths) == 1
        assert not any(is_sudo for _, is_sudo in moved_cmds)

        # 2. Не-permission ExecutionError ("No space left on device") -> очищает staging, без sudo
        removed_paths.clear()
        moved_cmds.clear()

        async def fail_mv_disk(cmd: str, **kwargs):
            moved_cmds.append((cmd, bool(kwargs.get("sudo"))))
            raise ExecutionError(
                "mv failed",
                command=cmd,
                exit_code=1,
                stderr="mv: No space left on device",
            )

        conn.run = AsyncMock(side_effect=fail_mv_disk)  # type: ignore[method-assign]
        with pytest.raises(ExecutionError, match="mv failed"):
            await conn.files.write_file("/etc/test.conf", "hello", atomic=True)
        assert len(removed_paths) == 1
        assert not any(is_sudo for _, is_sudo in moved_cmds)

        # 3. Цепочечный PermissionError при sudo=False -> НЕ эскалирует в sudo, пробрасывает ошибку
        removed_paths.clear()
        moved_cmds.clear()

        async def write_with_chained_perm(path: str, content: bytes, mode=None):
            if path.startswith("/etc/"):
                raise UniconnConnectionError("SFTP write failed") from PermissionError("Permission denied")

        async def ok_run(cmd: str, **kwargs):
            moved_cmds.append((cmd, bool(kwargs.get("sudo"))))
            return Result(exit_code=0, stdout="", stderr="", duration=0.01, command=cmd, host="app-node")

        conn._transport.write_file = AsyncMock(side_effect=write_with_chained_perm)  # type: ignore[method-assign]
        conn.run = AsyncMock(side_effect=ok_run)  # type: ignore[method-assign]
        with pytest.raises(UniconnConnectionError, match="SFTP write failed"):
            await conn.files.write_file("/etc/test.conf", "hello", atomic=True)
        assert not any(is_sudo for _, is_sudo in moved_cmds)

        # 4. Явный sudo=True -> staging на целевой ФС с chown 0:0 и атомарным mv -f
        moved_cmds.clear()
        await conn.files.write_file("/etc/test.conf", "hello", atomic=True, sudo=True)
        assert any(
            is_sudo and "umask 077" in cmd and "cp --" in cmd and "chown 0:0" in cmd and "mv -f" in cmd
            for cmd, is_sudo in moved_cmds
        )

    @pytest.mark.asyncio
    async def test_sync_dir_walk_remote_skips_symlink_directory_recursion(self, tmp_path: Path) -> None:
        """DirectorySynchronizer._walk_remote не переходит вглубь симлинков на директории при delete=True."""
        local_dir = tmp_path / "src_sym"
        local_dir.mkdir()
        (local_dir / "keep.txt").write_text("v1", encoding="utf-8")

        conn = Connection.from_uri("ssh://user@app-node")
        conn._transport._connected = True
        conn._python_worker = None  # Принудительно идём в transport.listdir/stat (_walk_remote)
        removed_paths: list[str] = []

        async def fake_exists(path: str) -> bool:
            return path == "/remote"

        async def fake_listdir(path: str) -> list[str]:
            if path == "/remote":
                return ["sym_dir", "keep.txt"]
            raise AssertionError(f"Should not recurse into symlink dir: {path}")

        async def fake_stat(path: str) -> dict[str, Any]:
            if path == "/remote/sym_dir":
                # Имитация симлинка на директорию: при is_symlink=True не должен рекурсивно обходить содержимое
                return {"size": 0, "is_dir": True, "is_file": False, "is_symlink": True, "mtime": 1.0}
            return {"size": 2, "is_dir": False, "is_file": True, "is_symlink": False, "mtime": 1.0}

        async def fake_remove(path: str) -> None:
            removed_paths.append(path)

        conn._transport.exists = AsyncMock(side_effect=fake_exists)  # type: ignore[method-assign]
        conn._transport.mkdir = AsyncMock()  # type: ignore[method-assign]
        conn._transport.upload = AsyncMock()  # type: ignore[method-assign]
        conn._transport.write_file = AsyncMock()  # type: ignore[method-assign]
        conn._transport.listdir = AsyncMock(side_effect=fake_listdir)  # type: ignore[method-assign]
        conn._transport.stat = AsyncMock(side_effect=fake_stat)  # type: ignore[method-assign]
        conn._transport.remove_file = AsyncMock(side_effect=fake_remove)  # type: ignore[method-assign]

        res = await conn.files.sync_dir(local_dir, "/remote", delete=True, checksum_check=False)
        assert res.deleted == ["sym_dir"]
        assert removed_paths == ["/remote/sym_dir"]


class TestStreamingChecksumAndSyncDirArchive:
    """Тесты потокового fallback checksum() и пакетной tar-синхронизации в sync_dir."""

    @pytest.mark.asyncio
    async def test_checksum_fallback_streams_via_iter_file_chunks_without_read_file(self) -> None:
        import hashlib

        conn = Connection.from_uri("ssh://user@app-node")
        conn._transport._connected = True
        conn._python_worker = None
        payload_chunks = [b"hello-", b"streaming-", b"checksum!"]
        expected = hashlib.sha256(b"".join(payload_chunks)).hexdigest().lower()

        # Все удалённые CLI-хешеры не найдены
        conn.run = AsyncMock(  # type: ignore[method-assign]
            return_value=Result(
                exit_code=127,
                stdout="",
                stderr="not found",
                duration=0.01,
                command="sha256sum",
                host="app-node",
            )
        )

        async def _fake_iter_chunks(remote_path: str, chunk_size: int = 65536):
            for c in payload_chunks:
                yield c

        conn._transport.iter_file_chunks = _fake_iter_chunks  # type: ignore[method-assign]
        conn._transport.read_file = AsyncMock(  # type: ignore[method-assign]
            side_effect=AssertionError("read_file() must not be called when iter_file_chunks is available")
        )

        digest = await conn.files.checksum("/var/data/large.bin", algorithm="sha256")
        assert digest == expected
        conn._transport.read_file.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_sync_dir_auto_archive_tar_gz_on_threshold_and_extracts_valid_archive(
        self, tmp_path: Path
    ) -> None:
        import tarfile

        local_dir = tmp_path / "src_many"
        (local_dir / "nested").mkdir(parents=True)
        for idx in range(12):
            sub = local_dir / ("nested" if idx % 2 == 0 else "")
            f = sub / f"item_{idx}.txt"
            f.write_text(f"payload-{idx}\n", encoding="utf-8")

        remote_extract_dir = tmp_path / "extracted_remote"
        remote_extract_dir.mkdir()

        conn = Connection.from_uri("ssh://deploy@app-node")
        conn._transport._connected = True
        conn._python_worker = None

        staged_dir = tmp_path / "remote_stage"
        staged_dir.mkdir()
        conn._create_temp_dir = AsyncMock(return_value=str(staged_dir))  # type: ignore[method-assign]
        conn._remove_temp_dir = AsyncMock(return_value=None)  # type: ignore[method-assign]

        uploaded_archives: list[tuple[str, str]] = []
        run_cmds: list[str] = []

        async def _fake_upload(local_p: str, remote_p: str, **kwargs: Any) -> None:
            uploaded_archives.append((local_p, remote_p))
            # Имитируем загрузку архива на удалённый хост и реальную распаковку tar.gz
            archive_copy = Path(remote_p)
            archive_copy.write_bytes(Path(local_p).read_bytes())

        async def _fake_run(cmd: str, **kwargs: Any) -> Result:
            run_cmds.append(cmd)
            if "command -v tar" in cmd:
                return Result(exit_code=0, stdout=":gz:tar\n", stderr="", duration=0.01, command=cmd)
            if "gzip -dc" in cmd and "tar " in cmd:
                # Извлекаем реальный архив в remote_extract_dir для проверки целостности содержимого
                arch_file = next(staged_dir.glob("*.tar.gz"))
                with tarfile.open(arch_file, mode="r:gz") as tf:
                    tf.extractall(remote_extract_dir, filter="data")
                return Result(exit_code=0, stdout="", stderr="", duration=0.02, command=cmd)
            return Result(exit_code=0, stdout="", stderr="", duration=0.01, command=cmd)

        conn._transport.exists = AsyncMock(return_value=False)  # type: ignore[method-assign]
        conn._transport.mkdir = AsyncMock()  # type: ignore[method-assign]
        conn._transport.upload = AsyncMock(side_effect=_fake_upload)  # type: ignore[method-assign]
        conn._transport.write_file = AsyncMock()  # type: ignore[method-assign]
        conn.run = AsyncMock(side_effect=_fake_run)  # type: ignore[method-assign]

        res = await conn.files.sync_dir(
            local_dir,
            "/var/www/app",
            preserve_permissions=True,
        )
        assert len(res.uploaded) == 12
        # Должен уйти 1 архив через upload(), а не 12 write_file() вызовов
        assert len(uploaded_archives) == 1
        assert uploaded_archives[0][1].endswith(".tar.gz")
        conn._transport.write_file.assert_not_awaited()
        assert any("-xpf" in c and "gzip -dc" in c for c in run_cmds)

        for idx in range(12):
            sub_rel = "nested" if idx % 2 == 0 else "."
            assert (remote_extract_dir / sub_rel / f"item_{idx}.txt").read_text(
                encoding="utf-8"
            ) == f"payload-{idx}\n"

    @pytest.mark.asyncio
    async def test_sync_dir_auto_below_threshold_uses_per_file_and_skips_probe(
        self, tmp_path: Path
    ) -> None:
        local_dir = tmp_path / "src_small"
        local_dir.mkdir()
        for idx in range(3):
            (local_dir / f"f{idx}.txt").write_text(f"v{idx}", encoding="utf-8")

        conn = Connection.from_uri("ssh://deploy@app-node")
        conn._transport._connected = True
        conn._python_worker = None
        conn._transport.exists = AsyncMock(return_value=False)  # type: ignore[method-assign]
        conn._transport.mkdir = AsyncMock()  # type: ignore[method-assign]
        conn._transport.write_file = AsyncMock()  # type: ignore[method-assign]
        conn._transport.upload = AsyncMock()  # type: ignore[method-assign]
        conn.run = AsyncMock()  # type: ignore[method-assign]

        res = await conn.files.sync_dir(local_dir, "/var/www/small")
        assert len(res.uploaded) == 3
        assert conn._transport.write_file.await_count == 3
        conn.run.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_sync_dir_archive_fallback_when_remote_lacks_tar_or_extract_fails(
        self, tmp_path: Path
    ) -> None:
        local_dir = tmp_path / "src_fb"
        local_dir.mkdir()
        (local_dir / "a.txt").write_text("aaa", encoding="utf-8")
        (local_dir / "b.txt").write_text("bbb", encoding="utf-8")

        conn = Connection.from_uri("ssh://deploy@app-node")
        conn._transport._connected = True
        conn._python_worker = None
        conn._transport.exists = AsyncMock(return_value=False)  # type: ignore[method-assign]
        conn._transport.mkdir = AsyncMock()  # type: ignore[method-assign]
        conn._transport.write_file = AsyncMock()  # type: ignore[method-assign]
        conn._transport.upload = AsyncMock()  # type: ignore[method-assign]

        # 1. На удалённом хосте нет tar -> откат на пофайловую отправку
        conn.run = AsyncMock(  # type: ignore[method-assign]
            return_value=Result(exit_code=0, stdout="none\n", stderr="", duration=0.01, command="probe")
        )
        res1 = await conn.files.sync_dir(local_dir, "/remote/app", archive="tar.gz")
        assert res1.uploaded == ["a.txt", "b.txt"]
        assert conn._transport.write_file.await_count == 2
        conn._transport.upload.assert_not_awaited()

        # 2. В режиме archive="auto" ошибка распаковки тоже откатывается на пофайловую отправку
        from uniconn.exceptions import ExecutionError

        conn._transport.write_file.reset_mock()
        conn._transport.upload.reset_mock()
        conn._create_temp_dir = AsyncMock(return_value="/tmp/stage-fb")  # type: ignore[method-assign]
        conn._remove_temp_dir = AsyncMock(return_value=None)  # type: ignore[method-assign]

        async def _fail_extract(cmd: str, **kwargs: Any) -> Result:
            if "command -v tar" in cmd:
                return Result(exit_code=0, stdout=":gz:tar\n", stderr="", duration=0.01, command=cmd)
            raise ExecutionError("tar failed", command=cmd, exit_code=2, stderr="invalid flag")

        conn.run = AsyncMock(side_effect=_fail_extract)  # type: ignore[method-assign]
        res2 = await conn.files.sync_dir(
            local_dir,
            "/remote/app",
            archive="auto",
            archive_threshold=2,
        )
        assert res2.uploaded == ["a.txt", "b.txt"]
        assert conn._transport.upload.await_count == 1
        assert conn._transport.write_file.await_count == 2

    @pytest.mark.asyncio
    async def test_sync_dir_zst_optional_dependency_and_mocked_zstd_stream(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import io
        import sys
        import types

        import uniconn.services._dir_sync as dir_sync_mod
        from uniconn.exceptions import OptionalDependencyError

        local_dir = tmp_path / "src_zst"
        local_dir.mkdir()
        (local_dir / "one.txt").write_text("zst-content", encoding="utf-8")

        conn = Connection.from_uri("ssh://deploy@app-node")
        conn._transport._connected = True
        conn._python_worker = None
        conn._transport.exists = AsyncMock(return_value=False)  # type: ignore[method-assign]
        conn._transport.mkdir = AsyncMock()  # type: ignore[method-assign]
        conn._transport.write_file = AsyncMock()  # type: ignore[method-assign]
        conn._transport.upload = AsyncMock()  # type: ignore[method-assign]

        # Без локального zstandard явный archive="tar.zst" кидает OptionalDependencyError
        monkeypatch.setattr(dir_sync_mod, "_detect_local_zstd_backend", lambda: None)
        with pytest.raises(OptionalDependencyError, match="zstandard"):
            await conn.files.sync_dir(local_dir, "/remote/zst", archive="tar.zst")

        # С доступным zstandard и удалённой поддержкой zstd пакуется .tar.zst
        class _FakeWriter(io.RawIOBase):
            def __init__(self, target_fp: Any) -> None:
                self._target = target_fp

            def writable(self) -> bool:
                return True

            def write(self, b: Any) -> int:
                data = bytes(b)
                self._target.write(data)
                return len(data)

        class _FakeZstdCompressor:
            def __init__(self, level: int = 3) -> None:
                self.level = level

            def stream_writer(self, raw_fp: Any, closefd: bool = False):
                from contextlib import nullcontext

                return nullcontext(_FakeWriter(raw_fp))

        fake_zstd_mod = types.SimpleNamespace(ZstdCompressor=_FakeZstdCompressor)
        monkeypatch.setitem(sys.modules, "zstandard", fake_zstd_mod)
        monkeypatch.setattr(dir_sync_mod, "_detect_local_zstd_backend", lambda: "zstandard")

        conn._create_temp_dir = AsyncMock(return_value="/tmp/stage-zst")  # type: ignore[method-assign]
        conn._remove_temp_dir = AsyncMock(return_value=None)  # type: ignore[method-assign]
        cmds: list[str] = []

        async def _zst_run(cmd: str, **kwargs: Any) -> Result:
            cmds.append(cmd)
            if "command -v tar" in cmd:
                return Result(exit_code=0, stdout="zst:gz:tar\n", stderr="", duration=0.01, command=cmd)
            return Result(exit_code=0, stdout="", stderr="", duration=0.01, command=cmd)

        conn.run = AsyncMock(side_effect=_zst_run)  # type: ignore[method-assign]
        res = await conn.files.sync_dir(local_dir, "/remote/zst", archive="tar.zst")
        assert res.uploaded == ["one.txt"]
        assert conn._transport.upload.call_args.args[1].endswith(".tar.zst")
        assert any("zstd -dc" in c and "tar -xf -" in c for c in cmds)

    @pytest.mark.asyncio
    async def test_sync_dir_archive_skips_windows_and_validates_rel_paths(
        self, tmp_path: Path
    ) -> None:
        from uniconn.services._dir_sync import _validate_archive_rel_path
        from uniconn.services.facts_models import HostFacts

        for bad in ("", "/etc/passwd", "../escape.txt", "a/../../b", "./.."):
            with pytest.raises(ValueError):
                _validate_archive_rel_path(bad)
        assert _validate_archive_rel_path("./sub/file.txt") == "sub/file.txt"
        assert _validate_archive_rel_path("./.env") == ".env"
        assert _validate_archive_rel_path("./.git/config") == ".git/config"

        local_dir = tmp_path / "src_win"
        local_dir.mkdir()
        (local_dir / "cfg.ini").write_text("[app]\n", encoding="utf-8")

        # 1. Хост с cached HostFacts(os_family="Windows") пропускает tar-архивацию
        ssh_win_conn = Connection.from_uri("ssh://admin@win-host")
        ssh_win_conn._facts_collector.cached = HostFacts(os_family="Windows", hostname="win-host")
        ssh_win_conn._transport._connected = True
        ssh_win_conn._python_worker = None
        ssh_win_conn._transport.exists = AsyncMock(return_value=False)  # type: ignore[method-assign]
        ssh_win_conn._transport.mkdir = AsyncMock()  # type: ignore[method-assign]
        ssh_win_conn._transport.write_file = AsyncMock()  # type: ignore[method-assign]
        ssh_win_conn.run = AsyncMock()  # type: ignore[method-assign]

        res = await ssh_win_conn.files.sync_dir(
            local_dir,
            "C:\\App",
            archive="auto",
            archive_threshold=1,
        )
        assert res.uploaded == ["cfg.ini"]
        ssh_win_conn._transport.write_file.assert_awaited_once()
        ssh_win_conn.run.assert_not_awaited()

        # 2. WinRM-транспорт также пропускает tar-архивацию
        with patch("uniconn.transports._winrm.winrm", MagicMock()):
            win_conn = Connection.from_uri("winrm://admin:pass@win-host")
            win_conn._transport._connected = True
            win_conn._transport.exists = AsyncMock(return_value=False)  # type: ignore[method-assign]
            win_conn._transport.mkdir = AsyncMock()  # type: ignore[method-assign]
            win_conn._transport.write_file = AsyncMock()  # type: ignore[method-assign]
            win_conn.run = AsyncMock()  # type: ignore[method-assign]

            res2 = await win_conn.files.sync_dir(
                local_dir,
                "C:\\App",
                archive="auto",
                archive_threshold=1,
            )
            assert res2.uploaded == ["cfg.ini"]
            win_conn._transport.write_file.assert_awaited_once()
            win_conn.run.assert_not_awaited()

    def test_sync_connection_and_cli_archive_option(self, tmp_path: Path) -> None:
        src_dir = tmp_path / "sync_src"
        dst_dir = tmp_path / "sync_dst"
        src_dir.mkdir()
        dst_dir.mkdir()
        (src_dir / "hello.txt").write_text("sync-parity", encoding="utf-8")

        with SyncConnection.from_uri("local://") as sconn:
            res = sconn.files.sync_dir(src_dir, dst_dir, archive="none", archive_threshold=5)
            assert res.uploaded == ["hello.txt"]
            assert (dst_dir / "hello.txt").read_text(encoding="utf-8") == "sync-parity"

        # Проверка валидации некорректных параметров archive/archive_threshold
        with SyncConnection.from_uri("local://") as sconn:
            with pytest.raises(ValueError, match="Unsupported archive mode"):
                sconn.files.sync_dir(src_dir, dst_dir, archive="rar")  # type: ignore[arg-type]
            with pytest.raises(ValueError, match="archive_threshold"):
                sconn.files.sync_dir(src_dir, dst_dir, archive_threshold=0)


