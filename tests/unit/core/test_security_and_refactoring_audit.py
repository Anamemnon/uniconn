"""Unit tests for security hardening, bug fixes, and architectural refactoring audit."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from uniconn import (
    ActionRiskClassifier,
    ActionRiskTier,
    CommandASTParser,
    Connection,
    ConnectionConfig,
    ConnectionPool,
    DeclarativePolicyRule,
    EmbeddedPolicyEngine,
    PolicyDecision,
    allowlist_hook,
    blocklist_hook,
    build_auth_context,
)
from uniconn.security.ast_parser import normalize_target_path
from uniconn.transports.serial_protocols.exceptions import ModemProtocolError
from uniconn.transports.serial_protocols.ymodem import (
    AsyncYmodemReceiver,
    build_ymodem_header_packet,
)
from uniconn.transports.ssh.sftp import SFTPClientAdapter


class TestASTAndPolicyPathTraversalHardening:
    """Проверка нормализации путей, обёрток привилегий и process substitution в AST и Policy Engine."""

    def test_normalize_target_path_resolves_dot_segments(self) -> None:
        assert normalize_target_path("/tmp/../etc/shadow") == "/etc/shadow"
        assert normalize_target_path("//etc///sudoers") == "/etc/sudoers"
        assert normalize_target_path("../../etc/passwd") == "/etc/passwd"
        assert normalize_target_path("/var/log/../../etc/gshadow") == "/etc/gshadow"

    def test_ast_extracts_normalized_paths_and_process_substitutions(self) -> None:
        ast = CommandASTParser.parse("cat /tmp/../etc/shadow <(rm -rf /var/lib/postgresql)")
        assert "/etc/shadow" in ast.target_paths
        assert "rm" in ast.executables
        assert "/var/lib/postgresql" in ast.target_paths

    @pytest.mark.parametrize(
        ("cmd", "expected_bin"),
        [
            ("doas -u root systemctl restart nginx", "systemctl"),
            ("pkexec --user root chmod 777 /etc/hosts", "chmod"),
            ('su - root -c "rm -rf /var/lib/mysql"', "rm"),
            ("runuser -u postgres --command='dropdb prod'", "dropdb"),
            ("chroot /mnt/rootfs passwd root", "passwd"),
            ("nsenter -t 1 -m -p -- reboot", "reboot"),
            ("watch -n 2 systemctl stop kubelet", "systemctl"),
        ],
    )
    def test_ast_unwraps_privilege_and_namespace_wrappers(
        self, cmd: str, expected_bin: str
    ) -> None:
        ast = CommandASTParser.parse(cmd)
        assert expected_bin in ast.executables

    @pytest.mark.asyncio
    async def test_least_privilege_policy_blocks_path_traversal_to_protected_paths(self) -> None:
        engine = EmbeddedPolicyEngine(preset="least-privilege")
        cmd = "rm -f /tmp/../etc/shadow"
        ast = CommandASTParser.parse(cmd)
        ctx = build_auth_context(
            command=cmd,
            ast=ast,
            role="operator",
            risk_tier="MUTATING",
        )
        res = await engine.evaluate(ctx)
        assert res.decision == PolicyDecision.DENY
        assert any(v.rule_id == "least_privilege_system_paths" for v in res.violations)

    @pytest.mark.asyncio
    async def test_declarative_policy_rule_matches_traversed_path_prefix(self) -> None:
        rule = DeclarativePolicyRule.from_dict(
            {
                "id": "deny_etc_writes",
                "name": "deny_etc_writes",
                "decision": "DENY",
                "reason": "No touching /etc",
                "when": {"target_prefixes": ["/etc"]},
            }
        )
        engine = EmbeddedPolicyEngine(preset="default", rules=[rule.evaluate])
        cmd = "cp payload.conf /var/tmp/../../etc/systemd/system/evil.service"
        ast = CommandASTParser.parse(cmd)
        ctx = build_auth_context(command=cmd, ast=ast)
        res = await engine.evaluate(ctx)
        assert res.decision == PolicyDecision.DENY
        assert "deny_etc_writes" in res.rule_names


class TestHITLRiskClassifierHardening:
    """Проверка защиты ActionRiskClassifier от обхода через path traversal и порядок аргументов."""

    @pytest.mark.parametrize(
        "unsafe_path",
        [
            "/tmp/../etc/shadow",
            "/var/tmp/../../etc/gshadow",
            "../../etc/sudoers",
            "/tmp/../etc/sudoers.d/99-admin",
            "//dev//sda",
        ],
    )
    def test_classify_file_write_blocks_path_traversal_to_forbidden_files(
        self, unsafe_path: str
    ) -> None:
        classifier = ActionRiskClassifier()
        res = classifier.classify_file_write(unsafe_path)
        assert res.risk_tier == ActionRiskTier.TIER_3_FORBIDDEN

    def test_classify_file_write_detects_traversed_sensitive_etc_path(self) -> None:
        classifier = ActionRiskClassifier()
        res = classifier.classify_file_write("/opt/app/../../etc/nginx/nginx.conf")
        assert res.risk_tier == ActionRiskTier.TIER_2_DESTRUCTIVE

    def test_classify_command_find_delete_with_leading_flags_and_wrappers(self) -> None:
        classifier = ActionRiskClassifier()
        res1 = classifier.classify_command("find -L /var/log -name '*.log' -delete")
        assert res1.risk_tier == ActionRiskTier.TIER_2_DESTRUCTIVE

        res2 = classifier.classify_command('su - root -c "rm -rf /"')
        assert res2.risk_tier == ActionRiskTier.TIER_3_FORBIDDEN

        res3 = classifier.classify_command("cat <(mkfs.ext4 /dev/sdb1)")
        assert res3.risk_tier == ActionRiskTier.TIER_3_FORBIDDEN


class TestPipelineDryRunAndHooksSecurity:
    """Проверка выполнения before_run хуков при run_bytes(dry_run=True) и новых правил hooks.py."""

    @pytest.mark.asyncio
    async def test_run_bytes_executes_before_run_security_hooks(self) -> None:
        async with Connection.from_uri("local://") as conn:
            conn.add_hook("before_run", blocklist_hook())
            with pytest.raises(PermissionError, match="blocked by pattern"):
                await conn.run_bytes("rm -rf /")

            out = await conn.run_bytes("echo safe", dry_run=True)
            assert out == b""

    @pytest.mark.parametrize(
        "dangerous_cmd",
        [
            "rm -rf /",
            "rm -fr /",
            "rm -r -f /",
            "rm -f -r /",
            "rm -rf /*",
            "rm -fr /*",
        ],
    )
    def test_blocklist_hook_catches_all_rm_root_variants(self, dangerous_cmd: str) -> None:
        hook = blocklist_hook()
        with pytest.raises(PermissionError, match="blocked by pattern"):
            hook(dangerous_cmd, "localhost", {})

    def test_allowlist_hook_blocks_null_byte_injection(self) -> None:
        hook = allowlist_hook(["uptime", "ls"])
        with pytest.raises(PermissionError, match="null byte"):
            hook("uptime\x00; rm -rf /", "localhost", {})


class TestProvisioningSystemValidation:
    """Проверка валидации параметров в ensure_user, ensure_systemd_unit и ensure_sysctl."""

    @pytest.mark.asyncio
    async def test_ensure_systemd_unit_rejects_path_traversal(self) -> None:
        async with Connection.from_uri("local://", dry_run=True) as conn:
            for bad_unit in ("../../etc/cron.d/pwn", "../evil.service", "/etc/passwd", "-bad.service"):
                with pytest.raises(ValueError, match="Invalid systemd unit name"):
                    await conn.state.ensure_systemd_unit(bad_unit, content="[Unit]\n")

    @pytest.mark.asyncio
    async def test_ensure_sysctl_rejects_key_and_value_injection(self) -> None:
        async with Connection.from_uri("local://", dry_run=True) as conn:
            for bad_key in ("../etc/passwd", "net.ipv4.ip_forward\nkernel.sysrq", "-e", "a..b"):
                with pytest.raises(ValueError, match="Invalid sysctl parameter name"):
                    await conn.state.ensure_sysctl(bad_key, 1)

            with pytest.raises(ValueError, match="Invalid sysctl parameter value"):
                await conn.state.ensure_sysctl("net.ipv4.ip_forward", "1\nkernel.sysrq = 1")

    @pytest.mark.asyncio
    async def test_ensure_user_validates_username_and_updates_groups_without_primary_group(
        self,
    ) -> None:
        async with Connection.from_uri("local://", dry_run=True) as conn:
            for bad_user in ("-o", "root;id", "user name", "../etc", ""):
                with pytest.raises(ValueError, match="Invalid system username"):
                    await conn.state.ensure_user(bad_user)

        # Verify supplementary groups update when primary group is None
        conn_mock = Connection.from_uri("local://")
        recorded_cmds: list[str] = []

        async def _fake_run(cmd: str, **kwargs: Any) -> Any:
            from uniconn import Result

            recorded_cmds.append(cmd)
            if cmd.startswith("getent passwd"):
                return Result(
                    exit_code=0,
                    stdout="deploy:x:1001:1001::/home/deploy:/bin/bash\n",
                    stderr="",
                    duration=0.01,
                    command=cmd,
                )
            if cmd.startswith("id -Gn"):
                return Result(
                    exit_code=0,
                    stdout="deploy\n",
                    stderr="",
                    duration=0.01,
                    command=cmd,
                )
            return Result(exit_code=0, stdout="", stderr="", duration=0.01, command=cmd)

        conn_mock.run = _fake_run  # type: ignore[method-assign]
        res = await conn_mock.state.ensure_user("deploy", groups=["docker", "wheel"])
        assert res.ok is True
        assert res.changed is True
        assert any("usermod -G" in c for c in recorded_cmds)


class TestYmodemAndSFTPHardening:
    """Проверка защиты YMODEM от '..' и корректной работы SFTPClientAdapter.mkdir."""

    @pytest.mark.asyncio
    async def test_ymodem_receive_batch_rejects_dotdot_filename(self, tmp_path: Path) -> None:
        reader = asyncio.StreamReader()
        pkt0 = build_ymodem_header_packet(filename="..", filesize=4)
        reader.feed_data(pkt0)

        writer = MagicMock()
        writer.write = MagicMock()
        writer.drain = AsyncMock()

        receiver = AsyncYmodemReceiver(reader, writer, packet_timeout=0.5, max_retries=2)
        with pytest.raises(ModemProtocolError, match="unsafe filename"):
            await receiver.receive_batch(tmp_path)

    @pytest.mark.asyncio
    async def test_sftp_mkdir_exist_ok_and_parents_fallback(self) -> None:
        class _FakeSFTPError(Exception):
            pass

        class _FakeAsyncSSH:
            Error = _FakeSFTPError

        class _FakeSFTPClient:
            def __init__(self) -> None:
                self.existing_dirs: set[str] = {"/var", "/var/data"}
                self.created: list[str] = []

            async def __aenter__(self) -> _FakeSFTPClient:
                return self

            async def __aexit__(self, *args: Any) -> None:
                pass

            async def mkdir(self, path: str) -> None:
                if path in self.existing_dirs:
                    raise _FakeSFTPError(f"File exists: {path}")
                self.existing_dirs.add(path)
                self.created.append(path)

            async def isdir(self, path: str) -> bool:
                return path in self.existing_dirs

        fake_sftp = _FakeSFTPClient()
        fake_conn = MagicMock()
        fake_conn.start_sftp_client = MagicMock(return_value=fake_sftp)

        fake_transport = MagicMock()
        fake_transport.config = ConnectionConfig(transport="ssh", host="10.0.0.5")
        fake_transport._conn = fake_conn

        adapter = SFTPClientAdapter(fake_transport)

        # 1. parents=False, exist_ok=True on existing directory -> no error
        await adapter.mkdir(_FakeAsyncSSH, "/var/data", parents=False, exist_ok=True)

        # 2. parents=False, exist_ok=False on existing directory -> raises ConnectionError
        from uniconn.exceptions import ConnectionError as UniconnConnectionError

        with pytest.raises(UniconnConnectionError, match="SFTP mkdir failed"):
            await adapter.mkdir(_FakeAsyncSSH, "/var/data", parents=False, exist_ok=False)

        # 3. parents=True when sftp has no makedirs -> creates intermediate directories iteratively
        await adapter.mkdir(_FakeAsyncSSH, "/var/data/app/releases", parents=True, exist_ok=True)
        assert "/var/data/app" in fake_sftp.created
        assert "/var/data/app/releases" in fake_sftp.created


class TestPoolSelectWithCassette:
    """Проверка сохранения кассетных соединений при вызове ConnectionPool.select()."""

    @pytest.mark.asyncio
    async def test_pool_select_preserves_cassette_connections(self, tmp_path: Path) -> None:
        cassette_dir = tmp_path / "pool_cassettes"
        pool = ConnectionPool(["local://node-a", "local://node-b"])

        async with pool.use_cassette(cassette_dir, mode="all"):
            sub = pool.select(["node-a"])
            res_list = await sub.map("echo hello_from_a")
            assert len(res_list) == 1
            assert res_list[0].stdout.strip() == "hello_from_a"

        # Replay via sub-pool without hitting real transport
        async with pool.use_cassette(cassette_dir, mode="none"):
            sub_replay = pool.select(["node-a"])
            replay_list = await sub_replay.map("echo hello_from_a")
            assert len(replay_list) == 1
            assert replay_list[0].stdout.strip() == "hello_from_a"
            ping_map = await sub_replay.ping()
            assert ping_map["local://node-a"].alive is True
