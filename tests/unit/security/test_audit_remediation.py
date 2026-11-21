# tests/unit/security/test_audit_remediation.py
"""Регрессионные unit-тесты для исправлений аудита безопасности и надёжности (SEC-01..13, BUG-01..14)."""

from __future__ import annotations

import asyncio
import base64
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from uniconn.background._cleanup import BackgroundCleanupManager
from uniconn.config.models import ConnectionConfig
from uniconn.config.uri import URIParser
from uniconn.core._middlewares import HITLApprovalMiddleware
from uniconn.core._shell_quoting import (
    has_cmd_metacharacters,
    parse_bool,
    parse_verify_ssl,
    ps_encoded_command,
    ps_quote,
    validate_env_key,
    validate_windows_interpreter,
)
from uniconn.core.pipeline import CommandPipeline, CommandRequest
from uniconn.core.resilience import RateLimiter
from uniconn.exceptions import (
    AuthenticationError,
    ConfigurationError,
    ExecutionError,
    PolicyViolationError,
)
from uniconn.mcp.flows import _RESERVED_MCP_FLOW_ARGS
from uniconn.mcp.hitl import ActionRiskClassifier, ApprovalManager
from uniconn.mcp.models import ActionRiskTier, HITLPolicy, MCPHostEntry, MCPSecurityPolicy
from uniconn.mcp.registry import MCPHostRegistry
from uniconn.mcp.server import MCPServer
from uniconn.pool.connection_pool import ConnectionPool
from uniconn.result import Result
from uniconn.security._policy_opa import OPAPolicyEngine
from uniconn.security.engine import PolicyGuardrailMiddleware
from uniconn.security.models import PolicyGuardrailConfig, build_auth_context
from uniconn.security.regex_safety import validate_safe_regex
from uniconn.security.url_validation import validate_outbound_url
from uniconn.services._dir_sync import _build_checksum_command
from uniconn.services.provisioning.service_managers import SysVStrategy, UniversalServiceStrategy
from uniconn.services.provisioning.system import build_useradd_command
from uniconn.services.templates import TemplateEngine, render_template
from uniconn.transports._docker import DockerTransport
from uniconn.transports._kubectl import KubectlTransport
from uniconn.transports._telnet import TelnetTransport
from uniconn.transports._winrm import WinRMTransport, clean_clixml_stderr
from uniconn.transports.network.gnmi import GnmiTransport
from uniconn.transports.network.netconf_protocol import NetconfFrameCodec, NetconfVendorAdapter
from uniconn.transports.network.restconf import RestconfTransport
from uniconn.transports.ssh.config_parser import OpenSSHConfigParser
from uniconn.transports.ssh.tunnel_chain import SSHJumpChainManager
from uniconn.transports.virtualization.guest_base import GuestAgentTransportBase
from uniconn.transports.virtualization.pve import PveTransport


class TestShellQuotingAndWindowsHardening:
    """SEC-02 / BUG-07 / BUG-08: безопасное экранирование Windows и строгий парсинг булевых флагов."""

    def test_ps_encoded_command_roundtrips_payload_safely(self) -> None:
        malicious = "C:\\temp\\a'; Start-Process calc.exe; 'b"
        cmd = ps_encoded_command(f"Get-Item -LiteralPath {ps_quote(malicious)}")
        assert cmd.startswith("powershell -NoProfile -NonInteractive -EncodedCommand ")
        b64 = cmd.rsplit(" ", 1)[-1]
        decoded = base64.b64decode(b64).decode("utf-16-le")
        assert "Start-Process calc.exe" in decoded
        assert "''" in decoded

    def test_validate_env_key_and_windows_interpreter(self) -> None:
        assert validate_env_key("APP_ENV") == "APP_ENV"
        with pytest.raises(ValueError):
            validate_env_key("FOO&calc")
        assert validate_windows_interpreter("python3") == "python3"
        assert validate_windows_interpreter("C:\\Python311\\python.exe") == "C:\\Python311\\python.exe"
        with pytest.raises(ValueError):
            validate_windows_interpreter("python.exe; calc.exe")

    def test_windows_checksum_falls_back_to_encoded_command_on_metacharacters(self) -> None:
        safe_cmd = _build_checksum_command("C:\\app\\config.json", "sha256", os_family="Windows")
        assert "certutil -hashfile" in safe_cmd

        unsafe_cmd = _build_checksum_command("C:\\app\\a&whoami.txt", "sha256", os_family="Windows")
        assert has_cmd_metacharacters("C:\\app\\a&whoami.txt")
        assert "-EncodedCommand" in unsafe_cmd
        assert "certutil" not in unsafe_cmd

    def test_guest_base_windows_env_injection_switches_to_encoded_command(self) -> None:
        class _DummyGuest(GuestAgentTransportBase):
            @property
            def name(self) -> str:
                return "dummy"

            async def connect(self) -> None:
                self._connected = True

            async def disconnect(self) -> None:
                self._connected = False

            async def run(self, command: str, **kwargs):
                raise NotImplementedError

            async def _guest_exec_raw(self, *args, **kwargs):
                raise NotImplementedError

        cfg = ConnectionConfig(transport="qga", host="win-vm", options={"os_type": "windows"})
        tr = _DummyGuest(cfg)
        prepared = tr._prepare_guest_command(
            "whoami",
            cwd="C:\\work&calc",
            env={"SAFE_KEY": "val&calc"},
            inject_env_in_shell=True,
        )
        assert "-EncodedCommand" in prepared
        assert prepared.startswith("powershell -NoProfile -NonInteractive -EncodedCommand ")

    def test_parse_bool_and_verify_ssl_handle_string_false_values(self) -> None:
        assert parse_bool("false", default=True) is False
        assert parse_bool("0", default=True) is False
        assert parse_bool("no", default=True) is False
        assert parse_bool("true", default=False) is True
        assert parse_bool(None, default=True) is True
        assert parse_verify_ssl("false") is False
        assert parse_verify_ssl("true") is True
        assert parse_verify_ssl("/etc/ssl/certs/ca.pem") == "/etc/ssl/certs/ca.pem"

    def test_uri_and_transports_handle_string_false_ssl_flags(self) -> None:
        winrm_cfg = URIParser.parse("winrm://user:pass@10.0.0.5?ssl=false&verify_ssl=false")
        assert winrm_cfg.port == 5985
        tr = WinRMTransport(winrm_cfg)
        assert tr.use_ssl is False
        assert tr.server_cert_validation == "ignore"

        gnmi_cfg = ConnectionConfig(
            transport="gnmi",
            host="10.0.0.10",
            options={"insecure": "false", "verify_tls": "true", "tls": "False"},
        )
        gnmi_tr = GnmiTransport(gnmi_cfg)
        assert gnmi_tr._insecure is False
        assert gnmi_tr._build_ssl_context() is None

        pve_tr = PveTransport(
            ConnectionConfig(transport="pve", host="10.0.0.20", options={"vmid": 100, "verify_ssl": "false"})
        )
        assert pve_tr.verify_ssl is False

        restconf_tr = RestconfTransport(
            ConnectionConfig(transport="restconf", host="10.0.0.30", options={"insecure": "false"})
        )
        assert restconf_tr._client.verify_ssl is True


class TestSecretScopingAndControllerRCE:
    """SEC-03 / SEC-04: ограничение SecretResolver и защита от RCE через URI-опции."""

    def test_secret_resolver_only_resolves_secret_fields(self, tmp_path: Path, monkeypatch) -> None:
        secret_file = tmp_path / "secret.txt"
        secret_file.write_text("top-secret-value\n", encoding="utf-8")
        monkeypatch.setenv("UNICONN_TEST_SECRET", "env-secret-value")

        cfg = ConnectionConfig(
            transport="ssh",
            host="10.0.0.1",
            password="env://UNICONN_TEST_SECRET",  # type: ignore[arg-type]
            options={
                "sudo_password": f"file://{secret_file}",
                "non_secret_note": f"file://{secret_file}",
            },
        )
        assert cfg.password is not None
        assert cfg.password.get_secret_value() == "env-secret-value"
        assert cfg.options["sudo_password"] == "top-secret-value"
        assert cfg.options["non_secret_note"] == f"file://{secret_file}"

    def test_uri_parser_resolve_secrets_false_skips_resolution(self, tmp_path: Path) -> None:
        secret_file = tmp_path / "pw.txt"
        secret_file.write_text("leaked", encoding="utf-8")
        cfg = URIParser.parse(f"ssh://user@host?sudo_password=file://{secret_file}", resolve_secrets=False)
        assert cfg.options["sudo_password"] == f"file://{secret_file}"

    def test_docker_and_kubectl_block_custom_binary_by_default(self) -> None:
        for bad_runtime in ("/tmp/evil", "/tmp/evil/docker", "C:\\evil\\docker.exe"):
            with pytest.raises(ConfigurationError, match="Untrusted container runtime"):
                _ = DockerTransport(
                    ConnectionConfig(transport="docker", host="web", options={"runtime": bad_runtime})
                ).runtime
        for bad_kubectl in ("/tmp/evil", "/tmp/evil/kubectl"):
            with pytest.raises(ConfigurationError, match="Untrusted kubectl binary"):
                _ = KubectlTransport(
                    ConnectionConfig(transport="kubectl", host="pod", options={"kubectl_bin": bad_kubectl})
                ).kubectl_bin

        ok_docker = DockerTransport(
            ConnectionConfig(
                transport="docker",
                host="web",
                options={"runtime": "/usr/local/bin/docker", "allow_custom_runtime": True},
            )
        )
        assert ok_docker.runtime == "/usr/local/bin/docker"

    def test_mcp_dynamic_uri_blocks_dangerous_transports_and_options(self) -> None:
        registry = MCPHostRegistry(policy=MCPSecurityPolicy(allow_dynamic_uri=True))
        for bad_uri in (
            "local://",
            "replay:///tmp/cassette.json",
            "serial:///dev/ttyUSB0",
            "ssh://ops@10.0.0.1?proxy_command=id",
            "ssh://ops@10.0.0.1?password=file:///etc/passwd",
            "ssh://ops:file%3A%2F%2F%2Fetc%2Fpasswd@10.0.0.1",
            "ssh://ops@10.0.0.1?key_file=/root/.ssh/id_rsa",
            "docker://web?runtime=/tmp/pwn",
            "docker://web?allow_custom_runtime=true",
            "kubectl://pod?kubectl_bin=/tmp/pwn",
        ):
            with pytest.raises(PermissionError):
                registry.get_entry(bad_uri)


class TestMCPRBACAndClassifierHardening:
    """SEC-01 / SEC-07 / BUG-13: защита от подмены role и обходов классификатора рисков."""

    @pytest.mark.asyncio
    async def test_mcp_run_ignores_client_supplied_role_override(self) -> None:
        entry = MCPHostEntry(
            name="prod1",
            uri="local://",
            masked_uri="local://",
            transport="local",
            host="prod1",
            groups=("production",),
            raw_config={"uri": "local://", "environment": "production"},
        )
        registry = MCPHostRegistry(
            policy=MCPSecurityPolicy(
                guardrails=PolicyGuardrailConfig(
                    enabled=True,
                    preset="strict",
                    default_role="readonly",
                )
            ),
            entries=[entry],
        )
        server = MCPServer(registry=registry)
        with pytest.raises(PolicyViolationError, match="readonly"):
            await server._tool_run(
                {
                    "target": "prod1",
                    "command": "mkdir /tmp/should_be_denied",
                    "role": "admin",
                }
            )

    def test_role_is_reserved_mcp_flow_argument(self) -> None:
        assert "role" in _RESERVED_MCP_FLOW_ARGS

    @pytest.mark.parametrize(
        "cmd,expected_tier",
        [
            ("cat /etc/shadow", ActionRiskTier.TIER_3_FORBIDDEN),
            ("cat < /etc/shadow", ActionRiskTier.TIER_3_FORBIDDEN),
            ("dd if=/etc/shadow of=/tmp/out", ActionRiskTier.TIER_3_FORBIDDEN),
            ("grep -f /etc/shadow /tmp/a", ActionRiskTier.TIER_3_FORBIDDEN),
            ("head -n 1 /tmp/../etc/shadow", ActionRiskTier.TIER_3_FORBIDDEN),
            ("grep root /root/.ssh/id_rsa", ActionRiskTier.TIER_3_FORBIDDEN),
            ("awk '{print $1}' /tmp/file.txt", ActionRiskTier.TIER_1_MUTATING),
            ("awk -e 'BEGIN { system(\"id\") }'", ActionRiskTier.TIER_3_FORBIDDEN),
            ("awk -e 'BEGIN { print \"x\" > \"/etc/cron.d/pwn\" }'", ActionRiskTier.TIER_2_DESTRUCTIVE),
            ("awk 'BEGIN { print \"x\" > \"/etc/cron.d/pwn\" }'", ActionRiskTier.TIER_2_DESTRUCTIVE),
            ("find /tmp -fprint /tmp/out.txt", ActionRiskTier.TIER_1_MUTATING),
            ("find /tmp -okdir chmod 777 {} \\;", ActionRiskTier.TIER_1_MUTATING),
        ],
    )
    def test_risk_classifier_blocks_sensitive_reads_and_awk_find_bypasses(
        self, cmd: str, expected_tier: ActionRiskTier
    ) -> None:
        assessment = ActionRiskClassifier.classify_command(cmd)
        assert assessment.risk_tier == expected_tier

    def test_classify_file_write_blocks_master_passwd_and_kmem(self) -> None:
        assert ActionRiskClassifier.classify_file_write("/etc/master.passwd").risk_tier == (
            ActionRiskTier.TIER_3_FORBIDDEN
        )
        assert ActionRiskClassifier.classify_file_write("/dev/kmem").risk_tier == ActionRiskTier.TIER_3_FORBIDDEN


class TestSSRFRegexXMLAndTemplateHardening:
    """SEC-06 / SEC-08 / SEC-09 / SEC-10 / SEC-11: SSRF, XML, ReDoS, TemplateEngine, OPA fail-closed."""

    @pytest.mark.parametrize(
        "bad_url",
        [
            "http://2130706433/admin",
            "http://0x7f000001/admin",
            "http://0177.0.0.1/admin",
            "http://127.1/admin",
            "http://169.254.169.254/latest/meta-data/",
            "http://100.100.100.200/latest/meta-data/",
            "http://100.64.0.1/internal",
            "http://[fd00:ec2::254]/latest/meta-data/",
            "http://[2002:7f00:0001::1]/admin",
        ],
    )
    def test_ssrf_blocks_nonstandard_ipv4_and_cloud_metadata(self, bad_url: str) -> None:
        with pytest.raises(ConfigurationError):
            validate_outbound_url(bad_url, allow_private_network=False, resolve_dns=False)

    def test_ssrf_blocks_cloud_metadata_even_when_private_network_allowed(self) -> None:
        with pytest.raises(ConfigurationError, match="metadata"):
            validate_outbound_url("http://169.254.169.254/latest/meta-data/", allow_private_network=True)

    def test_opa_default_is_fail_closed_and_propagates_ssrf_errors(self) -> None:
        cfg = PolicyGuardrailConfig()
        assert cfg.allow_safe_on_opa_failure is False

        def _ssrf_sender(_url: str, _payload: dict[str, object], _timeout: float) -> dict[str, object]:
            raise ConfigurationError("HTTP redirect blocked by SSRF policy")

        opa = OPAPolicyEngine(
            opa_url="https://opa.example.com/v1/data/uniconn/allow",
            fail_closed=False,
            allow_safe_on_failure=True,
            sender=_ssrf_sender,
        )
        ctx = build_auth_context(command="uptime", risk_tier="SAFE", host="node-1")
        with pytest.raises(ConfigurationError, match="SSRF"):
            opa.evaluate_sync(ctx)

    @pytest.mark.parametrize(
        "redos_pattern",
        [
            r"(a|a)+$",
            r"(.*)(.*)(.*)(.*)x",
            r"\\.*\\.*\\.*x",
            r"\w+\w+\w+x",
            r"(a+)\1+",
            r"(a+)+$",
        ],
    )
    def test_regex_safety_rejects_redos_patterns(self, redos_pattern: str) -> None:
        with pytest.raises(ConfigurationError):
            validate_safe_regex(redos_pattern)

    def test_regex_safety_accepts_literal_closing_bracket_and_char_class_dots(self) -> None:
        compiled = validate_safe_regex(r"[]a-z]+")
        assert compiled.search("]abc") is not None
        cc_dots = validate_safe_regex(r"[.*][.*][.*]")
        assert cc_dots.search("...") is not None

    @pytest.mark.asyncio
    async def test_netconf_read_frame_enforces_max_frame_bytes(self) -> None:
        reader = MagicMock()
        reader.read = AsyncMock(return_value=b"A" * 4096)
        with pytest.raises(ExecutionError, match="maximum allowed size"):
            await NetconfFrameCodec.read_frame(
                reader,
                bytearray(b"\n#50000\n"),
                version="1.1",
                max_frame_bytes=2048,
            )

    def test_netconf_filter_xml_escapes_and_validates_tags(self) -> None:
        xpath = NetconfVendorAdapter.build_filter_xml("/a/b[@x='<1>&\"2\"']", filter_type="xpath")
        assert "&lt;1&gt;&amp;&quot;2&quot;" in xpath
        subtree = NetconfVendorAdapter.build_filter_xml("/interfaces/interface[name=eth0<bad>]", filter_type="subtree")
        assert "<name>eth0&lt;bad&gt;</name>" in subtree
        with pytest.raises(ValueError, match="Invalid XML element name"):
            NetconfVendorAdapter.build_filter_xml("/interfaces/bad<tag>", filter_type="subtree")

    def test_winrm_clixml_blocks_doctype_entity(self) -> None:
        xxe = '#< CLIXML\n<!DOCTYPE foo [<!ENTITY xxe "pwn">]><Objs><S S="Error">boom</S></Objs>'
        cleaned = clean_clixml_stderr(xxe)
        assert "boom" in cleaned

    def test_template_engine_does_not_probe_filesystem_for_str(self, tmp_path: Path) -> None:
        secret = tmp_path / "secret.conf"
        secret.write_text("DB_PASS=supersecret\n", encoding="utf-8")
        assert render_template(str(secret), {}) == str(secret)
        assert render_template(secret, {}) == "DB_PASS=supersecret\n"
        assert TemplateEngine.render_file(secret, {}) == "DB_PASS=supersecret\n"
        assert render_template(str(secret), {}, allow_file_path=True) == "DB_PASS=supersecret\n"


class TestReliabilityAndBugFixes:
    """BUG-01..14 + SEC-12: пул, HITL double-consume, сервисы, telnet, ssh config, uid, weakref."""

    @pytest.mark.asyncio
    async def test_connection_pool_closes_opened_connections_on_partial_failure(self) -> None:
        ok_conn = MagicMock()
        ok_conn.__aenter__ = AsyncMock(return_value=ok_conn)
        ok_conn.__aexit__ = AsyncMock(return_value=None)
        bad_conn = MagicMock()
        bad_conn.__aenter__ = AsyncMock(side_effect=RuntimeError("boom"))
        bad_conn.__aexit__ = AsyncMock(return_value=None)

        pool = ConnectionPool(["local://?id=1", "local://?id=2"])
        pool._build_conn = MagicMock(side_effect=[ok_conn, bad_conn])  # type: ignore[method-assign]
        with pytest.raises(ExceptionGroup):
            await pool.connect()
        ok_conn.__aexit__.assert_awaited_once()
        assert pool._active_conns == {}

    def test_connection_pool_select_preserves_duplicate_uri_keys(self) -> None:
        pool = ConnectionPool(["local://", "local://"])
        assert pool._target_keys == ["local://#1", "local://#2"]
        sub = pool.select(predicate=lambda key, _conn: key.endswith("#2"))
        assert sub._target_keys == ["local://#2"]

    @pytest.mark.asyncio
    async def test_policy_and_hitl_middleware_do_not_double_consume_token(self) -> None:
        mgr = ApprovalManager(policy=HITLPolicy(enabled=True))
        req = await mgr.create_request(
            target_host="prod1",
            tool_name="conn.run",
            risk_tier=ActionRiskTier.TIER_2_DESTRUCTIVE,
            command="rm -rf /tmp/cache",
            parameters={"command": "rm -rf /tmp/cache", "sudo": False, "cwd": ""},
        )
        await mgr.approve(req.approval_id, decided_by="ops")

        conn = SimpleNamespace(
            config=ConnectionConfig(transport="local", host="prod1"),
            transport_name="local",
            current_cwd=None,
            _approval_manager=mgr,
            _hitl_policy=mgr.policy,
        )
        policy_mw = PolicyGuardrailMiddleware(
            conn,
            config=PolicyGuardrailConfig(enabled=True, preset="prod-guard"),
            approval_manager=mgr,
            host="prod1",
            is_production=True,
            maintenance_window_override=False,
        )
        hitl_mw = HITLApprovalMiddleware(conn)  # type: ignore[arg-type]

        async def _final(cmd_req: CommandRequest) -> Result:
            return Result(exit_code=0, stdout="ok", stderr="", duration=0.01, command=cmd_req.command)

        pipeline = CommandPipeline([policy_mw, hitl_mw])
        cmd_req = CommandRequest(
            raw_command="rm -rf /tmp/cache",
            command="rm -rf /tmp/cache",
            exec_command="rm -rf /tmp/cache",
            approval_id=req.approval_id,
        )
        res = await pipeline.execute(cmd_req, _final)
        assert res.ok
        assert cmd_req.metadata.get("hitl_approval_verified") is True
        assert cmd_req.approval_id is None

    @pytest.mark.asyncio
    async def test_policy_allow_does_not_consume_downstream_hitl_token(self) -> None:
        hitl_mgr = ApprovalManager(policy=HITLPolicy(enabled=True))
        req = await hitl_mgr.create_request(
            target_host="dev1",
            tool_name="conn.run",
            risk_tier=ActionRiskTier.TIER_2_DESTRUCTIVE,
            command="rm -rf /tmp/cache",
            parameters={"command": "rm -rf /tmp/cache", "sudo": False, "cwd": ""},
        )
        await hitl_mgr.approve(req.approval_id, decided_by="ops")

        separate_policy_mgr = ApprovalManager(policy=HITLPolicy(enabled=True))
        conn = SimpleNamespace(
            config=ConnectionConfig(transport="local", host="dev1"),
            transport_name="local",
            current_cwd=None,
            _approval_manager=hitl_mgr,
            _hitl_policy=hitl_mgr.policy,
        )
        policy_mw = PolicyGuardrailMiddleware(
            conn,
            config=PolicyGuardrailConfig(enabled=True, preset="default"),
            approval_manager=separate_policy_mgr,
            host="dev1",
            is_production=False,
        )
        hitl_mw = HITLApprovalMiddleware(conn)  # type: ignore[arg-type]

        async def _final(cmd_req: CommandRequest) -> Result:
            return Result(exit_code=0, stdout="ok", stderr="", duration=0.01, command=cmd_req.command)

        pipeline = CommandPipeline([policy_mw, hitl_mw])
        cmd_req = CommandRequest(
            raw_command="rm -rf /tmp/cache",
            command="rm -rf /tmp/cache",
            exec_command="rm -rf /tmp/cache",
            approval_id=req.approval_id,
        )
        res = await pipeline.execute(cmd_req, _final)
        assert res.ok
        assert cmd_req.metadata.get("hitl_approval_verified") is True

    @pytest.mark.asyncio
    async def test_cleanup_manager_quotes_pool_id_and_rejects_traversal_in_stale_sentinel(self) -> None:
        mgr = BackgroundCleanupManager(pool_id='p$(id)"')
        script = mgr.generate_cleanup_script([])
        assert "POOL_ID='p$(id)\"'" in script

        fake_conn = MagicMock()
        fake_conn.transport_name = "local"
        fake_conn.config = ConnectionConfig(transport="local", host="localhost")
        fake_conn.run = AsyncMock(
            return_value=Result(
                command="scan",
                stdout='/tmp/uniconn_x.active\t{"pool_id": "../evil", "created_at": 1}\n',
                stderr="",
                exit_code=0,
                duration=0.01,
            )
        )
        cleaned = await mgr.cleanup_stale(fake_conn, max_age_seconds=1.0)
        assert cleaned == []
        assert fake_conn.run.await_count == 1

    @pytest.mark.asyncio
    async def test_hitl_whitespace_approval_id_wakes_event_and_file_lock(self, tmp_path: Path) -> None:
        store = tmp_path / "state.db"
        mgr = ApprovalManager(policy=HITLPolicy(enabled=True), store_path=store)
        try:
            req = await mgr.create_request(
                target_host="host1",
                tool_name="uniconn_run",
                risk_tier=ActionRiskTier.TIER_2_DESTRUCTIVE,
                command="reboot",
            )
            await mgr.approve(f"  {req.approval_id}  ", decided_by="alice")
            assert mgr._events[req.approval_id].is_set()
            assert store.is_file()
        finally:
            await mgr.close()

    def test_sysv_and_universal_service_enable_do_not_hardcode_systemctl(self) -> None:
        sysv = SysVStrategy()
        assert "systemctl" not in sysv.is_enabled_cmd("nginx")
        assert "systemctl" not in sysv.set_enabled_cmd("nginx", True)
        assert "update-rc.d" in sysv.set_enabled_cmd("nginx", True)

        uni = UniversalServiceStrategy()
        assert "rc-update" in uni.is_enabled_cmd("nginx")
        assert "update-rc.d" in uni.set_enabled_cmd("nginx", False)

    @pytest.mark.asyncio
    async def test_telnet_propagates_authentication_error_and_closes_writer(self) -> None:
        reader = MagicMock()
        reader.read = AsyncMock(side_effect=[b"login: ", b"Password: ", b"Login incorrect\r\nlogin: "])
        writer = MagicMock()
        writer.write = MagicMock()
        writer.drain = AsyncMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        fake_telnetlib3 = MagicMock()
        fake_telnetlib3.open_connection = AsyncMock(return_value=(reader, writer))

        cfg = ConnectionConfig(
            transport="telnet",
            host="10.0.0.2",
            username="admin",
            password="wrong",  # type: ignore[arg-type]
        )
        with patch("uniconn.transports._telnet.telnetlib3", fake_telnetlib3):
            tr = TelnetTransport(cfg)
            with pytest.raises(AuthenticationError):
                await tr.connect()
        writer.close.assert_called_once()
        assert tr.is_connected is False

    def test_openssh_config_parser_resets_match_block(self, tmp_path: Path) -> None:
        cfg_file = tmp_path / "ssh_config"
        cfg_file.write_text(
            "Host prod-app\n"
            "    User deploy\n"
            "Match host *.bastion\n"
            "    ProxyCommand nc evil 22\n"
            "    Port 9999\n",
            encoding="utf-8",
        )
        parsed = OpenSSHConfigParser.parse_file(cfg_file, "prod-app")
        assert parsed == {"user": "deploy"}

    @pytest.mark.asyncio
    async def test_ssh_jump_chain_close_all_closes_remaining_on_error(self) -> None:
        mgr = SSHJumpChainManager(ConnectionConfig(transport="ssh", host="target"))
        c1 = MagicMock()
        c1.close = MagicMock()
        c1.wait_closed = AsyncMock()
        c2 = MagicMock()
        c2.close = MagicMock(side_effect=RuntimeError("broken"))
        c2.wait_closed = AsyncMock(side_effect=RuntimeError("broken"))
        proc = MagicMock()
        proc.terminate = MagicMock()
        proc.wait = AsyncMock()

        mgr.tunnel_conns = [c1, c2]
        mgr.proxy_procs = [proc]
        mgr.active_proxy_command = "nc h 22"

        await mgr.close_all()
        c1.close.assert_called_once()
        proc.terminate.assert_called_once()
        assert mgr.active_proxy_command is None

    @pytest.mark.asyncio
    async def test_rate_limiter_uses_weakref_for_event_loop(self) -> None:
        rl = RateLimiter(rate=100.0, burst=5)
        await rl.acquire()
        assert rl._async_lock_loop is asyncio.get_running_loop()
        assert rl._async_lock_loop_ref is not None

    def test_useradd_uid_validation_rejects_non_int_and_bool(self) -> None:
        cmd = build_useradd_command(
            "deploy", uid=1001, group=None, groups=None, shell=None, home=None, create_home=True, system=False
        )
        assert "-u 1001" in cmd
        with pytest.raises(ValueError, match="Invalid numeric UID"):
            build_useradd_command(
                "deploy",
                uid="1001; id",  # type: ignore[arg-type]
                group=None,
                groups=None,
                shell=None,
                home=None,
                create_home=True,
                system=False,
            )
        with pytest.raises(ValueError, match="Invalid numeric UID"):
            build_useradd_command(
                "deploy",
                uid=True,
                group=None,
                groups=None,
                shell=None,
                home=None,
                create_home=True,
                system=False,
            )
