# tests/unit/security/test_audit_v020_remediation.py
"""Регрессионные unit-тесты на исправления безопасности SEC-01..SEC-12 (аудит v0.20.0)."""

from __future__ import annotations

import ast
import hashlib
import hmac
import http.client
import json
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from uniconn._logging import SecretMaskingFilter
from uniconn.core._shell_quoting import ps_quote, validate_windows_interpreter
from uniconn.core._worker_runtime import WORKER_BOOTSTRAP_SCRIPT
from uniconn.exceptions import ConfigurationError, PolicyViolationError
from uniconn.mcp.flows import FlowCheckpointStore
from uniconn.mcp.hitl import ApprovalManager, WebhookApprovalChannel
from uniconn.mcp.models import ActionRiskTier, HITLPolicy, MCPHostEntry
from uniconn.mcp.risk_classifier import ActionRiskClassifier
from uniconn.mcp.server import MCPHostRegistry, MCPServer
from uniconn.orchestration import Flow, task
from uniconn.security import (
    ActionContext,
    AuthContext,
    CommandASTParser,
    DeclarativePolicyRule,
    EmbeddedPolicyEngine,
    PolicyDecision,
    ResourceContext,
)
from uniconn.security.url_validation import resolve_and_validate_outbound_url
from uniconn.transports.network.gnmi import GnmiTransport


class TestSec02AstParserHardening:
    """SEC-02: Проверка устойчивости CommandASTParser против обходов shell/интерпретаторов."""

    @pytest.mark.parametrize(
        "payload",
        [
            "exec rm -rf /",
            "command rm -rf /etc",
            "builtin eval 'rm -rf /'",
            "(rm -rf /etc)",
            "{ rm -rf /etc; }",
            "if true; then rm -rf /etc; fi",
            "echo $(( $(rm -rf /etc/passwd) ))",
            "echo $(( a[$(rm -rf /)] ))",
            "bash -lc 'rm -rf /'",
            "sh -ec 'rm -rf /'",
            "python3.11 -c 'import os; os.system(\"id\")'",
            "bash <<< 'rm -rf /'",
            "echo 'rm -rf /' | sh",
            "printf 'import os' | python3 -",
            "cat script.sh | bash -s",
            ". /tmp/evil.sh",
            "source /tmp/evil.sh",
        ],
    )
    def test_bypass_payloads_are_not_classified_as_safe(self, payload: str) -> None:
        parsed = CommandASTParser.parse(payload)
        assessment = ActionRiskClassifier().classify_command(payload)
        assert assessment.risk_tier != ActionRiskTier.TIER_0_SAFE, (
            f"Bypass payload {payload!r} was misclassified as SAFE (verbs={parsed.verbs}, "
            f"obf={parsed.is_obfuscated}, reasons={parsed.obfuscation_reasons})"
        )

    def test_legitimate_arithmetic_and_command_v_remain_safe(self) -> None:
        classifier = ActionRiskClassifier()
        assert classifier.classify_command("echo $((1 + 2))").risk_tier == ActionRiskTier.TIER_0_SAFE
        assert classifier.classify_command("command -v docker").risk_tier == ActionRiskTier.TIER_0_SAFE
        assert classifier.classify_command("ls -la /tmp").risk_tier == ActionRiskTier.TIER_0_SAFE


class TestSec03DashboardSecurity:
    """SEC-03: Проверка защиты дашборда от path traversal и DNS rebinding."""

    def test_dashboard_rejects_untrusted_host_and_docs_traversal(self) -> None:
        from examples.dashboard.server import create_dashboard_handler

        handler_cls = create_dashboard_handler(bind_host="127.0.0.1")
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            # 1. DNS Rebinding: Host: evil.com на GET / -> 403 Forbidden (CSRF-токен не утекает)
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/", headers={"Host": "evil.com"})
            resp = conn.getresponse()
            body = resp.read().decode("utf-8", errors="replace")
            conn.close()
            assert resp.status == 403
            assert "csrf" not in body.lower()

            # 2. Path traversal за пределы docs/: /docs/../pyproject.toml -> 404
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/docs/../pyproject.toml", headers={"Host": f"127.0.0.1:{port}"})
            resp = conn.getresponse()
            resp.read()
            conn.close()
            assert resp.status == 404

            # 3. Dotfile блокировка: /docs/../.env -> 404
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/docs/../.env", headers={"Host": f"127.0.0.1:{port}"})
            resp = conn.getresponse()
            resp.read()
            conn.close()
            assert resp.status == 404

            # 4. URL-кодированный path traversal: /docs/%2e%2e/pyproject.toml -> 404
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/docs/%2e%2e/pyproject.toml", headers={"Host": f"127.0.0.1:{port}"})
            resp = conn.getresponse()
            resp.read()
            conn.close()
            assert resp.status == 404

            # 5. DNS Rebinding на OPTIONS: Host: evil.com -> 403 Forbidden
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("OPTIONS", "/api/status", headers={"Host": "evil.com"})
            resp = conn.getresponse()
            resp.read()
            conn.close()
            assert resp.status == 403

            # 6. Доверенный Host: 127.0.0.1:<port> на /api/status -> 200 OK
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/api/status", headers={"Host": f"127.0.0.1:{port}"})
            resp = conn.getresponse()
            resp.read()
            conn.close()
            assert resp.status == 200
        finally:
            server.shutdown()
            server.server_close()


class TestSec04SsrfAndWebhookHardening:
    """SEC-04: DNS-пининг, запрет редиректов, изоляция ключей и проверка подписи ответа webhook."""

    def test_resolve_and_validate_pins_public_ip_and_blocks_private(self) -> None:
        fake_public = [(2, 1, 6, "", ("93.184.216.34", 443))]
        with patch("socket.getaddrinfo", return_value=fake_public):
            url, hostname, pinned_ip = resolve_and_validate_outbound_url(
                "https://example.com/hook", allow_private_network=False
            )
            assert url == "https://example.com/hook"
            assert hostname == "example.com"
            assert pinned_ip == "93.184.216.34"

        fake_private = [(2, 1, 6, "", ("127.0.0.1", 443))]
        with (
            patch("socket.getaddrinfo", return_value=fake_private),
            pytest.raises(ConfigurationError),
        ):
            resolve_and_validate_outbound_url("https://rebind.example.com/hook", allow_private_network=False)

        # IPv6: публичный литерал разрешён, loopback ::1 заблокирован
        fake_public_v6 = [(10, 1, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 443, 0, 0))]
        with patch("socket.getaddrinfo", return_value=fake_public_v6):
            _, hostname_v6, pinned_v6 = resolve_and_validate_outbound_url(
                "https://[2606:2800:220:1:248:1893:25c8:1946]/hook", allow_private_network=False
            )
            assert hostname_v6 == "2606:2800:220:1:248:1893:25c8:1946"
            assert pinned_v6 == "2606:2800:220:1:248:1893:25c8:1946"

        with pytest.raises(ConfigurationError):
            resolve_and_validate_outbound_url("https://[::1]/hook", allow_private_network=False)

    def test_webhook_rejects_unsigned_and_accepts_signed_sync_decision(self) -> None:
        secret = "top-secret-webhook-key"
        payload_bytes = json.dumps({"decision": "APPROVED", "decided_by": "secops"}).encode("utf-8")
        good_sig = "sha256=" + hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()

        class _FakeResp:
            def __init__(self, body: bytes, hdrs: dict[str, str]) -> None:
                self._body = body
                self.headers = hdrs

            def read(self, _n: int = -1) -> bytes:
                return self._body

            def __enter__(self) -> _FakeResp:
                return self

            def __exit__(self, *_a: Any) -> None:
                return None

        # Без подписи -> отклоняется (None)
        with patch(
            "uniconn.mcp.hitl.open_ssrf_safe_url",
            return_value=_FakeResp(payload_bytes, {}),
        ):
            res = WebhookApprovalChannel._default_send(
                "https://hooks.example.com/hitl",
                b"{}",
                {},
                5.0,
                secret=secret,
                require_signed_response=True,
            )
            assert res is None

        # С неверной подписью -> отклоняется (None)
        with patch(
            "uniconn.mcp.hitl.open_ssrf_safe_url",
            return_value=_FakeResp(payload_bytes, {"X-Uniconn-Response-Signature": "sha256=deadbeef"}),
        ):
            res = WebhookApprovalChannel._default_send(
                "https://hooks.example.com/hitl",
                b"{}",
                {},
                5.0,
                secret=secret,
                require_signed_response=True,
            )
            assert res is None

        # С валидной подписью -> принимается
        with patch(
            "uniconn.mcp.hitl.open_ssrf_safe_url",
            return_value=_FakeResp(payload_bytes, {"X-Uniconn-Response-Signature": good_sig}),
        ):
            res = WebhookApprovalChannel._default_send(
                "https://hooks.example.com/hitl",
                b"{}",
                {},
                5.0,
                secret=secret,
                require_signed_response=True,
            )
            assert res is not None
            assert res["decision"] == "APPROVED"

    def test_approval_manager_isolates_internal_secret_from_webhook_secret(self) -> None:
        policy = HITLPolicy(
            enabled=True,
            channels=["webhook"],
            webhook_url="https://hooks.example.com/hitl",
            webhook_secret="shared-external-webhook-token",
        )
        mgr = ApprovalManager(policy=policy)
        assert mgr._secret != "shared-external-webhook-token"
        assert len(mgr._channels) == 1
        ch = mgr._channels[0]
        assert isinstance(ch, WebhookApprovalChannel)
        assert ch.secret == "shared-external-webhook-token"


class TestSec05PolicyAndFlowGuardrails:
    """SEC-05: Относительные пути в политиках, валидация ключей и блокировка flow:/dry_run."""

    def test_relative_path_resolved_against_cwd_in_system_paths_rule(self) -> None:
        engine = EmbeddedPolicyEngine(preset="least-privilege")
        ctx = AuthContext(
            resource=ResourceContext(host="app-01", environment="production", target_path="passwd"),
            action=ActionContext(type="file_write", cwd="/etc", sudo=False),
        )
        res = engine.evaluate_sync(ctx)
        assert res.decision == PolicyDecision.DENY

    def test_unknown_declarative_condition_key_fails_closed(self) -> None:
        with pytest.raises(ConfigurationError, match="Unknown policy condition key"):
            DeclarativePolicyRule.from_dict(
                {
                    "id": "bad-rule",
                    "decision": "DENY",
                    "when": {"target_env": "prod"},  # опечатка вместо resource.environment
                }
            )

    @pytest.mark.asyncio
    async def test_shell_command_starting_with_flow_is_not_bypassed(self) -> None:
        entry = MCPHostEntry(name="local", uri="local://", masked_uri="local://", transport="local", host="localhost")
        registry = MCPHostRegistry(entries=(entry,))
        server = MCPServer(registry=registry)
        auth_ctx, _ = await server._evaluate_policy_gate(
            entry=entry,
            tool_name="uniconn_run",
            action_type="command_execution",
            risk_tier=ActionRiskTier.TIER_2_DESTRUCTIVE,
            risk_reasons=("test",),
            command="flow:echo; rm -rf /",
            sudo=False,
            enforce_deny=False,
        )
        # AST-анализ не пропущен, несмотря на префикс "flow:" в shell-команде
        assert "rm" in (auth_ctx.action.ast.get("executables") or ())

    @pytest.mark.asyncio
    async def test_dry_run_flow_still_enforces_policy_deny(self) -> None:
        entry = MCPHostEntry(
            name="prod-01",
            uri="local://",
            masked_uri="local://",
            transport="local",
            host="localhost",
            groups=("prod",),
        )
        registry = MCPHostRegistry(entries=(entry,))
        deny_rule = DeclarativePolicyRule.from_dict(
            {
                "id": "deny-prod-flow",
                "decision": "DENY",
                "when": {"resource.environment": "prod"},
            }
        )
        engine = EmbeddedPolicyEngine(declarative_rules=[deny_rule])
        server = MCPServer(registry=registry, policy_engine=engine)

        @task
        async def step1(conn: Any) -> str:
            _ = conn
            return "ok"

        flow = Flow(name="deploy_prod", tasks=[step1])

        with pytest.raises(PolicyViolationError):
            await server._execute_flow_by_object(
                flow,
                tool_name="flow_deploy_prod",
                arguments={"target": "prod-01", "dry_run": True},
            )


class TestSec06WindowsPowerShellQuoting:
    """SEC-06: Экранирование Unicode-апострофов PowerShell."""

    @pytest.mark.parametrize("quote_char", ["'", "\u2018", "\u2019", "\u201a", "\u201b"])
    def test_ps_quote_escapes_all_powershell_single_quote_delimiters(self, quote_char: str) -> None:
        payload = f"foo{quote_char}; whoami"
        quoted = ps_quote(payload)
        assert quoted.startswith("'") and quoted.endswith("'")
        inner = quoted[1:-1]
        assert quote_char * 2 in inner

    def test_validate_windows_interpreter_blocks_unicode_quotes(self) -> None:
        with pytest.raises(ValueError):
            validate_windows_interpreter("powershell\u2019;calc")


class TestSec07SecretMaskingAndCheckpoints:
    """SEC-07: Маскирование Bearer/API-key/PEM/PVEAPIToken и чекпоинтов Flow."""

    @pytest.mark.parametrize(
        ("raw", "secret"),
        [
            ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig", "eyJhbGciOiJIUzI1NiJ9.payload.sig"),
            ("authorization: bearer lower_secret_jwt_456", "lower_secret_jwt_456"),
            ("PVEAPIToken=root@pam!ci=12345678-1234-1234-1234-1234567890ab", "12345678-1234-1234-1234-1234567890ab"),
            ("api_key: supersecretapikey999", "supersecretapikey999"),
            ("password: MyColonPassword42", "MyColonPassword42"),
            (
                "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAsecret\n-----END RSA PRIVATE KEY-----",
                "MIIEowIBAAKCAQEAsecret",
            ),
            (
                "-----begin private key-----\nlowercase_pem_secret_body\n-----end private key-----",
                "lowercase_pem_secret_body",
            ),
        ],
    )
    def test_secret_masking_filter_redacts_extended_formats(self, raw: str, secret: str) -> None:
        masked = SecretMaskingFilter._mask_string(raw)
        assert secret not in masked
        assert "***" in masked

    @pytest.mark.asyncio
    async def test_flow_checkpoint_masks_prior_outputs_and_return_values(self) -> None:
        store = FlowCheckpointStore()
        fake_res = MagicMock()
        fake_res.status = "success"
        fake_res.skip_reason = None
        fake_res.task_name = "fetch"
        fake_res.ok = True
        fake_res.return_value = {"token": "Bearer secret_jwt_token_123"}

        report = MagicMock()
        report.run_id = "run_test_masking"
        report.flow_name = "deploy"
        report.ok = True
        report.results = {"app-01": [fake_res]}

        cp = await store.record_from_report(
            report,
            targets=["app-01"],
            prior_outputs={"app-01": {"prev": {"header": "Authorization: Bearer prior_secret_token_999"}}},
        )
        dumped = json.dumps(cp.task_outputs_by_host)
        assert "secret_jwt_token_123" not in dumped
        assert "prior_secret_token_999" not in dumped
        assert "***" in dumped


class TestSec09GnmiDefaultTls:
    """SEC-09: GnmiTransport использует tls=True по умолчанию."""

    def test_gnmi_transport_defaults_to_tls_true(self) -> None:
        from uniconn.config.models import ConnectionConfig

        cfg = ConnectionConfig(transport="gnmi", host="10.0.0.1", port=9339)
        tr = GnmiTransport(cfg)
        assert tr._tls_mode is True


class TestSec11WorkerSyncScanPathTraversal:
    """SEC-11: Воркер sync_scan блокирует path traversal и абсолютные пути."""

    def test_worker_sync_scan_rejects_traversal_outside_base(self, tmp_path: Path) -> None:
        # Извлекаем функцию _op_sync_scan из WORKER_BOOTSTRAP_SCRIPT без запуска цикла чтения stdin
        tree = ast.parse(WORKER_BOOTSTRAP_SCRIPT)
        tree.body = [
            node
            for node in tree.body
            if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef))
        ]
        ns: dict[str, Any] = {}
        exec(compile(tree, "<worker_bootstrap>", "exec"), ns)

        outside_file = tmp_path / "outside.txt"
        outside_file.write_text("keep-me", encoding="utf-8")
        sync_root = tmp_path / "sync_root"
        sync_root.mkdir()

        with pytest.raises(ValueError, match="Path traversal blocked"):
            ns["_op_sync_scan"]({"path": str(sync_root), "delete_paths": ["../outside.txt"]})
        assert outside_file.exists()

        with pytest.raises(ValueError, match="Path traversal blocked"):
            ns["_op_sync_scan"]({"path": str(sync_root), "mkdirs": ["../escaped_dir"]})
        assert not (tmp_path / "escaped_dir").exists()

        with pytest.raises(ValueError, match="Absolute path not allowed"):
            ns["_op_sync_scan"]({"path": str(sync_root), "delete_paths": [str(outside_file)]})
        assert outside_file.exists()


class TestSec12NoRuntimeAssertsInLibrary:
    """SEC-12: Отсутствие runtime assert в исходном коде src/uniconn/."""

    def test_no_assert_statements_in_src_uniconn(self) -> None:
        src_root = Path(__file__).resolve().parents[3] / "src" / "uniconn"
        found: list[str] = []
        for py_file in sorted(src_root.rglob("*.py")):
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
            for node in ast.walk(tree):
                if isinstance(node, ast.Assert):
                    found.append(f"{py_file.relative_to(src_root)}:{node.lineno}")
        assert found == [], f"Runtime assert statements found in src/uniconn: {found}"
