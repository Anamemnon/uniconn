# tests/unit/core/test_policy_guardrails_and_ast.py
"""Unit-тесты для AST-анализатора команд (CommandASTParser) и Policy-as-Code Guardrails (uniconn.security)."""

from __future__ import annotations

import io
import json
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console

from examples.dashboard.handlers.api import _execute_endpoint_direct
from uniconn import (
    ActionRiskClassifier,
    ActionRiskTier,
    ApprovalManager,
    ApprovalRequiredError,
    CommandASTParser,
    CommandRequest,
    DeclarativePolicyRule,
    EmbeddedPolicyEngine,
    HITLPolicy,
    MCPHostEntry,
    MCPHostRegistry,
    MCPSecurityPolicy,
    MCPServer,
    OPAPolicyEngine,
    PolicyDecision,
    PolicyEngineUnavailableError,
    PolicyGuardrailConfig,
    PolicyGuardrailMiddleware,
    PolicyViolationError,
    Result,
    build_auth_context,
    create_policy_engine,
    is_within_maintenance_windows,
    load_declarative_rules,
)
from uniconn.cli.app import create_cli_app


class TestCommandASTParser:
    """Проверка декомпозиции shell-команд, раскрытия обёрток и детекции обфускации."""

    def test_splits_pipelines_chains_and_subshells(self) -> None:
        ast = CommandASTParser.parse("cd /var/log && ls -la | grep error; echo $(whoami)")
        assert ast.is_obfuscated is False
        assert "cd" in ast.verbs
        assert "ls" in ast.verbs
        assert "grep" in ast.verbs
        assert "echo" in ast.verbs
        assert "whoami" in ast.verbs
        assert ast.max_depth >= 1

    def test_unwraps_indirect_wrappers_find_xargs_sudo_sh(self) -> None:
        cmd = 'sudo timeout 10 sh -c "find /var/tmp -name \'*.old\' -exec rm -rf / \\;"'
        ast = CommandASTParser.parse(cmd)
        assert "find" in ast.verbs
        assert "rm" in ast.verbs
        assert ast.has_destructive_verbs is True
        rm_atoms = [c for c in ast.commands if c.executable == "rm"]
        assert len(rm_atoms) == 1
        assert "sudo" in rm_atoms[0].wrappers
        assert "find -exec" in rm_atoms[0].wrappers

    def test_unwraps_xargs_and_container_exec(self) -> None:
        ast = CommandASTParser.parse("cat targets.txt | xargs -n 1 docker exec -it web-01 kill -9 1")
        assert "cat" in ast.verbs
        assert "kill" in ast.verbs
        assert ast.has_destructive_verbs is True

    @pytest.mark.parametrize(
        "obfuscated_cmd",
        [
            "echo cm0gLXJmIC8= | base64 -d | sh",
            "printf '\\x72\\x6d -rf /' | bash",
            "$'\\x72\\x6d' -rf /tmp/test",
            "eval $(echo rm -rf /)",
            "C1=r; C2=m; $C1$C2 -rf /",
            "r'm' -rf /var/log",
            "r\\m -rf /var/log",
            "/bin/r? -rf /var/log",
            "PATH=/tmp/evil:$PATH ls",
            "LD_PRELOAD=/tmp/hook.so ls",
            "python3 -c 'import shutil; shutil.rmtree(\"/var/lib\")'",
            "awk 'BEGIN { system(\"rm -rf /tmp/x\") }'",
        ],
    )
    def test_detects_obfuscation_vectors(self, obfuscated_cmd: str) -> None:
        ast = CommandASTParser.parse(obfuscated_cmd)
        assert ast.is_obfuscated is True
        assert len(ast.obfuscation_reasons) >= 1

    def test_decodes_base64_payload_into_ast(self) -> None:
        # "rm -rf /" in base64 is "cm0gLXJmIC8="
        ast = CommandASTParser.parse("echo cm0gLXJmIC8= | base64 -d | sh")
        assert ast.is_obfuscated is True
        assert "rm" in ast.verbs
        assert ast.has_destructive_verbs is True

    def test_complexity_limits_exceeded(self) -> None:
        long_pipe = " | ".join(["cat"] * 10)
        ast = CommandASTParser.parse(long_pipe, max_pipeline_length=5)
        assert ast.complexity_exceeded is True

    def test_action_risk_classifier_blocks_obfuscated_commands(self) -> None:
        assessment = ActionRiskClassifier.classify_command(
            "echo cm0gLXJmIC8= | base64 -d | sh",
            is_production=False,
        )
        assert assessment.risk_tier == ActionRiskTier.TIER_3_FORBIDDEN
        assert any("base64" in r.lower() or "obfuscation" in r.lower() for r in assessment.reasons)


class TestEmbeddedAndDeclarativePolicyEngine:
    """Проверка встроенного движка политик, пресетов, окон обслуживания и YAML-правил."""

    def test_maintenance_window_evaluation(self) -> None:
        # 2026-11-11 is Wednesday (wed)
        wed_03_utc = datetime(2026, 11, 11, 3, 0, tzinfo=UTC)
        assert is_within_maintenance_windows(("wed 02:00-04:00",), now=wed_03_utc) is True
        assert is_within_maintenance_windows(("wed 04:30-06:00",), now=wed_03_utc) is False
        assert is_within_maintenance_windows(("22:00-04:00",), now=wed_03_utc) is True

    @pytest.mark.asyncio
    async def test_prod_guard_preset_requires_approval_outside_window(self) -> None:
        cfg = PolicyGuardrailConfig(
            enabled=True,
            preset="prod-guard",
            maintenance_window_active=False,
        )
        engine = create_policy_engine(cfg)
        cmd = "systemctl restart postgresql"
        ast = CommandASTParser.parse(cmd)
        ctx = build_auth_context(
            agent_id="sre-bot",
            role="operator",
            host_name="prod-db-01",
            environment="prod",
            is_production=True,
            tool_name="uniconn_run",
            command=cmd,
            ast=ast,
            sudo=True,
            risk_tier="MUTATING",
            maintenance_window_override=False,
        )
        res = await engine.evaluate(ctx)
        assert res.decision == PolicyDecision.REQUIRE_APPROVAL
        assert "prod_maintenance_window_guard" in res.rule_names

        # Second call hits TTL cache
        res_cached = await engine.evaluate(ctx)
        assert res_cached.cached is True
        assert res_cached.decision == PolicyDecision.REQUIRE_APPROVAL

    @pytest.mark.asyncio
    async def test_least_privilege_readonly_role_denied_on_mutation(self) -> None:
        cfg = PolicyGuardrailConfig(enabled=True, preset="least-privilege")
        engine = create_policy_engine(cfg)
        cmd = "apt-get install -y nginx"
        ast = CommandASTParser.parse(cmd)
        ctx = build_auth_context(
            agent_id="observer-bot",
            role="readonly",
            host_name="stage-web-01",
            environment="staging",
            is_production=False,
            tool_name="uniconn_run",
            command=cmd,
            ast=ast,
            risk_tier="MUTATING",
        )
        res = await engine.evaluate(ctx)
        assert res.decision == PolicyDecision.DENY
        assert "readonly_role_guard" in res.rule_names
        assert res.remediation_hint is not None

    @pytest.mark.asyncio
    async def test_declarative_yaml_policy_rules(self, tmp_path: Path) -> None:
        policy_yaml = tmp_path / "policy.yaml"
        policy_yaml.write_text(
            """
rules:
  - name: block_docker_prune_in_prod
    decision: DENY
    environments: [prod]
    denied_verbs: [docker]
    command_regex: "system\\\\s+prune"
    reason: "docker system prune is prohibited on production nodes"
    remediation_hint: "Remove unused images selectively during maintenance."
""",
            encoding="utf-8",
        )
        rules = load_declarative_rules(policy_yaml)
        assert len(rules) == 1
        assert isinstance(rules[0], DeclarativePolicyRule)

        cfg = PolicyGuardrailConfig(
            enabled=True,
            preset="default",
            policy_file=str(policy_yaml),
        )
        engine = create_policy_engine(cfg)
        cmd = "docker system prune -af"
        ctx = build_auth_context(
            host_name="prod-app-01",
            environment="prod",
            is_production=True,
            command=cmd,
            ast=CommandASTParser.parse(cmd),
            risk_tier="DESTRUCTIVE",
        )
        res = await engine.evaluate(ctx)
        assert res.decision == PolicyDecision.DENY
        assert "block_docker_prune_in_prod" in res.rule_names


class TestOPAPolicyEngine:
    """Проверка интеграции с Open Policy Agent (OPA REST API) и режима fail_closed."""

    @pytest.mark.asyncio
    async def test_opa_engine_evaluates_structured_response(self) -> None:
        class _OPAHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                inp = body.get("input", {})
                cmd = inp.get("action", {}).get("command", "")
                if "dropdb" in cmd:
                    resp: dict[str, Any] = {
                        "result": {
                            "allow": False,
                            "decision": "DENY",
                            "reasons": ["OPA Rego policy blocked dropdb"],
                            "remediation_hint": "Do not drop databases via AI agent",
                        }
                    }
                else:
                    resp = {"result": {"allow": True, "decision": "ALLOW"}}
                raw = json.dumps(resp).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        server = HTTPServer(("127.0.0.1", 0), _OPAHandler)
        port = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            opa = OPAPolicyEngine(f"http://127.0.0.1:{port}/v1/data/uniconn/authz")
            ctx_deny = build_auth_context(
                command="dropdb prod_main",
                ast=CommandASTParser.parse("dropdb prod_main"),
                risk_tier="DESTRUCTIVE",
            )
            res_deny = await opa.evaluate(ctx_deny)
            assert res_deny.decision == PolicyDecision.DENY
            assert "OPA Rego policy blocked dropdb" in res_deny.reasons

            ctx_allow = build_auth_context(
                command="uptime",
                ast=CommandASTParser.parse("uptime"),
                risk_tier="SAFE",
            )
            res_allow = await opa.evaluate(ctx_allow)
            assert res_allow.decision == PolicyDecision.ALLOW
        finally:
            server.shutdown()
            server.server_close()

    @pytest.mark.asyncio
    async def test_opa_fail_closed_and_safe_fallback(self) -> None:
        opa_strict = OPAPolicyEngine(
            "http://127.0.0.1:1/v1/data/uniconn/authz",
            timeout=0.2,
            fail_closed=True,
            allow_safe_on_failure=True,
        )
        ctx_mutating = build_auth_context(
            command="systemctl restart nginx",
            ast=CommandASTParser.parse("systemctl restart nginx"),
            risk_tier="MUTATING",
        )
        with pytest.raises(PolicyEngineUnavailableError):
            await opa_strict.evaluate(ctx_mutating)

        ctx_safe = build_auth_context(
            command="uptime",
            ast=CommandASTParser.parse("uptime"),
            risk_tier="SAFE",
        )
        res_safe = await opa_strict.evaluate(ctx_safe)
        assert res_safe.decision == PolicyDecision.ALLOW


class TestPolicyGuardrailMiddlewareAndMCPServer:
    """Проверка работы PolicyGuardrailMiddleware в CommandPipeline и MCPServer."""

    @pytest.mark.asyncio
    async def test_pipeline_middleware_denies_obfuscated_and_triggers_hitl(
        self, tmp_path: Path
    ) -> None:
        store_path = tmp_path / "approvals.json"
        mgr = ApprovalManager(
            policy=HITLPolicy(enabled=True, store_path=str(store_path)),
            store_path=store_path,
        )
        engine = EmbeddedPolicyEngine(preset="prod-guard")
        mw = PolicyGuardrailMiddleware(
            engine,
            approval_manager=mgr,
            host="prod-db-01",
            environment="prod",
            is_production=True,
            maintenance_window_override=False,
        )

        async def _terminal(req: CommandRequest) -> Result:
            return Result(
                exit_code=0,
                stdout="executed",
                stderr="",
                duration=0.01,
                command=req.command,
                host="prod-db-01",
            )

        # 1. Obfuscated command -> PolicyViolationError (DENY)
        with pytest.raises(PolicyViolationError) as exc_info:
            await mw(
                CommandRequest(
                    raw_command="echo cm0gLXJmIC8= | base64 -d | sh",
                    command="echo cm0gLXJmIC8= | base64 -d | sh",
                    exec_command="echo cm0gLXJmIC8= | base64 -d | sh",
                ),
                _terminal,
            )
        assert exc_info.value.violations
        assert "no_obfuscation" in exc_info.value.rule_names

        # 2. Mutating command in prod outside window -> ApprovalRequiredError
        with pytest.raises(ApprovalRequiredError) as appr_exc:
            await mw(
                CommandRequest(
                    raw_command="systemctl restart postgresql",
                    command="systemctl restart postgresql",
                    exec_command="systemctl restart postgresql",
                    sudo=True,
                ),
                _terminal,
            )
        appr_id = appr_exc.value.approval_id
        assert appr_id is not None

        # Approve and re-execute with approval_id
        await mgr.approve(appr_id, decided_by="sre_lead", reason="Emergency fix")
        res = await mw(
            CommandRequest(
                raw_command="systemctl restart postgresql",
                command="systemctl restart postgresql",
                exec_command="systemctl restart postgresql",
                sudo=True,
                approval_id=appr_id,
            ),
            _terminal,
        )
        assert res.ok is True
        assert res.stdout == "executed"

    @pytest.mark.asyncio
    async def test_mcp_server_evaluate_policy_tool_and_guardrails_resource(
        self, tmp_path: Path
    ) -> None:
        store_path = tmp_path / "mcp_approvals.json"
        pol = MCPSecurityPolicy(
            allow_write=True,
            allow_sudo=True,
            hitl=HITLPolicy(enabled=True, store_path=str(store_path)),
            guardrails=PolicyGuardrailConfig(
                enabled=True,
                preset="least-privilege",
                default_role="readonly",
            ),
        )
        entry = MCPHostEntry(
            name="prod-node",
            uri="local://",
            masked_uri="local://",
            transport="local",
            groups=("prod",),
        )
        registry = MCPHostRegistry(policy=pol, entries=[entry])
        server = MCPServer(registry=registry)

        # 1. Dry-run evaluation via uniconn_evaluate_policy
        eval_resp = await server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "uniconn_evaluate_policy",
                    "arguments": {
                        "target": "prod-node",
                        "command": "apt-get update && apt-get install -y curl",
                        "role": "readonly",
                    },
                },
            }
        )
        assert isinstance(eval_resp, dict)
        eval_data = json.loads(eval_resp["result"]["content"][0]["text"])
        assert eval_data["decision"] == "DENY"
        assert eval_data["allowed"] is False

        # 2. Executing mutating command as readonly role via uniconn_run returns structured PolicyViolationError
        run_resp = await server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "uniconn_run",
                    "arguments": {
                        "target": "prod-node",
                        "command": "apt-get install -y nginx",
                        "role": "readonly",
                    },
                },
            }
        )
        assert isinstance(run_resp, dict)
        assert run_resp["result"]["isError"] is True
        err_data = json.loads(run_resp["result"]["content"][0]["text"])
        assert err_data["error"] == "PolicyViolationError"
        assert err_data["decision"] == "DENY"
        assert "readonly_role_guard" in err_data["rule_names"]

        # 3. Read uniconn://security/guardrails resource
        res_resp = await server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "resources/read",
                "params": {"uri": "uniconn://security/guardrails"},
            }
        )
        assert isinstance(res_resp, dict)
        res_data = json.loads(res_resp["result"]["contents"][0]["text"])
        assert res_data["guardrails"]["preset"] == "least-privilege"


class TestCLIPolicyAndDashboardSandbox:
    """Проверка CLI-команд `uniconn policy parse/eval` и эндпоинта Dashboard `/api/policy`."""

    def test_cli_policy_parse_and_eval_json(self) -> None:
        buf = io.StringIO()
        con = Console(file=buf, force_terminal=False, color_system=None)
        app = create_cli_app(console=con)

        app(
            [
                "policy",
                "parse",
                "sudo find /tmp -name '*.tmp' -exec rm -f {} \\;",
                "--format",
                "json",
            ],
            result_action="return_value",
        )
        parsed_out = json.loads(buf.getvalue())
        assert "find" in parsed_out["verbs"]
        assert "rm" in parsed_out["verbs"]

        buf.seek(0)
        buf.truncate(0)
        app(
            [
                "policy",
                "eval",
                "systemctl restart postgresql",
                "--host",
                "prod-db-01",
                "--env",
                "prod",
                "--role",
                "operator",
                "--sudo",
                "--preset",
                "prod-guard",
                "--format",
                "json",
            ],
            result_action="return_value",
        )
        eval_out = json.loads(buf.getvalue())
        assert eval_out["decision"] == "REQUIRE_APPROVAL"
        assert eval_out["requires_approval"] is True

    def test_dashboard_policy_endpoint(self) -> None:
        res = _execute_endpoint_direct(
            "policy",
            {
                "command": "echo cm0gLXJmIC8= | base64 -d | sh",
                "preset": "prod-guard",
                "role": "operator",
                "host": "prod-db-01",
                "environment": "prod",
            },
        )
        assert res["ok"] is True
        assert res["decision"] == "DENY"
        assert res["ast"]["is_obfuscated"] is True
        assert "rm" in res["ast"]["verbs"]

    def test_quoted_executable_not_false_positive_and_wrapped_quote_splice_detected(self) -> None:
        clean_ast = CommandASTParser.parse('"/usr/bin/ls" -la /var/log')
        assert clean_ast.is_obfuscated is False
        assert clean_ast.executables == ("ls",)

        wrapped_splice = CommandASTParser.parse("sudo r'm' -rf /var/log/app")
        assert wrapped_splice.is_obfuscated is True
        assert "rm" in wrapped_splice.executables

        env_backslash = CommandASTParser.parse(r"FOO=1 r\m -rf /var/log/app")
        assert env_backslash.is_obfuscated is True
        assert "rm" in env_backslash.executables

    def test_nested_parentheses_subshell_and_base64_herestring(self) -> None:
        sub_inline = CommandASTParser.parse(
            'echo $(python3 -c \'import shutil; shutil.rmtree("/var/lib/postgresql")\')'
        )
        assert sub_inline.has_subshells is True
        assert sub_inline.has_inline_script is True
        assert sub_inline.is_obfuscated is True
        assert "python3" in sub_inline.executables

        herestring_b64 = CommandASTParser.parse("base64 -d <<< cm0gLXJmIC8= | sh")
        assert herestring_b64.is_obfuscated is True
        assert "rm" in herestring_b64.executables

    @pytest.mark.asyncio
    async def test_mcp_evaluate_unregistered_prod_target_and_declarative_flow_rule(self) -> None:
        rules = load_declarative_rules(
            {
                "rules": [
                    {
                        "id": "block-db-flow-for-junior",
                        "decision": "DENY",
                        "flow_name": "db_migrate",
                        "role": "junior-ai",
                        "message": "Junior AI cannot run db_migrate flow",
                    }
                ]
            }
        )
        engine = EmbeddedPolicyEngine(preset="prod-guard", declarative_rules=rules)
        ctx = build_auth_context(
            role="junior-ai",
            host="prod-db-99",
            environment="prod",
            tool_name="uniconn_run_flow",
            flow_name="db_migrate",
            flow_tasks=("backup", "migrate"),
            risk_tier="MUTATING",
        )
        res = await engine.evaluate(ctx)
        assert res.decision == PolicyDecision.DENY
        assert "block-db-flow-for-junior" in res.rule_names

        policy = MCPSecurityPolicy(
            guardrails=PolicyGuardrailConfig(enabled=True, preset="prod-guard"),
        )
        entry = MCPHostEntry(
            name="dev-box",
            uri="local://",
            masked_uri="local://",
            transport="local",
            groups=("dev",),
        )
        registry = MCPHostRegistry(policy=policy, entries=[entry])
        server = MCPServer(registry=registry)
        eval_resp = await server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 99,
                "method": "tools/call",
                "params": {
                    "name": "uniconn_evaluate_policy",
                    "arguments": {
                        "target": "prod-db-99",
                        "command": "systemctl restart nginx",
                        "sudo": True,
                        "role": "operator",
                    },
                },
            }
        )
        assert isinstance(eval_resp, dict)
        eval_data = json.loads(eval_resp["result"]["content"][0]["text"])
        assert eval_data["auth_context"]["resource"]["host"] == "prod-db-99"
        assert eval_data["auth_context"]["resource"]["environment"] == "production"
        assert eval_data["decision"] == "REQUIRE_APPROVAL"

    @pytest.mark.asyncio
    async def test_policy_guardrail_middleware_attach_to_local_connection(self) -> None:
        from uniconn import Connection

        async with Connection.from_uri("local://") as conn:
            mw = PolicyGuardrailMiddleware(
                conn,
                config=PolicyGuardrailConfig(preset="least-privilege", default_role="readonly"),
            ).attach()
            assert mw in conn.pipeline.middlewares
            res = await conn.run("echo policy-ok")
            assert res.ok is True
            assert "policy-ok" in res.stdout

            with pytest.raises(PolicyViolationError) as exc_info:
                await conn.run("rm -rf /tmp/nonexistent_policy_test")
            assert len(exc_info.value.serialized_violations()) >= 1

