"""Unit-тесты для проверки декомпозиции модулей, обработки сбоев и усиления безопасности Phase 4."""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock, MagicMock

import pytest

from uniconn import Connection
from uniconn.core._middlewares import RetryMiddleware
from uniconn.core.pipeline import (
    _ACTIVE_DIAGNOSTIC_PROBE,
    CommandRequest,
    HITLApprovalMiddleware,
    format_command,
)
from uniconn.core.python_worker import (
    WORKER_BOOTSTRAP_SCRIPT,
    WORKER_RPC_PREFIX,
    CallableSerializer,
    RemotePythonWorker,
)
from uniconn.exceptions import ConnectionError as UniconnConnectionError
from uniconn.exceptions import ExecutionError
from uniconn.mcp.models import ActionRiskTier
from uniconn.mcp.risk_classifier import ActionRiskClassifier
from uniconn.mcp.server import MCPServer
from uniconn.result import Result
from uniconn.security.ast_parser import normalize_target_path
from uniconn.security.engine import EmbeddedPolicyEngine, OPAPolicyEngine
from uniconn.services.files import DirectorySynchronizer, FileOperationsService


class TestPhase4ReExports:
    """Проверка обратной совместимости канонических реэкспортов после декомпозиции."""

    def test_canonical_module_exports(self) -> None:
        assert isinstance(WORKER_BOOTSTRAP_SCRIPT, str) and WORKER_RPC_PREFIX in WORKER_BOOTSTRAP_SCRIPT
        assert CallableSerializer is not None
        assert _ACTIVE_DIAGNOSTIC_PROBE.get() is False
        assert CommandRequest is not None
        assert HITLApprovalMiddleware is not None
        assert format_command(["echo", "hello world"]) == "echo 'hello world'"
        assert DirectorySynchronizer is not None
        assert FileOperationsService is not None
        assert normalize_target_path("/tmp/../etc/passwd") == "/etc/passwd"
        assert EmbeddedPolicyEngine is not None
        assert OPAPolicyEngine is not None
        assert MCPServer is not None


class TestPhase4WorkerAndRetryHardening:
    """Проверка сброса состояния воркера при битом JSON-RPC и логирования сбоя disconnect в RetryMiddleware."""

    @pytest.mark.asyncio
    async def test_send_over_pipe_resets_worker_on_malformed_json(self) -> None:
        conn = Connection.from_uri("local://")
        worker = RemotePythonWorker(conn)

        shell_proc = MagicMock()
        shell_proc.stdin = MagicMock()
        shell_proc.stdin.write = MagicMock()
        shell_proc.stdin.drain = AsyncMock()
        shell_proc.stdout = MagicMock()
        shell_proc.stdout.read = AsyncMock(return_value=f"{WORKER_RPC_PREFIX}{{not-valid-json\n".encode())
        shell_proc.close = MagicMock()
        shell_proc.wait_closed = AsyncMock()

        worker._shell_proc = shell_proc
        worker._active = True

        with pytest.raises(ExecutionError, match="Malformed JSON-RPC frame"):
            await worker._send_over_pipe({"id": 1, "op": "ping"}, timeout=2.0)

        assert worker._shell_proc is None
        assert worker._active is False
        shell_proc.close.assert_called_once()
        shell_proc.wait_closed.assert_awaited_once()
        await conn.close()

    @pytest.mark.asyncio
    async def test_retry_middleware_logs_disconnect_error_and_continues_retry(
        self, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from tenacity import wait_none

        monkeypatch.setattr("uniconn.core._middlewares.wait_exponential_jitter", lambda **_kw: wait_none())
        conn = Connection.from_uri("local://", retry_attempts=2)
        conn.logger.setLevel(logging.DEBUG)
        mock_transport = MagicMock()
        mock_transport.is_connected = True
        mock_transport.connect = AsyncMock()
        mock_transport.disconnect = AsyncMock(side_effect=OSError("broken socket"))
        conn.swap_transport(mock_transport)

        mw = RetryMiddleware(conn)
        req = CommandRequest(
            raw_command="uptime",
            command="uptime",
            exec_command="uptime",
        )
        attempts = 0

        async def _call_next(_r: CommandRequest) -> Result:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise UniconnConnectionError("transient drop", host="localhost")
            return Result(exit_code=0, stdout="up\n", stderr="", duration=0.01, command="uptime", host="localhost")

        with caplog.at_level(logging.DEBUG):
            res = await mw(req, _call_next)

        assert res.exit_code == 0
        assert res.text == "up"
        assert attempts == 2
        conn.transport.disconnect.assert_awaited_once()
        assert any(
            "command.retry_disconnect_failed" in r.getMessage() or "broken socket" in r.getMessage()
            for r in caplog.records
        )


class TestPhase4RiskClassifierHardening:
    """Проверка усиленных правил ActionRiskClassifier против обёрток и path traversal."""

    @pytest.mark.parametrize(
        "cmd",
        [
            'su - root -c "rm -rf /"',
            "sudo rm -r -f /tmp/..",
            "doas rm --recursive -f /",
            "cat <(mkfs.ext4 /dev/sdb1)",
        ],
    )
    def test_classify_command_enforces_tier_3_forbidden(self, cmd: str) -> None:
        res = ActionRiskClassifier.classify_command(cmd)
        assert res.risk_tier == ActionRiskTier.TIER_3_FORBIDDEN


class TestReviewRefinements:
    """Регрессионные тесты по результатам ревью изменений (политики, HTTP-клиенты, sudo и provisioning)."""

    def test_declarative_policy_rule_path_regex_normalizes_and_checks_ast_targets(self) -> None:
        from uniconn.security._policy_rules import DeclarativePolicyRule
        from uniconn.security.models import PolicyDecision, build_auth_context

        rule = DeclarativePolicyRule.from_dict(
            {
                "id": "deny-etc-shadow",
                "decision": "DENY",
                "message": "Access to /etc/shadow is denied",
                "when": {"path_regex": r"^/etc/shadow$"},
            }
        )
        # 1. Shell command with path traversal in AST targets
        ctx_cmd = build_auth_context(command="cat /var/log/../../etc/shadow")
        res_cmd = rule.evaluate(ctx_cmd)
        assert res_cmd is not None
        assert res_cmd.decision == PolicyDecision.DENY

        # 2. File tool with path traversal in resource.target_path
        ctx_file = build_auth_context(
            tool_name="uniconn_read_file",
            command="",
            path="/tmp/../etc/shadow",
        )
        res_file = rule.evaluate(ctx_file)
        assert res_file is not None
        assert res_file.decision == PolicyDecision.DENY

    @pytest.mark.asyncio
    async def test_restconf_client_closes_session_when_root_discovery_fails(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from uniconn.transports.network.restconf import RestconfClient

        fake_session = MagicMock()
        fake_session.close = AsyncMock()
        client = RestconfClient(base_url="https://10.0.0.1", discover_root=True)
        monkeypatch.setattr(client, "_build_session", lambda **_kw: fake_session)

        async def _boom() -> str:
            raise UniconnConnectionError("discovery failed", host="10.0.0.1")

        monkeypatch.setattr(client, "_discover_restconf_root", _boom)

        with pytest.raises(UniconnConnectionError, match="discovery failed"):
            await client.connect()

        assert client.is_connected is False
        assert client.session is None
        fake_session.close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_redfish_try_create_session_maps_timeout_error(self) -> None:
        from uniconn.exceptions import TimeoutError as UniconnTimeoutError
        from uniconn.transports.bmc.redfish.client import RedfishHttpClient

        client = RedfishHttpClient(
            base_url="https://10.0.0.1",
            username="admin",
            password="secret",
            verify=False,
            multiplexed=True,
            auth_pref="auto",
            default_timeout=5.0,
        )
        fake_session = MagicMock()
        fake_session.post = AsyncMock(side_effect=TimeoutError("session post timed out"))

        with pytest.raises(UniconnTimeoutError, match="timed out"):
            await client.try_create_redfish_session(fake_session, "admin", "secret", timeout=2.0)

    @pytest.mark.asyncio
    async def test_sudo_middleware_does_not_cache_nopasswd_on_generic_sudo_error(self) -> None:
        from uniconn.core._middlewares import SudoMiddleware

        conn = Connection.from_uri("ssh://admin:pass@10.0.0.1?sudo_password=secret")
        mw = SudoMiddleware(conn)
        req = CommandRequest(
            raw_command="id",
            command="id",
            exec_command="id",
            sudo=True,
            sudo_user="root",
        )

        async def _call_next(_r: CommandRequest) -> Result:
            return Result(
                exit_code=1,
                stdout="",
                stderr="sudo: unknown user: root\n",
                duration=0.01,
                command="sudo -n -u root -- id",
                host="10.0.0.1",
            )

        res = await mw(req, _call_next)
        assert res.exit_code == 1
        assert getattr(conn, "_sudo_nopasswd_cache", {}).get("root") is None

    @pytest.mark.asyncio
    async def test_provisioning_validates_username_and_groups(self) -> None:
        conn = Connection.from_uri("local://", dry_run=True)
        with pytest.raises(ValueError, match="Invalid system username"):
            await conn.state.ensure_authorized_key("root/../../etc", "ssh-ed25519 AAAAC3Nza...")
        with pytest.raises(ValueError, match="Invalid system username"):
            await conn.state.ensure_user("alice", groups=["docker,sudo"])
        await conn.close()

