# src/uniconn/mcp/_tools_hosts.py
"""MCP-инструменты управления хостами, выполнения команд и сбора фактов."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from .._logging import SecretMaskingFilter
from ..parsing import ParseSpec
from ..security.ast_parser import CommandASTParser
from ..security.models import PolicyDecision
from ..services.facts_models import HostFacts, diff_facts
from ._server_gates import MCPServerGatesMixin, _sanitize_json_value
from .hitl import ActionRiskClassifier
from .models import MCPHostEntry, MCPSecurityPolicy

if TYPE_CHECKING:
    from .registry import MCPHostRegistry

_logger = logging.getLogger("uniconn.mcp.server")


class MCPHostToolsMixin(MCPServerGatesMixin):
    """Миксин MCP-инструментов для хостов (``list_hosts``, ``ping``, ``run``, ``facts``)."""

    if TYPE_CHECKING:
        registry: MCPHostRegistry

        @property
        def policy(self) -> MCPSecurityPolicy: ...

    async def _tool_list_hosts(self, arguments: dict[str, Any]) -> dict[str, Any]:
        group = arguments.get("group")
        entries = self.registry.list_entries(group=str(group) if group else None)
        return {
            "hosts": [e.to_public_dict() for e in entries],
            "groups": self.registry.list_groups(),
            "security_policy": self.policy.to_summary_dict(),
        }

    async def _tool_ping(self, arguments: dict[str, Any]) -> dict[str, Any]:
        raw_targets = arguments.get("targets")
        if not raw_targets:
            raise ValueError("Parameter 'targets' is required")
        timeout = float(arguments.get("timeout", 5.0))
        entries = self.registry.resolve_targets(raw_targets)

        async def _ping_one(entry: MCPHostEntry) -> tuple[str, dict[str, Any]]:
            try:
                async with self.registry.create_connection(entry) as conn:
                    ping_res = await conn.ping(timeout=timeout)
                    return entry.name, {
                        "alive": ping_res.alive,
                        "reachable": ping_res.alive,
                        "latency_ms": round(ping_res.latency_ms, 3),
                        "transport": ping_res.transport,
                        "error": SecretMaskingFilter._mask_string(ping_res.error)
                        if ping_res.error
                        else None,
                    }
            except Exception as exc:
                return entry.name, {
                    "alive": False,
                    "reachable": False,
                    "latency_ms": 0.0,
                    "transport": entry.transport,
                    "error": SecretMaskingFilter._mask_string(str(exc)),
                }

        pairs = await asyncio.gather(*(_ping_one(e) for e in entries))
        return {"results": dict(pairs)}

    async def _tool_run(self, arguments: dict[str, Any]) -> dict[str, Any]:
        target = arguments.get("target")
        command = arguments.get("command")
        if not isinstance(target, str) or not target.strip():
            raise ValueError("Parameter 'target' is required")
        if not isinstance(command, str) or not command.strip():
            raise ValueError("Parameter 'command' must be a non-empty string")

        sudo = bool(arguments.get("sudo", False))
        hitl_override_ok = self.policy.hitl.enabled and self.policy.hitl.allow_operator_override
        if sudo and not self.policy.allow_sudo and not hitl_override_ok:
            raise PermissionError(
                "Privileged execution (sudo=True) is disabled by MCP security policy "
                "(start server with --allow-sudo to enable)."
            )

        entry = self.registry.get_entry(target)
        is_prod = entry.is_production(self.policy.hitl.prod_groups)
        parsed_ast = CommandASTParser.parse(
            command,
            max_depth=self.policy.guardrails.max_ast_depth,
            max_pipeline_length=self.policy.guardrails.max_pipeline_length,
        )
        assessment = ActionRiskClassifier.classify_command(
            command,
            sudo=sudo,
            is_production=is_prod,
            policy=self.policy.hitl,
            ast=parsed_ast,
        )
        timeout = float(arguments.get("timeout", 30.0))
        cwd = arguments.get("cwd")
        cwd_str = cwd.strip() if isinstance(cwd, str) and cwd.strip() else None
        raw_agent_id = arguments.get("agent_id")
        raw_role = arguments.get("role")

        self._assert_not_forbidden(assessment, f"Command {command!r} on host {entry.name!r}")

        _, policy_eval = await self._evaluate_policy_gate(
            entry=entry,
            tool_name="uniconn_run",
            risk_tier=assessment.risk_tier,
            risk_reasons=assessment.reasons,
            command=command,
            ast=parsed_ast,
            sudo=sudo,
            cwd=cwd_str,
            agent_id=str(raw_agent_id) if raw_agent_id else None,
            role=str(raw_role) if raw_role else None,
            enforce_deny=True,
        )

        diagnose = bool(arguments.get("diagnose", True))
        raw_parse = arguments.get("parse", True)
        parse_spec: ParseSpec
        if raw_parse is True:
            parse_spec = "auto"
        elif raw_parse is False or raw_parse is None:
            parse_spec = None
        else:
            parse_spec = str(raw_parse)

        approval_id = arguments.get("approval_id")
        wait_for_appr = bool(arguments.get("wait_for_approval", self.policy.hitl.wait_for_approval))
        policy_requires_appr = policy_eval.decision == PolicyDecision.REQUIRE_APPROVAL
        needs_approval = policy_requires_appr or (
            self.policy.hitl.enabled
            and (assessment.requires_approval or (sudo and not self.policy.allow_sudo))
        )
        merged_reasons = self._merge_reasons(assessment.reasons, policy_eval.reasons)
        hmac_params = {"command": command, "sudo": sudo, "cwd": cwd_str or ""}

        consumed_req, pending_payload = await self._resolve_hitl_gate(
            entry=entry,
            tool_name="uniconn_run",
            risk_tier=assessment.risk_tier,
            risk_reasons=tuple(merged_reasons),
            requires_approval=needs_approval,
            approval_id=str(approval_id) if approval_id is not None else None,
            wait_for_approval=wait_for_appr,
            command=command,
            sudo=sudo,
            cwd=cwd_str,
            parameters=hmac_params,
            agent_id=str(raw_agent_id) if raw_agent_id else None,
        )
        if pending_payload is not None:
            return pending_payload

        run_kwargs: dict[str, Any] = {}
        if cwd_str:
            run_kwargs["cwd"] = cwd_str

        async with self.registry.create_connection(entry) as conn:
            res = await conn.run(
                command,
                timeout=timeout,
                sudo=sudo,
                parse=parse_spec,
                diagnose=diagnose,
                raise_on_error=False,
                **run_kwargs,
            )
            parsed_data: Any = None
            if parse_spec is not None:
                try:
                    parsed_data = _sanitize_json_value(res.parsed)
                except (ValueError, KeyError, TypeError, RuntimeError) as parse_exc:
                    _logger.debug("Ignoring output parse failure in uniconn_run: %s", parse_exc)
                    parsed_data = None

            payload: dict[str, Any] = {
                "host": res.host or entry.name,
                "command": SecretMaskingFilter._mask_string(res.command),
                "ok": res.ok,
                "exit_code": res.exit_code,
                "duration_ms": round(res.duration * 1000, 3),
                "stdout": SecretMaskingFilter._mask_string(res.stdout),
                "stderr": SecretMaskingFilter._mask_string(res.stderr),
                "parsed": parsed_data,
                "risk_tier": assessment.risk_tier.value,
                "policy_decision": policy_eval.decision.value,
                "dry_run": self.policy.dry_run,
            }
            if res.diagnostic is not None:
                payload["diagnostic"] = _sanitize_json_value(res.diagnostic.to_dict())
            if consumed_req is not None:
                payload["approval"] = self._serialize_approval(consumed_req)
            return payload

    async def _tool_gather_facts(self, arguments: dict[str, Any]) -> dict[str, Any]:
        target = arguments.get("target")
        if not isinstance(target, str) or not target.strip():
            raise ValueError("Parameter 'target' is required")
        timeout = float(arguments.get("timeout", 15.0))

        async with self.registry.create_connection(target) as conn:
            facts = await conn.gather_facts(refresh=True, timeout=timeout)
            return {
                "target": target,
                "facts": _sanitize_json_value(facts.to_dict()),
            }

    async def _tool_diff_facts(self, arguments: dict[str, Any]) -> dict[str, Any]:
        raw_targets = arguments.get("targets")
        group = arguments.get("group")
        entries = self.registry.resolve_targets(
            raw_targets,
            group=str(group) if group else None,
        )
        if len(entries) < 2:
            raise ValueError("uniconn_diff_facts requires at least 2 target hosts to compare")

        async def _gather_one(entry: MCPHostEntry) -> tuple[str, HostFacts]:
            async with self.registry.create_connection(entry) as conn:
                return entry.name, await conn.gather_facts(refresh=True)

        gathered_pairs = await asyncio.gather(*(_gather_one(e) for e in entries))
        facts_by_host: dict[str, HostFacts] = dict(gathered_pairs)

        report = diff_facts(facts_by_host)
        return _sanitize_json_value(
            {
                "hosts": list(facts_by_host.keys()),
                "is_identical": not report.has_drift,
                **report.to_dict(),
            }
        )


__all__ = ["MCPHostToolsMixin"]
