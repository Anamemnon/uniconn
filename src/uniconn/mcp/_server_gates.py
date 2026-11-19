# src/uniconn/mcp/_server_gates.py
"""Шлюзы Policy-as-Code, HITL и вспомогательные функции сериализации для MCPServer."""

from __future__ import annotations

import contextlib
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from .._logging import SecretMaskingFilter
from ..exceptions import ApprovalRejectedError, PolicyViolationError
from ..result import _serialize_parsed_value
from ..security.ast_parser import CommandASTParser, ParsedCommandAST
from ..security.models import (
    AuthContext,
    PolicyDecision,
    PolicyEvaluationResult,
    build_auth_context,
)
from .models import (
    ActionRiskTier,
    ApprovalRequest,
    ApprovalStatus,
    MCPHostEntry,
    MCPSecurityPolicy,
)

if TYPE_CHECKING:
    from ..security.engine import PolicyEngine
    from .hitl import ApprovalManager
    from .registry import MCPHostRegistry


def _sanitize_json_value(val: Any) -> Any:
    """Преобразовать значение в JSON-совместимый тип и замаскировать секреты в строках."""
    serialized = _serialize_parsed_value(val)
    if isinstance(serialized, str):
        return SecretMaskingFilter._mask_string(serialized)
    if isinstance(serialized, list):
        return [_sanitize_json_value(item) for item in serialized]
    if isinstance(serialized, dict):
        return {str(k): _sanitize_json_value(v) for k, v in serialized.items()}
    return serialized


def _build_pending_approval_payload(
    req: ApprovalRequest,
    *,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Сформировать ответ со статусом PENDING_APPROVAL для двухфазного протокола MCP."""
    payload: dict[str, Any] = {
        "status": "PENDING_APPROVAL",
        "ok": False,
        "requires_approval": True,
        "approval_id": req.approval_id,
        "target_host": req.target_host,
        "tool_name": req.tool_name,
        "risk_tier": req.risk_tier.value,
        "risk_reasons": list(req.risk_reasons),
        "diff": req.diff,
        "expires_at": req.expires_at.isoformat(),
        "approval": req.to_public_dict(),
        "next_step": (
            f"Action requires human operator approval (id={req.approval_id}). "
            f"Operator can run 'uniconn approval approve {req.approval_id}' or approve in the Dashboard. "
            f"Then call 'uniconn_wait_approval' or re-invoke {req.tool_name!r} with approval_id={req.approval_id!r}."
        ),
    }
    if extra:
        payload.update(extra)
    return payload


def _parse_tags_list(raw_tags: Any) -> list[str] | None:
    """Нормализовать аргумент ``tags`` (строка через запятую или последовательность) в список строк."""
    if isinstance(raw_tags, str) and raw_tags.strip():
        return [t.strip() for t in raw_tags.split(",") if t.strip()]
    if isinstance(raw_tags, Sequence) and not isinstance(raw_tags, str):
        return [str(t).strip() for t in raw_tags if str(t).strip()]
    return None


class MCPServerGatesMixin:
    """Миксин проверки Policy-as-Code и HITL-согласования для ``MCPServer``."""

    if TYPE_CHECKING:
        registry: MCPHostRegistry
        approval_manager: ApprovalManager
        policy_engine: PolicyEngine

        @property
        def policy(self) -> MCPSecurityPolicy: ...

    def _resolve_flow_targets_and_tags(
        self,
        arguments: dict[str, Any],
        *,
        default_targets: Any = None,
        default_group: str | None = None,
        default_tags: list[str] | None = None,
    ) -> tuple[list[MCPHostEntry], str | None, list[str] | None]:
        """Разрешить целевые хосты, группу и теги из аргументов MCP-инструмента Flow."""
        raw_targets = arguments.get("targets") or arguments.get("target") or default_targets
        if isinstance(raw_targets, str) and "," in raw_targets:
            raw_targets = [t.strip() for t in raw_targets.split(",") if t.strip()]
        raw_group = arguments.get("group") if "group" in arguments else default_group
        group_str = str(raw_group).strip() if raw_group else None
        entries = self.registry.resolve_targets(raw_targets, group=group_str)
        raw_tags = arguments.get("tags") if "tags" in arguments else default_tags
        tags_list = _parse_tags_list(raw_tags)
        return entries, group_str, tags_list

    async def _evaluate_policy_gate(
        self,
        *,
        entry: MCPHostEntry | None = None,
        entries: Sequence[MCPHostEntry] = (),
        target_host: str | None = None,
        tool_name: str,
        action_type: str | None = None,
        risk_tier: ActionRiskTier,
        risk_reasons: Sequence[str],
        command: str | None = None,
        ast: ParsedCommandAST | None = None,
        sudo: bool = False,
        cwd: str | None = None,
        path: str | None = None,
        flow_name: str | None = None,
        flow_tasks: Sequence[str] = (),
        agent_id: str | None = None,
        role: str | None = None,
        allow_role_override: bool = False,
        enforce_deny: bool = True,
    ) -> tuple[AuthContext, PolicyEvaluationResult]:
        """Построить ``AuthContext`` и вычислить решение активного ``PolicyEngine``."""
        guardrails = self.policy.guardrails
        primary_entry = entry or (entries[0] if entries else None)
        if entries and len(entries) > 1:
            host_name = ",".join(e.name for e in entries)
            groups: list[str] = []
            for item in entries:
                for g in item.groups:
                    if g not in groups:
                        groups.append(g)
            is_prod = any(e.is_production(self.policy.hitl.prod_groups) for e in entries)
            transport = entries[0].transport
            host_addr = entries[0].host
            env_name = "prod" if is_prod else "default"
        elif primary_entry is not None:
            host_name = primary_entry.name
            groups = list(primary_entry.groups)
            is_prod = primary_entry.is_production(self.policy.hitl.prod_groups)
            transport = primary_entry.transport
            host_addr = primary_entry.host
            raw_env = str(
                primary_entry.raw_config.get("env")
                or primary_entry.raw_config.get("environment")
                or ""
            ).strip()
            env_name = raw_env or ("prod" if is_prod else "default")
        else:
            host_name = target_host.strip() if isinstance(target_host, str) and target_host.strip() else "local"
            groups = []
            is_prod = any(tok in host_name.lower() for tok in ("prod", "prd"))
            transport = "local"
            host_addr = None
            env_name = "prod" if is_prod else "default"

        parsed_ast = ast
        if parsed_ast is None and command and not command.startswith("flow:"):
            parsed_ast = CommandASTParser.parse(
                command,
                max_depth=guardrails.max_ast_depth,
                max_pipeline_length=guardrails.max_pipeline_length,
            )

        eff_agent_id = (
            str(agent_id).strip()
            if isinstance(agent_id, str) and str(agent_id).strip()
            else guardrails.default_agent_id
        )
        eff_role = (
            str(role).strip()
            if allow_role_override and isinstance(role, str) and str(role).strip()
            else guardrails.default_role
        )
        auth_ctx = build_auth_context(
            agent_id=eff_agent_id,
            role=eff_role,
            host_name=host_name,
            host_address=host_addr,
            transport=transport,
            groups=groups,
            environment=env_name,
            is_production=is_prod,
            tool_name=tool_name,
            action_type=action_type,
            command=command,
            ast=parsed_ast,
            sudo=sudo,
            cwd=cwd,
            path=path,
            flow_name=flow_name,
            flow_tasks=flow_tasks,
            risk_tier=risk_tier.value,
            risk_reasons=risk_reasons,
            maintenance_windows=guardrails.maintenance_windows,
            maintenance_window_override=guardrails.maintenance_window_active,
        )
        if not guardrails.enabled:
            eval_res = PolicyEvaluationResult(
                decision=PolicyDecision.ALLOW,
                reasons=(),
                violations=(),
                engine_name="disabled",
            )
            return auth_ctx, eval_res

        eval_res = await self.policy_engine.evaluate(auth_ctx)
        if enforce_deny and eval_res.decision == PolicyDecision.DENY:
            reasons_str = "; ".join(eval_res.reasons) or "Blocked by Policy-as-Code guardrail"
            raise PolicyViolationError(
                f"Policy violation on host {host_name!r} ({tool_name}): {reasons_str}",
                command=command,
                host=host_name,
                violations=[v.to_dict() for v in eval_res.violations],
                rule_names=eval_res.rule_names,
                remediation_hint=eval_res.remediation_hint,
            )
        return auth_ctx, eval_res

    async def _resolve_hitl_gate(
        self,
        *,
        entry: MCPHostEntry | None = None,
        target_host: str | None = None,
        tool_name: str,
        allowed_tool_names: Sequence[str] = (),
        risk_tier: ActionRiskTier,
        risk_reasons: tuple[str, ...],
        requires_approval: bool,
        approval_id: str | None,
        wait_for_approval: bool,
        command: str | None = None,
        sudo: bool = False,
        cwd: str | None = None,
        parameters: dict[str, Any] | None = None,
        diff: str | None = None,
        agent_id: str | None = None,
        pending_extra: dict[str, Any] | None = None,
    ) -> tuple[ApprovalRequest | None, dict[str, Any] | None]:
        """Выполнить проверку HITL-шлюза: вернуть (consumed_request, pending_payload)."""
        host_label = target_host or (entry.name if entry is not None else "fleet")
        if approval_id is not None and str(approval_id).strip():
            appr_key = str(approval_id).strip()
            effective_tool = tool_name
            if allowed_tool_names:
                with contextlib.suppress(KeyError):
                    existing_req = await self.approval_manager.get_request(appr_key)
                    if existing_req.tool_name in allowed_tool_names:
                        effective_tool = existing_req.tool_name
            consumed = await self.approval_manager.verify_and_consume(
                appr_key,
                target_host=host_label,
                tool_name=effective_tool,
                command=command,
                sudo=sudo,
                cwd=cwd,
                parameters=parameters,
                diff=diff,
            )
            return consumed, None

        if not requires_approval:
            return None, None

        req = await self.approval_manager.create_request(
            target_host=host_label,
            tool_name=tool_name,
            risk_tier=risk_tier,
            risk_reasons=risk_reasons,
            command=command,
            sudo=sudo,
            cwd=cwd,
            parameters=parameters,
            diff=diff,
            agent_id=agent_id,
        )
        if req.status == ApprovalStatus.APPROVED:
            consumed = await self.approval_manager.verify_and_consume(
                req.approval_id,
                target_host=host_label,
                tool_name=tool_name,
                command=command,
                sudo=sudo,
                cwd=cwd,
                parameters=parameters,
                diff=diff,
            )
            return consumed, None
        if req.status == ApprovalStatus.REJECTED:
            raise ApprovalRejectedError(
                f"Action rejected by operator ({req.decided_by or 'operator'}): "
                f"{req.decision_reason or 'Rejected'}",
                approval_id=req.approval_id,
                decided_by=req.decided_by,
                decision_reason=req.decision_reason,
                approval_request=req,
                command=command,
                host=host_label,
            )

        if wait_for_approval:
            decided = await self.approval_manager.wait_for_decision(
                req.approval_id,
                timeout=self.policy.hitl.wait_timeout_seconds,
            )
            if decided.status == ApprovalStatus.APPROVED:
                consumed = await self.approval_manager.verify_and_consume(
                    decided.approval_id,
                    target_host=host_label,
                    tool_name=tool_name,
                    command=command,
                    sudo=sudo,
                    cwd=cwd,
                    parameters=parameters,
                    diff=diff,
                )
                return consumed, None
            if decided.status == ApprovalStatus.REJECTED:
                raise ApprovalRejectedError(
                    f"Action rejected by operator ({decided.decided_by or 'operator'}): "
                    f"{decided.decision_reason or 'Rejected'}",
                    approval_id=decided.approval_id,
                    decided_by=decided.decided_by,
                    decision_reason=decided.decision_reason,
                    approval_request=decided,
                    command=command,
                    host=host_label,
                )
            return None, _build_pending_approval_payload(decided, extra=pending_extra)

        return None, _build_pending_approval_payload(req, extra=pending_extra)

    @staticmethod
    def _merge_reasons(primary: Sequence[str], secondary: Sequence[str]) -> list[str]:
        """Объединить списки причин без дубликатов с сохранением порядка."""
        merged = list(primary)
        for reason in secondary:
            if reason not in merged:
                merged.append(reason)
        return merged

    @staticmethod
    def _serialize_approval(req: ApprovalRequest) -> dict[str, Any]:
        """Сериализовать использованный approval-токен для ответа MCP-инструмента."""
        return {
            "approval_id": req.approval_id,
            "status": req.status.value,
            "approved_by": req.decided_by,
            "approved_at": req.decided_at.isoformat() if req.decided_at else None,
            "decision_reason": req.decision_reason,
        }

    @staticmethod
    def _assert_not_forbidden(assessment: Any, subject: str) -> None:
        """Выбросить PermissionError, если классификатор присвоил TIER_3_FORBIDDEN."""
        if assessment.risk_tier == ActionRiskTier.TIER_3_FORBIDDEN:
            raise PermissionError(
                f"{subject} is forbidden by security policy: {'; '.join(assessment.reasons)}"
            )

    @staticmethod
    def _build_policy_eval_response(
        assessment: Any,
        policy_eval: PolicyEvaluationResult,
        auth_ctx: Any,
        **extra: Any,
    ) -> dict[str, Any]:
        """Сформировать унифицированный ответ dry-run оценки политики безопасности."""
        is_forbidden = assessment.risk_tier == ActionRiskTier.TIER_3_FORBIDDEN
        payload: dict[str, Any] = {
            "decision": PolicyDecision.DENY.value if is_forbidden else policy_eval.decision.value,
            "allowed": False if is_forbidden else policy_eval.allowed,
            "requires_approval": (
                False
                if is_forbidden
                else (policy_eval.requires_approval or assessment.requires_approval)
            ),
            "risk_assessment": assessment.to_dict(),
            "policy": policy_eval.to_dict(),
            "auth_context": auth_ctx.to_dict(),
        }
        payload.update(extra)
        return payload
