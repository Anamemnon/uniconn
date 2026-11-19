# src/uniconn/security/engine.py
"""Движки политик безопасности (EmbeddedPolicyEngine, OPAPolicyEngine) и PolicyGuardrailMiddleware."""

from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from ..exceptions import (
    ConfigurationError,
    PolicyViolationError,
)
from ._policy_opa import OPAPolicyEngine, OPASenderCallable
from ._policy_rules import (
    BUILTIN_POLICY_PRESETS,
    DeclarativePolicyRule,
    PolicyRule,
    PolicyRuleCallable,
    PolicyRuleResult,
    _PolicyTTLCache,
    load_declarative_rules,
    rule_least_privilege_system_paths,
    rule_no_forbidden_risk_tier,
    rule_no_obfuscation,
    rule_opaque_complexity_guard,
    rule_prod_maintenance_window_guard,
    rule_readonly_role_guard,
    rule_strict_prod_deny_junior,
)
from .ast_parser import CommandASTParser
from .models import (
    AuthContext,
    PolicyDecision,
    PolicyEvaluationResult,
    PolicyGuardrailConfig,
    PolicyViolation,
    build_auth_context,
)

if TYPE_CHECKING:
    from ..core.connection import Connection
    from ..core.pipeline import CommandRequest, NextHandler
    from ..result import Result


class PolicyEngineProtocol(Protocol):
    """Протокол движка оценки политик безопасности (Embedded или OPA)."""

    async def evaluate(self, context: AuthContext) -> PolicyEvaluationResult:
        """Асинхронно оценить контекст авторизации и вернуть решение политики."""
        ...

    def evaluate_sync(self, context: AuthContext) -> PolicyEvaluationResult:
        """Синхронно оценить контекст авторизации."""
        ...


PolicyEngine = PolicyEngineProtocol


class EmbeddedPolicyEngine:
    """Встроенный высокопроизводительный движок Policy-as-Code на чистом Python (< 0.1 мс)."""

    def __init__(
        self,
        *,
        preset: str = "default",
        rules: Sequence[PolicyRuleCallable] = (),
        declarative_rules: Sequence[DeclarativePolicyRule] = (),
        rules_path: str | Path | None = None,
        policy_file: str | Path | None = None,
        cache_ttl_seconds: float = 5.0,
    ) -> None:
        """Инициализировать встроенный движок политик с пресетом и пользовательскими правилами."""
        preset_key = (preset or "default").strip().lower()
        if preset_key not in BUILTIN_POLICY_PRESETS:
            valid = ", ".join(sorted(BUILTIN_POLICY_PRESETS))
            raise ConfigurationError(f"Unknown policy preset {preset!r}. Available presets: {valid}")
        self.preset = preset_key
        self._callable_rules: list[PolicyRuleCallable] = [
            *BUILTIN_POLICY_PRESETS[preset_key],
            *rules,
        ]
        self._declarative_rules: list[DeclarativePolicyRule] = list(declarative_rules)
        eff_path = rules_path or policy_file
        if eff_path:
            self._declarative_rules.extend(load_declarative_rules(eff_path))
        self._cache = _PolicyTTLCache(ttl_seconds=cache_ttl_seconds)

    def add_rule(self, rule: PolicyRuleCallable | DeclarativePolicyRule) -> None:
        """Добавить пользовательское правило в движок и очистить кэш."""
        if isinstance(rule, DeclarativePolicyRule):
            self._declarative_rules.append(rule)
        else:
            self._callable_rules.append(rule)
        self._cache.clear()

    def evaluate_sync(self, context: AuthContext) -> PolicyEvaluationResult:
        """Синхронно оценить ``AuthContext`` против всех активных правил."""
        ckey = f"embedded:{self.preset}:{context.cache_key()}"
        cached = self._cache.get(ckey)
        if cached is not None:
            return cached

        t0 = time.perf_counter()
        violations: list[PolicyViolation] = []
        reasons: list[str] = []
        final_decision = PolicyDecision.ALLOW

        all_results: list[PolicyRuleResult] = []
        for fn in self._callable_rules:
            if res := fn(context):
                all_results.append(res)
        for dec_rule in self._declarative_rules:
            if res := dec_rule.evaluate(context):
                all_results.append(res)

        explicit_allow = False
        for r in all_results:
            if r.decision == PolicyDecision.DENY:
                final_decision = PolicyDecision.DENY
                violations.append(
                    PolicyViolation(
                        rule_id=r.rule_id,
                        rule_name=r.rule_name,
                        message=r.message,
                        severity="ERROR",
                        remediation_hint=r.remediation_hint,
                    )
                )
                if r.message not in reasons:
                    reasons.append(r.message)
            elif r.decision == PolicyDecision.REQUIRE_APPROVAL:
                if final_decision != PolicyDecision.DENY:
                    final_decision = PolicyDecision.REQUIRE_APPROVAL
                violations.append(
                    PolicyViolation(
                        rule_id=r.rule_id,
                        rule_name=r.rule_name,
                        message=r.message,
                        severity="WARNING",
                        remediation_hint=r.remediation_hint,
                    )
                )
                if r.message not in reasons:
                    reasons.append(r.message)
            elif r.decision == PolicyDecision.ALLOW:
                explicit_allow = True
                if r.message and r.message not in reasons:
                    reasons.append(r.message)

        if not reasons:
            if explicit_allow:
                reasons.append("Allowed by explicit policy rule")
            else:
                reasons.append(f"Allowed by embedded policy preset ({self.preset!r})")

        dur_ms = (time.perf_counter() - t0) * 1000.0
        result = PolicyEvaluationResult(
            decision=final_decision,
            allowed=(final_decision == PolicyDecision.ALLOW),
            requires_approval=(final_decision == PolicyDecision.REQUIRE_APPROVAL),
            reasons=tuple(reasons),
            violations=tuple(violations),
            risk_tier=context.action.risk_tier,
            ast=context.action.ast,
            evaluation_duration_ms=round(dur_ms, 4),
            engine_name="embedded",
            cached=False,
        )
        self._cache.put(ckey, result)
        return result

    async def evaluate(self, context: AuthContext) -> PolicyEvaluationResult:
        """Асинхронно оценить ``AuthContext``."""
        return self.evaluate_sync(context)


def create_policy_engine(config: PolicyGuardrailConfig | None = None) -> EmbeddedPolicyEngine | OPAPolicyEngine:
    """Создать экземпляр движка политик по объекту ``PolicyGuardrailConfig``."""
    cfg = config or PolicyGuardrailConfig()
    embedded = EmbeddedPolicyEngine(
        preset=cfg.preset,
        rules_path=cfg.rules_path or cfg.policy_file,
        cache_ttl_seconds=cfg.cache_ttl_seconds,
    )
    if cfg.engine.strip().lower() == "opa" and cfg.opa_url:
        return OPAPolicyEngine(
            opa_url=cfg.opa_url,
            timeout_seconds=cfg.opa_timeout_seconds,
            fail_closed=cfg.fail_closed,
            allow_safe_on_failure=cfg.allow_safe_on_opa_failure,
            allow_private_network=cfg.opa_allow_private_network,
            cache_ttl_seconds=cfg.cache_ttl_seconds,
            fallback_embedded=embedded,
        )
    return embedded


class PolicyGuardrailMiddleware:
    """Промежуточный слой Policy-as-Code и AST-верификации в конвейере ``CommandPipeline``."""

    def __init__(
        self,
        conn_or_engine: Connection | PolicyEngineProtocol | None = None,
        *,
        config: PolicyGuardrailConfig | None = None,
        engine: PolicyEngineProtocol | None = None,
        approval_manager: Any = None,
        agent_id: str | None = None,
        role: str | None = None,
        host: str | None = None,
        environment: str | None = None,
        is_production: bool | None = None,
        is_maintenance_window: bool | None = None,
        maintenance_window_override: bool | None = None,
    ) -> None:
        """Инициализировать PolicyGuardrailMiddleware (принимает Connection или PolicyEngine)."""
        if conn_or_engine is not None and hasattr(conn_or_engine, "evaluate"):
            self._conn: Connection | None = None
            resolved_engine: PolicyEngineProtocol | None = conn_or_engine  # type: ignore[assignment]
        else:
            self._conn = conn_or_engine  # type: ignore[assignment]
            resolved_engine = engine

        self._config = config or PolicyGuardrailConfig()
        self._engine: PolicyEngineProtocol = resolved_engine or create_policy_engine(self._config)
        self._approval_manager = approval_manager
        self.agent_id = agent_id
        self.role = role or self._config.default_role
        self.host = host
        self.environment = environment
        self.is_production = is_production
        self.is_maintenance_window = (
            is_maintenance_window
            if is_maintenance_window is not None
            else maintenance_window_override
        )

    @property
    def config(self) -> PolicyGuardrailConfig:
        """Активная конфигурация PolicyGuardrailConfig."""
        return self._config

    @property
    def engine(self) -> PolicyEngineProtocol:
        """Активный движок оценки политик."""
        return self._engine

    @property
    def approval_manager(self) -> Any:
        """Экземпляр ApprovalManager для обработки решений REQUIRE_APPROVAL."""
        if self._approval_manager is not None:
            return self._approval_manager
        conn_mgr = getattr(self._conn, "_approval_manager", None) if self._conn is not None else None
        if conn_mgr is not None:
            return conn_mgr
        from ..mcp.hitl import ApprovalManager
        from ..mcp.models import HITLPolicy

        hitl_pol = (
            getattr(self._conn, "_hitl_policy", None)
            if self._conn is not None
            else None
        ) or HITLPolicy(enabled=True)
        self._approval_manager = ApprovalManager(policy=hitl_pol)
        return self._approval_manager

    def attach(self, conn: Connection | None = None) -> PolicyGuardrailMiddleware:
        """Встроить PolicyGuardrailMiddleware в ``Connection.pipeline`` (после ContextMiddleware)."""
        target = conn or self._conn
        if target is None:
            raise ValueError("Cannot attach PolicyGuardrailMiddleware without a target Connection")
        self._conn = target
        if not any(isinstance(m, PolicyGuardrailMiddleware) for m in target.pipeline.middlewares):
            insert_idx = min(1, len(target.pipeline.middlewares))
            target.pipeline.insert_middleware(insert_idx, self)
        return self

    async def __call__(self, request: CommandRequest, call_next: NextHandler) -> Result:
        """Разобрать AST команды, проверить политику безопасности и при необходимости вызвать HITL."""
        from ..core.pipeline import _ACTIVE_DIAGNOSTIC_PROBE

        if not self._config.enabled or request.dry_run or _ACTIVE_DIAGNOSTIC_PROBE.get():
            return await call_next(request)

        from ..mcp.hitl import ActionRiskClassifier

        opts: Mapping[str, Any] = self._conn.config.options if self._conn is not None else {}
        host = (
            self.host
            or getattr(request, "host", None)
            or (self._conn.config.host if self._conn is not None else None)
            or (self._conn.transport_name if self._conn is not None else None)
            or "localhost"
        )
        transport_name = self._conn.transport_name if self._conn is not None else "local"
        from ..core._shell_quoting import parse_bool

        opt_is_prod = parse_bool(opts.get("is_production"), default=False)
        eff_env = (
            self.environment
            or opts.get("environment")
            or opts.get("env")
            or ("production" if (self.is_production or opt_is_prod) else None)
        )
        is_prod = (
            bool(self.is_production)
            or str(eff_env or "").lower() in ("prod", "production", "prd", "critical")
            or opt_is_prod
        )

        ast = CommandASTParser.parse(
            request.command,
            sudo=request.sudo,
            max_depth=self._config.max_ast_depth,
            max_pipeline_length=self._config.max_pipeline_length,
        )
        assessment = ActionRiskClassifier.classify_command(
            request.command,
            sudo=request.sudo,
            is_production=is_prod,
            _preparsed_ast=ast,
        )

        req_role = str(request.metadata.get("role") or opts.get("role") or self.role)
        req_agent = str(request.metadata.get("agent_id") or opts.get("agent_id") or self.agent_id or "uniconn-agent")
        raw_groups = opts.get("groups") or ()
        groups = tuple(raw_groups) if isinstance(raw_groups, list | tuple) else ()
        raw_tags = opts.get("tags")
        tags = dict(raw_tags) if isinstance(raw_tags, Mapping) else {}

        auth_ctx = build_auth_context(
            command=request.command,
            ast=ast,
            action_type="command_execution",
            tool_name="conn.run",
            sudo=request.sudo,
            dry_run=request.dry_run,
            risk_tier=assessment.risk_tier.value,
            risk_reasons=assessment.reasons,
            host=host,
            transport=transport_name,
            environment="production" if is_prod and not eff_env else (str(eff_env) if eff_env else None),
            is_production=is_prod,
            groups=groups,
            tags=tags,
            agent_id=req_agent,
            role=req_role,
            is_maintenance_window=self.is_maintenance_window,
            maintenance_windows=self._config.maintenance_windows,
        )

        eval_res = await self._engine.evaluate(auth_ctx)
        request.metadata["policy_evaluation"] = eval_res

        if eval_res.decision == PolicyDecision.DENY:
            raise PolicyViolationError(
                f"Command {request.command!r} on host {host!r} denied by security policy: "
                f"{'; '.join(eval_res.reasons)}",
                decision=eval_res.decision.value,
                violations=list(eval_res.violations),
                rule_names=list(eval_res.rule_names),
                remediation_hint=eval_res.remediation_hint,
                command=request.command,
                host=host,
            )

        if eval_res.decision != PolicyDecision.REQUIRE_APPROVAL:
            return await call_next(request)

        from ..core._middlewares import enforce_pipeline_hitl

        cwd = (
            self._conn.current_cwd
            if self._conn is not None
            else request.transport_kwargs.get("cwd")
        )
        combined_reasons = tuple(dict.fromkeys([*assessment.reasons, *eval_res.reasons]))
        return await enforce_pipeline_hitl(
            request,
            call_next,
            manager=self.approval_manager,
            host=host,
            cwd=cwd,
            requires_approval=True,
            risk_tier=assessment.risk_tier,
            risk_reasons=combined_reasons,
            agent_id=req_agent,
            reason_suffix=f"reasons={'; '.join(eval_res.reasons)}",
        )


__all__ = [
    "BUILTIN_POLICY_PRESETS",
    "DeclarativePolicyRule",
    "EmbeddedPolicyEngine",
    "OPAPolicyEngine",
    "OPASenderCallable",
    "PolicyEngine",
    "PolicyEngineProtocol",
    "PolicyGuardrailMiddleware",
    "PolicyRule",
    "PolicyRuleCallable",
    "PolicyRuleResult",
    "create_policy_engine",
    "load_declarative_rules",
    "rule_least_privilege_system_paths",
    "rule_no_forbidden_risk_tier",
    "rule_no_obfuscation",
    "rule_opaque_complexity_guard",
    "rule_prod_maintenance_window_guard",
    "rule_readonly_role_guard",
    "rule_strict_prod_deny_junior",
]
