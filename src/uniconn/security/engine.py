# src/uniconn/security/engine.py
"""Движки политик безопасности (EmbeddedPolicyEngine, OPAPolicyEngine) и PolicyGuardrailMiddleware."""

from __future__ import annotations

import asyncio
import inspect
import json
import re
import time
import urllib.error
import urllib.request
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, cast

import yaml

from ..exceptions import (
    ApprovalExpiredError,
    ApprovalRejectedError,
    ApprovalRequiredError,
    ConfigurationError,
    PolicyEngineUnavailableError,
    PolicyViolationError,
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

_SYSTEM_PROTECTED_PREFIXES: tuple[str, ...] = (
    "/etc",
    "/boot",
    "/usr",
    "/lib",
    "/lib64",
    "/sbin",
    "/bin",
    "/proc/sys",
    "/sys",
)
_PRIVILEGED_ROLES: frozenset[str] = frozenset({"lead_sre", "senior_sre", "admin", "root", "platform_admin", "sre"})
_READONLY_ROLES: frozenset[str] = frozenset({"triage_bot", "readonly", "observer", "auditor"})


class PolicyEngineProtocol(Protocol):
    """Протокол движка оценки политик безопасности (Embedded или OPA)."""

    async def evaluate(self, context: AuthContext) -> PolicyEvaluationResult:
        """Асинхронно оценить контекст авторизации и вернуть решение политики."""
        ...

    def evaluate_sync(self, context: AuthContext) -> PolicyEvaluationResult:
        """Синхронно оценить контекст авторизации."""
        ...


PolicyEngine = PolicyEngineProtocol


@dataclass(frozen=True, slots=True)
class PolicyRuleResult:
    """Промежуточный результат срабатывания одного правила встроенного движка."""

    decision: PolicyDecision
    rule_id: str
    rule_name: str
    message: str
    remediation_hint: str | None = None


PolicyRuleCallable = Callable[[AuthContext], PolicyRuleResult | None]
PolicyRule = PolicyRuleCallable


def rule_no_obfuscation(ctx: AuthContext) -> PolicyRuleResult | None:
    """Правило 1: Безусловный запрет обфусцированных команд (base64, hex, eval, склейка переменных)."""
    ast_data = ctx.action.ast
    if ast_data.get("is_obfuscated"):
        reasons = ast_data.get("obfuscation_reasons") or ["Obfuscated command syntax detected"]
        joined = "; ".join(str(r) for r in reasons)
        return PolicyRuleResult(
            decision=PolicyDecision.DENY,
            rule_id="no_obfuscation",
            rule_name="Strict Anti-Obfuscation Guard",
            message=f"Obfuscated or dynamically evaluated shell commands are strictly forbidden: {joined}",
            remediation_hint=(
                "Rewrite the command using plain, explicit POSIX binaries and arguments without "
                "base64/hex decoding, eval, variable concatenation, or inline destructive scripts."
            ),
        )
    return None


def rule_no_forbidden_risk_tier(ctx: AuthContext) -> PolicyRuleResult | None:
    """Правило 2: Запрет операций уровня риска TIER_3_FORBIDDEN."""
    if ctx.action.risk_tier == "FORBIDDEN":
        reasons = "; ".join(ctx.action.risk_reasons) or "Critical forbidden operation"
        return PolicyRuleResult(
            decision=PolicyDecision.DENY,
            rule_id="no_forbidden_risk_tier",
            rule_name="Forbidden Risk Tier Block",
            message=f"Operation is classified as FORBIDDEN: {reasons}",
            remediation_hint="Do not target raw block devices, root filesystem deletion, or critical shadow files.",
        )
    return None


def rule_opaque_complexity_guard(ctx: AuthContext) -> PolicyRuleResult | None:
    """Правило 3: Скрипты, превышающие порог сложности AST, требуют согласования оператора."""
    if ctx.action.ast.get("complexity_exceeded"):
        return PolicyRuleResult(
            decision=PolicyDecision.REQUIRE_APPROVAL,
            rule_id="opaque_complexity_guard",
            rule_name="Opaque Script Complexity Guard",
            message="Command or script exceeds AST complexity threshold and requires human operator review",
            remediation_hint="Split the script into smaller atomic commands or request operator approval.",
        )
    return None


def rule_readonly_role_guard(ctx: AuthContext) -> PolicyRuleResult | None:
    """Правило 4: Роли только для чтения (triage_bot, readonly) не могут выполнять мутации и sudo."""
    role = ctx.subject.role.lower()
    if role in _READONLY_ROLES and (
        ctx.action.sudo or ctx.action.risk_tier in ("MUTATING", "DESTRUCTIVE", "FORBIDDEN")
    ):
        return PolicyRuleResult(
            decision=PolicyDecision.DENY,
            rule_id="readonly_role_guard",
            rule_name="Read-Only Role Enforcement",
            message=(
                f"Subject role {ctx.subject.role!r} is restricted to read-only inspection "
                f"(attempted {ctx.action.risk_tier} action)"
            ),
            remediation_hint="Use read-only diagnostic commands (ls, cat, journalctl, df, ps) without sudo.",
        )
    return None


def rule_least_privilege_system_paths(ctx: AuthContext) -> PolicyRuleResult | None:
    """Правило 5: Запрет модификации системных каталогов (/etc, /boot, /usr, /lib) без привилегированной роли."""
    role = ctx.subject.role.lower()
    if role in _PRIVILEGED_ROLES:
        return None

    is_mutating = (
        ctx.action.risk_tier in ("MUTATING", "DESTRUCTIVE")
        or bool(ctx.action.ast.get("has_destructive_verbs"))
        or ctx.action.type == "file_write"
    )
    if not is_mutating:
        return None

    targets: list[str] = list(ctx.action.ast.get("targets") or [])
    if ctx.resource.target_path and ctx.resource.target_path not in targets:
        targets.append(ctx.resource.target_path)

    for target in targets:
        norm = target.rstrip("/") or "/"
        for prefix in _SYSTEM_PROTECTED_PREFIXES:
            if norm == prefix or norm.startswith(prefix + "/"):
                return PolicyRuleResult(
                    decision=PolicyDecision.DENY,
                    rule_id="least_privilege_system_paths",
                    rule_name="System Directory Least-Privilege Guard",
                    message=(
                        f"Role {ctx.subject.role!r} is not permitted to modify or delete protected "
                        f"system path {target!r} (requires 'lead_sre' or 'admin')"
                    ),
                    remediation_hint=(
                        "Operate within application directories (/tmp, /var/log, /opt) or escalate "
                        "with an authorized 'lead_sre' role."
                    ),
                )
    return None


def rule_prod_maintenance_window_guard(ctx: AuthContext) -> PolicyRuleResult | None:
    """Правило 6: Деструктивные и мутирующие операции на production вне окна обслуживания требуют HITL."""
    if ctx.resource.environment != "production":
        return None
    if ctx.environment.is_maintenance_window:
        return None

    has_dest = bool(ctx.action.ast.get("has_destructive_verbs")) or ctx.action.risk_tier == "DESTRUCTIVE"
    is_mut = ctx.action.risk_tier == "MUTATING" or ctx.action.type in ("file_write", "flow_execution")
    if has_dest or is_mut:
        return PolicyRuleResult(
            decision=PolicyDecision.REQUIRE_APPROVAL,
            rule_id="prod_maintenance_window_guard",
            rule_name="Production Maintenance Window Guard",
            message=(
                f"{ctx.action.risk_tier} operation on production host {ctx.resource.host!r} "
                "outside scheduled maintenance window requires human approval (HITL)"
            ),
            remediation_hint=(
                "Request two-phase operator approval via 'uniconn_propose_action' or execute "
                "during an active maintenance window."
            ),
        )
    return None


def rule_strict_prod_deny_junior(ctx: AuthContext) -> PolicyRuleResult | None:
    """Правило 7 (для пресета strict): Запрет деструктивных команд на production для младших ролей и агентов."""
    if ctx.resource.environment != "production":
        return None
    role = ctx.subject.role.lower()
    has_dest = bool(ctx.action.ast.get("has_destructive_verbs")) or ctx.action.risk_tier == "DESTRUCTIVE"
    if has_dest and role not in _PRIVILEGED_ROLES and not ctx.environment.is_maintenance_window:
        return PolicyRuleResult(
            decision=PolicyDecision.DENY,
            rule_id="strict_prod_deny_junior",
            rule_name="Strict Production Destructive Block",
            message=(
                f"Role {ctx.subject.role!r} is forbidden from running destructive commands on "
                f"production host {ctx.resource.host!r} outside maintenance windows"
            ),
            remediation_hint="Use read-only diagnostics or escalate to 'lead_sre'.",
        )
    return None


BUILTIN_POLICY_PRESETS: dict[str, tuple[PolicyRuleCallable, ...]] = {
    "default": (
        rule_no_obfuscation,
        rule_no_forbidden_risk_tier,
        rule_opaque_complexity_guard,
        rule_readonly_role_guard,
    ),
    "prod-guard": (
        rule_no_obfuscation,
        rule_no_forbidden_risk_tier,
        rule_opaque_complexity_guard,
        rule_readonly_role_guard,
        rule_prod_maintenance_window_guard,
    ),
    "least-privilege": (
        rule_no_obfuscation,
        rule_no_forbidden_risk_tier,
        rule_opaque_complexity_guard,
        rule_readonly_role_guard,
        rule_least_privilege_system_paths,
        rule_prod_maintenance_window_guard,
    ),
    "strict": (
        rule_no_obfuscation,
        rule_no_forbidden_risk_tier,
        rule_opaque_complexity_guard,
        rule_readonly_role_guard,
        rule_least_privilege_system_paths,
        rule_strict_prod_deny_junior,
        rule_prod_maintenance_window_guard,
    ),
}

_TOP_LEVEL_CONDITION_KEYS: frozenset[str] = frozenset(
    {
        "role",
        "roles",
        "not_role",
        "not_roles",
        "environment",
        "environments",
        "host",
        "hosts",
        "group",
        "groups",
        "sudo",
        "action_type",
        "risk_tier",
        "risk_tiers",
        "is_obfuscated",
        "has_destructive_verbs",
        "is_maintenance_window",
        "executables",
        "executable",
        "denied_verbs",
        "subcommands",
        "subcommand",
        "target_prefixes",
        "targets",
        "command_regex",
        "tool_name",
        "tool_names",
        "flow_name",
        "flow_names",
    }
)


@dataclass(frozen=True, slots=True)
class DeclarativePolicyRule:
    """Декларативное правило политики, загружаемое из YAML/JSON файла конфигурации."""

    id: str
    name: str
    decision: PolicyDecision
    message: str
    remediation_hint: str | None = None
    when: dict[str, Any] | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], index: int = 0) -> DeclarativePolicyRule:
        """Сконструировать декларативное правило из словаря YAML/JSON."""
        rule_id = str(data.get("id") or data.get("name") or f"custom_rule_{index + 1}")
        name = str(data.get("name") or rule_id)
        raw_dec = str(data.get("decision") or data.get("effect") or "DENY").strip().upper()
        try:
            decision = PolicyDecision(raw_dec)
        except ValueError as exc:
            raise ConfigurationError(f"Invalid policy decision {raw_dec!r} in rule {rule_id!r}") from exc
        message = str(data.get("message") or data.get("reason") or f"Triggered declarative policy rule {name!r}")
        hint = data.get("remediation_hint")
        when_raw = data.get("when") or data.get("match") or {}
        if not isinstance(when_raw, Mapping):
            raise ConfigurationError(f"'when' block in policy rule {rule_id!r} must be a mapping")
        merged_when = dict(when_raw)
        for k in _TOP_LEVEL_CONDITION_KEYS:
            if k in data and k not in merged_when:
                merged_when[k] = data[k]
        return cls(
            id=rule_id,
            name=name,
            decision=decision,
            message=message,
            remediation_hint=str(hint) if hint else None,
            when=merged_when,
        )

    def evaluate(self, ctx: AuthContext) -> PolicyRuleResult | None:
        """Проверить все условия в блоке ``when`` против контекста ``AuthContext``."""
        if not self.when:
            return None
        ast_data = ctx.action.ast
        for cond_key, expected in self.when.items():
            if not self._match_condition(cond_key, expected, ctx, ast_data):
                return None
        return PolicyRuleResult(
            decision=self.decision,
            rule_id=self.id,
            rule_name=self.name,
            message=self.message,
            remediation_hint=self.remediation_hint,
        )

    @staticmethod
    def _match_condition(
        key: str,
        expected: Any,
        ctx: AuthContext,
        ast_data: Mapping[str, Any],
    ) -> bool:
        """Сопоставить одиночное условие правила с полями AuthContext."""
        if key in ("role", "roles", "subject.role"):
            opts = {str(x).lower() for x in (expected if isinstance(expected, list | tuple) else [expected])}
            return ctx.subject.role.lower() in opts
        if key in ("not_role", "not_roles", "subject.not_role"):
            opts = {str(x).lower() for x in (expected if isinstance(expected, list | tuple) else [expected])}
            return ctx.subject.role.lower() not in opts
        if key in ("environment", "environments", "resource.environment"):
            raw_opts = {str(x).lower() for x in (expected if isinstance(expected, list | tuple) else [expected])}
            expanded_opts = set(raw_opts)
            if expanded_opts & {"prod", "production", "prd"}:
                expanded_opts.update({"prod", "production", "prd"})
            if expanded_opts & {"stage", "staging", "stg"}:
                expanded_opts.update({"stage", "staging", "stg"})
            return ctx.resource.environment.lower() in expanded_opts
        if key in ("host", "hosts", "resource.host"):
            opts = {str(x).lower() for x in (expected if isinstance(expected, list | tuple) else [expected])}
            return ctx.resource.host.lower() in opts
        if key in ("group", "groups", "resource.groups"):
            opts = {str(x).lower() for x in (expected if isinstance(expected, list | tuple) else [expected])}
            return any(g.lower() in opts for g in ctx.resource.groups)
        if key in ("sudo", "action.sudo"):
            return bool(ctx.action.sudo) is bool(expected)
        if key in ("action_type", "action.type"):
            opts = {str(x).lower() for x in (expected if isinstance(expected, list | tuple) else [expected])}
            return ctx.action.type.lower() in opts
        if key in ("tool_name", "tool_names", "action.tool_name"):
            opts = {str(x).lower() for x in (expected if isinstance(expected, list | tuple) else [expected])}
            return ctx.action.tool_name.lower() in opts
        if key in ("flow_name", "flow_names", "action.flow_name"):
            opts = {str(x).lower() for x in (expected if isinstance(expected, list | tuple) else [expected])}
            return bool(ctx.action.flow_name and ctx.action.flow_name.lower() in opts)
        if key in ("risk_tier", "risk_tiers", "action.risk_tier"):
            opts = {str(x).upper() for x in (expected if isinstance(expected, list | tuple) else [expected])}
            return ctx.action.risk_tier.upper() in opts
        if key in ("is_obfuscated", "ast.is_obfuscated"):
            return bool(ast_data.get("is_obfuscated", False)) is bool(expected)
        if key in ("has_destructive_verbs", "ast.has_destructive_verbs"):
            return bool(ast_data.get("has_destructive_verbs", False)) is bool(expected)
        if key in ("is_maintenance_window", "environment.is_maintenance_window"):
            return bool(ctx.environment.is_maintenance_window) is bool(expected)
        if key in ("executables", "executable", "denied_verbs", "ast.executables"):
            opts = {str(x).lower() for x in (expected if isinstance(expected, list | tuple) else [expected])}
            execs = {str(x).lower() for x in (ast_data.get("executables") or ())}
            return bool(opts & execs)
        if key in ("subcommands", "subcommand", "ast.subcommands"):
            opts = {str(x).lower() for x in (expected if isinstance(expected, list | tuple) else [expected])}
            subs = {str(x).lower() for x in (ast_data.get("subcommands") or ())}
            return bool(opts & subs)
        if key == "command_regex":
            pattern = str(expected)
            return bool(re.search(pattern, ctx.action.raw_command))
        if key in ("target_prefixes", "targets", "ast.targets"):
            prefixes = [str(x) for x in (expected if isinstance(expected, list | tuple) else [expected])]
            targets = [str(x) for x in (ast_data.get("targets") or ())]
            if ctx.resource.target_path:
                targets.append(ctx.resource.target_path)
            return any(
                t == pref.rstrip("/") or t.startswith(pref.rstrip("/") + "/")
                for t in targets
                for pref in prefixes
            )
        return False


def load_declarative_rules(
    source: str | Path | Mapping[str, Any] | Sequence[Mapping[str, Any]],
) -> list[DeclarativePolicyRule]:
    """Загрузить список декларативных правил из YAML/JSON файла, строки или словаря."""
    raw_data: Any
    if isinstance(source, Path) or (isinstance(source, str) and "\n" not in source and Path(source).is_file()):
        path_obj = Path(source)
        text = path_obj.read_text(encoding="utf-8")
        raw_data = yaml.safe_load(text)
    elif isinstance(source, str):
        raw_data = yaml.safe_load(source)
    else:
        raw_data = source

    if isinstance(raw_data, Mapping):
        rules_seq = raw_data.get("rules") or []
    elif isinstance(raw_data, Sequence):
        rules_seq = raw_data
    else:
        raise ConfigurationError("Declarative policy specification must be a mapping with 'rules' or a list of rules")

    if not isinstance(rules_seq, Sequence):
        raise ConfigurationError("'rules' in policy specification must be a list")

    loaded: list[DeclarativePolicyRule] = []
    for idx, item in enumerate(rules_seq):
        if not isinstance(item, Mapping):
            raise ConfigurationError(f"Policy rule at index {idx} must be a dictionary")
        loaded.append(DeclarativePolicyRule.from_dict(item, index=idx))
    return loaded


class _PolicyTTLCache:
    """Компактный in-memory TTL-кэш результатов вычисления политик."""

    def __init__(self, ttl_seconds: float = 5.0, max_entries: int = 512) -> None:
        self.ttl_seconds = max(0.0, float(ttl_seconds))
        self.max_entries = max_entries
        self._store: dict[str, tuple[float, PolicyEvaluationResult]] = {}

    def get(self, key: str) -> PolicyEvaluationResult | None:
        if self.ttl_seconds <= 0.0:
            return None
        entry = self._store.get(key)
        if entry is None:
            return None
        expires_at, val = entry
        if time.monotonic() >= expires_at:
            self._store.pop(key, None)
            return None
        return val.model_copy(update={"cached": True, "evaluation_duration_ms": 0.0})

    def put(self, key: str, value: PolicyEvaluationResult) -> None:
        if self.ttl_seconds <= 0.0:
            return
        if len(self._store) >= self.max_entries:
            oldest_key = next(iter(self._store))
            self._store.pop(oldest_key, None)
        self._store[key] = (time.monotonic() + self.ttl_seconds, value)

    def clear(self) -> None:
        self._store.clear()


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
            res = fn(context)
            if res is not None:
                all_results.append(res)

        for dec_rule in self._declarative_rules:
            res = dec_rule.evaluate(context)
            if res is not None:
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


OPASenderCallable = Callable[[str, dict[str, Any], float], Awaitable[dict[str, Any]] | dict[str, Any]]


class OPAPolicyEngine:
    """Клиент оценки политик через внешний сервер Open Policy Agent (OPA REST API / Rego)."""

    def __init__(
        self,
        opa_url: str = "http://localhost:8181/v1/data/uniconn/authz",
        *,
        timeout_seconds: float = 3.0,
        timeout: float | None = None,
        fail_closed: bool = True,
        allow_safe_on_failure: bool = True,
        cache_ttl_seconds: float = 5.0,
        fallback_embedded: EmbeddedPolicyEngine | None = None,
        sender: OPASenderCallable | None = None,
    ) -> None:
        """Инициализировать OPA-движок с URL политики, режимом fail-closed и TTL-кэшем."""
        self.opa_url = opa_url.strip()
        eff_timeout = timeout if timeout is not None else timeout_seconds
        self.timeout_seconds = max(0.05, float(eff_timeout))
        self.fail_closed = fail_closed
        self.allow_safe_on_failure = allow_safe_on_failure
        self._cache = _PolicyTTLCache(ttl_seconds=cache_ttl_seconds)
        self._pre_guard = fallback_embedded or EmbeddedPolicyEngine(preset="default", cache_ttl_seconds=0.0)
        self._sender = sender

    async def evaluate(self, context: AuthContext) -> PolicyEvaluationResult:
        """Отправить канонический документ ``{"input": ...}`` в OPA и интерпретировать ответ Rego."""
        local_check = self._pre_guard.evaluate_sync(context)
        if local_check.decision == PolicyDecision.DENY:
            return local_check.model_copy(update={"engine_name": "opa+ast_guard"})

        ckey = f"opa:{self.opa_url}:{context.cache_key()}"
        cached = self._cache.get(ckey)
        if cached is not None:
            return cached

        t0 = time.perf_counter()
        payload = {"input": context.to_input_dict()}
        try:
            if self._sender is not None:
                raw_resp = self._sender(self.opa_url, payload, self.timeout_seconds)
                if inspect.isawaitable(raw_resp):
                    resp_data = await raw_resp
                else:
                    resp_data = cast(dict[str, Any], raw_resp)
            else:
                resp_data = await asyncio.to_thread(
                    self._default_http_post,
                    self.opa_url,
                    payload,
                    self.timeout_seconds,
                )
        except Exception as exc:
            return self._handle_opa_unavailable(context, exc, t0)

        dur_ms = (time.perf_counter() - t0) * 1000.0
        result = self._parse_opa_response(resp_data, context, dur_ms)
        self._cache.put(ckey, result)
        return result

    def evaluate_sync(self, context: AuthContext) -> PolicyEvaluationResult:
        """Синхронная обёртка оценки политики через OPA."""
        local_check = self._pre_guard.evaluate_sync(context)
        if local_check.decision == PolicyDecision.DENY:
            return local_check.model_copy(update={"engine_name": "opa+ast_guard"})

        ckey = f"opa:{self.opa_url}:{context.cache_key()}"
        cached = self._cache.get(ckey)
        if cached is not None:
            return cached

        t0 = time.perf_counter()
        payload = {"input": context.to_input_dict()}
        try:
            if self._sender is not None:
                raw_resp = self._sender(self.opa_url, payload, self.timeout_seconds)
                if inspect.isawaitable(raw_resp):
                    if asyncio.iscoroutine(raw_resp):
                        raw_resp.close()
                    raise RuntimeError("Cannot call async OPA sender from evaluate_sync")
                resp_data = cast(dict[str, Any], raw_resp)
            else:
                resp_data = self._default_http_post(self.opa_url, payload, self.timeout_seconds)
        except Exception as exc:
            return self._handle_opa_unavailable(context, exc, t0)

        dur_ms = (time.perf_counter() - t0) * 1000.0
        result = self._parse_opa_response(resp_data, context, dur_ms)
        self._cache.put(ckey, result)
        return result

    def _handle_opa_unavailable(
        self,
        context: AuthContext,
        exc: Exception,
        t0: float,
    ) -> PolicyEvaluationResult:
        """Обработать отказ сервера OPA согласно политикам fail_closed и allow_safe_on_failure."""
        dur_ms = (time.perf_counter() - t0) * 1000.0
        is_safe_ro = (
            context.action.risk_tier == "SAFE"
            and not context.action.sudo
            and not context.action.ast.get("has_destructive_verbs")
            and not context.action.ast.get("is_obfuscated")
            and context.action.type == "command_execution"
        )
        if not self.fail_closed or (self.allow_safe_on_failure and is_safe_ro):
            return PolicyEvaluationResult(
                decision=PolicyDecision.ALLOW,
                allowed=True,
                requires_approval=False,
                reasons=(f"OPA unreachable ({exc}); permitted as safe read-only fallback",),
                violations=(),
                risk_tier=context.action.risk_tier,
                ast=context.action.ast,
                evaluation_duration_ms=round(dur_ms, 4),
                engine_name="opa_fallback",
            )

        raise PolicyEngineUnavailableError(
            f"Open Policy Agent endpoint {self.opa_url!r} is unreachable and fail_closed=True: {exc}",
            engine_name="opa",
            endpoint=self.opa_url,
            command=context.action.raw_command or None,
            host=context.resource.host,
        ) from exc

    @staticmethod
    def _default_http_post(url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
        if not url.lower().startswith(("http://", "https://")):
            raise ValueError(f"Unsupported OPA URL scheme: {url!r}")
        raw_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=raw_bytes,
            headers={"Content-Type": "application/json; charset=utf-8"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_body = resp.read(65536).decode("utf-8", errors="replace")
            parsed = json.loads(resp_body) if resp_body.strip() else {}
            if not isinstance(parsed, dict):
                return {"result": parsed}
            return parsed

    @staticmethod
    def _parse_opa_response(
        resp_data: Mapping[str, Any],
        context: AuthContext,
        dur_ms: float,
    ) -> PolicyEvaluationResult:
        """Преобразовать ответ Rego (`result`) в `PolicyEvaluationResult`."""
        reg_res = resp_data.get("result")
        violations: list[PolicyViolation] = []
        reasons: list[str] = []
        top_hint: str | None = None

        if isinstance(reg_res, bool):
            decision = PolicyDecision.ALLOW if reg_res else PolicyDecision.DENY
            if not reg_res:
                msg = "Denied by Open Policy Agent boolean rule"
                reasons.append(msg)
                violations.append(PolicyViolation(rule_id="opa.boolean", rule_name="OPA Rego Policy", message=msg))
            else:
                reasons.append("Allowed by Open Policy Agent")
        elif isinstance(reg_res, Mapping):
            raw_hint = reg_res.get("remediation_hint")
            if raw_hint:
                top_hint = str(raw_hint)
            raw_deny_items: Any = reg_res.get("deny") or reg_res.get("violations") or []
            deny_items: list[Any] = [raw_deny_items] if isinstance(raw_deny_items, str) else list(raw_deny_items)
            raw_reasons: Any = reg_res.get("reasons") or []
            reason_items: list[Any] = [raw_reasons] if isinstance(raw_reasons, str) else list(raw_reasons)
            for r_str in reason_items:
                if str(r_str) not in reasons:
                    reasons.append(str(r_str))

            explicit_dec_str = str(reg_res.get("decision") or "").strip().upper()
            req_appr = bool(reg_res.get("require_approval", False)) or explicit_dec_str == "REQUIRE_APPROVAL"
            allow_flag = bool(reg_res.get("allow", False)) or explicit_dec_str == "ALLOW"

            for idx, item in enumerate(deny_items):
                if isinstance(item, Mapping):
                    item_map = cast(Mapping[str, Any], item)
                    item_hint = item_map.get("remediation_hint")
                    v = PolicyViolation(
                        rule_id=str(item_map.get("rule_id") or f"opa.deny.{idx + 1}"),
                        rule_name=str(item_map.get("rule_name") or "OPA Rego Deny Rule"),
                        message=str(item_map.get("message") or item_map),
                        remediation_hint=str(item_hint) if item_hint else top_hint,
                    )
                else:
                    v = PolicyViolation(
                        rule_id=f"opa.deny.{idx + 1}",
                        rule_name="OPA Rego Deny Rule",
                        message=str(item),
                        remediation_hint=top_hint,
                    )
                violations.append(v)
                if v.message not in reasons:
                    reasons.append(v.message)

            if violations or explicit_dec_str == "DENY":
                decision = PolicyDecision.DENY
                if not violations:
                    msg = reasons[0] if reasons else "Denied by OPA Rego policy"
                    violations.append(
                        PolicyViolation(
                            rule_id="opa.deny",
                            rule_name="OPA Rego Policy",
                            message=msg,
                            remediation_hint=top_hint,
                        )
                    )
                    if msg not in reasons:
                        reasons.append(msg)
            elif req_appr:
                decision = PolicyDecision.REQUIRE_APPROVAL
                appr_msg = str(
                    reg_res.get("approval_reason")
                    or (reasons[0] if reasons else "Action requires human operator approval per OPA Rego policy")
                )
                if appr_msg not in reasons:
                    reasons.append(appr_msg)
                violations.append(
                    PolicyViolation(
                        rule_id="opa.require_approval",
                        rule_name="OPA HITL Requirement",
                        message=appr_msg,
                        severity="WARNING",
                        remediation_hint=top_hint,
                    )
                )
            elif allow_flag:
                decision = PolicyDecision.ALLOW
                if not reasons:
                    reasons.append("Allowed by Open Policy Agent Rego policy")
            else:
                decision = PolicyDecision.DENY
                msg = reasons[0] if reasons else "Denied by default OPA policy (allow=false)"
                if msg not in reasons:
                    reasons.append(msg)
                violations.append(
                    PolicyViolation(
                        rule_id="opa.default_deny",
                        rule_name="OPA Default Deny",
                        message=msg,
                        remediation_hint=top_hint,
                    )
                )
        else:
            decision = PolicyDecision.DENY
            msg = "Denied: empty or unrecognized OPA response payload"
            reasons.append(msg)
            violations.append(PolicyViolation(rule_id="opa.invalid_response", rule_name="OPA Guard", message=msg))

        return PolicyEvaluationResult(
            decision=decision,
            allowed=(decision == PolicyDecision.ALLOW),
            requires_approval=(decision == PolicyDecision.REQUIRE_APPROVAL),
            reasons=tuple(reasons),
            violations=tuple(violations),
            risk_tier=context.action.risk_tier,
            ast=context.action.ast,
            evaluation_duration_ms=round(dur_ms, 4),
            engine_name="opa",
            explicit_remediation_hint=top_hint,
        )


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
        from ..mcp.models import ApprovalStatus

        opts: Mapping[str, Any] = self._conn.config.options if self._conn is not None else {}
        host = (
            self.host
            or getattr(request, "host", None)
            or (self._conn.config.host if self._conn is not None else None)
            or (self._conn.transport_name if self._conn is not None else None)
            or "localhost"
        )
        transport_name = self._conn.transport_name if self._conn is not None else "local"
        eff_env = (
            self.environment
            or opts.get("environment")
            or opts.get("env")
            or ("production" if (self.is_production or opts.get("is_production")) else None)
        )
        is_prod = (
            bool(self.is_production)
            or str(eff_env or "").lower() in ("prod", "production", "prd", "critical")
            or bool(opts.get("is_production", False))
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

        appr_id = request.approval_id or request.transport_kwargs.pop("approval_id", None)
        mgr = self.approval_manager
        cwd = (
            self._conn.current_cwd
            if self._conn is not None
            else request.transport_kwargs.get("cwd")
        )
        hmac_params = {"command": request.command, "sudo": request.sudo, "cwd": cwd or ""}

        if appr_id is not None and mgr is not None:
            await mgr.verify_and_consume(
                str(appr_id),
                target_host=host,
                tool_name="conn.run",
                command=request.command,
                sudo=request.sudo,
                cwd=cwd,
                parameters=hmac_params,
            )
            return await call_next(request)

        if eval_res.decision == PolicyDecision.REQUIRE_APPROVAL and mgr is not None:
            combined_reasons = tuple(dict.fromkeys([*assessment.reasons, *eval_res.reasons]))
            req = await mgr.create_request(
                target_host=host,
                tool_name="conn.run",
                risk_tier=assessment.risk_tier,
                risk_reasons=combined_reasons,
                command=request.command,
                sudo=request.sudo,
                cwd=cwd,
                parameters=hmac_params,
                agent_id=req_agent,
            )
            hitl_pol = getattr(mgr, "policy", None)
            if getattr(hitl_pol, "wait_for_approval", False):
                decided = await mgr.wait_for_decision(
                    req.approval_id,
                    timeout=getattr(hitl_pol, "wait_timeout_seconds", 30.0),
                )
                if decided.status == ApprovalStatus.APPROVED:
                    await mgr.verify_and_consume(
                        req.approval_id,
                        target_host=host,
                        tool_name="conn.run",
                        command=request.command,
                        sudo=request.sudo,
                        cwd=cwd,
                        parameters=hmac_params,
                    )
                    return await call_next(request)
                if decided.status == ApprovalStatus.REJECTED:
                    raise ApprovalRejectedError(
                        f"Command {request.command!r} on {host!r} was rejected by operator "
                        f"({decided.decided_by or 'operator'}): {decided.decision_reason or 'Rejected'}",
                        approval_id=decided.approval_id,
                        decided_by=decided.decided_by,
                        decision_reason=decided.decision_reason,
                        approval_request=decided,
                        command=request.command,
                        host=host,
                    )
                if decided.status == ApprovalStatus.EXPIRED:
                    raise ApprovalExpiredError(
                        f"Approval request {decided.approval_id!r} for {request.command!r} expired",
                        approval_id=decided.approval_id,
                        approval_request=decided,
                        command=request.command,
                        host=host,
                    )
            raise ApprovalRequiredError(
                f"Command {request.command!r} on {host!r} requires human operator approval per policy "
                f"(approval_id={req.approval_id!r}, reasons={'; '.join(eval_res.reasons)})",
                approval_id=req.approval_id,
                approval_request=req,
                command=request.command,
                host=host,
            )

        return await call_next(request)


__all__ = [
    "BUILTIN_POLICY_PRESETS",
    "DeclarativePolicyRule",
    "EmbeddedPolicyEngine",
    "OPAPolicyEngine",
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
