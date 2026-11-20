# src/uniconn/security/_policy_rules.py
"""Встроенные правила, пресеты, декларативные YAML/JSON-правила и кэш движка политик."""

from __future__ import annotations

import posixpath
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..exceptions import ConfigurationError
from .ast_parser import normalize_target_path
from .models import AuthContext, PolicyDecision, PolicyEvaluationResult
from .regex_safety import validate_safe_regex

_SYSTEM_PROTECTED_PREFIXES: tuple[str, ...] = (
    "/etc",
    "/boot",
    "/root",
    "/dev",
    "/var/spool/cron",
    "~/.ssh",
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
    """Правило 3: Скрипты с превышением сложности AST или синтаксическими ошибками требуют согласования."""
    if ctx.action.ast.get("syntax_errors") or ctx.action.ast.get("has_syntax_errors"):
        errs = "; ".join(str(e) for e in (ctx.action.ast.get("syntax_errors") or ()))
        return PolicyRuleResult(
            decision=PolicyDecision.REQUIRE_APPROVAL,
            rule_id="opaque_complexity_guard",
            rule_name="AST Syntax Anomaly Guard (Fail-Closed)",
            message=f"Command contains malformed shell/PowerShell syntax and requires review: {errs}",
            remediation_hint="Fix quoting/syntax errors so static AST analysis can safely inspect the command.",
        )
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

    targets = _extract_candidate_paths(ctx, ctx.action.ast)

    for target in targets:
        norm = normalize_target_path(target).rstrip("/") or "/"
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
        "path_regex",
        "tool_name",
        "tool_names",
        "flow_name",
        "flow_names",
        "dialect",
        "has_syntax_errors",
    }
)


_VALID_CONDITION_KEYS: frozenset[str] = _TOP_LEVEL_CONDITION_KEYS | frozenset(
    {
        "subject.role",
        "subject.not_role",
        "resource.environment",
        "resource.host",
        "resource.groups",
        "action.type",
        "action.tool_name",
        "action.flow_name",
        "action.risk_tier",
        "action.sudo",
        "ast.executables",
        "ast.subcommands",
        "ast.targets",
        "ast.is_obfuscated",
        "ast.has_destructive_verbs",
        "ast.dialect",
        "ast.has_syntax_errors",
        "environment.is_maintenance_window",
    }
)


def _to_norm_set(expected: Any, *, upper: bool = False) -> set[str]:
    items = expected if isinstance(expected, list | tuple) else [expected]
    return {str(x).upper() if upper else str(x).lower() for x in items}


def _match_env_condition(expected: Any, ctx: AuthContext) -> bool:
    expanded_opts = _to_norm_set(expected)
    if expanded_opts & {"prod", "production", "prd"}:
        expanded_opts.update({"prod", "production", "prd"})
    if expanded_opts & {"stage", "staging", "stg"}:
        expanded_opts.update({"stage", "staging", "stg"})
    return ctx.resource.environment.lower() in expanded_opts


def _extract_candidate_paths(ctx: AuthContext, ast_data: Mapping[str, Any]) -> list[str]:
    raw_targets = [str(x) for x in (ast_data.get("targets") or ())]
    if ctx.resource.target_path:
        raw_targets.append(ctx.resource.target_path)
    cwd = (ctx.action.cwd or "").strip()
    if cwd:
        # Также учитываем относительные аргументы команд (например, `rm passwd` при `cwd=/etc`)
        for atom in ast_data.get("atomic_commands") or ():
            if isinstance(atom, Mapping):
                for arg in atom.get("arguments") or ():
                    arg_s = str(arg).strip()
                    if arg_s and not arg_s.startswith("-") and arg_s not in raw_targets:
                        raw_targets.append(arg_s)
    candidates: list[str] = []

    def _add(val: str) -> None:
        if val and val not in candidates:
            candidates.append(val)

    for raw in raw_targets:
        if not raw:
            continue
        norm = normalize_target_path(raw)
        _add(norm)
        _add(raw)
        if cwd and not raw.startswith(("/", "~")) and not (len(raw) >= 2 and raw[1] == ":"):
            joined = normalize_target_path(posixpath.join(cwd, raw))
            _add(joined)
    return candidates


def _match_target_prefixes(expected: Any, ctx: AuthContext, ast_data: Mapping[str, Any]) -> bool:
    prefixes = [
        normalize_target_path(str(x)).rstrip("/") or "/"
        for x in (expected if isinstance(expected, list | tuple) else [expected])
    ]
    targets = _extract_candidate_paths(ctx, ast_data)
    return any(t == pref or t.startswith(pref + "/") for t in targets for pref in prefixes)


def _match_path_regex(pattern: re.Pattern[str], ctx: AuthContext, ast_data: Mapping[str, Any]) -> bool:
    targets = _extract_candidate_paths(ctx, ast_data)
    return bool(targets and any(pattern.search(t) for t in targets))


@dataclass(frozen=True, slots=True)
class DeclarativePolicyRule:
    """Декларативное правило политики, загружаемое из YAML/JSON файла конфигурации."""

    id: str
    name: str
    decision: PolicyDecision
    message: str
    remediation_hint: str | None = None
    when: dict[str, Any] | None = None
    _compiled_command_re: re.Pattern[str] | None = None
    _compiled_path_re: re.Pattern[str] | None = None

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
        unknown_keys = sorted(str(k) for k in merged_when if str(k) not in _VALID_CONDITION_KEYS)
        if unknown_keys:
            raise ConfigurationError(
                f"Unknown policy condition key(s) {unknown_keys!r} in rule {rule_id!r} (fail-closed validation)"
            )
        cmd_re = (
            validate_safe_regex(str(merged_when["command_regex"]))
            if "command_regex" in merged_when and merged_when["command_regex"] is not None
            else None
        )
        path_re = (
            validate_safe_regex(str(merged_when["path_regex"]))
            if "path_regex" in merged_when and merged_when["path_regex"] is not None
            else None
        )
        return cls(
            id=rule_id,
            name=name,
            decision=decision,
            message=message,
            remediation_hint=str(hint) if hint else None,
            when=merged_when,
            _compiled_command_re=cmd_re,
            _compiled_path_re=path_re,
        )

    def evaluate(self, ctx: AuthContext) -> PolicyRuleResult | None:
        """Проверить все условия в блоке ``when`` против контекста ``AuthContext``."""
        if not self.when:
            return None
        ast_data = ctx.action.ast
        for cond_key, expected in self.when.items():
            if cond_key == "command_regex" and self._compiled_command_re is not None:
                if not self._compiled_command_re.search(ctx.action.raw_command):
                    return None
                continue
            if cond_key == "path_regex" and self._compiled_path_re is not None:
                if not _match_path_regex(self._compiled_path_re, ctx, ast_data):
                    return None
                continue
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
            return ctx.subject.role.lower() in _to_norm_set(expected)
        if key in ("not_role", "not_roles", "subject.not_role"):
            return ctx.subject.role.lower() not in _to_norm_set(expected)
        if key in ("environment", "environments", "resource.environment"):
            return _match_env_condition(expected, ctx)
        if key in ("host", "hosts", "resource.host"):
            return ctx.resource.host.lower() in _to_norm_set(expected)
        if key in ("group", "groups", "resource.groups"):
            opts = _to_norm_set(expected)
            return any(g.lower() in opts for g in ctx.resource.groups)
        if key in ("action_type", "action.type"):
            return ctx.action.type.lower() in _to_norm_set(expected)
        if key in ("tool_name", "tool_names", "action.tool_name"):
            return ctx.action.tool_name.lower() in _to_norm_set(expected)
        if key in ("flow_name", "flow_names", "action.flow_name"):
            return bool(ctx.action.flow_name and ctx.action.flow_name.lower() in _to_norm_set(expected))
        if key in ("risk_tier", "risk_tiers", "action.risk_tier"):
            return ctx.action.risk_tier.upper() in _to_norm_set(expected, upper=True)
        if key in ("executables", "executable", "denied_verbs", "ast.executables"):
            execs = {str(x).lower() for x in (ast_data.get("executables") or ())}
            return bool(_to_norm_set(expected) & execs)
        if key in ("subcommands", "subcommand", "ast.subcommands"):
            subs = {str(x).lower() for x in (ast_data.get("subcommands") or ())}
            return bool(_to_norm_set(expected) & subs)
        if key in ("target_prefixes", "targets", "ast.targets"):
            return _match_target_prefixes(expected, ctx, ast_data)
        if key in ("dialect", "ast.dialect"):
            return str(ast_data.get("dialect", "posix")).lower() in _to_norm_set(expected)

        bool_checks: dict[str, bool] = {
            "sudo": bool(ctx.action.sudo),
            "action.sudo": bool(ctx.action.sudo),
            "is_obfuscated": bool(ast_data.get("is_obfuscated", False)),
            "ast.is_obfuscated": bool(ast_data.get("is_obfuscated", False)),
            "has_destructive_verbs": bool(ast_data.get("has_destructive_verbs", False)),
            "ast.has_destructive_verbs": bool(ast_data.get("has_destructive_verbs", False)),
            "has_syntax_errors": bool(ast_data.get("has_syntax_errors") or ast_data.get("syntax_errors")),
            "ast.has_syntax_errors": bool(ast_data.get("has_syntax_errors") or ast_data.get("syntax_errors")),
            "is_maintenance_window": bool(ctx.environment.is_maintenance_window),
            "environment.is_maintenance_window": bool(ctx.environment.is_maintenance_window),
        }
        if key in bool_checks:
            return bool_checks[key] is bool(expected)
        if key == "command_regex":
            return bool(validate_safe_regex(str(expected)).search(ctx.action.raw_command))
        if key == "path_regex":
            return _match_path_regex(validate_safe_regex(str(expected)), ctx, ast_data)
        return False


def load_declarative_rules(
    source: str | Path | Mapping[str, Any] | Sequence[Mapping[str, Any]],
) -> list[DeclarativePolicyRule]:
    """Загрузить список декларативных правил из YAML/JSON файла, строки или словаря."""
    raw_data: Any
    if isinstance(source, Path) or (isinstance(source, str) and "\n" not in source and Path(source).is_file()):
        raw_data = yaml.safe_load(Path(source).read_text(encoding="utf-8"))
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
