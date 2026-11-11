# src/uniconn/security/models.py
"""Модели данных контекста авторизации (AuthContext) и результатов оценки Policy-as-Code."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .ast_parser import ParsedCommandAST


class PolicyDecision(StrEnum):
    """Решение движка политик безопасности по запрошенной операции."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class PolicyViolation(BaseModel):
    """Описание сработавшего запрещающего или ограничивающего правила политики."""

    model_config = ConfigDict(frozen=True)

    rule_id: str = "policy_rule"
    rule_name: str
    message: str
    severity: str = "ERROR"
    remediation_hint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Сериализовать нарушение политики в словарь."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "message": self.message,
            "severity": self.severity,
            "remediation_hint": self.remediation_hint,
        }


class SubjectContext(BaseModel):
    """Субъект авторизации (ИИ-агент, роль оператора или идентификатор сессии)."""

    model_config = ConfigDict(frozen=True)

    agent_id: str = "uniconn-agent"
    role: str = "agent"
    authenticated: bool = True
    session_id: str | None = None


class ResourceContext(BaseModel):
    """Целевой инфраструктурный ресурс (хост, окружение, критичность, группы и теги)."""

    model_config = ConfigDict(frozen=True)

    host: str = "localhost"
    host_address: str | None = None
    transport: str = "local"
    environment: str = "development"
    criticality: str = "standard"
    groups: tuple[str, ...] = ()
    tags: dict[str, str] = Field(default_factory=dict)
    target_path: str | None = None


class ActionContext(BaseModel):
    """Выполняемое действие (команда, запись файла или оркестрационный Flow) с AST-деревом."""

    model_config = ConfigDict(frozen=True)

    type: str = "command_execution"
    tool_name: str = "uniconn_run"
    raw_command: str = ""
    sudo: bool = False
    dry_run: bool = False
    cwd: str | None = None
    risk_tier: str = "SAFE"
    risk_reasons: tuple[str, ...] = ()
    ast: dict[str, Any] = Field(default_factory=dict)
    flow_name: str | None = None
    flow_tasks: tuple[str, ...] = ()

    @property
    def command(self) -> str:
        """Алиас сырой команды ``raw_command``."""
        return self.raw_command


class EnvironmentContext(BaseModel):
    """Внешний контекст окружения (время UTC, день недели, окно обслуживания)."""

    model_config = ConfigDict(frozen=True)

    time_utc: str = Field(default_factory=lambda: datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))
    day_of_week: str = Field(default_factory=lambda: datetime.now(UTC).strftime("%A"))
    is_maintenance_window: bool = False
    active_severity_1_alerts: int = 0


_DAY_PREFIX_MAP: dict[str, int] = {
    "mon": 0,
    "monday": 0,
    "tue": 1,
    "tues": 1,
    "tuesday": 1,
    "wed": 2,
    "wednesday": 2,
    "thu": 3,
    "thur": 3,
    "thurs": 3,
    "thursday": 3,
    "fri": 4,
    "friday": 4,
    "sat": 5,
    "saturday": 5,
    "sun": 6,
    "sunday": 6,
}


def is_within_maintenance_windows(
    windows: Sequence[str],
    *,
    now: datetime | None = None,
) -> bool:
    """Проверить, попадает ли текущее время UTC в одно из заданных окон '[DAY] HH:MM-HH:MM'."""
    if not windows:
        return False
    ref = (now or datetime.now(UTC)).astimezone(UTC)
    cur_minutes = ref.hour * 60 + ref.minute
    cur_weekday = ref.weekday()

    for raw_win in windows:
        spec = raw_win.strip()
        if not spec or "-" not in spec:
            continue
        parts = spec.split()
        time_range = spec
        if len(parts) >= 2 and parts[0].lower().rstrip(",") in _DAY_PREFIX_MAP:
            target_day = _DAY_PREFIX_MAP[parts[0].lower().rstrip(",")]
            if target_day != cur_weekday:
                continue
            time_range = " ".join(parts[1:])

        if "-" not in time_range:
            continue
        start_s, end_s = time_range.split("-", 1)
        try:
            sh, sm = (int(x) for x in start_s.strip().split(":", 1))
            eh, em = (int(x) for x in end_s.strip().split(":", 1))
        except ValueError:
            continue
        start_m = sh * 60 + sm
        end_m = eh * 60 + em
        if start_m <= end_m:
            if start_m <= cur_minutes <= end_m:
                return True
        elif cur_minutes >= start_m or cur_minutes <= end_m:
            return True
    return False


class AuthContext(BaseModel):
    """Канонический документ контекста авторизации (Input Document) для движков политик."""

    model_config = ConfigDict(frozen=True)

    subject: SubjectContext = Field(default_factory=SubjectContext)
    resource: ResourceContext = Field(default_factory=ResourceContext)
    action: ActionContext = Field(default_factory=ActionContext)
    environment: EnvironmentContext = Field(default_factory=EnvironmentContext)

    def to_input_dict(self) -> dict[str, Any]:
        """Сформировать JSON-совместимый словарь ``input`` для OPA или встроенного движка."""
        action_dump = self.action.model_dump(mode="json")
        action_dump["command"] = self.action.raw_command
        action_dump["risk_reasons"] = list(self.action.risk_reasons)
        action_dump["flow_tasks"] = list(self.action.flow_tasks)
        return {
            "subject": self.subject.model_dump(mode="json"),
            "resource": {
                **self.resource.model_dump(mode="json"),
                "groups": list(self.resource.groups),
            },
            "action": action_dump,
            "environment": self.environment.model_dump(mode="json"),
        }

    def to_dict(self) -> dict[str, Any]:
        """Сериализовать контекст авторизации в словарь."""
        return self.to_input_dict()

    def cache_key(self) -> str:
        """Вычислить детерминированный SHA-256 ключ кэширования без учёта секунд времени."""
        doc = self.to_input_dict()
        env_section = dict(doc.get("environment") or {})
        env_section.pop("time_utc", None)
        doc["environment"] = env_section
        raw_json = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(raw_json.encode("utf-8")).hexdigest()


class PolicyEvaluationResult(BaseModel):
    """Результат проверки операции движком политик безопасности."""

    model_config = ConfigDict(frozen=True)

    decision: PolicyDecision
    allowed: bool = True
    requires_approval: bool = False
    reasons: tuple[str, ...] = ()
    violations: tuple[PolicyViolation, ...] = ()
    risk_tier: str = "SAFE"
    ast: dict[str, Any] = Field(default_factory=dict)
    evaluation_duration_ms: float = 0.0
    engine_name: str = "embedded"
    cached: bool = False
    explicit_remediation_hint: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _normalize_fields(cls, data: Any) -> Any:
        if not isinstance(data, Mapping):
            return data
        out = dict(data)
        dec = out.get("decision", PolicyDecision.ALLOW)
        dec_enum = PolicyDecision(str(dec)) if not isinstance(dec, PolicyDecision) else dec
        out["decision"] = dec_enum
        if "allowed" not in out:
            out["allowed"] = dec_enum == PolicyDecision.ALLOW
        if "requires_approval" not in out:
            out["requires_approval"] = dec_enum == PolicyDecision.REQUIRE_APPROVAL
        if "engine" in out and "engine_name" not in out:
            out["engine_name"] = str(out.pop("engine"))
        elif "engine" in out:
            out.pop("engine")
        if "remediation_hint" in out and "explicit_remediation_hint" not in out:
            out["explicit_remediation_hint"] = out.pop("remediation_hint")
        return out

    @property
    def engine(self) -> str:
        """Имя движка оценки политик (`embedded`, `opa` и т.д.)."""
        return self.engine_name

    @property
    def rule_names(self) -> tuple[str, ...]:
        """Кортеж идентификаторов сработавших правил политики."""
        names: list[str] = []
        for v in self.violations:
            if v.rule_id and v.rule_id not in names:
                names.append(v.rule_id)
            if v.rule_name and v.rule_name not in names:
                names.append(v.rule_name)
        return tuple(names)

    @property
    def remediation_hint(self) -> str | None:
        """Рекомендация для ИИ-агента по исправлению заблокированной операции."""
        if self.explicit_remediation_hint:
            return self.explicit_remediation_hint
        for v in self.violations:
            if v.remediation_hint:
                return v.remediation_hint
        return None

    def to_dict(self) -> dict[str, Any]:
        """Сериализовать результат проверки политики в словарь."""
        return {
            "decision": self.decision.value,
            "allowed": self.allowed,
            "requires_approval": self.requires_approval,
            "reasons": list(self.reasons),
            "violations": [v.to_dict() for v in self.violations],
            "rule_names": list(self.rule_names),
            "remediation_hint": self.remediation_hint,
            "risk_tier": self.risk_tier,
            "ast": dict(self.ast),
            "evaluation_duration_ms": round(self.evaluation_duration_ms, 3),
            "engine_name": self.engine_name,
            "engine": self.engine_name,
            "cached": self.cached,
        }


class PolicyGuardrailConfig(BaseModel):
    """Конфигурация рубежа Policy-as-Code Guardrails для ядра и MCP-сервера."""

    model_config = ConfigDict(frozen=True)

    enabled: bool = True
    engine: str = "embedded"
    preset: str = "default"
    rules_path: str | None = None
    policy_file: str | None = None
    opa_url: str | None = None
    opa_timeout_seconds: float = Field(default=3.0, gt=0.05)
    fail_closed: bool = True
    allow_safe_on_opa_failure: bool = True
    cache_ttl_seconds: float = Field(default=5.0, ge=0.0)
    maintenance_windows: tuple[str, ...] = ()
    maintenance_window_active: bool | None = None
    default_agent_id: str = "uniconn-agent"
    default_role: str = "agent"
    max_ast_depth: int = Field(default=6, ge=1)
    max_pipeline_length: int = Field(default=64, ge=1)

    @model_validator(mode="before")
    @classmethod
    def _sync_rules_path_and_policy_file(cls, data: Any) -> Any:
        if not isinstance(data, Mapping):
            return data
        out = dict(data)
        rp = out.get("rules_path") or out.get("policy_file")
        if rp is not None:
            out["rules_path"] = str(rp)
            out["policy_file"] = str(rp)
        return out

    def to_summary_dict(self) -> dict[str, Any]:
        """Вернуть публичную сводку настроек Policy-as-Code Guardrails."""
        return {
            "enabled": self.enabled,
            "engine": self.engine,
            "preset": self.preset,
            "rules_path": self.rules_path,
            "policy_file": self.policy_file,
            "opa_url": self.opa_url,
            "fail_closed": self.fail_closed,
            "allow_safe_on_opa_failure": self.allow_safe_on_opa_failure,
            "cache_ttl_seconds": self.cache_ttl_seconds,
            "maintenance_windows": list(self.maintenance_windows),
            "maintenance_window_active": self.maintenance_window_active,
            "default_agent_id": self.default_agent_id,
            "default_role": self.default_role,
            "max_ast_depth": self.max_ast_depth,
            "max_pipeline_length": self.max_pipeline_length,
        }


def build_auth_context(
    *,
    command: str | None = "",
    ast: ParsedCommandAST | None = None,
    action_type: str | None = None,
    tool_name: str = "uniconn_run",
    sudo: bool = False,
    dry_run: bool = False,
    cwd: str | None = None,
    risk_tier: str = "SAFE",
    risk_reasons: Sequence[str] = (),
    host: str = "localhost",
    host_name: str | None = None,
    host_address: str | None = None,
    transport: str = "local",
    environment: str | None = None,
    is_production: bool | None = None,
    criticality: str = "standard",
    groups: Sequence[str] = (),
    tags: Mapping[str, Any] | None = None,
    target_path: str | None = None,
    path: str | None = None,
    flow_name: str | None = None,
    flow_tasks: Sequence[str] = (),
    agent_id: str | None = None,
    role: str | None = None,
    session_id: str | None = None,
    is_maintenance_window: bool | None = None,
    maintenance_window_override: bool | None = None,
    maintenance_windows: Sequence[str] = (),
    now: datetime | None = None,
) -> AuthContext:
    """Собрать полный документ ``AuthContext`` для передачи в движок политик."""
    from .ast_parser import CommandASTParser

    cmd_str = command or ""
    eff_host = (host_name or host or "localhost").strip() or "localhost"
    eff_target_path = target_path or path

    if action_type is None:
        if flow_name or tool_name in ("uniconn_run_flow", "uniconn_resume_flow") or tool_name.startswith("flow_"):
            eff_action_type = "flow_execution"
        elif tool_name == "uniconn_write_file" or (eff_target_path and not cmd_str):
            eff_action_type = "file_write"
        else:
            eff_action_type = "command_execution"
    else:
        eff_action_type = action_type

    parsed_ast = ast if ast is not None else CommandASTParser.parse(cmd_str, sudo=sudo)
    ast_dict = parsed_ast.to_dict()
    if eff_target_path and eff_target_path not in ast_dict.get("target_paths", []):
        merged_targets = [*ast_dict.get("target_paths", []), eff_target_path]
        ast_dict["targets"] = merged_targets
        ast_dict["target_paths"] = merged_targets

    group_tuple = tuple(str(g) for g in groups if str(g).strip())
    str_tags = {str(k): str(v) for k, v in (tags or {}).items()}

    raw_env = (environment or str_tags.get("env") or str_tags.get("environment") or "").strip().lower()
    prod_markers = {"prod", "production", "prd", "critical"}
    if raw_env in prod_markers or is_production is True:
        resolved_env = "production"
    elif raw_env in ("staging", "stage", "stg"):
        resolved_env = "staging"
    elif raw_env and raw_env != "default":
        resolved_env = raw_env
    elif any(g.lower() in prod_markers for g in group_tuple) or eff_host.lower().startswith(("prod-", "prd-")):
        resolved_env = "production"
    elif any(g.lower() in ("staging", "stage", "stg") for g in group_tuple):
        resolved_env = "staging"
    else:
        resolved_env = "development"

    maint_override = is_maintenance_window if is_maintenance_window is not None else maintenance_window_override
    eff_maint = (
        maint_override
        if maint_override is not None
        else is_within_maintenance_windows(maintenance_windows, now=now)
    )
    ref_time = (now or datetime.now(UTC)).astimezone(UTC)

    return AuthContext(
        subject=SubjectContext(
            agent_id=(agent_id or "uniconn-agent").strip() or "uniconn-agent",
            role=(role or "agent").strip() or "agent",
            authenticated=True,
            session_id=session_id,
        ),
        resource=ResourceContext(
            host=eff_host,
            host_address=host_address,
            transport=transport or "local",
            environment=resolved_env,
            criticality="tier-1" if resolved_env == "production" and criticality == "standard" else criticality,
            groups=group_tuple,
            tags=str_tags,
            target_path=eff_target_path,
        ),
        action=ActionContext(
            type=eff_action_type,
            tool_name=tool_name,
            raw_command=cmd_str,
            sudo=sudo or any(c.is_sudo for c in parsed_ast.atomic_commands),
            dry_run=dry_run,
            cwd=cwd,
            risk_tier=risk_tier,
            risk_reasons=tuple(str(r) for r in risk_reasons),
            ast=ast_dict,
            flow_name=flow_name,
            flow_tasks=tuple(str(t) for t in flow_tasks),
        ),
        environment=EnvironmentContext(
            time_utc=ref_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            day_of_week=ref_time.strftime("%A"),
            is_maintenance_window=eff_maint,
        ),
    )


__all__ = [
    "ActionContext",
    "AuthContext",
    "EnvironmentContext",
    "PolicyDecision",
    "PolicyEvaluationResult",
    "PolicyGuardrailConfig",
    "PolicyViolation",
    "ResourceContext",
    "SubjectContext",
    "build_auth_context",
    "is_within_maintenance_windows",
]
