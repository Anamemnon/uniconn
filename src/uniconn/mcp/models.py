# src/uniconn/mcp/models.py
"""Модели данных, политики безопасности и определения инструментов для MCP-сервера uniconn."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..security.models import PolicyGuardrailConfig


class ActionRiskTier(StrEnum):
    """Уровень риска операции ИИ-агента согласно Tiered Risk Model."""

    TIER_0_SAFE = "SAFE"
    TIER_1_MUTATING = "MUTATING"
    TIER_2_DESTRUCTIVE = "DESTRUCTIVE"
    TIER_3_FORBIDDEN = "FORBIDDEN"

    @property
    def severity(self) -> int:
        """Числовой ранг критичности уровня риска (0..3)."""
        order = {
            ActionRiskTier.TIER_0_SAFE: 0,
            ActionRiskTier.TIER_1_MUTATING: 1,
            ActionRiskTier.TIER_2_DESTRUCTIVE: 2,
            ActionRiskTier.TIER_3_FORBIDDEN: 3,
        }
        return order[self]


class ApprovalStatus(StrEnum):
    """Статус жизненного цикла заявки на двухфазное подтверждение."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    CONSUMED = "CONSUMED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class RiskAssessment(BaseModel):
    """Результат оценки риска команды или вызова инструмента."""

    model_config = ConfigDict(frozen=True)

    risk_tier: ActionRiskTier
    reasons: tuple[str, ...] = ()
    is_production: bool = False
    requires_approval: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Сериализовать оценку риска в словарь."""
        return {
            "risk_tier": self.risk_tier.value,
            "reasons": list(self.reasons),
            "is_production": self.is_production,
            "requires_approval": self.requires_approval,
        }


class ApprovalRequest(BaseModel):
    """Заявка на двухфазное согласование действия ИИ-агента (HITL)."""

    approval_id: str = Field(description="Уникальный ID заявки (например, appr_7f9c2e1b)")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime
    agent_id: str | None = None
    target_host: str
    tool_name: str
    command: str | None = None
    sudo: bool = False
    cwd: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    risk_tier: ActionRiskTier
    risk_reasons: list[str] = Field(default_factory=list)
    diff: str | None = None
    status: ApprovalStatus = ApprovalStatus.PENDING
    decided_by: str | None = None
    decided_at: datetime | None = None
    decision_reason: str | None = None
    consumed_at: datetime | None = None
    hmac_signature: str = Field(
        description="Криптографическая подпись HMAC-SHA256 канонических параметров вызова"
    )

    def is_expired(self, now: datetime | None = None) -> bool:
        """Проверить, истёк ли срок действия заявки."""
        ref = now or datetime.now(UTC)
        return ref >= self.expires_at

    def remaining_seconds(self, now: datetime | None = None) -> float:
        """Вернуть оставшееся время жизни заявки в секундах (не меньше 0.0)."""
        ref = now or datetime.now(UTC)
        return max(0.0, round((self.expires_at - ref).total_seconds(), 3))

    def to_public_dict(self, *, now: datetime | None = None) -> dict[str, Any]:
        """Преобразовать заявку в JSON-совместимый словарь для агента, CLI или Dashboard."""
        return {
            "approval_id": self.approval_id,
            "status": self.status.value,
            "target_host": self.target_host,
            "tool_name": self.tool_name,
            "command": self.command,
            "sudo": self.sudo,
            "cwd": self.cwd,
            "parameters": dict(self.parameters),
            "risk_tier": self.risk_tier.value,
            "risk_reasons": list(self.risk_reasons),
            "diff": self.diff,
            "agent_id": self.agent_id,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "remaining_seconds": self.remaining_seconds(now),
            "decided_by": self.decided_by,
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,
            "decision_reason": self.decision_reason,
            "consumed_at": self.consumed_at.isoformat() if self.consumed_at else None,
            "hmac_signature": self.hmac_signature,
        }


class HITLPolicy(BaseModel):
    """Конфигурация политики Human-in-the-Loop (HITL) и двухфазных подтверждений."""

    model_config = ConfigDict(frozen=True)

    enabled: bool = False
    require_approval_for: tuple[ActionRiskTier, ...] = (ActionRiskTier.TIER_2_DESTRUCTIVE,)
    prod_require_approval_for: tuple[ActionRiskTier, ...] = (
        ActionRiskTier.TIER_1_MUTATING,
        ActionRiskTier.TIER_2_DESTRUCTIVE,
    )
    prod_groups: tuple[str, ...] = ("prod", "production", "prd", "critical")
    timeout_seconds: float = Field(default=300.0, gt=0.0)
    wait_for_approval: bool = False
    wait_timeout_seconds: float = Field(default=30.0, gt=0.0)
    channels: tuple[str, ...] = ("cli", "dashboard")
    store_path: str | None = None
    webhook_url: str | None = None
    webhook_secret: str | None = None
    audit_log_path: str | None = None
    allow_operator_override: bool = True

    def is_production_groups(self, groups: Sequence[str]) -> bool:
        """Определить, относится ли хост со списком групп к production-контуру."""
        prod_set = {g.strip().lower() for g in self.prod_groups if g.strip()}
        return any(str(g).strip().lower() in prod_set for g in groups)

    def requires_approval(self, tier: ActionRiskTier, *, is_production: bool = False) -> bool:
        """Проверить, требует ли указанный уровень риска подтверждения оператором."""
        if not self.enabled or tier == ActionRiskTier.TIER_3_FORBIDDEN:
            return False
        active_tiers = (
            self.prod_require_approval_for if is_production else self.require_approval_for
        )
        return tier in active_tiers

    def to_summary_dict(self) -> dict[str, Any]:
        """Вернуть публичную сводку политики HITL без раскрытия секретов."""
        return {
            "enabled": self.enabled,
            "require_approval_for": [t.value for t in self.require_approval_for],
            "prod_require_approval_for": [t.value for t in self.prod_require_approval_for],
            "prod_groups": list(self.prod_groups),
            "timeout_seconds": self.timeout_seconds,
            "wait_for_approval": self.wait_for_approval,
            "wait_timeout_seconds": self.wait_timeout_seconds,
            "channels": list(self.channels),
            "store_path": self.store_path,
            "webhook_configured": bool(self.webhook_url),
            "allow_operator_override": self.allow_operator_override,
        }


class MCPSecurityPolicy(BaseModel):
    """Политика безопасности и guardrails для MCP-сервера ``uniconn mcp``.

    По умолчанию сервер запускается в безопасном режиме (Safe Mode):
    - Запись файлов (``allow_write=False``) и ``sudo`` (``allow_sudo=False``) отключены.
    - Произвольные динамические URI вне реестра (``allow_dynamic_uri=False``) запрещены.
    - Включён базовый ``blocklist_hook`` против деструктивных команд и маскирование секретов.
    """

    model_config = ConfigDict(frozen=True)

    allow_write: bool = False
    allow_sudo: bool = False
    allow_dynamic_uri: bool = False
    dry_run: bool = False
    allowlist: tuple[str, ...] = ()
    blocklist: tuple[str, ...] | None = None
    audit_log_path: str | None = None
    max_read_bytes: int = Field(default=65536, ge=1024, le=10_485_760)
    hitl: HITLPolicy = Field(default_factory=HITLPolicy)
    guardrails: PolicyGuardrailConfig = Field(default_factory=PolicyGuardrailConfig)

    def to_summary_dict(self) -> dict[str, Any]:
        """Вернуть публичную сводку активной политики безопасности."""
        return {
            "allow_write": self.allow_write,
            "allow_sudo": self.allow_sudo,
            "allow_dynamic_uri": self.allow_dynamic_uri,
            "dry_run": self.dry_run,
            "allowlist": list(self.allowlist),
            "custom_blocklist": list(self.blocklist) if self.blocklist is not None else None,
            "audit_log_enabled": self.audit_log_path is not None,
            "max_read_bytes": self.max_read_bytes,
            "hitl": self.hitl.to_summary_dict(),
            "guardrails": self.guardrails.to_summary_dict(),
        }


class MCPHostEntry(BaseModel):
    """Запись о зарегистрированном хосте в реестре MCP-сервера."""

    model_config = ConfigDict(frozen=True)

    name: str
    uri: str
    masked_uri: str
    transport: str
    host: str | None = None
    groups: tuple[str, ...] = ()
    raw_config: dict[str, Any] = Field(default_factory=dict, repr=False, exclude=True)

    def is_production(self, prod_groups: Sequence[str] = ("prod", "production", "prd", "critical")) -> bool:
        """Проверить, входит ли хост в production-группу или имеет тег окружения prod."""
        prod_set = {g.strip().lower() for g in prod_groups if g.strip()}
        if any(g.strip().lower() in prod_set for g in self.groups):
            return True
        env_val = str(self.raw_config.get("env") or self.raw_config.get("environment") or "").strip().lower()
        return env_val in prod_set

    def to_public_dict(self) -> dict[str, Any]:
        """Сериализовать запись хоста без раскрытия секретов и паролей."""
        return {
            "name": self.name,
            "uri": self.masked_uri,
            "transport": self.transport,
            "host": self.host,
            "groups": list(self.groups),
        }


class MCPToolDefinition(BaseModel):
    """Описание MCP-инструмента (Tool) в формате JSON Schema."""

    model_config = ConfigDict(frozen=True)

    name: str
    description: str
    input_schema: dict[str, Any]

    def to_mcp_dict(self) -> dict[str, Any]:
        """Преобразовать определение в формат ответа ``tools/list`` протокола MCP."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


class MCPResourceDefinition(BaseModel):
    """Описание статического MCP-ресурса (Resource)."""

    model_config = ConfigDict(frozen=True)

    uri: str
    name: str
    description: str
    mime_type: str = "application/json"

    def to_mcp_dict(self) -> dict[str, Any]:
        """Преобразовать ресурс в формат ответа ``resources/list`` протокола MCP."""
        return {
            "uri": self.uri,
            "name": self.name,
            "description": self.description,
            "mimeType": self.mime_type,
        }


class MCPResourceTemplate(BaseModel):
    """Описание параметризованного шаблона MCP-ресурса (Resource Template)."""

    model_config = ConfigDict(frozen=True)

    uri_template: str
    name: str
    description: str
    mime_type: str = "application/json"

    def to_mcp_dict(self) -> dict[str, Any]:
        """Преобразовать шаблон в формат ответа ``resources/templates/list``."""
        return {
            "uriTemplate": self.uri_template,
            "name": self.name,
            "description": self.description,
            "mimeType": self.mime_type,
        }


__all__ = [
    "ActionRiskTier",
    "ApprovalRequest",
    "ApprovalStatus",
    "HITLPolicy",
    "MCPHostEntry",
    "MCPResourceDefinition",
    "MCPResourceTemplate",
    "MCPSecurityPolicy",
    "MCPToolDefinition",
    "RiskAssessment",
]

