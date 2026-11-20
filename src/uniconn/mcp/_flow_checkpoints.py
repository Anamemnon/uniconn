# src/uniconn/mcp/_flow_checkpoints.py
"""Оценка рисков Flow (FlowRiskEvaluator) и хранилище чекпоинтов (FlowCheckpointStore)."""

from __future__ import annotations

import dataclasses
import json
import os
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .._logging import SecretMaskingFilter
from ..orchestration.flow import Flow
from ..orchestration.models import FlowReport
from ..orchestration.scheduler import compute_active_tasks_by_tags
from ..orchestration.task import Task
from .models import ActionRiskTier, HITLPolicy, MCPHostEntry, RiskAssessment

_HIGH_RISK_TAGS: frozenset[str] = frozenset(
    {"destructive", "danger", "dangerous", "drop", "purge", "format", "wipe", "reboot", "shutdown", "delete"}
)
_MEDIUM_RISK_TAGS: frozenset[str] = frozenset(
    {
        "mutating", "write", "deploy", "release", "restart", "reload", "upgrade", "update",
        "rollback", "migrate", "migration", "provision", "configure", "install",
    }
)
_SAFE_TAGS: frozenset[str] = frozenset(
    {
        "safe", "readonly", "read_only", "read-only", "check", "preflight", "verify",
        "audit", "inspect", "diagnostics", "status", "ping", "facts",
    }
)


def _mask_nested_value(val: Any) -> Any:
    """Рекурсивно замаскировать секреты в строках, словарях и списках."""
    if isinstance(val, str):
        return SecretMaskingFilter._mask_string(val)
    if isinstance(val, Mapping):
        return {str(k): _mask_nested_value(v) for k, v in val.items()}
    if isinstance(val, list | tuple):
        return [_mask_nested_value(item) for item in val]
    return val


def _to_checkpoint_json_safe(val: Any) -> Any:
    """Преобразовать возвращаемое значение задачи в JSON-безопасное представление с маскированием секретов."""
    if val is None or isinstance(val, bool | int | float):
        return val
    if isinstance(val, str):
        return SecretMaskingFilter._mask_string(val)
    if isinstance(val, Mapping):
        return {str(k): _to_checkpoint_json_safe(v) for k, v in val.items()}
    if isinstance(val, list | tuple | set | frozenset):
        return [_to_checkpoint_json_safe(item) for item in val]
    if hasattr(val, "to_dict"):
        to_dict_fn = getattr(val, "to_dict", None)
        if callable(to_dict_fn):
            try:
                return _to_checkpoint_json_safe(to_dict_fn())
            except Exception:
                return None
    if hasattr(val, "model_dump"):
        dump_fn = getattr(val, "model_dump", None)
        if callable(dump_fn):
            try:
                return _to_checkpoint_json_safe(dump_fn())
            except Exception:
                return None
    if dataclasses.is_dataclass(val) and not isinstance(val, type):
        try:
            return _to_checkpoint_json_safe(dataclasses.asdict(val))
        except Exception:
            return None
    return SecretMaskingFilter._mask_string(str(val))


class FlowRiskEvaluator:
    """Статический анализатор уровня риска ``ActionRiskTier`` и генератор плана для ``Flow``."""

    _EXPLICIT_TIER_MAP: dict[str, ActionRiskTier] = {
        "safe": ActionRiskTier.TIER_0_SAFE,
        "tier_0_safe": ActionRiskTier.TIER_0_SAFE,
        "readonly": ActionRiskTier.TIER_0_SAFE,
        "low": ActionRiskTier.TIER_1_MUTATING,
        "tier_1_low": ActionRiskTier.TIER_1_MUTATING,
        "tier_1_mutating": ActionRiskTier.TIER_1_MUTATING,
        "medium": ActionRiskTier.TIER_1_MUTATING,
        "tier_2_medium": ActionRiskTier.TIER_1_MUTATING,
        "mutating": ActionRiskTier.TIER_1_MUTATING,
        "high": ActionRiskTier.TIER_2_DESTRUCTIVE,
        "tier_2_destructive": ActionRiskTier.TIER_2_DESTRUCTIVE,
        "tier_3_high": ActionRiskTier.TIER_2_DESTRUCTIVE,
        "destructive": ActionRiskTier.TIER_2_DESTRUCTIVE,
        "forbidden": ActionRiskTier.TIER_3_FORBIDDEN,
        "tier_3_forbidden": ActionRiskTier.TIER_3_FORBIDDEN,
    }

    @classmethod
    def evaluate(
        cls,
        flow: Flow,
        *,
        entries: Sequence[MCPHostEntry] = (),
        vars: Mapping[str, Any] | None = None,
        tags: Sequence[str] | None = None,
        mode: str | None = None,
        dry_run: bool = False,
        policy: HITLPolicy | None = None,
    ) -> tuple[RiskAssessment, str]:
        """Оценить риск запуска ``Flow`` и сформировать ASCII DAG-план для ``ApprovalRequest.diff``."""
        eff_policy = policy or HITLPolicy()
        target_names = [e.name for e in entries]
        masked_vars: dict[str, Any] = _mask_nested_value(dict(vars)) if vars else {}

        plan_preview = flow.describe_plan(
            targets=target_names,
            vars=masked_vars,
            tags=tags,
            mode=mode,
            dry_run=dry_run,
        )

        prod_hosts = [e.name for e in entries if e.is_production(eff_policy.prod_groups)]
        any_prod = bool(prod_hosts)

        if dry_run:
            return (
                RiskAssessment(
                    risk_tier=ActionRiskTier.TIER_0_SAFE,
                    reasons=("Flow invoked with dry_run=True (simulation only)",),
                    is_production=any_prod,
                    requires_approval=False,
                ),
                plan_preview,
            )

        reasons: list[str] = []
        tier: ActionRiskTier | None = None

        if flow.risk_tier and flow.risk_tier in cls._EXPLICIT_TIER_MAP:
            tier = cls._EXPLICIT_TIER_MAP[flow.risk_tier]
            reasons.append(f"Flow explicitly declares risk_tier={flow.risk_tier!r}")

        active_names = compute_active_tasks_by_tags(flow.tasks, flow.dag, tags)
        active_tasks: list[Task[Any, Any]] = [
            t for name, t in flow.tasks.items() if active_names is None or name in active_names
        ]
        active_tags = {tag.lower() for t in active_tasks for tag in t.tags}

        high_matched = sorted(active_tags & _HIGH_RISK_TAGS)
        medium_matched = sorted(active_tags & _MEDIUM_RISK_TAGS)
        has_post_hooks = any(bool(t.post) for t in active_tasks)

        if high_matched:
            if tier not in (ActionRiskTier.TIER_3_FORBIDDEN, ActionRiskTier.TIER_2_DESTRUCTIVE):
                tier = ActionRiskTier.TIER_2_DESTRUCTIVE
            reasons.append(f"Flow contains destructive task tags: {', '.join(high_matched)}")
        elif medium_matched or has_post_hooks:
            if tier is None or tier == ActionRiskTier.TIER_0_SAFE:
                tier = ActionRiskTier.TIER_1_MUTATING
            if medium_matched:
                reasons.append(f"Flow contains mutating task tags: {', '.join(medium_matched)}")
            if has_post_hooks:
                reasons.append("Flow tasks trigger post-execution handlers")
        elif active_tags and active_tags <= _SAFE_TAGS and tier is None:
            tier = ActionRiskTier.TIER_0_SAFE
            reasons.append(f"All active tasks are marked read-only/safe ({', '.join(sorted(active_tags))})")
        if tier is None:
            tier = ActionRiskTier.TIER_1_MUTATING
            reasons.append(f"Multi-step orchestration flow {flow.name!r} ({len(active_tasks)} active tasks)")

        if any_prod and tier == ActionRiskTier.TIER_1_MUTATING:
            tier = ActionRiskTier.TIER_2_DESTRUCTIVE
            reasons.append(f"Targets production host(s): {', '.join(prod_hosts)}")
        elif any_prod and tier == ActionRiskTier.TIER_2_DESTRUCTIVE:
            reasons.append(f"Targets production host(s): {', '.join(prod_hosts)}")

        requires_appr = eff_policy.requires_approval(tier, is_production=any_prod) or (
            eff_policy.enabled
            and tier in (ActionRiskTier.TIER_1_MUTATING, ActionRiskTier.TIER_2_DESTRUCTIVE)
        )
        return (
            RiskAssessment(
                risk_tier=tier,
                reasons=tuple(reasons),
                is_production=any_prod,
                requires_approval=requires_appr,
            ),
            plan_preview,
        )


@dataclass(slots=True)
class FlowCheckpointRecord:
    """Запись чекпоинта выполнения сценария ``Flow`` для возобновления по ``run_id``."""

    run_id: str
    flow_name: str
    targets: list[str]
    group: str | None = None
    vars: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    mode: str = "barrier"
    completed_by_host: dict[str, list[str]] = field(default_factory=dict)
    task_outputs_by_host: dict[str, dict[str, Any]] = field(default_factory=dict)
    failed_tasks: list[dict[str, Any]] = field(default_factory=list)
    ok: bool = False
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        """Преобразовать запись чекпоинта в сериализуемый словарь."""
        return {
            "run_id": self.run_id,
            "flow_name": self.flow_name,
            "targets": list(self.targets),
            "group": self.group,
            "vars": dict(self.vars),
            "tags": list(self.tags),
            "mode": self.mode,
            "completed_by_host": {h: list(tasks) for h, tasks in self.completed_by_host.items()},
            "task_outputs_by_host": {h: dict(outputs) for h, outputs in self.task_outputs_by_host.items()},
            "failed_tasks": list(self.failed_tasks),
            "ok": self.ok,
            "can_resume": not self.ok,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> FlowCheckpointRecord:
        """Восстановить ``FlowCheckpointRecord`` из словаря."""
        raw_completed = data.get("completed_by_host") or {}
        completed_map: dict[str, list[str]] = {}
        if isinstance(raw_completed, Mapping):
            for h, t_list in raw_completed.items():
                if isinstance(t_list, Sequence) and not isinstance(t_list, str):
                    completed_map[str(h)] = [str(x) for x in t_list]
        raw_outputs = data.get("task_outputs_by_host") or {}
        outputs_map: dict[str, dict[str, Any]] = {}
        if isinstance(raw_outputs, Mapping):
            for h, out_dict in raw_outputs.items():
                if isinstance(out_dict, Mapping):
                    outputs_map[str(h)] = {str(k): v for k, v in out_dict.items()}
        raw_targets = data.get("targets") or ()
        targets_list = (
            [str(t) for t in raw_targets]
            if isinstance(raw_targets, Sequence) and not isinstance(raw_targets, str)
            else []
        )
        raw_tags = data.get("tags") or ()
        tags_list = (
            [str(t) for t in raw_tags]
            if isinstance(raw_tags, Sequence) and not isinstance(raw_tags, str)
            else []
        )
        raw_vars = data.get("vars")
        vars_dict = dict(raw_vars) if isinstance(raw_vars, Mapping) else {}
        raw_failed = data.get("failed_tasks") or ()
        failed_list = (
            [dict(item) for item in raw_failed if isinstance(item, Mapping)]
            if isinstance(raw_failed, Sequence)
            else []
        )
        return cls(
            run_id=str(data.get("run_id") or f"run_{uuid.uuid4().hex[:12]}"),
            flow_name=str(data.get("flow_name") or "uniconn_flow"),
            targets=targets_list,
            group=str(data["group"]) if data.get("group") else None,
            vars=vars_dict,
            tags=tags_list,
            mode=str(data.get("mode") or "barrier"),
            completed_by_host=completed_map,
            task_outputs_by_host=outputs_map,
            failed_tasks=failed_list,
            ok=bool(data.get("ok", False)),
            created_at=str(data.get("created_at") or datetime.now(UTC).isoformat()),
            updated_at=str(data.get("updated_at") or datetime.now(UTC).isoformat()),
        )


class FlowCheckpointStore:
    """Хранилище чекпоинтов выполнения ``Flow`` (в памяти и опционально на диске)."""

    def __init__(self, store_path: str | Path | None = None) -> None:
        self.store_path = Path(store_path).expanduser() if store_path is not None else None
        self._records: dict[str, FlowCheckpointRecord] = {}
        if self.store_path is not None and self.store_path.is_file():
            self._load_from_disk()

    def _load_from_disk(self) -> None:
        if self.store_path is None or not self.store_path.is_file():
            return
        try:
            raw = json.loads(self.store_path.read_text(encoding="utf-8"))
            items = raw.get("checkpoints", {}) if isinstance(raw, Mapping) else {}
            if isinstance(items, Mapping):
                for r_id, item in items.items():
                    if isinstance(item, Mapping):
                        self._records[str(r_id)] = FlowCheckpointRecord.from_dict(item)
        except Exception:
            return

    def _save_to_disk(self) -> None:
        if self.store_path is None:
            return
        try:
            self.store_path.parent.mkdir(parents=True, exist_ok=True)
            with os.fdopen(
                os.open(
                    str(self.store_path) + ".tmp",
                    os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                    0o600,
                ),
                "w",
                encoding="utf-8",
            ) as fh:
                payload = {"checkpoints": {k: v.to_dict() for k, v in self._records.items()}}
                json.dump(payload, fh, ensure_ascii=False, indent=2)
            os.replace(str(self.store_path) + ".tmp", self.store_path)
        except Exception:
            return

    def record_from_report(
        self,
        report: FlowReport,
        *,
        targets: Sequence[str],
        group: str | None = None,
        vars: Mapping[str, Any] | None = None,
        tags: Sequence[str] | None = None,
        mode: str = "barrier",
        prior_completed: Mapping[str, Sequence[str]] | None = None,
        prior_outputs: Mapping[str, Mapping[str, Any]] | None = None,
        run_id: str | None = None,
    ) -> FlowCheckpointRecord:
        """Сохранить состояние выполнения ``FlowReport`` в чекпоинт и вернуть запись."""
        if self.store_path is not None:
            self._load_from_disk()

        eff_run_id = run_id or report.run_id or f"run_{uuid.uuid4().hex[:12]}"
        completed_map: dict[str, list[str]] = {}
        if prior_completed:
            for h, tasks in prior_completed.items():
                completed_map[str(h)] = list(dict.fromkeys(str(t) for t in tasks))

        outputs_map: dict[str, dict[str, Any]] = {}
        if prior_outputs:
            for h, out_dict in prior_outputs.items():
                if isinstance(out_dict, Mapping):
                    outputs_map[str(h)] = {
                        str(k): _mask_nested_value(_to_checkpoint_json_safe(v))
                        for k, v in out_dict.items()
                    }

        failed_tasks: list[dict[str, Any]] = []
        for host, results in report.results.items():
            host_done = completed_map.setdefault(host, [])
            host_outputs = outputs_map.setdefault(host, {})
            for r in results:
                if r.status == "success" or r.skip_reason == "checkpoint_completed":
                    if r.task_name not in host_done:
                        host_done.append(r.task_name)
                    if r.return_value is not None:
                        host_outputs[r.task_name] = _mask_nested_value(
                            _to_checkpoint_json_safe(r.return_value)
                        )
                elif not r.ok:
                    fail_entry: dict[str, Any] = {
                        "host": host,
                        "task_name": r.task_name,
                        "error": SecretMaskingFilter._mask_string(
                            r.error or (str(r.exception) if r.exception else "failed")
                        ),
                        "attempts": r.attempts,
                    }
                    r_dict = r.to_dict()
                    if "diagnostic" in r_dict:
                        fail_entry["diagnostic"] = r_dict["diagnostic"]
                    failed_tasks.append(fail_entry)

        now_iso = datetime.now(UTC).isoformat()
        existing = self._records.get(eff_run_id)
        created_iso = existing.created_at if existing is not None else now_iso
        masked_vars: dict[str, Any] = _mask_nested_value(dict(vars)) if vars else {}

        record = FlowCheckpointRecord(
            run_id=eff_run_id,
            flow_name=report.flow_name,
            targets=[str(t) for t in targets],
            group=group,
            vars=masked_vars,
            tags=[str(t) for t in (tags or ())],
            mode=mode,
            completed_by_host=completed_map,
            task_outputs_by_host=outputs_map,
            failed_tasks=failed_tasks,
            ok=report.ok,
            created_at=created_iso,
            updated_at=now_iso,
        )
        self._records[eff_run_id] = record
        self._save_to_disk()
        return record

    def get(self, run_id: str) -> FlowCheckpointRecord:
        """Получить чекпоинт по ``run_id`` или выбросить ``KeyError``."""
        if self.store_path is not None:
            self._load_from_disk()
        key = run_id.strip()
        if key not in self._records:
            raise KeyError(f"Flow checkpoint run_id {key!r} not found")
        return self._records[key]

    def list_records(self, *, only_resumable: bool = False) -> list[FlowCheckpointRecord]:
        """Вернуть список сохранённых чекпоинтов."""
        if self.store_path is not None:
            self._load_from_disk()
        items = list(self._records.values())
        if only_resumable:
            items = [r for r in items if not r.ok]
        return items


__all__ = [
    "FlowCheckpointRecord",
    "FlowCheckpointStore",
    "FlowRiskEvaluator",
    "_mask_nested_value",
    "_to_checkpoint_json_safe",
]
