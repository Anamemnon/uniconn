# src/uniconn/mcp/_flow_checkpoints.py
"""Оценка рисков Flow (FlowRiskEvaluator) и хранилище чекпоинтов (FlowCheckpointStore)."""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import hashlib
import hmac
import json
import logging
import math
import os
import secrets
import time
import uuid
import zlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self

from .._logging import SecretMaskingFilter
from ..orchestration.flow import Flow
from ..orchestration.models import FlowReport
from ..orchestration.scheduler import compute_active_tasks_by_tags
from ..orchestration.task import Task
from .models import ActionRiskTier, HITLPolicy, MCPHostEntry, RiskAssessment
from .storage import (
    FLOW_CHECKPOINT_NAMESPACE,
    SQLiteStateStore,
    StateStore,
    resolve_state_store,
    sync_meta_secret,
)

_LOGGER = logging.getLogger("uniconn.mcp.checkpoints")

CHECKPOINT_TOKEN_PREFIX: str = "ucp1."
MAX_CHECKPOINT_TOKEN_BYTES: int = 65_536
MAX_CHECKPOINT_DECOMPRESSED_BYTES: int = 524_288

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


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + pad).encode("ascii"))


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
    """Запись чекпоинта выполнения сценария ``Flow`` для возобновления по ``run_id`` или токену."""

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
    tenant_id: str | None = None
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
            "tenant_id": self.tenant_id,
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
            tenant_id=str(data["tenant_id"]).strip() if data.get("tenant_id") else None,
            created_at=str(data.get("created_at") or datetime.now(UTC).isoformat()),
            updated_at=str(data.get("updated_at") or datetime.now(UTC).isoformat()),
        )


class FlowCheckpointStore:
    """Асинхронное хранилище чекпоинтов ``Flow`` поверх ``StateStore`` и подписанных opaque-токенов."""

    def __init__(
        self,
        store_path: str | Path | None = None,
        *,
        store: StateStore | None = None,
        ttl_seconds: float = 86400.0,
        signing_secret: str | bytes | None = None,
        max_token_bytes: int = MAX_CHECKPOINT_TOKEN_BYTES,
    ) -> None:
        """Инициализировать хранилище чекпоинтов (по умолчанию zero-disk ``InMemoryStateStore``)."""
        self.ttl_seconds = max(1.0, float(ttl_seconds))
        self.max_token_bytes = max(1024, int(max_token_bytes))
        self._secret_lock = asyncio.Lock()

        if store is not None:
            self._store: StateStore = store
            self._owns_store = False
            db_attr = getattr(store, "db_path", None)
            self.store_path: Path | None = db_attr if isinstance(db_attr, Path) else None
        else:
            self._store, self.store_path = resolve_state_store(store_path)
            self._owns_store = True

        raw_secret: str | bytes | None = signing_secret
        if raw_secret is None:
            raw_secret = os.environ.get("UNICONN_CHECKPOINT_SECRET")

        if raw_secret is not None and (
            (isinstance(raw_secret, bytes) and len(raw_secret) > 0)
            or (isinstance(raw_secret, str) and raw_secret.strip())
        ):
            self._signing_key: bytes = (
                raw_secret if isinstance(raw_secret, bytes) else raw_secret.strip().encode("utf-8")
            )
            self._secret_synced = True
        elif isinstance(self._store, SQLiteStateStore):
            meta = self._store.get_or_create_meta_sync(
                "flow_checkpoint_secret",
                {"secret": secrets.token_hex(32)},
            )
            self._signing_key = str(meta.get("secret") or secrets.token_hex(32)).encode("utf-8")
            self._secret_synced = True
        else:
            self._signing_key = secrets.token_hex(32).encode("utf-8")
            self._secret_synced = False

    @property
    def store(self) -> StateStore:
        """Активный бэкенд ``StateStore`` хранилища чекпоинтов."""
        return self._store

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()

    async def close(self) -> None:
        """Освободить ресурсы собственного ``StateStore`` (если создан хранилищем)."""
        if self._owns_store:
            await self._store.close()

    async def ensure_ready(self) -> None:
        """Гарантировать синхронизацию ключа подписи токенов с общим ``StateStore``."""
        await self._ensure_secret_synced()

    async def _ensure_secret_synced(self) -> bytes:
        if self._secret_synced:
            return self._signing_key
        async with self._secret_lock:
            if self._secret_synced:
                return self._signing_key
            candidate = self._signing_key.decode("utf-8")
            synced = await sync_meta_secret(self._store, "flow_checkpoint_secret", candidate)
            self._signing_key = synced.encode("utf-8")
            self._secret_synced = True
            return self._signing_key

    @staticmethod
    def _normalize_tenant_id(tenant_id: str | None) -> str | None:
        return tenant_id.strip() if isinstance(tenant_id, str) and tenant_id.strip() else None

    def encode_token(
        self,
        record: FlowCheckpointRecord,
        *,
        ttl_seconds: float | None = None,
    ) -> str:
        """Закодировать чекпоинт в подписанный HMAC-SHA256 сжатый opaque-токен ``ucp1.<data>.<sig>``."""
        if ttl_seconds is not None:
            raw_ttl = float(ttl_seconds)
            if not math.isfinite(raw_ttl):
                raise ValueError("ttl_seconds must be a finite number")
            eff_ttl = max(0.1, raw_ttl)
        else:
            eff_ttl = self.ttl_seconds
        envelope = {
            "v": 1,
            "exp": round(time.time() + eff_ttl, 3),
            "rec": record.to_dict(),
        }
        canonical = json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        compressed = zlib.compress(canonical, level=6)
        payload_b64 = _b64url_encode(compressed)
        signing_input = f"{CHECKPOINT_TOKEN_PREFIX}{payload_b64}".encode("ascii")
        sig = hmac.new(self._signing_key, signing_input, hashlib.sha256).digest()
        sig_b64 = _b64url_encode(sig)
        token = f"{CHECKPOINT_TOKEN_PREFIX}{payload_b64}.{sig_b64}"
        if len(token.encode("ascii")) > self.max_token_bytes:
            raise ValueError(
                f"Signed checkpoint token size ({len(token)} bytes) exceeds max_token_bytes={self.max_token_bytes}"
            )
        return token

    def try_encode_token(
        self,
        record: FlowCheckpointRecord,
        *,
        ttl_seconds: float | None = None,
    ) -> str | None:
        """Сформировать подписанный opaque-токен или вернуть ``None`` при превышении лимита размера."""
        try:
            return self.encode_token(record, ttl_seconds=ttl_seconds)
        except ValueError as exc:
            _LOGGER.warning("Omitting stateless checkpoint_token for run %s: %s", record.run_id, exc)
            return None

    def decode_token(
        self,
        token: str,
        *,
        tenant_id: str | None = None,
        strict_tenant: bool = False,
        now: float | None = None,
    ) -> FlowCheckpointRecord:
        """Проверить подпись, TTL, защиту от zip-bomb и ``tenant_id`` и декодировать ``checkpoint_token``."""
        raw_token = token.strip() if isinstance(token, str) else ""
        if not raw_token or not raw_token.startswith(CHECKPOINT_TOKEN_PREFIX):
            raise ValueError("Invalid checkpoint_token format (expected 'ucp1.<payload>.<signature>')")
        if len(raw_token.encode("utf-8")) > max(self.max_token_bytes * 2, 131_072):
            raise ValueError("Checkpoint token exceeds maximum allowed encoded length")

        parts = raw_token.split(".")
        if len(parts) != 3 or parts[0] != "ucp1" or not parts[1] or not parts[2]:
            raise ValueError("Invalid checkpoint_token structure")

        _, payload_b64, sig_b64 = parts
        try:
            signing_input = f"{CHECKPOINT_TOKEN_PREFIX}{payload_b64}".encode("ascii")
            sig_b64.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError("Invalid checkpoint_token format (non-ASCII characters)") from exc
        expected_sig = _b64url_encode(hmac.new(self._signing_key, signing_input, hashlib.sha256).digest())
        if not hmac.compare_digest(expected_sig, sig_b64):
            raise ValueError("Invalid checkpoint_token HMAC signature")

        try:
            compressed = _b64url_decode(payload_b64)
        except Exception as exc:
            raise ValueError("Malformed checkpoint_token base64 payload") from exc

        try:
            decompressor = zlib.decompressobj()
            raw_bytes = decompressor.decompress(compressed, MAX_CHECKPOINT_DECOMPRESSED_BYTES + 1)
            if (
                len(raw_bytes) > MAX_CHECKPOINT_DECOMPRESSED_BYTES
                or decompressor.unconsumed_tail
                or not decompressor.eof
            ):
                raise ValueError("Checkpoint token decompressed payload exceeds safety limit")
            envelope = json.loads(raw_bytes.decode("utf-8"))
        except ValueError:
            raise
        except Exception as exc:
            raise ValueError("Malformed checkpoint_token compressed payload") from exc

        if not isinstance(envelope, Mapping) or envelope.get("v") != 1:
            raise ValueError("Unsupported checkpoint_token schema version")

        exp = envelope.get("exp")
        ref_now = time.time() if now is None else float(now)
        if isinstance(exp, bool) or not isinstance(exp, int | float) or not math.isfinite(exp) or ref_now >= float(exp):
            raise ValueError("Checkpoint token has expired")

        rec_data = envelope.get("rec")
        if not isinstance(rec_data, Mapping):
            raise ValueError("Malformed checkpoint_token record payload")

        record = FlowCheckpointRecord.from_dict(rec_data)
        norm_tenant = self._normalize_tenant_id(tenant_id)
        if (strict_tenant or norm_tenant is not None) and record.tenant_id != norm_tenant:
            raise PermissionError("Flow checkpoint token does not belong to the active tenant")
        return record

    async def record_from_report(
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
        tenant_id: str | None = None,
    ) -> FlowCheckpointRecord:
        """Асинхронно сохранить состояние выполнения ``FlowReport`` в ``StateStore`` и вернуть запись."""
        await self._ensure_secret_synced()
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
        norm_tenant = self._normalize_tenant_id(tenant_id)
        existing = await self._store.get(FLOW_CHECKPOINT_NAMESPACE, eff_run_id)
        if existing is not None and not existing.is_expired() and existing.tenant_id != norm_tenant:
            raise PermissionError(
                f"Flow checkpoint run_id {eff_run_id!r} belongs to another tenant"
            )
        created_iso = (
            str(existing.value.get("created_at") or now_iso)
            if existing is not None
            else now_iso
        )
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
            tenant_id=norm_tenant,
            created_at=created_iso,
            updated_at=now_iso,
        )
        await self._store.put(
            FLOW_CHECKPOINT_NAMESPACE,
            eff_run_id,
            record.to_dict(),
            tenant_id=norm_tenant,
            status="completed" if record.ok else "resumable",
            ttl_seconds=self.ttl_seconds,
        )
        await self._store.prune_expired(FLOW_CHECKPOINT_NAMESPACE)
        return record

    async def get(
        self,
        run_id: str,
        *,
        tenant_id: str | None = None,
        strict_tenant: bool = False,
    ) -> FlowCheckpointRecord:
        """Асинхронно получить чекпоинт по ``run_id`` (с проверкой изоляции ``tenant_id`` и TTL)."""
        key = run_id.strip()
        norm_tenant = self._normalize_tenant_id(tenant_id)
        rec = await self._store.get(
            FLOW_CHECKPOINT_NAMESPACE,
            key,
            tenant_id=norm_tenant,
            strict_tenant=strict_tenant,
        )
        if rec is None or rec.is_expired():
            raise KeyError(f"Flow checkpoint run_id {key!r} not found")
        return FlowCheckpointRecord.from_dict(rec.value)

    async def list_records(
        self,
        *,
        only_resumable: bool = False,
        tenant_id: str | None = None,
        strict_tenant: bool = False,
    ) -> list[FlowCheckpointRecord]:
        """Асинхронно вернуть список сохранённых чекпоинтов (с фильтрацией по ``tenant_id`` и TTL)."""
        norm_tenant = self._normalize_tenant_id(tenant_id)
        rows = await self._store.list(
            FLOW_CHECKPOINT_NAMESPACE,
            tenant_id=norm_tenant,
            strict_tenant=strict_tenant,
            status="resumable" if only_resumable else None,
            include_expired=False,
        )
        return [FlowCheckpointRecord.from_dict(r.value) for r in rows]

    async def delete(self, run_id: str) -> bool:
        """Удалить чекпоинт по ``run_id`` из ``StateStore``."""
        return await self._store.delete(FLOW_CHECKPOINT_NAMESPACE, run_id.strip())

    async def prune_expired(self) -> int:
        """Удалить просроченные чекпоинты из ``StateStore``."""
        return await self._store.prune_expired(FLOW_CHECKPOINT_NAMESPACE)


__all__ = [
    "CHECKPOINT_TOKEN_PREFIX",
    "MAX_CHECKPOINT_DECOMPRESSED_BYTES",
    "MAX_CHECKPOINT_TOKEN_BYTES",
    "FlowCheckpointRecord",
    "FlowCheckpointStore",
    "FlowRiskEvaluator",
    "_mask_nested_value",
    "_to_checkpoint_json_safe",
]

