# src/uniconn/services/provisioning/_fleet_plan.py
"""Агрегированный план изменений флота (FleetChangePlan), перехватчик PlanRecorder и защита от дрейфа PlanApplier."""

from __future__ import annotations

import contextlib
import contextvars
import hashlib
import json
import os
import threading
from collections import deque
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ...exceptions import StateDriftError, UniconnError
from ...result import EnsureResult

if TYPE_CHECKING:
    from ...core.connection import Connection
    from .facade import StateManagementService

CURRENT_PLAN_HOST: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "uniconn_plan_host", default=None
)
CURRENT_PLAN_TASK: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "uniconn_plan_task", default=None
)
IN_NOTIFY_HANDLER: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "uniconn_in_notify_handler", default=False
)


def normalize_plan_host(conn: Connection, host_override: str | None = None) -> str:
    """Определить стабильный идентификатор хоста для записи в ``FleetChangePlan``."""
    if host_override and host_override.strip():
        return host_override.strip()
    ctx_host = CURRENT_PLAN_HOST.get()
    if ctx_host and ctx_host.strip():
        return ctx_host.strip()
    return conn.config.host or conn.config.uri_safe or "localhost"


def _short_host_name(host_key: str) -> str:
    """Извлечь короткое имя хоста из URI или ключа пула."""
    authority = host_key.split("://", 1)[-1].split("/", 1)[0].rsplit("@", 1)[-1]
    if authority.startswith("[") and "]" in authority:
        return authority.split("]", 1)[0] + "]"
    return authority.split(":", 1)[0]


def _extract_explicit_port(host_key: str) -> str | None:
    """Извлечь явно указанный порт из URI или ``host:port`` (или ``None``)."""
    authority = host_key.split("://", 1)[-1].split("/", 1)[0].rsplit("@", 1)[-1]
    if authority.startswith("["):
        if "]:" in authority:
            port = authority.rsplit("]:", 1)[1]
            return port if port.isdigit() else None
        return None
    if authority.count(":") == 1:
        _, port = authority.rsplit(":", 1)
        return port if port.isdigit() else None
    return None


def _ports_compatible(query: str, target: str) -> bool:
    """Проверить отсутствие конфликта явно указанных портов у двух идентификаторов хоста."""
    q_port = _extract_explicit_port(query)
    t_port = _extract_explicit_port(target)
    return q_port is None or t_port is None or q_port == t_port


def _build_unique_short_host_map(hosts: set[str] | list[str]) -> dict[str, str]:
    """Построить отображение ``short_name -> full_host`` только для однозначных коротких имён."""
    counts: dict[str, int] = {}
    mapping: dict[str, str] = {}
    for h in hosts:
        short = _short_host_name(h)
        counts[short] = counts.get(short, 0) + 1
        mapping[short] = h
    return {short: full for short, full in mapping.items() if counts[short] == 1}


def extract_actions_from_result(res: EnsureResult) -> tuple[str, ...]:
    """Извлечь кортеж кратких действий из ``EnsureResult``."""
    if not res.changed:
        return ()
    details = (res.details or "").strip()
    if details.startswith("[DRY-RUN] "):
        details = details[len("[DRY-RUN] ") :].strip()
    if not details:
        return (f"state={res.state}",)
    if ": " in details:
        _, tail = details.split(": ", 1)
        items = [part.strip() for part in tail.split(",") if part.strip()]
        if items:
            return tuple(items)
    return (details,)


def _extract_target_arg(
    op_name: str, args: tuple[Any, ...], kwargs: Mapping[str, Any]
) -> str | None:
    """Извлечь целевой путь или имя ресурса из аргументов вызова ``ensure_*``."""
    if args:
        first = args[0]
        if isinstance(first, (str, Path)):
            return str(first)
        if isinstance(first, (list, tuple)):
            return ", ".join(str(x) for x in first)
        return str(first)
    for key in ("remote_path", "path", "package", "service", "name", "username", "user"):
        val = kwargs.get(key)
        if val is not None:
            if isinstance(val, (list, tuple)):
                return ", ".join(str(x) for x in val)
            return str(val)
    _ = op_name
    return None


async def capture_before_snapshot(
    svc: StateManagementService,
    op_name: str,
    args: tuple[Any, ...],
    kwargs: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Снять лёгкий read-only снимок исходного состояния ресурса для надёжного ``before_digest``."""
    if op_name not in ("ensure_file", "ensure_line", "ensure_directory"):
        return None
    if not svc._can_inspect_in_dry_run():
        return None
    target_path = _extract_target_arg(op_name, args, kwargs)
    if not target_path:
        return None

    conn = svc._conn
    sudo = bool(kwargs.get("sudo", False))
    try:
        if op_name in ("ensure_file", "ensure_line"):
            if conn.transport_name == "local" and not sudo:
                eff = Path(conn.context.resolve_path(target_path))
                if eff.is_symlink():
                    return {
                        "kind": "symlink",
                        "exists": True,
                        "link_target": os.readlink(eff),
                    }
            exists = await conn.files.exists(target_path)
            if not exists:
                return {"kind": "file", "exists": False}
            snap: dict[str, Any] = {"kind": "file", "exists": True}
            with contextlib.suppress(OSError, UniconnError, UnicodeDecodeError):
                raw = await conn.files.read_file(target_path, encoding=None)
                raw_bytes = raw if isinstance(raw, bytes) else raw.encode("utf-8", errors="replace")
                snap["content_sha256"] = hashlib.sha256(raw_bytes).hexdigest()
                snap["size"] = len(raw_bytes)
            with contextlib.suppress(OSError, UniconnError, ValueError):
                st = await conn.files.stat(target_path)
                mode_val = svc._extract_stat_mode(st)
                if mode_val >= 0:
                    snap["mode"] = mode_val
            return snap

        # ensure_directory
        exists = await conn.files.exists(target_path)
        if not exists:
            return {"kind": "directory", "exists": False}
        dir_snap: dict[str, Any] = {"kind": "directory", "exists": True}
        with contextlib.suppress(OSError, UniconnError, ValueError):
            st = await conn.files.stat(target_path)
            mode_val = svc._extract_stat_mode(st)
            if mode_val >= 0:
                dir_snap["mode"] = mode_val
        return dir_snap
    except Exception:
        return None


def compute_before_digest(
    *,
    operation: str,
    target: str,
    state: str,
    changed: bool,
    ok: bool,
    diff: str | None,
    actions: tuple[str, ...] = (),
    snapshot: Mapping[str, Any] | None = None,
) -> str:
    """Вычислить детерминированный SHA-256 отпечаток исходного состояния ресурса до мутации."""
    payload = {
        "operation": operation,
        "target": target,
        "state": state,
        "changed": changed,
        "ok": ok,
        "actions": list(actions),
        "diff": diff,
        "snapshot": dict(snapshot) if snapshot is not None else None,
    }
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class PlannedChange:
    """Единичная запланированная операция изменения состояния на конкретном хосте."""

    host: str
    operation: str
    target: str
    state: str
    changed: bool
    ok: bool = True
    actions: tuple[str, ...] = ()
    unified_diff: str | None = None
    details: str = ""
    before_digest: str = ""
    task_name: str | None = None
    reboot_required: bool = False

    @property
    def diff(self) -> str | None:
        """Псевдоним для ``unified_diff``."""
        return self.unified_diff

    def to_dict(self) -> dict[str, Any]:
        """Преобразовать запись плана в JSON-сериализуемый словарь."""
        return {
            "host": self.host,
            "operation": self.operation,
            "target": self.target,
            "state": self.state,
            "changed": self.changed,
            "ok": self.ok,
            "actions": list(self.actions),
            "unified_diff": self.unified_diff,
            "details": self.details,
            "before_digest": self.before_digest,
            "task_name": self.task_name,
            "reboot_required": self.reboot_required,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> PlannedChange:
        """Восстановить ``PlannedChange`` из сериализованного словаря."""
        raw_actions = payload.get("actions") or ()
        actions_tuple = tuple(str(a) for a in raw_actions) if isinstance(raw_actions, (list, tuple)) else ()
        diff_val = payload.get("unified_diff")
        if diff_val is None and "diff" in payload:
            diff_val = payload.get("diff")
        task_val = payload.get("task_name")
        return cls(
            host=str(payload["host"]),
            operation=str(payload["operation"]),
            target=str(payload["target"]),
            state=str(payload.get("state") or ""),
            changed=bool(payload.get("changed", False)),
            ok=bool(payload.get("ok", True)),
            actions=actions_tuple,
            unified_diff=str(diff_val) if diff_val is not None else None,
            details=str(payload.get("details") or ""),
            before_digest=str(payload.get("before_digest") or ""),
            task_name=str(task_val) if task_val is not None else None,
            reboot_required=bool(payload.get("reboot_required", False)),
        )


@dataclass(slots=True)
class FleetChangePlan:
    """Агрегированный план изменений по одному хосту или флоту (Plan → Diff → Apply)."""

    flow_name: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    hosts: list[str] = field(default_factory=list)
    changes: dict[str, list[PlannedChange]] = field(default_factory=dict)
    host_errors: dict[str, str] = field(default_factory=dict)

    def register_host(self, host: str) -> None:
        """Зарегистрировать хост в плане (сохраняя порядок и без дубликатов)."""
        if host not in self.hosts:
            self.hosts.append(host)
        self.changes.setdefault(host, [])

    def record(self, change: PlannedChange) -> None:
        """Добавить запланированное изменение ``PlannedChange`` в план."""
        self.register_host(change.host)
        self.changes[change.host].append(change)

    def record_host_error(self, host: str, error: str) -> None:
        """Зафиксировать ошибку подключения или задачи на хосте во время планирования."""
        self.register_host(host)
        existing = self.host_errors.get(host)
        self.host_errors[host] = f"{existing}; {error}" if existing else error

    def _ordered_hosts(self) -> list[str]:
        ordered = list(self.hosts)
        for h in self.changes:
            if h not in ordered:
                ordered.append(h)
        for h in self.host_errors:
            if h not in ordered:
                ordered.append(h)
        return ordered

    @property
    def total_changes(self) -> int:
        """Общее число зафиксированных проверок ресурсов по всем хостам."""
        return sum(len(items) for items in self.changes.values())

    @property
    def changed_count(self) -> int:
        """Количество ресурсов, требующих изменения (``changed=True``)."""
        return sum(1 for items in self.changes.values() for c in items if c.changed)

    @property
    def has_changes(self) -> bool:
        """Вернуть ``True``, если хотя бы на одном хосте запланировано изменение."""
        return any(c.changed for items in self.changes.values() for c in items)

    @property
    def has_drift(self) -> bool:
        """Псевдоним для ``has_changes`` (обнаружены расхождения относительно эталонного состояния)."""
        return self.has_changes

    @property
    def failed_hosts(self) -> list[str]:
        """Список хостов, на которых произошла ошибка планирования или инспекции ресурса."""
        failed: list[str] = []
        for host in self._ordered_hosts():
            if host in self.host_errors or any(not c.ok for c in self.changes.get(host, ())):
                failed.append(host)
        return failed

    @property
    def ok(self) -> bool:
        """Вернуть ``True``, если планирование завершилось без ошибок на всех хостах."""
        return not self.failed_hosts

    @property
    def changed_hosts(self) -> list[str]:
        """Список хостов, на которых требуется хотя бы одно изменение."""
        return [
            host
            for host in self._ordered_hosts()
            if any(c.changed for c in self.changes.get(host, ()))
        ]

    @property
    def unchanged_hosts(self) -> list[str]:
        """Список хостов без ошибок и без запланированных изменений."""
        failed_set = set(self.failed_hosts)
        changed_set = set(self.changed_hosts)
        return [
            host
            for host in self._ordered_hosts()
            if host not in failed_set and host not in changed_set
        ]

    @property
    def plan_hash(self) -> str:
        """Детерминированный SHA-256 отпечаток плана (не зависит от порядка ответов хостов и времени)."""
        canonical_hosts: list[dict[str, Any]] = []
        for host in sorted(self._ordered_hosts()):
            host_changes = [
                {
                    "operation": c.operation,
                    "target": c.target,
                    "state": c.state,
                    "changed": c.changed,
                    "ok": c.ok,
                    "actions": list(c.actions),
                    "unified_diff": c.unified_diff,
                    "before_digest": c.before_digest,
                    "task_name": c.task_name,
                }
                for c in self.changes.get(host, ())
            ]
            canonical_hosts.append(
                {
                    "host": host,
                    "error": self.host_errors.get(host),
                    "changes": host_changes,
                }
            )
        payload = {
            "flow_name": self.flow_name,
            "hosts": canonical_hosts,
        }
        raw = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def for_host(self, host: str) -> list[PlannedChange]:
        """Вернуть список запланированных изменений для указанного хоста."""
        if host in self.changes:
            return list(self.changes[host])
        unique_short = _build_unique_short_host_map(list(self.changes.keys()))
        matched = unique_short.get(host) or unique_short.get(_short_host_name(host))
        if matched is not None and _ports_compatible(host, matched):
            return list(self.changes[matched])
        return []

    def to_diff(self) -> str:
        """Собрать единый unified diff по всем изменяемым ресурсам флота."""
        blocks: list[str] = []
        for host in self._ordered_hosts():
            for change in self.changes.get(host, ()):
                if not change.changed:
                    continue
                task_suffix = f" [task={change.task_name}]" if change.task_name else ""
                header = f"# Host: {host} | {change.operation}({change.target}){task_suffix}"
                if change.unified_diff:
                    blocks.append(f"{header}\n{change.unified_diff.rstrip()}")
                else:
                    actions_txt = ", ".join(change.actions) if change.actions else f"state={change.state}"
                    blocks.append(f"{header}\n~ {actions_txt}")
        if not blocks:
            return ""
        return "\n\n".join(blocks) + "\n"

    def to_summary(self, *, _plan_hash: str | None = None) -> str:
        """Сформировать компактную человекочитаемую сводку плана по флоту."""
        digest = _plan_hash if _plan_hash is not None else self.plan_hash
        title = f"FleetChangePlan ({self.flow_name})" if self.flow_name else "FleetChangePlan"
        lines: list[str] = [
            f"{title} | hash={digest[:12]} | ok={self.ok} | drift={self.has_drift}",
            (
                f"Hosts: {len(self._ordered_hosts())} total, "
                f"{len(self.changed_hosts)} changed, "
                f"{len(self.unchanged_hosts)} unchanged, "
                f"{len(self.failed_hosts)} failed | "
                f"Resources: {self.changed_count}/{self.total_changes} to change"
            ),
        ]
        for host in self._ordered_hosts():
            err = self.host_errors.get(host)
            items = self.changes.get(host, ())
            failed_items = [c for c in items if not c.ok]
            changed_items = [c for c in items if c.changed]
            if err or failed_items:
                fail_parts: list[str] = []
                if err:
                    fail_parts.append(err)
                fail_parts.extend(
                    f"{c.operation}({c.target}): {c.details or 'failed'}"
                    for c in failed_items
                )
                lines.append(f"  [FAILED] {host}: {'; '.join(fail_parts)}")
            elif changed_items:
                summary_parts = [
                    f"{c.operation}({c.target}): {', '.join(c.actions) or c.state}"
                    for c in changed_items
                ]
                lines.append(f"  [CHANGE] {host}: {'; '.join(summary_parts)}")
            else:
                lines.append(f"  [OK]     {host}: no changes ({len(items)} checked)")
        return "\n".join(lines)

    def to_dict(self, *, include_rendered: bool = False) -> dict[str, Any]:
        """Преобразовать ``FleetChangePlan`` в JSON-сериализуемый словарь."""
        ordered = self._ordered_hosts()
        digest = self.plan_hash
        payload: dict[str, Any] = {
            "flow_name": self.flow_name,
            "created_at": self.created_at,
            "plan_hash": digest,
            "ok": self.ok,
            "has_changes": self.has_changes,
            "has_drift": self.has_drift,
            "total_changes": self.total_changes,
            "changed_count": self.changed_count,
            "hosts": ordered,
            "changed_hosts": self.changed_hosts,
            "unchanged_hosts": self.unchanged_hosts,
            "failed_hosts": self.failed_hosts,
            "host_errors": dict(self.host_errors),
            "changes": {
                host: [c.to_dict() for c in self.changes.get(host, ())]
                for host in ordered
            },
        }
        if include_rendered:
            payload["summary"] = self.to_summary(_plan_hash=digest)
            payload["diff"] = self.to_diff()
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> FleetChangePlan:
        """Восстановить ``FleetChangePlan`` из сериализованного словаря."""
        raw_hosts = payload.get("hosts") or ()
        hosts_list = [str(h) for h in raw_hosts] if isinstance(raw_hosts, (list, tuple)) else []
        raw_changes = payload.get("changes") or {}
        changes_map: dict[str, list[PlannedChange]] = {}
        if isinstance(raw_changes, Mapping):
            for host_key, items in raw_changes.items():
                h_str = str(host_key)
                if h_str not in hosts_list:
                    hosts_list.append(h_str)
                parsed_items: list[PlannedChange] = []
                if isinstance(items, (list, tuple)):
                    for item in items:
                        if isinstance(item, Mapping):
                            parsed_items.append(PlannedChange.from_dict(item))
                changes_map[h_str] = parsed_items
        for h in hosts_list:
            changes_map.setdefault(h, [])
        raw_errors = payload.get("host_errors") or {}
        errors_map = (
            {str(k): str(v) for k, v in raw_errors.items()}
            if isinstance(raw_errors, Mapping)
            else {}
        )
        flow_name = payload.get("flow_name")
        created_at = str(payload.get("created_at") or datetime.now(UTC).isoformat())
        return cls(
            flow_name=str(flow_name) if flow_name is not None else None,
            created_at=created_at,
            hosts=hosts_list,
            changes=changes_map,
            host_errors=errors_map,
        )

    def to_json(self, *, indent: int = 2) -> str:
        """Сериализовать ``FleetChangePlan`` в JSON-строку."""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    @classmethod
    def from_json(cls, raw: str) -> FleetChangePlan:
        """Десериализовать ``FleetChangePlan`` из JSON-строки."""
        data = json.loads(raw)
        if not isinstance(data, Mapping):
            raise ValueError("Invalid FleetChangePlan JSON payload: expected a JSON object")
        return cls.from_dict(data)

    def to_rich_table(self) -> Any:
        """Построить ``rich.table.Table`` со сводкой запланированных изменений по хостам."""
        from rich import box
        from rich.table import Table

        title_name = self.flow_name or "Ad-Hoc State Plan"
        table = Table(
            title=f"Fleet Change Plan: {title_name} ({self.plan_hash[:12]})",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Host", style="cyan")
        table.add_column("Task", style="dim")
        table.add_column("Operation", style="white")
        table.add_column("Target", style="white")
        table.add_column("Status", width=14)
        table.add_column("Actions / Details", style="yellow")

        for host in self._ordered_hosts():
            items = self.changes.get(host, ())
            err = self.host_errors.get(host)
            if err and not items:
                table.add_row(host, "-", "-", "-", "[bold red]✖ error[/bold red]", err)
                continue
            if not items:
                table.add_row(host, "-", "-", "-", "[green]✔ clean[/green]", "No changes")
                continue
            for c in items:
                if not c.ok:
                    st = "[bold red]✖ failed[/bold red]"
                elif c.changed:
                    st = "[bold magenta]~ change[/bold magenta]"
                else:
                    st = "[green]✔ unchanged[/green]"
                detail = ", ".join(c.actions) if c.actions else (c.details or c.state)
                if len(detail) > 64:
                    detail = detail[:61] + "..."
                table.add_row(
                    host,
                    c.task_name or "-",
                    c.operation,
                    c.target,
                    st,
                    detail,
                )
            if err:
                table.add_row(host, "-", "-", "-", "[bold red]✖ error[/bold red]", err)
        return table


class PlanRecorder:
    """Перехватчик read-only вызовов ``ensure_*``, наполняющий ``FleetChangePlan``."""

    def __init__(
        self,
        plan: FleetChangePlan | None = None,
        *,
        flow_name: str | None = None,
        host_override: str | None = None,
    ) -> None:
        """Инициализировать перехватчик плана изменений."""
        self.plan = plan if plan is not None else FleetChangePlan(flow_name=flow_name)
        self.host_override = host_override
        self._lock = threading.Lock()

    def register_host(self, host: str) -> None:
        """Потокобезопасно зарегистрировать хост в плане."""
        with self._lock:
            self.plan.register_host(host)

    def record_host_error(self, host: str, error: str) -> None:
        """Потокобезопасно зафиксировать ошибку планирования на хосте."""
        with self._lock:
            self.plan.record_host_error(host, error)

    def record_result(
        self,
        *,
        conn: Connection,
        operation: str,
        res: EnsureResult,
        before_digest: str,
        host_override: str | None = None,
    ) -> PlannedChange:
        """Зафиксировать результат ``EnsureResult`` как ``PlannedChange`` в ``FleetChangePlan``."""
        eff_host = normalize_plan_host(conn, host_override or self.host_override)
        task_name = CURRENT_PLAN_TASK.get()
        change = PlannedChange(
            host=eff_host,
            operation=operation,
            target=res.target,
            state=res.state,
            changed=res.changed,
            ok=res.ok,
            actions=extract_actions_from_result(res),
            unified_diff=res.diff,
            details=res.details,
            before_digest=before_digest,
            task_name=task_name,
            reboot_required=res.reboot_required,
        )
        with self._lock:
            self.plan.record(change)
        return change


class PlanApplier:
    """Оптимистичная защита от дрейфа при применении утверждённого ``FleetChangePlan``."""

    def __init__(self, plan: FleetChangePlan, *, strict: bool = True) -> None:
        """Инициализировать верификатор плана с очередями ожидаемых изменений по ресурсам."""
        self.plan = plan
        self.strict = strict
        self._lock = threading.Lock()
        self._queues: dict[tuple[str, str, str], deque[PlannedChange]] = {}
        self._mutated_targets: set[tuple[str, str]] = set()
        self._verified_count = 0

        for host, items in plan.changes.items():
            for change in items:
                key = (host, change.operation, change.target)
                self._queues.setdefault(key, deque()).append(change)

    @property
    def verified_count(self) -> int:
        """Количество операций, успешно прошедших проверку соответствия плану."""
        return self._verified_count

    @property
    def remaining_count(self) -> int:
        """Количество ещё не потреблённых записей утверждённого плана."""
        with self._lock:
            return sum(len(q) for q in self._queues.values())

    def _resolve_plan_host(
        self, conn: Connection, host_override: str | None = None
    ) -> tuple[str, bool]:
        """Сопоставить хост текущего соединения с ключом хоста в ``FleetChangePlan``."""
        eff_host = normalize_plan_host(conn, host_override)
        known_hosts = set(self.plan._ordered_hosts())
        exact_candidates = (
            eff_host,
            conn.config.host or "",
            conn.config.uri_safe or "",
        )
        for cand in exact_candidates:
            if cand and cand in known_hosts:
                return cand, True

        # Фолбэк по короткому имени допускается только если сопоставление однозначно
        # и нет конфликта явно указанных портов (например, ssh://10.0.0.1:2222 vs :2224).
        unique_short = _build_unique_short_host_map(known_hosts)
        short_candidates = (*exact_candidates, _short_host_name(eff_host))
        for cand in short_candidates:
            matched = unique_short.get(cand) if cand else None
            if matched is not None and _ports_compatible(eff_host, matched):
                return matched, True
        return eff_host, False

    async def verify_and_prepare(
        self,
        svc: StateManagementService,
        op_name: str,
        op_fn: Callable[..., Awaitable[EnsureResult]],
        args: tuple[Any, ...],
        kwargs: Mapping[str, Any],
        *,
        host_override: str | None = None,
    ) -> tuple[str, str] | None:
        """Выполнить read-only pre-flight проверку ресурса перед мутацией и выбросить ``StateDriftError`` при дрейфе."""
        probe_kwargs = dict(kwargs)
        probe_kwargs["dry_run"] = True

        # Снимаем исходный снимок и dry_run-инспекцию ДО любых мутаций
        snapshot = await capture_before_snapshot(svc, op_name, args, probe_kwargs)
        probe_res = await op_fn(svc, *args, **probe_kwargs)
        actual_digest = compute_before_digest(
            operation=op_name,
            target=probe_res.target,
            state=probe_res.state,
            changed=probe_res.changed,
            ok=probe_res.ok,
            diff=probe_res.diff,
            actions=extract_actions_from_result(probe_res),
            snapshot=snapshot,
        )

        with self._lock:
            plan_host, host_found = self._resolve_plan_host(svc._conn, host_override)
            if not host_found:
                if self.strict:
                    raise StateDriftError(
                        f"Host {plan_host!r} is not present in approved FleetChangePlan "
                        f"(plan_hash={self.plan.plan_hash[:12]})",
                        host=plan_host,
                        resource_kind=op_name,
                        target=probe_res.target,
                        actual_digest=actual_digest,
                        actual_diff=probe_res.diff,
                        reason="plan_host_missing",
                    )
                return None

            if plan_host in self.plan.host_errors:
                raise StateDriftError(
                    f"Cannot apply {op_name}({probe_res.target!r}) on host {plan_host!r}: "
                    f"planning failed for this host ({self.plan.host_errors[plan_host]})",
                    host=plan_host,
                    resource_kind=op_name,
                    target=probe_res.target,
                    actual_digest=actual_digest,
                    actual_diff=probe_res.diff,
                    reason="plan_failed",
                )

            q_key = (plan_host, op_name, probe_res.target)
            queue = self._queues.get(q_key)
            if not queue:
                if self.strict:
                    raise StateDriftError(
                        f"Unexpected resource mutation {op_name}({probe_res.target!r}) on host "
                        f"{plan_host!r}: not present in approved FleetChangePlan "
                        f"(plan_hash={self.plan.plan_hash[:12]})",
                        host=plan_host,
                        resource_kind=op_name,
                        target=probe_res.target,
                        actual_digest=actual_digest,
                        actual_diff=probe_res.diff,
                        reason="unexpected_resource",
                    )
                return None

            expected = queue[0]
            if not expected.ok:
                raise StateDriftError(
                    f"Cannot apply {op_name}({probe_res.target!r}) on host {plan_host!r}: "
                    f"planned inspection had ok=False ({expected.details or 'unknown error'})",
                    host=plan_host,
                    resource_kind=op_name,
                    target=probe_res.target,
                    expected_digest=expected.before_digest,
                    actual_digest=actual_digest,
                    expected_diff=expected.unified_diff,
                    actual_diff=probe_res.diff,
                    reason="plan_failed",
                )

            already_mutated_by_plan = (plan_host, probe_res.target) in self._mutated_targets
            if not already_mutated_by_plan and expected.before_digest and actual_digest != expected.before_digest:
                raise StateDriftError(
                    f"State drift detected before {op_name}({probe_res.target!r}) on host {plan_host!r}: "
                    f"expected digest {expected.before_digest[:12]}, got {actual_digest[:12]}",
                    host=plan_host,
                    resource_kind=op_name,
                    target=probe_res.target,
                    expected_digest=expected.before_digest,
                    actual_digest=actual_digest,
                    expected_diff=expected.unified_diff,
                    actual_diff=probe_res.diff,
                    reason="digest_mismatch",
                )

            # Извлекаем элемент очереди и увеличиваем счётчик только после успешной проверки
            queue.popleft()
            self._verified_count += 1
        return (plan_host, probe_res.target)

    def mark_mutated(self, target_token: tuple[str, str] | None, *, changed: bool) -> None:
        """Отметить ресурс как изменённый в рамках текущей сессии применения плана."""
        if target_token is not None and changed:
            with self._lock:
                self._mutated_targets.add(target_token)


@dataclass(slots=True)
class _ServicePlanBinding:
    """Внутренняя привязка ``PlanRecorder`` к конкретному ``StateManagementService``."""

    recorder: PlanRecorder
    host_override: str | None = None


@dataclass(slots=True)
class _ServiceApplierBinding:
    """Внутренняя привязка ``PlanApplier`` к конкретному ``StateManagementService``."""

    applier: PlanApplier
    host_override: str | None = None


class ConnectionPlanContext:
    """Асинхронный контекстный менеджер ``conn.state.plan()`` для сбора ``FleetChangePlan``."""

    def __init__(
        self,
        service: StateManagementService,
        *,
        flow_name: str | None = None,
        plan: FleetChangePlan | None = None,
    ) -> None:
        self._service = service
        self._recorder = PlanRecorder(plan=plan, flow_name=flow_name)
        self._binding: _ServicePlanBinding | None = None

    @property
    def plan(self) -> FleetChangePlan:
        """Собираемый объект ``FleetChangePlan``."""
        return self._recorder.plan

    async def __aenter__(self) -> FleetChangePlan:
        host_key = normalize_plan_host(self._service._conn)
        self._recorder.register_host(host_key)
        self._binding = _ServicePlanBinding(recorder=self._recorder, host_override=host_key)
        self._service._push_plan_recorder(self._binding)
        return self._recorder.plan

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._binding is not None:
            self._service._pop_plan_recorder(self._binding)
            self._binding = None


class ConnectionApplyPlanContext:
    """Асинхронный контекстный менеджер ``conn.state.apply_plan(plan)`` с защитой от дрейфа."""

    def __init__(
        self,
        service: StateManagementService,
        plan: FleetChangePlan,
        *,
        strict: bool = True,
    ) -> None:
        self._service = service
        self._applier = PlanApplier(plan, strict=strict)
        self._binding: _ServiceApplierBinding | None = None

    @property
    def applier(self) -> PlanApplier:
        """Активный верификатор ``PlanApplier``."""
        return self._applier

    async def __aenter__(self) -> PlanApplier:
        host_key = normalize_plan_host(self._service._conn)
        self._binding = _ServiceApplierBinding(applier=self._applier, host_override=host_key)
        self._service._push_plan_applier(self._binding)
        return self._applier

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._binding is not None:
            self._service._pop_plan_applier(self._binding)
            self._binding = None


__all__ = [
    "CURRENT_PLAN_HOST",
    "CURRENT_PLAN_TASK",
    "IN_NOTIFY_HANDLER",
    "ConnectionApplyPlanContext",
    "ConnectionPlanContext",
    "FleetChangePlan",
    "PlanApplier",
    "PlanRecorder",
    "PlannedChange",
    "_ServiceApplierBinding",
    "_ServicePlanBinding",
    "capture_before_snapshot",
    "compute_before_digest",
    "extract_actions_from_result",
    "normalize_plan_host",
]
