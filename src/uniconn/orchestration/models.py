# src/uniconn/orchestration/models.py
"""Модели результатов выполнения задач и сводного отчёта оркестрации Flow."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Self

from ..exceptions import FlowExecutionError
from ..result import EnsureResult, PingResult, Result, SyncResult

TaskStatus = Literal["success", "failed", "skipped"]
SkipReason = Literal[
    "when_false",
    "host_filtered",
    "tag_filtered",
    "upstream_failed",
    "aborted",
]


def extract_task_outcome_metadata(
    val: Any,
) -> tuple[bool, bool, str | None, str | None, bool]:
    """Извлечь ``(is_failed, changed, diff, error_detail, notified)`` из возвращаемого значения задачи."""
    if isinstance(val, BaseException):
        return True, False, None, str(val) or type(val).__name__, False

    if isinstance(val, EnsureResult):
        err = (val.details or f"ensure {val.target} failed") if not val.ok else None
        return not val.ok, val.changed, val.diff, err, val.notified

    if isinstance(val, Result):
        err: str | None = None
        if not val.ok:
            stderr_clean = val.stderr.strip() if not val.sensitive else "***REDACTED***"
            err = stderr_clean or f"exit_code={val.exit_code}"
        return not val.ok, False, None, err, False

    if isinstance(val, PingResult):
        err = (val.error or "host is unreachable") if not val.alive else None
        return not val.alive, False, None, err, False

    if isinstance(val, SyncResult):
        changed = bool(val.uploaded or val.deleted)
        return False, changed, None, None, False

    ok_attr = getattr(val, "ok", True)
    if ok_attr is False:
        detail = getattr(val, "details", None) or getattr(val, "error", None) or "ok=False"
        return True, False, None, str(detail), False

    return False, False, None, None, False


@dataclass(frozen=True, slots=True)
class TaskResult:
    """Результат выполнения отдельной задачи ``@task`` на конкретном хосте."""

    task_name: str
    host: str
    status: TaskStatus
    return_value: Any = None
    exception: BaseException | None = None
    error: str | None = None
    skip_reason: SkipReason | None = None
    duration: float = 0.0
    attempts: int = 1
    diff: str | None = None
    changed: bool = False
    notified: bool = False
    ignored_error: bool = False

    @property
    def ok(self) -> bool:
        """Вернуть ``True``, если задача успешна, пропущена или её ошибка проигнорирована."""
        return self.status in ("success", "skipped") or self.ignored_error

    def to_dict(self) -> dict[str, Any]:
        """Преобразовать результат задачи в сериализуемый словарь."""
        serialized_ret: Any = self.return_value
        if hasattr(serialized_ret, "to_dict") and callable(serialized_ret.to_dict):
            serialized_ret = serialized_ret.to_dict()
        elif not isinstance(
            serialized_ret, (str, int, float, bool, list, dict, type(None))
        ):
            serialized_ret = repr(serialized_ret)

        return {
            "task_name": self.task_name,
            "host": self.host,
            "status": self.status,
            "ok": self.ok,
            "changed": self.changed,
            "notified": self.notified,
            "ignored_error": self.ignored_error,
            "attempts": self.attempts,
            "duration": round(self.duration, 6),
            "skip_reason": self.skip_reason,
            "error": self.error
            or (str(self.exception) if self.exception is not None else None),
            "diff": self.diff,
            "return_value": serialized_ret,
        }


@dataclass(slots=True)
class FlowReport:
    """Сводный отчёт о выполнении сценария ``Flow`` на одном хосте или пуле хостов."""

    flow_name: str
    ok: bool
    duration: float
    results: dict[str, list[TaskResult]] = field(default_factory=dict)
    mode: Literal["single", "barrier", "independent"] = "single"
    notified_handlers: dict[str, list[str]] = field(default_factory=dict)

    @property
    def total_tasks(self) -> int:
        """Общее число зафиксированных результатов задач по всем хостам."""
        return sum(len(items) for items in self.results.values())

    @property
    def succeeded_count(self) -> int:
        """Количество задач со статусом ``success``."""
        return sum(
            1
            for items in self.results.values()
            for r in items
            if r.status == "success"
        )

    @property
    def failed_count(self) -> int:
        """Количество задач со статусом ``failed`` (включая ``ignore_errors=True``)."""
        return sum(
            1
            for items in self.results.values()
            for r in items
            if r.status == "failed"
        )

    @property
    def skipped_count(self) -> int:
        """Количество пропущенных задач (``status == 'skipped'``)."""
        return sum(
            1
            for items in self.results.values()
            for r in items
            if r.status == "skipped"
        )

    @property
    def changed_count(self) -> int:
        """Количество задач, которые внесли изменения на хосте (``changed=True``)."""
        return sum(
            1 for items in self.results.values() for r in items if r.changed
        )

    @property
    def failed_hosts(self) -> list[str]:
        """Список хостов, на которых хотя бы одна задача завершилась с неигнорируемой ошибкой."""
        failed: list[str] = []
        for host, items in self.results.items():
            if any(not r.ok for r in items):
                failed.append(host)
        return failed

    def for_host(self, host: str) -> list[TaskResult]:
        """Вернуть список результатов задач для указанного хоста."""
        if host in self.results:
            return list(self.results[host])
        for key, items in self.results.items():
            short = key.split("://", 1)[-1].rsplit("@", 1)[-1].split(":", 1)[0]
            if short == host:
                return list(items)
        return []

    def for_task(self, task_name: str) -> dict[str, TaskResult]:
        """Вернуть словарь ``{host: TaskResult}`` для указанного имени задачи."""
        out: dict[str, TaskResult] = {}
        for host, items in self.results.items():
            for item in items:
                if item.task_name == task_name:
                    out[host] = item
        return out

    def get_summary(self) -> str:
        """Сформировать текстовую сводку результатов выполнения сценария."""
        details: list[str] = []
        for host, items in self.results.items():
            for item in items:
                if not item.ok:
                    msg = item.error or (
                        str(item.exception) if item.exception else "failed"
                    )
                    details.append(f"{host}:{item.task_name} ({msg})")
        summary_head = (
            f"flow={self.flow_name!r}, ok={self.ok}, "
            f"total={self.total_tasks}, success={self.succeeded_count}, "
            f"failed={self.failed_count}, skipped={self.skipped_count}, "
            f"changed={self.changed_count}, duration={self.duration:.3f}s"
        )
        if details:
            return f"{summary_head} | failures: {'; '.join(details)}"
        return summary_head

    def raise_for_status(self) -> Self:
        """Выбросить ``FlowExecutionError``, если ``ok is False``."""
        if not self.ok:
            raise FlowExecutionError(
                f"Flow {self.flow_name!r} failed: {self.get_summary()}",
                report=self,
                failed_hosts=self.failed_hosts,
            )
        return self

    def to_dict(self) -> dict[str, Any]:
        """Преобразовать сводный отчёт в сериализуемый словарь."""
        return {
            "flow_name": self.flow_name,
            "mode": self.mode,
            "ok": self.ok,
            "duration": round(self.duration, 6),
            "total_tasks": self.total_tasks,
            "succeeded_count": self.succeeded_count,
            "failed_count": self.failed_count,
            "skipped_count": self.skipped_count,
            "changed_count": self.changed_count,
            "failed_hosts": self.failed_hosts,
            "notified_handlers": {
                h: list(names) for h, names in self.notified_handlers.items()
            },
            "results": {
                host: [r.to_dict() for r in items]
                for host, items in self.results.items()
            },
        }

    def to_rich_table(self) -> Any:
        """Построить ``rich.table.Table`` со сводкой выполнения по хостам и задачам."""
        from rich import box
        from rich.table import Table

        table = Table(
            title=f"Flow Report: {self.flow_name} ({self.mode})",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Host", style="cyan")
        table.add_column("Task", style="white")
        table.add_column("Status", width=16)
        table.add_column("Changed", width=9)
        table.add_column("Attempts", width=8, justify="right")
        table.add_column("Duration", style="yellow", width=10, justify="right")
        table.add_column("Details / Error", style="dim")

        for host, items in self.results.items():
            for item in items:
                if item.status == "success":
                    status_str = "[green]✔ success[/green]"
                elif item.status == "skipped":
                    reason = f" ({item.skip_reason})" if item.skip_reason else ""
                    status_str = f"[yellow]↷ skipped{reason}[/yellow]"
                elif item.ignored_error:
                    status_str = "[yellow]⚠ failed (ignored)[/yellow]"
                else:
                    status_str = "[bold red]✖ failed[/bold red]"

                changed_str = "[magenta]yes[/magenta]" if item.changed else "no"
                dur_str = f"{item.duration:.3f}s"
                detail_str = item.error or (item.diff.splitlines()[0] if item.diff else "")
                if len(detail_str) > 60:
                    detail_str = detail_str[:57] + "..."
                table.add_row(
                    host,
                    item.task_name,
                    status_str,
                    changed_str,
                    str(item.attempts),
                    dur_str,
                    detail_str,
                )
        return table


__all__ = [
    "FlowReport",
    "SkipReason",
    "TaskResult",
    "TaskStatus",
    "extract_task_outcome_metadata",
]
