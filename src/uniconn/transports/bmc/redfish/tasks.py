# src/uniconn/transports/bmc/redfish/tasks.py
"""Мониторинг и ожидание асинхронных задач DMTF Redfish TaskService (HTTP 202 Accepted)."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import Any

from ....exceptions import BMCCapabilityError, TimeoutError
from .client import normalize_redfish_path
from .models import TaskSummaryDict

RequestJsonFn = Callable[..., Awaitable[tuple[int, dict[str, Any]]]]

TERMINAL_SUCCESS_STATES: frozenset[str] = frozenset({"Completed", "Service"})
TERMINAL_FAILURE_STATES: frozenset[str] = frozenset(
    {"Exception", "Killed", "Cancelled", "Suspended", "Interrupted"}
)
TERMINAL_TASK_STATES: frozenset[str] = TERMINAL_SUCCESS_STATES | TERMINAL_FAILURE_STATES


def resolve_task_uri(task_ref: str) -> str:
    """Нормализовать идентификатор или путь задачи к ``/redfish/v1/TaskService/Tasks/...``."""
    stripped = task_ref.strip()
    if stripped.startswith(("http://", "https://", "/redfish/")):
        return normalize_redfish_path(stripped)
    return f"/redfish/v1/TaskService/Tasks/{stripped}"


def extract_task_uri_from_response(
    status_code: int,
    resp_data: dict[str, Any],
    resp_headers: dict[str, str],
) -> str | None:
    """Извлечь URI фоновой задачи из ответа HTTP 202 Accepted (Location или тело Task)."""
    if status_code != 202:
        return None
    location = resp_headers.get("Location") or resp_headers.get("location")
    if location:
        return normalize_redfish_path(str(location))
    odata_id = resp_data.get("@odata.id")
    if odata_id and (
        "Task" in str(odata_id)
        or "TaskState" in resp_data
        or "Task" in str(resp_data.get("@odata.type") or "")
    ):
        return normalize_redfish_path(str(odata_id))
    return None


def parse_task_summary(task_uri: str, data: dict[str, Any]) -> TaskSummaryDict:
    """Сформировать нормализованную сводку задачи Redfish Task."""
    messages: list[str] = []
    for msg in data.get("Messages") or []:
        if isinstance(msg, dict):
            text = msg.get("Message") or msg.get("MessageId")
            if text:
                messages.append(str(text))

    pct_raw = data.get("PercentComplete")
    pct: int | None = None
    if isinstance(pct_raw, (int, float)):
        pct = int(pct_raw)

    task_status = (data.get("TaskStatus") or (data.get("Status") or {}).get("Health") or "OK")
    return {
        "task_uri": task_uri,
        "id": str(data.get("Id") or task_uri.rsplit("/", 1)[-1]),
        "name": str(data.get("Name") or "Redfish Task"),
        "task_state": str(data.get("TaskState") or "Unknown"),
        "task_status": str(task_status),
        "percent_complete": pct,
        "messages": messages,
    }


class RedfishTaskMonitor:
    """Сервис отслеживания и поллинга задач Redfish TaskService."""

    def __init__(
        self,
        request_json: RequestJsonFn,
        *,
        default_timeout: float = 30.0,
        poll_interval: float = 0.05,
    ) -> None:
        self._request_json = request_json
        self._default_timeout = default_timeout
        self._poll_interval = poll_interval

    async def wait_for_task(
        self,
        task_ref: str,
        *,
        timeout: float | None = None,
        initial_data: dict[str, Any] | None = None,
    ) -> tuple[int, TaskSummaryDict]:
        """Ожидать завершения фоновой задачи Redfish до финального состояния или таймаута."""
        task_uri = resolve_task_uri(task_ref)
        eff_timeout = timeout if timeout is not None else self._default_timeout
        deadline = time.monotonic() + eff_timeout

        if isinstance(initial_data, dict) and initial_data.get("TaskState") in TERMINAL_TASK_STATES:
            summary = parse_task_summary(task_uri, initial_data)
            st = 200 if summary["task_state"] in TERMINAL_SUCCESS_STATES else 500
            return st, summary

        last_state = "Running"
        while True:
            rem = deadline - time.monotonic()
            req_timeout = max(0.1, rem) if eff_timeout > 0 else 0.1
            status, data = await self._request_json(
                "GET", task_uri, timeout=req_timeout
            )
            if not (200 <= status < 300):
                return status, {
                    "task_uri": task_uri,
                    "id": task_uri.rsplit("/", 1)[-1],
                    "name": "Redfish Task",
                    "task_state": "Exception",
                    "task_status": "Critical",
                    "percent_complete": None,
                    "messages": [f"HTTP {status} polling task {task_uri}"],
                }

            summary = parse_task_summary(task_uri, data)
            state = summary["task_state"]
            last_state = state

            if state in TERMINAL_SUCCESS_STATES:
                return 200, summary
            if state in TERMINAL_FAILURE_STATES:
                return 500, summary

            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"Redfish task {task_uri} timed out after {eff_timeout}s (state={last_state})"
                )
            await asyncio.sleep(min(self._poll_interval, max(0.01, deadline - time.monotonic())))

    async def handle_task_command(
        self,
        cmd_stripped: str,
        timeout: float | None = None,
    ) -> tuple[int, dict[str, Any]]:
        """Обработать команды ``tasks``, ``task status <id>`` и ``task wait <id> [timeout]``."""
        parts = cmd_stripped.split()
        if len(parts) == 1 or (len(parts) == 2 and parts[1].lower() == "list"):
            st, col = await self._request_json(
                "GET", "/redfish/v1/TaskService/Tasks", timeout=timeout
            )
            members = col.get("Members") or []
            tasks: list[dict[str, Any]] = []
            for m in members:
                if not isinstance(m, dict) or "@odata.id" not in m:
                    continue
                t_uri = normalize_redfish_path(str(m["@odata.id"]))
                if "TaskState" in m:
                    tasks.append(dict(parse_task_summary(t_uri, m)))
                else:
                    tst, tdata = await self._request_json("GET", t_uri, timeout=timeout)
                    if 200 <= tst < 300:
                        tasks.append(dict(parse_task_summary(t_uri, tdata)))
            return st, {
                "count": len(tasks),
                "tasks": tasks,
            }

        sub = parts[1].lower()
        if sub == "status":
            if len(parts) < 3:
                raise BMCCapabilityError("task status requires a <task_id_or_uri> argument")
            task_uri = resolve_task_uri(parts[2])
            st, data = await self._request_json("GET", task_uri, timeout=timeout)
            summary = parse_task_summary(task_uri, data)
            return st, dict(summary)

        if sub == "wait":
            if len(parts) < 3:
                raise BMCCapabilityError("task wait requires a <task_id_or_uri> argument")
            wait_timeout = timeout
            if len(parts) >= 4:
                try:
                    wait_timeout = float(parts[3])
                except ValueError as exc:
                    raise BMCCapabilityError(
                        f"Invalid timeout value in task wait: {parts[3]!r}"
                    ) from exc
            st, summary = await self.wait_for_task(parts[2], timeout=wait_timeout)
            return st, {
                "ok": 200 <= st < 300,
                **summary,
            }

        raise BMCCapabilityError(
            f"Unsupported task command: {cmd_stripped!r}. "
            "Use 'tasks', 'task status <id>', or 'task wait <id> [timeout]'"
        )


__all__ = [
    "TERMINAL_FAILURE_STATES",
    "TERMINAL_SUCCESS_STATES",
    "TERMINAL_TASK_STATES",
    "RedfishTaskMonitor",
    "extract_task_uri_from_response",
    "parse_task_summary",
    "resolve_task_uri",
]
