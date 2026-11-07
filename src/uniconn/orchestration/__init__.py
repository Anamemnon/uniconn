# src/uniconn/orchestration/__init__.py
"""Модуль декларативной оркестрации задач с графом зависимостей (Task DAG Runner)."""

from .context import FlowContext, normalize_host_id
from .flow import Flow, SyncFlow
from .models import (
    FlowReport,
    SkipReason,
    TaskResult,
    TaskStatus,
    extract_task_outcome_metadata,
)
from .scheduler import (
    compute_active_tasks_by_tags,
    execute_flow,
    run_barrier_fleet,
    run_independent_fleet,
    run_single_host_dag,
)
from .task import Task, TaskOptions, invoke_flow_callable, task

__all__ = [
    "Flow",
    "FlowContext",
    "FlowReport",
    "SkipReason",
    "SyncFlow",
    "Task",
    "TaskOptions",
    "TaskResult",
    "TaskStatus",
    "compute_active_tasks_by_tags",
    "execute_flow",
    "extract_task_outcome_metadata",
    "invoke_flow_callable",
    "normalize_host_id",
    "run_barrier_fleet",
    "run_independent_fleet",
    "run_single_host_dag",
    "task",
]
