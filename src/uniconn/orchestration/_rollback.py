# src/uniconn/orchestration/_rollback.py
"""Движок компенсирующих транзакций (Saga-откат) и обработчиков on_failure для Flow."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

from .._logging import get_logger
from .context import CURRENT_FLOW_HOST, FlowContext
from .models import (
    RollbackResult,
    TaskResult,
    extract_task_diagnostic,
    extract_task_outcome_metadata,
)
from .task import Task, invoke_flow_callable

if TYPE_CHECKING:
    from ..core.connection import Connection
    from ..pool.connection_pool import ConnectionPool
    from ._barrier_window import _BarrierConnectionWindow, _WindowedHostConn
    from .flow import Flow
    from .scheduler import _TaskExecutionEngine

_logger = get_logger("uniconn.orchestration.rollback")


def build_reverse_rollback_layers(
    flow: Flow,
    succeeded_order: Mapping[str, int],
) -> list[list[Task[Any, Any]]]:
    """Построить слои компенсирующего отката в строгом обратном топологическом порядке.

    Внутри каждого слоя задачи упорядочиваются в обратном порядке их завершения (LIFO),
    а между слоями гарантируется, что зависимые задачи откатываются строго раньше своих
    предшественников.
    """
    if not succeeded_order:
        return []

    reverse_layers: list[list[Task[Any, Any]]] = []
    for layer in reversed(flow.get_layers()):
        candidates = [
            t_obj
            for t_obj in layer
            if t_obj.compensate is not None and t_obj.name in succeeded_order
        ]
        if candidates:
            candidates.sort(key=lambda t: succeeded_order[t.name], reverse=True)
            reverse_layers.append(candidates)
    return reverse_layers


def make_rollback_connection_error_results(
    tasks: Sequence[Task[Any, Any]],
    host_key: str,
    exc: BaseException,
) -> list[RollbackResult]:
    """Сформировать список ``RollbackResult(status='failed')`` при сбое подключения во время отката."""
    diag = extract_task_diagnostic(None, exc)
    err_msg = f"rollback connection error: {exc}"
    return [
        RollbackResult(
            task_name=t_obj.name,
            host=host_key,
            status="failed",
            exception=exc,
            error=err_msg,
            diagnostic=diag,
        )
        for t_obj in tasks
    ]


async def invoke_on_failure_handler(
    task_obj: Task[Any, Any],
    host_key: str,
    eff_conn: Connection,
    ctx: FlowContext,
    failed_result: TaskResult,
) -> None:
    """Безопасно выполнить локальный обработчик ``on_failure`` упавшей задачи."""
    handler = task_obj.on_failure
    if handler is None:
        return

    extra_vars: dict[str, Any] = {
        "error": (
            failed_result.exception
            if failed_result.exception is not None
            else failed_result.error
        ),
        "exc": failed_result.exception,
        "exception": failed_result.exception,
        "result": failed_result,
        "task_result": failed_result,
    }
    host_token = CURRENT_FLOW_HOST.set(host_key)
    try:
        await invoke_flow_callable(handler, eff_conn, ctx, extra_vars=extra_vars)
    except Exception as exc:
        _logger.warning(
            "on_failure handler for task %r on host %r raised %s: %s",
            task_obj.name,
            host_key,
            type(exc).__name__,
            exc,
        )
    finally:
        CURRENT_FLOW_HOST.reset(host_token)


async def execute_compensate_for_task(
    task_obj: Task[Any, Any],
    host_key: str,
    eff_conn: Connection,
    ctx: FlowContext,
    task_result: TaskResult | None = None,
) -> RollbackResult:
    """Выполнить функцию ``compensate`` одной задачи в режиме best-effort (без выброса исключений)."""
    comp_fn = task_obj.compensate
    if comp_fn is None:
        return RollbackResult(
            task_name=task_obj.name,
            host=host_key,
            status="success",
            duration=0.0,
        )

    extra_vars: dict[str, Any] = {
        "result": task_result,
        "output": task_result.return_value if task_result is not None else None,
    }
    start_ts = time.perf_counter()
    host_token = CURRENT_FLOW_HOST.set(host_key)
    try:
        val = await invoke_flow_callable(comp_fn, eff_conn, ctx, extra_vars=extra_vars)
        is_failed, _changed, _diff, err_detail, _notified = (
            extract_task_outcome_metadata(val)
        )
        duration = time.perf_counter() - start_ts
        if is_failed:
            return RollbackResult(
                task_name=task_obj.name,
                host=host_key,
                status="failed",
                return_value=val,
                error=err_detail or f"compensate for {task_obj.name!r} returned ok=False",
                duration=duration,
                diagnostic=extract_task_diagnostic(val, None),
            )
        return RollbackResult(
            task_name=task_obj.name,
            host=host_key,
            status="success",
            return_value=val,
            duration=duration,
            diagnostic=extract_task_diagnostic(val, None),
        )
    except Exception as exc:
        duration = time.perf_counter() - start_ts
        _logger.warning(
            "compensate handler for task %r on host %r failed with %s: %s",
            task_obj.name,
            host_key,
            type(exc).__name__,
            exc,
        )
        return RollbackResult(
            task_name=task_obj.name,
            host=host_key,
            status="failed",
            exception=exc,
            error=str(exc) or type(exc).__name__,
            duration=duration,
            diagnostic=extract_task_diagnostic(None, exc),
        )
    finally:
        CURRENT_FLOW_HOST.reset(host_token)


async def rollback_host_tasks(
    flow: Flow,
    host_key: str,
    eff_conn: Connection,
    ctx: FlowContext,
    host_results: Mapping[str, TaskResult],
    completion_order: Mapping[str, int],
) -> list[RollbackResult]:
    """Откатить все успешно выполненные задачи хоста в обратном топологическом порядке (best-effort)."""
    succeeded_order: dict[str, int] = {}
    for name, res in host_results.items():
        if res.status == "success":
            succeeded_order[name] = completion_order.get(name, -1)

    reverse_layers = build_reverse_rollback_layers(flow, succeeded_order)
    if not reverse_layers:
        return []

    rollbacks: list[RollbackResult] = []
    for layer in reverse_layers:
        for t_obj in layer:
            rb_res = await execute_compensate_for_task(
                t_obj,
                host_key,
                eff_conn,
                ctx,
                task_result=host_results.get(t_obj.name),
            )
            rollbacks.append(rb_res)
    return rollbacks


async def rollback_barrier_hosts(
    flow: Flow,
    pool: ConnectionPool,
    conn_window: _BarrierConnectionWindow,
    target_entries: Sequence[tuple[int, Any]],
    engine: _TaskExecutionEngine,
    host_task_maps: Mapping[str, Mapping[str, TaskResult]],
    host_completion_orders: Mapping[str, Mapping[str, int]],
    *,
    max_layer_idx: int,
) -> dict[str, list[RollbackResult]]:
    """Откатить группу хостов в ``barrier``-режиме послойно в обратном топологическом порядке."""
    layers = flow.get_layers()
    if not layers or not target_entries:
        return {}

    rollbacks_by_host: dict[str, list[RollbackResult]] = {}
    top_idx = min(max_layer_idx, len(layers) - 1)

    for layer_idx in range(top_idx, -1, -1):
        comp_tasks = [t for t in layers[layer_idx] if t.compensate is not None]
        if not comp_tasks:
            continue

        host_work: list[tuple[int, Any, str, list[Task[Any, Any]]]] = []
        for idx, target in target_entries:
            key = pool.target_key(target)
            if engine.is_host_rolled_back(key):
                continue
            task_map = host_task_maps.get(key, {})
            order_map = host_completion_orders.get(key, {})
            succeeded_here = [
                t
                for t in comp_tasks
                if (res := task_map.get(t.name)) is not None and res.status == "success"
            ]
            if succeeded_here:
                succeeded_here.sort(
                    key=lambda t: order_map.get(t.name, -1),
                    reverse=True,
                )
                host_work.append((idx, target, key, succeeded_here))

        if not host_work:
            continue

        async def _rollback_layer_on_host(
            idx: int,
            target: Any,
            key: str,
            tasks_to_undo: list[Task[Any, Any]],
        ) -> tuple[str, list[RollbackResult]]:
            async with pool.semaphore:
                entry: _WindowedHostConn | None = None
                host_rbs: list[RollbackResult] = []
                try:
                    entry = await conn_window.acquire(idx, target, key)
                    if engine.is_dry_run_for(entry.conn):
                        return key, []
                    # Сбрасываем невыполненный NotificationBatch прерванного сценария, чтобы
                    # вызовы ensure_*(..., notify=...) внутри compensate выполнялись сразу.
                    conn_window.discard_notifications(entry)
                    eff_conn = engine._prepare_effective_conn(entry.conn)
                    task_map = host_task_maps.get(key, {})
                    for t_obj in tasks_to_undo:
                        rb_res = await execute_compensate_for_task(
                            t_obj,
                            key,
                            eff_conn,
                            engine.ctx,
                            task_result=task_map.get(t_obj.name),
                        )
                        host_rbs.append(rb_res)
                except Exception as exc:
                    host_rbs.extend(
                        make_rollback_connection_error_results(
                            tasks_to_undo[len(host_rbs) :], key, exc
                        )
                    )
                finally:
                    if entry is not None:
                        await conn_window.release(entry, close_now=False)
                return key, host_rbs

        layer_outcomes = await asyncio.gather(
            *(
                _rollback_layer_on_host(idx, target, key, tasks_to_undo)
                for idx, target, key, tasks_to_undo in host_work
            )
        )
        for key, host_rbs in layer_outcomes:
            if host_rbs:
                rollbacks_by_host.setdefault(key, []).extend(host_rbs)

    for key, rbs in rollbacks_by_host.items():
        engine.record_host_rollbacks(key, rbs)
    for _idx, target in target_entries:
        engine.mark_host_rolled_back(pool.target_key(target))
    return rollbacks_by_host


__all__ = [
    "build_reverse_rollback_layers",
    "execute_compensate_for_task",
    "invoke_on_failure_handler",
    "make_rollback_connection_error_results",
    "rollback_barrier_hosts",
    "rollback_host_tasks",
]
