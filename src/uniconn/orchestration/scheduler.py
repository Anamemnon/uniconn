# src/uniconn/orchestration/scheduler.py
"""Планировщики исполнения DAG-сценариев для одиночного хоста и пула ConnectionPool."""

from __future__ import annotations

import asyncio
import builtins
import time
from collections.abc import Mapping, Sequence
from collections.abc import Set as AbstractSet
from graphlib import TopologicalSorter
from typing import TYPE_CHECKING, Any

from ..exceptions import BatchAbortedError, ConfigurationError, StateDriftError
from ..exceptions import TimeoutError as UniconnTimeoutError
from ..services.provisioning._fleet_plan import (
    CURRENT_PLAN_HOST,
    CURRENT_PLAN_TASK,
    FleetChangePlan,
    PlanApplier,
    PlanRecorder,
    _ServiceApplierBinding,
    _ServicePlanBinding,
)
from ..services.provisioning._notify import NotificationBatch
from ._barrier_window import _BarrierConnectionWindow, _WindowedHostConn
from ._rollback import (
    build_reverse_rollback_layers,
    invoke_on_failure_handler,
    make_rollback_connection_error_results,
    rollback_barrier_hosts,
    rollback_host_tasks,
)
from .context import CURRENT_FLOW_HOST, FlowContext, normalize_host_id
from .models import (
    FlowReport,
    RollbackResult,
    SkipReason,
    TaskResult,
    extract_task_diagnostic,
    extract_task_outcome_metadata,
)
from .task import Task, invoke_flow_callable

if TYPE_CHECKING:
    from ..core.connection import Connection
    from ..pool.connection_pool import ConnectionPool
    from .flow import Flow


def compute_active_tasks_by_tags(
    tasks: dict[str, Task[Any, Any]],
    dag: dict[str, set[str]],
    tags: Sequence[str] | None,
) -> set[str] | None:
    """Вычислить множество активных задач (включая их транзитивные зависимости, post-шаги и always_run)."""
    if not tags:
        return None
    tag_set = set(tags)
    seed_tasks: list[str] = []
    for name, t_obj in tasks.items():
        if bool(set(t_obj.tags) & tag_set) or t_obj.always_run:
            seed_tasks.append(name)
            for post_t in t_obj.post:
                if post_t.name in tasks:
                    seed_tasks.append(post_t.name)

    active: set[str] = set()
    stack: list[str] = list(seed_tasks)
    while stack:
        cur = stack.pop()
        if cur in active:
            continue
        active.add(cur)
        for dep in dag.get(cur, ()):
            if dep not in active:
                stack.append(dep)
    return active


def _resolve_rollout_limits(
    flow: Flow,
    pool: ConnectionPool,
    batch_size: int | None,
    max_fail_ratio: float | None,
) -> tuple[int | None, float, bool]:
    """Определить эффективные ``(eff_batch, eff_ratio, enforce_ratio)`` для флотского запуска."""
    eff_batch = flow.batch_size if batch_size is None else batch_size
    if eff_batch is None:
        eff_batch = pool.batch_size
    eff_ratio = flow.max_fail_ratio if max_fail_ratio is None else max_fail_ratio
    if eff_ratio == 0.0 and pool.max_fail_ratio > 0.0:
        eff_ratio = pool.max_fail_ratio

    enforce_ratio = (
        eff_batch is not None
        or max_fail_ratio is not None
        or flow.max_fail_ratio > 0.0
        or pool.batch_size is not None
    )
    return eff_batch, eff_ratio, enforce_ratio


def _slice_into_batches(
    uris: Sequence[Any], eff_batch: int | None
) -> list[list[tuple[int, Any]]]:
    """Разбить список элементов пула ``(idx, target)`` на волны размера ``eff_batch``."""
    if not uris:
        return []
    chunk_size = eff_batch if (eff_batch is not None and eff_batch > 0) else len(uris)
    items = list(enumerate(uris))
    return [items[i : i + chunk_size] for i in range(0, len(items), chunk_size)]


def _will_abort_batch(
    batch_items: Sequence[Any],
    batch_failures: Mapping[str, Any],
    eff_ratio: float,
) -> bool:
    """Проверить, превышает ли доля ошибок в батче порог ``eff_ratio``."""
    if not batch_items or not batch_failures:
        return False
    return (len(batch_failures) / len(batch_items)) > eff_ratio


def _check_batch_fail_ratio(
    flow_name: str,
    batch_idx: int,
    batch_items: Sequence[Any],
    batch_failures: dict[str, Any],
    eff_ratio: float,
    completed_results: dict[str, list[TaskResult]],
    *,
    layer_idx: int | None = None,
    rollbacks: Mapping[str, Sequence[RollbackResult]] | None = None,
) -> None:
    """Выбросить ``BatchAbortedError``, если доля ошибок в батче превысила ``eff_ratio``."""
    if not _will_abort_batch(batch_items, batch_failures, eff_ratio):
        return
    fail_ratio = len(batch_failures) / len(batch_items)
    layer_prefix = f"barrier layer {layer_idx} " if layer_idx is not None else ""
    rb_payload: dict[str, list[object]] = {
        host: list(items) for host, items in (rollbacks or {}).items() if items
    }
    raise BatchAbortedError(
        f"Flow {flow_name!r} {layer_prefix}batch {batch_idx} aborted: "
        f"fail_ratio={fail_ratio:.2f} exceeded max_fail_ratio={eff_ratio:.2f} "
        f"({len(batch_failures)}/{len(batch_items)} failed)",
        batch_index=batch_idx,
        fail_ratio=fail_ratio,
        max_fail_ratio=eff_ratio,
        completed_results=dict(completed_results),
        failed_hosts=batch_failures,
        rollbacks=rb_payload,
    )


async def _flush_host_notifications(
    batch_obj: NotificationBatch,
    host_key: str,
    host_results: list[TaskResult],
) -> list[str]:
    """Сбросить накопленные уведомления ``NotificationBatch`` и зафиксировать ошибки обработчиков."""
    if any(not r.ok for r in host_results):
        return []

    notified_keys = list(batch_obj.notified_keys)
    start_ts = time.perf_counter()
    try:
        outcomes = await batch_obj.flush()
    except Exception as exc:
        host_results.append(
            TaskResult(
                task_name="<notify>",
                host=host_key,
                status="failed",
                exception=exc,
                error=f"notify handler raised {type(exc).__name__}: {exc}",
                duration=time.perf_counter() - start_ts,
                notified=True,
                diagnostic=extract_task_diagnostic(None, exc),
            )
        )
        return notified_keys

    for outcome in outcomes:
        is_failed, changed, diff, err_detail, _ = extract_task_outcome_metadata(outcome)
        if is_failed:
            host_results.append(
                TaskResult(
                    task_name="<notify>",
                    host=host_key,
                    status="failed",
                    return_value=outcome,
                    error=err_detail or "notify handler returned ok=False",
                    duration=time.perf_counter() - start_ts,
                    changed=changed,
                    diff=diff,
                    notified=True,
                    diagnostic=extract_task_diagnostic(outcome, None),
                )
            )
    return notified_keys


class _TaskExecutionEngine:
    """Внутренний движок исполнения одиночного узла Task с ретраями, таймаутом и фильтрами."""

    def __init__(
        self,
        flow: Flow,
        ctx: FlowContext,
        active_by_tags: set[str] | None,
        dry_run_override: bool | None,
        completed_tasks_by_host: (
            Mapping[str, AbstractSet[str] | Sequence[str] | Mapping[str, Any]] | None
        ) = None,
        checkpoint_outputs_by_host: Mapping[str, Mapping[str, Any]] | None = None,
        plan_recorder: PlanRecorder | None = None,
        plan_applier: PlanApplier | None = None,
        rollback_on_failure: bool = True,
    ) -> None:
        self.flow = flow
        self.ctx = ctx
        self.active_by_tags = active_by_tags
        self.dry_run_override = dry_run_override
        self.plan_recorder = plan_recorder
        self.plan_applier = plan_applier
        self.rollback_on_failure = (
            bool(rollback_on_failure)
            and plan_recorder is None
            and dry_run_override is not True
        )
        self.rollbacks_by_host: dict[str, list[RollbackResult]] = {}
        self._rolled_back_hosts: set[str] = set()
        self.completed_by_host: dict[str, set[str]] = {}
        self.checkpoint_outputs_by_host: dict[str, dict[str, Any]] = {}
        for h, tasks in (completed_tasks_by_host or {}).items():
            h_str = str(h)
            if isinstance(tasks, Mapping):
                self.completed_by_host[h_str] = {str(k) for k in tasks}
                self.checkpoint_outputs_by_host[h_str] = {
                    str(k): v for k, v in tasks.items()
                }
            else:
                self.completed_by_host[h_str] = {str(t) for t in tasks}
        for h, outputs in (checkpoint_outputs_by_host or {}).items():
            h_str = str(h)
            if isinstance(outputs, Mapping):
                self.checkpoint_outputs_by_host.setdefault(h_str, {}).update(
                    {str(k): v for k, v in outputs.items()}
                )
        self._task_semaphores: dict[str, asyncio.Semaphore] = {
            name: asyncio.Semaphore(t.options.concurrency)
            for name, t in flow.tasks.items()
            if t.options.concurrency is not None and t.options.concurrency > 0
        }

    def is_dry_run_for(self, conn: Connection) -> bool:
        """Проверить, выполняется ли сценарий в режиме ``dry_run`` или ``flow.plan()`` для соединения."""
        if self.plan_recorder is not None:
            return True
        if self.dry_run_override is not None:
            return bool(self.dry_run_override)
        return bool(conn.dry_run)

    def should_rollback_pool(self, pool: ConnectionPool) -> bool:
        """Проверить, разрешён ли Saga-откат для флотского запуска пула (не ``dry_run``/``plan``)."""
        if not self.rollback_on_failure:
            return False
        return not (self.dry_run_override is None and pool.dry_run)

    def is_host_rolled_back(self, host_key: str) -> bool:
        """Проверить, был ли уже выполнен Saga-откат для указанного хоста."""
        return host_key in self._rolled_back_hosts

    def mark_host_rolled_back(self, host_key: str) -> None:
        """Отметить хост как уже прошедший фазу Saga-отката (защита от двойного отката)."""
        self._rolled_back_hosts.add(host_key)

    def record_host_rollbacks(
        self, host_key: str, rollbacks: Sequence[RollbackResult]
    ) -> None:
        """Зафиксировать результаты компенсирующих транзакций хоста."""
        if rollbacks:
            self.rollbacks_by_host.setdefault(host_key, []).extend(rollbacks)

    def _host_lookup_candidates(
        self,
        host_key: str,
        conn: Connection,
    ) -> tuple[str, ...]:
        primary, short = normalize_host_id(conn)
        key_short = host_key.split("://", 1)[-1].rsplit("@", 1)[-1].split(":", 1)[0]
        return (host_key, primary, short, key_short)

    def _is_completed_in_checkpoint(
        self,
        task_name: str,
        host_key: str,
        conn: Connection,
    ) -> bool:
        """Проверить, была ли задача уже успешно выполнена на этом хосте в чекпоинте."""
        if not self.completed_by_host:
            return False
        for cand in self._host_lookup_candidates(host_key, conn):
            if cand and task_name in self.completed_by_host.get(cand, ()):
                return True
        return False

    def _get_checkpoint_output(
        self,
        task_name: str,
        host_key: str,
        conn: Connection,
    ) -> Any:
        """Вернуть сохранённое возвращаемое значение задачи из чекпоинта (если имеется)."""
        if not self.checkpoint_outputs_by_host:
            return None
        for cand in self._host_lookup_candidates(host_key, conn):
            if cand and cand in self.checkpoint_outputs_by_host:
                host_map = self.checkpoint_outputs_by_host[cand]
                if task_name in host_map:
                    return host_map[task_name]
        return None

    def check_skip_reason(
        self,
        task_obj: Task[Any, Any],
        host_key: str,
        conn: Connection,
        host_results: dict[str, TaskResult],
        host_aborted: bool,
    ) -> SkipReason | None:
        """Проверить статические и графовые условия пропуска задачи до её вызова."""
        name = task_obj.name
        if self._is_completed_in_checkpoint(name, host_key, conn):
            return "checkpoint_completed"

        if self.active_by_tags is not None and name not in self.active_by_tags:
            return "tag_filtered"

        if not task_obj.matches_host(host_key, conn):
            return "host_filtered"

        if not task_obj.always_run:
            for parent_name in self.flow.dag.get(name, ()):
                parent_res = host_results.get(parent_name)
                if parent_res is None:
                    continue
                if not parent_res.ok or parent_res.skip_reason in (
                    "upstream_failed",
                    "aborted",
                ):
                    return "upstream_failed"
            if host_aborted:
                return "aborted"

        return None

    def _prepare_effective_conn(self, conn: Connection) -> Connection:
        """Вернуть соединение с учётом переопределения ``dry_run`` и общих стеков ``notify``/планирования."""
        if self.dry_run_override is None or conn.dry_run == self.dry_run_override:
            return conn
        eff_conn = conn.with_overrides(dry_run=self.dry_run_override)
        eff_conn.state.share_batches_from(conn.state)
        eff_conn.state._share_plan_hooks_from(conn.state)
        return eff_conn

    async def _evaluate_when(
        self,
        task_obj: Task[Any, Any],
        host_key: str,
        eff_conn: Connection,
    ) -> TaskResult | None:
        """Вычислить условие ``when`` и вернуть ``TaskResult`` при пропуске или ошибке предиката."""
        when_fn = task_obj.options.when
        if when_fn is None:
            return None
        try:
            should_run = bool(
                await invoke_flow_callable(when_fn, eff_conn, self.ctx)
            )
        except Exception as exc:
            return TaskResult(
                task_name=task_obj.name,
                host=host_key,
                status="failed",
                exception=exc,
                error=f"when predicate failed: {exc}",
                attempts=1,
                ignored_error=task_obj.options.ignore_errors,
            )
        if not should_run:
            return TaskResult(
                task_name=task_obj.name,
                host=host_key,
                status="skipped",
                skip_reason="when_false",
                attempts=0,
            )
        return None

    async def _invoke_once(
        self,
        task_obj: Task[Any, Any],
        host_key: str,
        eff_conn: Connection,
    ) -> Any:
        """Выполнить одну попытку вызова функции задачи с учётом семафора и таймаута."""
        opts = task_obj.options
        sem = self._task_semaphores.get(task_obj.name)

        async def _call() -> Any:
            if opts.timeout is not None:
                try:
                    async with asyncio.timeout(opts.timeout):
                        return await invoke_flow_callable(
                            task_obj.fn, eff_conn, self.ctx
                        )
                except builtins.TimeoutError as t_err:
                    raise UniconnTimeoutError(
                        f"Task {task_obj.name!r} timed out after {opts.timeout}s",
                        command=task_obj.name,
                        host=host_key,
                    ) from t_err
            return await invoke_flow_callable(task_obj.fn, eff_conn, self.ctx)

        if sem is not None:
            async with sem:
                return await _call()
        return await _call()

    async def execute_task_on_host(
        self,
        task_obj: Task[Any, Any],
        host_key: str,
        conn: Connection,
        host_results: dict[str, TaskResult],
        host_aborted: bool,
    ) -> TaskResult:
        """Выполнить задачу на конкретном хосте с учётом фильтров, ``when``, ``retries`` и ``timeout``."""
        name = task_obj.name
        opts = task_obj.options
        self.ctx.register_host_alias(host_key, conn)

        skip_reason = self.check_skip_reason(
            task_obj, host_key, conn, host_results, host_aborted
        )
        if skip_reason is not None:
            restored_val = (
                self._get_checkpoint_output(name, host_key, conn)
                if skip_reason == "checkpoint_completed"
                else None
            )
            res = TaskResult(
                task_name=name,
                host=host_key,
                status="skipped",
                return_value=restored_val,
                skip_reason=skip_reason,
                attempts=0,
            )
            self.ctx.record_task_result(host_key, res)
            return res

        eff_conn = self._prepare_effective_conn(conn)
        rec_binding: _ServicePlanBinding | None = None
        app_binding: _ServiceApplierBinding | None = None
        if self.plan_recorder is not None:
            rec_binding = _ServicePlanBinding(
                recorder=self.plan_recorder, host_override=host_key
            )
            eff_conn.state._push_plan_recorder(rec_binding)
        if self.plan_applier is not None:
            app_binding = _ServiceApplierBinding(
                applier=self.plan_applier, host_override=host_key
            )
            eff_conn.state._push_plan_applier(app_binding)

        host_token = CURRENT_PLAN_HOST.set(host_key)
        task_token = CURRENT_PLAN_TASK.set(name)
        flow_host_token = CURRENT_FLOW_HOST.set(host_key)
        final_res: TaskResult | None = None
        try:
            when_outcome = await self._evaluate_when(task_obj, host_key, eff_conn)
            if when_outcome is not None:
                self.ctx.record_task_result(host_key, when_outcome)
                final_res = when_outcome
                return when_outcome

            max_attempts = 1 + max(0, opts.retries)
            start_ts = time.perf_counter()
            last_val: Any = None
            last_exc: BaseException | None = None
            last_err: str | None = None
            changed = False
            diff: str | None = None
            notified = False
            attempts_used = 0

            for attempt in range(1, max_attempts + 1):
                attempts_used = attempt
                last_exc = None
                last_val = None
                try:
                    last_val = await self._invoke_once(task_obj, host_key, eff_conn)
                    is_failed, changed, diff, last_err, notified = (
                        extract_task_outcome_metadata(last_val)
                    )
                    if not is_failed:
                        res = TaskResult(
                            task_name=name,
                            host=host_key,
                            status="success",
                            return_value=last_val,
                            duration=time.perf_counter() - start_ts,
                            attempts=attempt,
                            diff=diff,
                            changed=changed,
                            notified=notified,
                            diagnostic=extract_task_diagnostic(last_val, None),
                        )
                        self.ctx.record_task_result(host_key, res)
                        final_res = res
                        return res
                except StateDriftError as exc:
                    last_exc = exc
                    last_err = str(exc) or type(exc).__name__
                    break
                except Exception as exc:
                    last_exc = exc
                    last_err = str(exc) or type(exc).__name__

                if attempt < max_attempts:
                    delay = opts.retry_delay * (opts.retry_backoff ** (attempt - 1))
                    if delay > 0:
                        await asyncio.sleep(delay)

            res = TaskResult(
                task_name=name,
                host=host_key,
                status="failed",
                return_value=last_val,
                exception=last_exc,
                error=last_err,
                duration=time.perf_counter() - start_ts,
                attempts=attempts_used or max_attempts,
                diff=diff,
                changed=changed,
                notified=notified,
                ignored_error=opts.ignore_errors,
                diagnostic=extract_task_diagnostic(last_val, last_exc),
            )
            self.ctx.record_task_result(host_key, res)
            final_res = res
            return res
        finally:
            CURRENT_FLOW_HOST.reset(flow_host_token)
            CURRENT_PLAN_TASK.reset(task_token)
            CURRENT_PLAN_HOST.reset(host_token)
            if rec_binding is not None:
                eff_conn.state._pop_plan_recorder(rec_binding)
            if app_binding is not None:
                eff_conn.state._pop_plan_applier(app_binding)
            if (
                final_res is not None
                and final_res.status == "failed"
                and task_obj.on_failure is not None
                and not self.is_dry_run_for(conn)
            ):
                await invoke_on_failure_handler(
                    task_obj, host_key, eff_conn, self.ctx, final_res
                )


async def run_single_host_dag(
    flow: Flow,
    host_key: str,
    conn: Connection,
    engine: _TaskExecutionEngine,
) -> tuple[list[TaskResult], list[str]]:
    """Динамически исполнить весь DAG задач на одном соединении ``Connection`` (с Saga-откатом при сбое)."""
    sorter: TopologicalSorter[str] = TopologicalSorter(flow.dag)
    sorter.prepare()

    host_results: dict[str, TaskResult] = {}
    completion_order: dict[str, int] = {}
    completion_seq = 0
    ordered_results: list[TaskResult] = []
    notified_keys: list[str] = []
    host_aborted = False

    batch_obj: NotificationBatch | None = None
    if flow.batch_notifications and engine.plan_recorder is None:
        batch_obj = conn.state.batch_notifications()
        await batch_obj.__aenter__()

    running: dict[asyncio.Task[TaskResult], str] = {}
    try:
        while sorter.is_active():
            for ready_name in sorter.get_ready():
                t_obj = flow.tasks[ready_name]
                coro = engine.execute_task_on_host(
                    t_obj, host_key, conn, host_results, host_aborted
                )
                running[asyncio.create_task(coro)] = ready_name

            if not running:
                break

            done, _ = await asyncio.wait(
                running.keys(), return_when=asyncio.FIRST_COMPLETED
            )
            for finished in done:
                t_name = running.pop(finished)
                res = finished.result()
                host_results[t_name] = res
                completion_order[t_name] = completion_seq
                completion_seq += 1
                ordered_results.append(res)
                if not res.ok and flow.fail_fast:
                    host_aborted = True
                sorter.done(t_name)

        if batch_obj is not None:
            try:
                notified_keys = await _flush_host_notifications(
                    batch_obj, host_key, ordered_results
                )
            finally:
                # Снимаем NotificationBatch до фазы Saga-отката, чтобы notify внутри compensate
                # не поглощались отменённым батчем основного сценария.
                conn.state.discard_batch(batch_obj)
                batch_obj = None

        if (
            engine.rollback_on_failure
            and not engine.is_dry_run_for(conn)
            and any(not r.ok for r in ordered_results)
        ):
            eff_conn = engine._prepare_effective_conn(conn)
            rbs = await rollback_host_tasks(
                flow,
                host_key,
                eff_conn,
                engine.ctx,
                host_results,
                completion_order,
            )
            engine.record_host_rollbacks(host_key, rbs)
            engine.mark_host_rolled_back(host_key)
    finally:
        if running:
            for pending_task in running:
                pending_task.cancel()
            await asyncio.gather(*running.keys(), return_exceptions=True)
        if batch_obj is not None:
            conn.state.discard_batch(batch_obj)

    return ordered_results, notified_keys


async def run_independent_fleet(
    flow: Flow,
    pool: ConnectionPool,
    engine: _TaskExecutionEngine,
    *,
    batch_size: int | None = None,
    max_fail_ratio: float | None = None,
) -> tuple[dict[str, list[TaskResult]], dict[str, list[str]]]:
    """Исполнить DAG независимо на каждом хосте пула ``ConnectionPool``."""
    results_by_host: dict[str, list[TaskResult]] = {}
    notified_by_host: dict[str, list[str]] = {}
    has_compensators = any(t.compensate is not None for t in flow.tasks.values())

    eff_batch, eff_ratio, enforce_ratio = _resolve_rollout_limits(
        flow, pool, batch_size, max_fail_ratio
    )
    batches = _slice_into_batches(pool.targets, eff_batch)

    async def _run_host(
        idx: int, target: Any
    ) -> tuple[str, list[TaskResult], list[str], BaseException | None]:
        key = pool.target_key(target)
        async with pool.semaphore:
            try:
                async with pool.use_target_connection(idx, target, with_defaults=True) as conn:
                    res_list, notif = await run_single_host_dag(
                        flow, key, conn, engine
                    )
                    return key, res_list, notif, None
            except Exception as exc:
                return key, [], [], exc

    async def _rollback_batch_member(idx: int, target: Any) -> None:
        key = pool.target_key(target)
        if engine.is_host_rolled_back(key):
            return
        res_list = results_by_host.get(key, [])
        host_map = {r.task_name: r for r in res_list}
        succeeded_order = {
            r.task_name: pos
            for pos, r in enumerate(res_list)
            if r.status == "success"
        }
        reverse_layers = build_reverse_rollback_layers(flow, succeeded_order)
        if not reverse_layers:
            engine.mark_host_rolled_back(key)
            return

        async with pool.semaphore:
            try:
                async with pool.use_target_connection(idx, target, with_defaults=True) as conn:
                    if engine.is_dry_run_for(conn):
                        return
                    eff_conn = engine._prepare_effective_conn(conn)
                    rbs = await rollback_host_tasks(
                        flow, key, eff_conn, engine.ctx, host_map, succeeded_order
                    )
                    engine.record_host_rollbacks(key, rbs)
            except Exception as exc:
                ordered_tasks = [t for layer in reverse_layers for t in layer]
                engine.record_host_rollbacks(
                    key, make_rollback_connection_error_results(ordered_tasks, key, exc)
                )
            finally:
                engine.mark_host_rolled_back(key)

    for batch_idx, batch_items in enumerate(batches):
        outcomes = await asyncio.gather(
            *(_run_host(idx, target) for idx, target in batch_items)
        )
        batch_failures: dict[str, Any] = {}
        for key, res_list, notif, exc in outcomes:
            if exc is not None:
                err_res = TaskResult(
                    task_name="<connect>",
                    host=key,
                    status="failed",
                    exception=exc,
                    error=str(exc),
                    diagnostic=extract_task_diagnostic(None, exc),
                )
                results_by_host[key] = [err_res]
                batch_failures[key] = exc
            else:
                results_by_host[key] = res_list
                if notif:
                    notified_by_host[key] = notif
                if any(not r.ok for r in res_list):
                    batch_failures[key] = [r for r in res_list if not r.ok]

        if enforce_ratio and _will_abort_batch(batch_items, batch_failures, eff_ratio):
            if engine.should_rollback_pool(pool) and has_compensators:
                await asyncio.gather(
                    *(_rollback_batch_member(idx, target) for idx, target in batch_items)
                )
            batch_rollbacks: dict[str, list[RollbackResult]] = {
                host_k: list(host_rbs)
                for _idx, target in batch_items
                if (host_rbs := engine.rollbacks_by_host.get(host_k := pool.target_key(target)))
            }
            _check_batch_fail_ratio(
                flow.name,
                batch_idx,
                batch_items,
                batch_failures,
                eff_ratio,
                results_by_host,
                rollbacks=batch_rollbacks,
            )

    return results_by_host, notified_by_host


async def run_barrier_fleet(
    flow: Flow,
    pool: ConnectionPool,
    engine: _TaskExecutionEngine,
    *,
    batch_size: int | None = None,
    max_fail_ratio: float | None = None,
    connection_window: int | None = None,
) -> tuple[dict[str, list[TaskResult]], dict[str, list[str]]]:
    """Исполнить DAG в барьерном режиме (по топологическим слоям и батчам хостов) с LRU-окном соединений."""
    if connection_window is not None and connection_window < 1:
        raise ConfigurationError(f"connection_window must be >= 1, got {connection_window}")

    uris = pool.targets
    results_by_host: dict[str, list[TaskResult]] = {
        pool.target_key(t): [] for t in uris
    }
    host_task_maps: dict[str, dict[str, TaskResult]] = {
        pool.target_key(t): {} for t in uris
    }
    host_completion_orders: dict[str, dict[str, int]] = {
        pool.target_key(t): {} for t in uris
    }
    host_seq: dict[str, int] = {pool.target_key(t): 0 for t in uris}
    host_aborted: dict[str, bool] = {pool.target_key(t): False for t in uris}
    notified_by_host: dict[str, list[str]] = {}

    if not uris:
        return results_by_host, notified_by_host

    has_compensators = any(t.compensate is not None for t in flow.tasks.values())
    eff_batch, eff_ratio, enforce_ratio = _resolve_rollout_limits(
        flow, pool, batch_size, max_fail_ratio
    )
    batches = _slice_into_batches(uris, eff_batch)
    layers = flow.get_layers()

    resolved_window = connection_window if connection_window is not None else flow.connection_window
    if resolved_window is not None:
        if resolved_window < 1:
            raise ConfigurationError(f"connection_window must be >= 1, got {resolved_window}")
        eff_window = resolved_window
    elif eff_batch is not None and eff_batch > 0:
        eff_window = eff_batch
    else:
        pool_limit = getattr(pool, "max_concurrent", None)
        eff_window = int(pool_limit) if isinstance(pool_limit, int) and pool_limit > 0 else len(uris)

    conn_window = _BarrierConnectionWindow(
        pool,
        max_open=eff_window,
        batch_notifications=flow.batch_notifications and engine.plan_recorder is None,
    )
    keep_warm_for_rollback = engine.should_rollback_pool(pool) and has_compensators

    try:
        async def _flush_entry_batch(entry: _WindowedHostConn, key: str) -> None:
            if entry.batch is None:
                return
            nb = entry.batch
            entry.batch = None
            try:
                notif_list = await _flush_host_notifications(
                    nb, key, results_by_host[key]
                )
                if notif_list:
                    notified_by_host[key] = notif_list
            finally:
                entry.conn.state.discard_batch(nb)

        async def _run_layer_on_host(
            idx: int,
            target: Any,
            layer_tasks: list[Task[Any, Any]],
            is_last_layer: bool,
        ) -> tuple[str, list[TaskResult], BaseException | None]:
            key = pool.target_key(target)
            async with pool.semaphore:
                entry: _WindowedHostConn | None = None
                try:
                    entry = await conn_window.acquire(idx, target, key)
                    conn = entry.conn
                    coros = [
                        engine.execute_task_on_host(
                            t_obj,
                            key,
                            conn,
                            host_task_maps[key],
                            host_aborted[key],
                        )
                        for t_obj in layer_tasks
                    ]
                    layer_res = list(await asyncio.gather(*coros))
                    for r in layer_res:
                        host_task_maps[key][r.task_name] = r
                        host_completion_orders[key][r.task_name] = host_seq[key]
                        host_seq[key] += 1
                        results_by_host[key].append(r)
                        if not r.ok and flow.fail_fast:
                            host_aborted[key] = True

                    if is_last_layer and not keep_warm_for_rollback:
                        await _flush_entry_batch(entry, key)

                    return key, layer_res, None
                except Exception as exc:
                    err_res = TaskResult(
                        task_name=(
                            layer_tasks[0].name if layer_tasks else "<connect>"
                        ),
                        host=key,
                        status="failed",
                        exception=exc,
                        error=str(exc),
                        diagnostic=extract_task_diagnostic(None, exc),
                    )
                    results_by_host[key].append(err_res)
                    host_aborted[key] = True
                    return key, [err_res], exc
                finally:
                    if entry is not None:
                        await conn_window.release(
                            entry,
                            close_now=is_last_layer and not keep_warm_for_rollback,
                        )

        async def _flush_deferred_batch_notifications(
            target_entries: Sequence[tuple[int, Any]],
        ) -> None:
            if not (flow.batch_notifications and engine.plan_recorder is None):
                return

            async def _flush_one(idx: int, target: Any) -> None:
                key = pool.target_key(target)
                if engine.is_host_rolled_back(key) or any(
                    not r.ok for r in results_by_host.get(key, ())
                ):
                    return
                async with pool.semaphore:
                    entry: _WindowedHostConn | None = None
                    try:
                        entry = await conn_window.acquire(idx, target, key)
                        await _flush_entry_batch(entry, key)
                    except Exception as exc:
                        results_by_host[key].append(
                            TaskResult(
                                task_name="<notify>",
                                host=key,
                                status="failed",
                                exception=exc,
                                error=f"notify flush connection error: {exc}",
                                notified=True,
                                diagnostic=extract_task_diagnostic(None, exc),
                            )
                        )
                    finally:
                        if entry is not None:
                            await conn_window.release(entry, close_now=False)

            await asyncio.gather(*(_flush_one(i, t) for i, t in target_entries))

        for layer_idx, layer_tasks in enumerate(layers):
            is_last = layer_idx == len(layers) - 1
            for batch_idx, batch_items in enumerate(batches):
                outcomes = await asyncio.gather(
                    *(
                        _run_layer_on_host(idx, target, layer_tasks, is_last)
                        for idx, target in batch_items
                    )
                )
                batch_failures: dict[str, Any] = {}
                for key, layer_res, exc in outcomes:
                    if exc is not None:
                        batch_failures[key] = exc
                    elif any(not r.ok for r in layer_res):
                        batch_failures[key] = [
                            r for r in layer_res if not r.ok
                        ]

                if enforce_ratio and _will_abort_batch(
                    batch_items, batch_failures, eff_ratio
                ):
                    batch_rollbacks: dict[str, list[RollbackResult]] = {}
                    if keep_warm_for_rollback:
                        batch_rollbacks = await rollback_barrier_hosts(
                            flow,
                            pool,
                            conn_window,
                            batch_items,
                            engine,
                            host_task_maps,
                            host_completion_orders,
                            max_layer_idx=layer_idx,
                        )
                    _check_batch_fail_ratio(
                        flow.name,
                        batch_idx,
                        batch_items,
                        batch_failures,
                        eff_ratio,
                        results_by_host,
                        layer_idx=layer_idx,
                        rollbacks=batch_rollbacks,
                    )
                elif (
                    not enforce_ratio
                    and batch_failures
                    and keep_warm_for_rollback
                    and flow.fail_fast
                ):
                    for k in host_aborted:
                        host_aborted[k] = True

                # В режиме с Saga-откатом сбрасываем уведомления последнего слоя только если
                # батч (или весь флот при not enforce_ratio) не содержит сбоев за все слои.
                if is_last and keep_warm_for_rollback:
                    has_any_fleet_failure = any(
                        not r.ok
                        for items in results_by_host.values()
                        for r in items
                    )
                    if enforce_ratio or not has_any_fleet_failure:
                        await _flush_deferred_batch_notifications(batch_items)

        if keep_warm_for_rollback:
            failed_keys = {
                k
                for k, items in results_by_host.items()
                if any(not r.ok for r in items)
            }
            if failed_keys:
                if not enforce_ratio:
                    targets_to_rollback = list(enumerate(uris))
                else:
                    targets_to_rollback = [
                        (idx, t)
                        for idx, t in enumerate(uris)
                        if pool.target_key(t) in failed_keys
                    ]
                await rollback_barrier_hosts(
                    flow,
                    pool,
                    conn_window,
                    targets_to_rollback,
                    engine,
                    host_task_maps,
                    host_completion_orders,
                    max_layer_idx=len(layers) - 1,
                )
    finally:
        await conn_window.close_all()

    return results_by_host, notified_by_host


async def execute_flow(
    flow: Flow,
    target: Connection | ConnectionPool,
    *,
    context: FlowContext | None = None,
    vars: dict[str, Any] | None = None,
    tags: Sequence[str] | None = None,
    dry_run: bool | None = None,
    batch_size: int | None = None,
    max_fail_ratio: float | None = None,
    connection_window: int | None = None,
    completed_tasks_by_host: (
        Mapping[str, AbstractSet[str] | Sequence[str] | Mapping[str, Any]] | None
    ) = None,
    checkpoint_outputs_by_host: Mapping[str, Mapping[str, Any]] | None = None,
    run_id: str | None = None,
    resumed_from: str | None = None,
    expected_plan: FleetChangePlan | None = None,
    strict_plan: bool = True,
    plan_recorder: PlanRecorder | None = None,
    rollback_on_failure: bool | None = None,
) -> FlowReport:
    """Точка входа исполнения сценария ``Flow`` на ``Connection`` или ``ConnectionPool``."""
    from ..pool.connection_pool import ConnectionPool

    flow.validate()
    ctx = context if context is not None else FlowContext(flow.name, initial_vars=vars)
    if context is not None and vars:
        ctx.update(vars)

    active_by_tags = compute_active_tasks_by_tags(flow.tasks, flow.dag, tags)
    plan_applier = (
        PlanApplier(expected_plan, strict=strict_plan)
        if expected_plan is not None and plan_recorder is None
        else None
    )
    eff_rollback = (
        flow.rollback_on_failure
        if rollback_on_failure is None
        else bool(rollback_on_failure)
    )
    engine = _TaskExecutionEngine(
        flow,
        ctx,
        active_by_tags,
        dry_run,
        completed_tasks_by_host=completed_tasks_by_host,
        checkpoint_outputs_by_host=checkpoint_outputs_by_host,
        plan_recorder=plan_recorder,
        plan_applier=plan_applier,
        rollback_on_failure=eff_rollback,
    )
    start_ts = time.perf_counter()

    if isinstance(target, ConnectionPool):
        if flow.mode == "independent":
            results_map, notified_map = await run_independent_fleet(
                flow,
                target,
                engine,
                batch_size=batch_size,
                max_fail_ratio=max_fail_ratio,
            )
            mode_label = "independent"
        else:
            results_map, notified_map = await run_barrier_fleet(
                flow,
                target,
                engine,
                batch_size=batch_size,
                max_fail_ratio=max_fail_ratio,
                connection_window=connection_window,
            )
            mode_label = "barrier"
    else:
        host_key = target.config.host or target.config.uri_safe or "localhost"
        res_list, notif_list = await run_single_host_dag(
            flow, host_key, target, engine
        )
        results_map = {host_key: res_list}
        notified_map = {host_key: notif_list} if notif_list else {}
        mode_label = "single"

    duration = time.perf_counter() - start_ts
    overall_ok = all(
        r.ok for host_items in results_map.values() for r in host_items
    )
    return FlowReport(
        flow_name=flow.name,
        ok=overall_ok,
        duration=duration,
        results=results_map,
        mode=mode_label,  # type: ignore[arg-type]
        notified_handlers=notified_map,
        run_id=run_id,
        can_resume=(not overall_ok) if run_id is not None else False,
        resumed_from=resumed_from,
        rollbacks={
            host: list(items)
            for host, items in engine.rollbacks_by_host.items()
            if items
        },
    )


def coerce_to_flow(
    flow: Any,
    *,
    mode: str | None = None,
) -> Flow:
    """Нормализовать аргумент ``flow`` (``Flow``, ``SyncFlow``, ``Task`` или список задач) в ``Flow``."""
    from .flow import Flow, SyncFlow

    eff_mode: Any = mode if mode in ("barrier", "independent") else "barrier"
    if isinstance(flow, SyncFlow):
        flow_obj = flow._async_flow
    elif isinstance(flow, Flow):
        flow_obj = flow
    elif isinstance(flow, Task) or callable(flow):
        flow_obj = Flow(
            name=getattr(flow, "name", "inline_flow"),
            tasks=[flow],
            mode=eff_mode,
        )
    elif isinstance(flow, Sequence) and not isinstance(flow, (str, bytes)):
        flow_obj = Flow(
            name="inline_flow",
            tasks=list(flow),
            mode=eff_mode,
        )
    else:
        raise TypeError(
            f"Expected Flow, Task, or sequence of tasks, got {type(flow).__name__}"
        )

    if mode in ("barrier", "independent") and flow_obj.mode != mode:
        return Flow(
            name=flow_obj.name,
            tasks=list(flow_obj.tasks.values()),
            mode=eff_mode,
            fail_fast=flow_obj.fail_fast,
            max_fail_ratio=flow_obj.max_fail_ratio,
            batch_size=flow_obj.batch_size,
            connection_window=flow_obj.connection_window,
            batch_notifications=flow_obj.batch_notifications,
            rollback_on_failure=flow_obj.rollback_on_failure,
            description=flow_obj.description,
            params_model=flow_obj.params_model,
            risk_tier=flow_obj.risk_tier,
            expose_as_tool=flow_obj.expose_as_tool,
        )
    return flow_obj


async def plan_flow(
    flow: Flow,
    target: Connection | ConnectionPool,
    *,
    context: FlowContext | None = None,
    vars: dict[str, Any] | None = None,
    tags: Sequence[str] | None = None,
    batch_size: int | None = None,
    max_fail_ratio: float | None = None,
    connection_window: int | None = None,
) -> FleetChangePlan:
    """Выполнить read-only планирование сценария ``Flow`` и собрать агрегированный ``FleetChangePlan``."""
    from ..pool.connection_pool import ConnectionPool

    flow.validate()
    recorder = PlanRecorder(flow_name=flow.name)
    if isinstance(target, ConnectionPool):
        for item in target.targets:
            recorder.register_host(target.target_key(item))
    else:
        host_key = target.config.host or target.config.uri_safe or "localhost"
        recorder.register_host(host_key)

    eff_ratio = 1.0 if max_fail_ratio is None else max_fail_ratio
    report = await execute_flow(
        flow,
        target,
        context=context,
        vars=vars,
        tags=tags,
        dry_run=True,
        batch_size=batch_size,
        max_fail_ratio=eff_ratio,
        connection_window=connection_window,
        plan_recorder=recorder,
        rollback_on_failure=False,
    )
    for host, items in report.results.items():
        recorder.register_host(host)
        for item in items:
            if not item.ok:
                err_msg = item.error or (
                    str(item.exception) if item.exception is not None else "failed"
                )
                recorder.record_host_error(host, f"{item.task_name}: {err_msg}")
    return recorder.plan


async def run_connection_flow(
    conn: Connection,
    flow: Any,
    *,
    context: FlowContext | None = None,
    vars: dict[str, Any] | None = None,
    tags: Sequence[str] | None = None,
    dry_run: bool | None = None,
    expected_plan: FleetChangePlan | None = None,
    strict_plan: bool = True,
    rollback_on_failure: bool | None = None,
) -> FlowReport:
    """Выполнить сценарий ``Flow`` (или ``@task`` / список задач) на одиночном ``Connection``."""
    flow_obj = coerce_to_flow(flow)
    return await flow_obj.run(
        conn,
        context=context,
        vars=vars,
        tags=tags,
        dry_run=dry_run,
        expected_plan=expected_plan,
        strict_plan=strict_plan,
        rollback_on_failure=rollback_on_failure,
    )


async def run_pool_flow(
    pool: ConnectionPool,
    flow: Any,
    *,
    context: FlowContext | None = None,
    vars: dict[str, Any] | None = None,
    tags: Sequence[str] | None = None,
    dry_run: bool | None = None,
    mode: str | None = None,
    batch_size: int | None = None,
    max_fail_ratio: float | None = None,
    connection_window: int | None = None,
    expected_plan: FleetChangePlan | None = None,
    strict_plan: bool = True,
    rollback_on_failure: bool | None = None,
) -> FlowReport:
    """Выполнить сценарий ``Flow`` (или ``@task`` / список задач) на пуле ``ConnectionPool``."""
    flow_obj = coerce_to_flow(flow, mode=mode)
    return await flow_obj.run(
        pool,
        context=context,
        vars=vars,
        tags=tags,
        dry_run=dry_run,
        batch_size=batch_size,
        max_fail_ratio=max_fail_ratio,
        connection_window=connection_window,
        expected_plan=expected_plan,
        strict_plan=strict_plan,
        rollback_on_failure=rollback_on_failure,
    )


__all__ = [
    "coerce_to_flow",
    "compute_active_tasks_by_tags",
    "execute_flow",
    "plan_flow",
    "run_barrier_fleet",
    "run_connection_flow",
    "run_independent_fleet",
    "run_pool_flow",
    "run_single_host_dag",
]
