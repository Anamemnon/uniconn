# tests/unit/orchestration/test_single_host_flow.py
"""Unit-тесты выполнения Flow на одиночном хосте: параллелизм, ошибки ok=False, retries, always_run и notify."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from uniconn import (
    Connection,
    EnsureResult,
    Flow,
    FlowContext,
    FlowExecutionError,
    Result,
    TimeoutError,
    task,
)


async def test_single_host_parallel_branches_and_context_passing() -> None:
    """Независимые ветки графа выполняются параллельно и обмениваются данными через FlowContext."""
    execution_order: list[str] = []

    @task
    async def prepare(conn: Connection, ctx: FlowContext) -> str:
        execution_order.append("prepare")
        ctx.set("shared_token", "xyz")
        ctx.host_set(conn, "multiplier", 3)
        return "ready"

    @task(depends_on=[prepare])
    async def slow_branch(conn: Connection, ctx: FlowContext) -> int:
        await asyncio.sleep(0.05)
        execution_order.append("slow_branch")
        return 10 * ctx.host_get(conn, "multiplier")

    @task(depends_on=[prepare])
    async def fast_branch(conn: Connection, ctx: FlowContext) -> str:
        await asyncio.sleep(0.005)
        execution_order.append("fast_branch")
        return f"fast:{ctx.get('shared_token')}"

    @task(depends_on=[fast_branch])
    async def fast_child(conn: Connection, ctx: FlowContext) -> str:
        # Должен выполниться ДО завершения slow_branch благодаря динамическому TopologicalSorter!
        execution_order.append("fast_child")
        parent_res = ctx.get_task_result(conn, fast_branch)
        assert parent_res is not None
        return f"child_of_{parent_res.return_value}"

    @task(depends_on=[slow_branch, fast_child])
    async def finalize(conn: Connection) -> Result:
        execution_order.append("finalize")
        return await conn.run("echo done")

    flow = Flow("parallel_single", tasks=[finalize])
    async with Connection.local() as conn:
        report = await conn.run_flow(flow)

    assert report.ok is True
    assert report.succeeded_count == 5
    assert report.failed_count == 0
    assert execution_order[0] == "prepare"
    # fast_branch и fast_child успевают завершиться раньше slow_branch
    assert execution_order.index("fast_child") < execution_order.index("slow_branch")
    assert execution_order[-1] == "finalize"


async def test_result_and_ensure_result_with_ok_false_treated_as_failed_and_trigger_retries() -> None:
    """Возврат Result(exit_code=1) или EnsureResult(ok=False) считается ошибкой и запускает retries."""
    attempts_counter = 0

    @task(retries=2, retry_delay=0.01, retry_backoff=1.0)
    async def flaky_cmd(conn: Connection) -> Result:
        nonlocal attempts_counter
        attempts_counter += 1
        if attempts_counter < 3:
            return Result(
                exit_code=1,
                stdout="",
                stderr="temporary failure",
                duration=0.01,
                command="flaky",
            )
        return Result(
            exit_code=0,
            stdout="recovered",
            stderr="",
            duration=0.01,
            command="flaky",
        )

    @task(depends_on=[flaky_cmd])
    async def failing_ensure(conn: Connection) -> EnsureResult:
        return EnsureResult(
            target="/etc/broken",
            state="present",
            changed=False,
            ok=False,
            details="validation failed",
        )

    @task(depends_on=[failing_ensure])
    async def unreachable_child(conn: Connection) -> str:
        return "should_not_run"

    @task(depends_on=[failing_ensure], always_run=True)
    async def guaranteed_cleanup(conn: Connection) -> str:
        return "cleaned_up"

    flow = Flow("failure_semantics", tasks=[unreachable_child, guaranteed_cleanup])
    async with Connection.local() as conn:
        report = await flow.run(conn)

    assert report.ok is False
    assert attempts_counter == 3

    by_task = {r.task_name: r for r in report.for_host("localhost")}
    assert by_task["flaky_cmd"].status == "success"
    assert by_task["flaky_cmd"].attempts == 3

    assert by_task["failing_ensure"].status == "failed"
    assert by_task["failing_ensure"].error == "validation failed"

    assert by_task["unreachable_child"].status == "skipped"
    assert by_task["unreachable_child"].skip_reason == "upstream_failed"

    # Финализатор с always_run=True обязан выполниться даже после падения предка!
    assert by_task["guaranteed_cleanup"].status == "success"
    assert by_task["guaranteed_cleanup"].return_value == "cleaned_up"

    with pytest.raises(FlowExecutionError) as exc_info:
        report.raise_for_status()
    assert exc_info.value.report is report
    assert exc_info.value.failed_hosts == ["localhost"]


async def test_when_predicate_and_ignore_errors_and_timeout() -> None:
    """Проверка работы when=False (не блокирует потомков), ignore_errors=True и таймаута задачи."""

    @task(when=lambda conn, ctx: ctx.get("enable_optional") is True)
    async def optional_step(conn: Connection) -> str:
        return "ran"

    @task(depends_on=[optional_step], ignore_errors=True)
    async def non_critical_error(conn: Connection) -> None:
        raise RuntimeError("non-critical boom")

    @task(depends_on=[non_critical_error])
    async def after_ignored(conn: Connection) -> str:
        return "continued"

    flow = Flow("when_and_ignore", tasks=[after_ignored])
    async with Connection.local() as conn:
        report = await flow.run(conn, vars={"enable_optional": False})

    assert report.ok is True
    by_task = {r.task_name: r for r in report.for_host("localhost")}
    assert by_task["optional_step"].status == "skipped"
    assert by_task["optional_step"].skip_reason == "when_false"
    assert by_task["non_critical_error"].status == "failed"
    assert by_task["non_critical_error"].ignored_error is True
    assert by_task["non_critical_error"].ok is True
    assert by_task["after_ignored"].status == "success"

    # Проверим превышение таймаута задачи
    @task(timeout=0.02)
    async def hung_task(conn: Connection) -> None:
        await asyncio.sleep(0.5)

    timeout_flow = Flow("timeout_test", tasks=[hung_task])
    async with Connection.local() as conn:
        t_report = await timeout_flow.run(conn)

    assert t_report.ok is False
    t_res = t_report.for_host("localhost")[0]
    assert t_res.status == "failed"
    assert isinstance(t_res.exception, TimeoutError)


async def test_flow_auto_batches_and_deduplicates_notify_handlers(tmp_path: Path) -> None:
    """Flow(batch_notifications=True) дедуплицирует notify-обработчики между разными задачами графа."""
    reload_calls = 0

    async def reload_service(conn: Connection) -> EnsureResult:
        nonlocal reload_calls
        reload_calls += 1
        return EnsureResult(target="nginx", state="reloaded", changed=True, ok=True)

    notify_spec = ("reload_nginx", reload_service)
    file1 = tmp_path / "conf1.conf"
    file2 = tmp_path / "conf2.conf"

    @task
    async def write_first(conn: Connection) -> EnsureResult:
        return await conn.state.ensure_file(
            str(file1), content="a=1\n", notify=notify_spec
        )

    @task(depends_on=[write_first])
    async def write_second(conn: Connection) -> EnsureResult:
        return await conn.state.ensure_file(
            str(file2), content="b=2\n", notify=notify_spec
        )

    flow = Flow("notify_dedup_flow", tasks=[write_second], batch_notifications=True)
    async with Connection.local() as conn:
        report = await flow.run(conn)

    assert report.ok is True
    assert report.changed_count == 2
    # Обработчик reload_nginx должен быть вызван ровно 1 раз в конце Flow!
    assert reload_calls == 1
    assert report.notified_handlers == {"localhost": ["reload_nginx"]}


async def test_notify_handler_failure_marks_flow_report_failed(tmp_path: Path) -> None:
    """Если отложенный обработчик notify возвращает ok=False при flush(), FlowReport.ok становится False."""
    target_file = tmp_path / "app.conf"

    async def broken_reload(conn: Connection) -> EnsureResult:
        return EnsureResult(
            target="app.service",
            state="reloaded",
            changed=False,
            ok=False,
            details="systemctl reload failed",
        )

    @task
    async def update_cfg(conn: Connection) -> EnsureResult:
        return await conn.state.ensure_file(
            str(target_file),
            content="x=1\n",
            notify=("reload_app", broken_reload),
        )

    flow = Flow("notify_fail_flow", tasks=[update_cfg], batch_notifications=True)
    async with Connection.local() as conn:
        report = await flow.run(conn)

    assert report.ok is False
    by_task = {r.task_name: r for r in report.for_host("localhost")}
    assert by_task["update_cfg"].status == "success"
    assert by_task["<notify>"].status == "failed"
    assert "systemctl reload failed" in (by_task["<notify>"].error or "")
