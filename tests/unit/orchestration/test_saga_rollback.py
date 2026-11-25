# tests/unit/orchestration/test_saga_rollback.py
"""Unit-тесты компенсирующих транзакций (Saga-отката) и on_failure-хуков в Flow."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

import pytest

from uniconn import (
    BatchAbortedError,
    ConfigurationError,
    Connection,
    ConnectionPool,
    EnsureResult,
    Result,
    SyncConnection,
    SyncConnectionPool,
)
from uniconn.orchestration import Flow, FlowContext, RollbackResult, SyncFlow, task


async def test_single_host_diamond_reverse_topological_rollback_with_ctx_outputs() -> None:
    """Diamond DAG A -> (B, C) -> D(fails) откатывает B и C строго до A с доступом к ctx.outputs."""
    rollback_log: list[tuple[str, dict[str, Any]]] = []

    async def undo_a(conn: Connection, ctx: FlowContext) -> str:
        rollback_log.append(("a", dict(ctx.outputs)))
        return f"undid:{ctx.outputs['step_a']}"

    async def undo_b(conn: Connection, ctx: FlowContext) -> str:
        rollback_log.append(("b", dict(ctx.outputs)))
        return f"undid:{ctx.outputs['step_b']}"

    async def undo_c(conn: Connection, ctx: FlowContext) -> str:
        rollback_log.append(("c", dict(ctx.outputs)))
        return f"undid:{ctx.outputs['step_c']}"

    async def undo_d(conn: Connection, ctx: FlowContext) -> str:
        rollback_log.append(("d", dict(ctx.outputs)))
        return "should-not-run"

    @task(name="step_a", compensate=undo_a)
    async def step_a(conn: Connection) -> str:
        return "val_a"

    @task(name="step_b", depends_on=[step_a], compensate=undo_b)
    async def step_b(conn: Connection) -> str:
        return "val_b"

    @task(name="step_c", depends_on=[step_a], compensate=undo_c)
    async def step_c(conn: Connection) -> str:
        return "val_c"

    @task(name="step_d", depends_on=[step_b, step_c], compensate=undo_d)
    async def step_d(conn: Connection) -> str:
        raise RuntimeError("boom at step_d")

    flow = Flow("diamond_saga", tasks=[step_d])
    async with Connection.from_uri("local://") as conn:
        report = await flow.run(conn)

    assert report.ok is False
    assert report.rolled_back is True
    assert report.rollback_ok is True

    order = [name for name, _ in rollback_log]
    assert set(order) == {"a", "b", "c"}
    assert "d" not in order
    assert order.index("b") < order.index("a")
    assert order.index("c") < order.index("a")

    # Проверяем, что ctx.outputs содержал возвращаемые значения всех успешных задач
    for _, outputs_snapshot in rollback_log:
        assert outputs_snapshot["step_a"] == "val_a"
        assert outputs_snapshot["step_b"] == "val_b"
        assert outputs_snapshot["step_c"] == "val_c"
        assert "step_d" not in outputs_snapshot

    host_key = next(iter(report.rollbacks))
    host_rollbacks = report.rollbacks[host_key]
    assert len(host_rollbacks) == 3
    assert all(isinstance(r, RollbackResult) and r.ok for r in host_rollbacks)

    summary = report.get_summary()
    assert "rollback: ok=True (3/3)" in summary

    as_dict = report.to_dict()
    assert as_dict["rolled_back"] is True
    assert as_dict["rollback_ok"] is True
    assert len(as_dict["rollbacks"][host_key]) == 3

    # Проверяем Rich-таблицу с колонкой/секцией отката
    table = report.to_rich_table()
    assert table is not None


async def test_on_failure_local_handler_and_ignore_errors_semantics() -> None:
    """on_failure срабатывает на упавшей задаче; ignore_errors=True не запускает Saga-откат."""
    events: list[str] = []

    async def undo_prep(conn: Connection, ctx: FlowContext) -> None:
        events.append("undo_prep")

    async def diag_ignored(conn: Connection, ctx: FlowContext, error: str | None) -> None:
        events.append(f"on_failure_ignored:{error}:{ctx.outputs.get('prep')}")

    @task(name="prep", compensate=undo_prep)
    async def prep(conn: Connection) -> str:
        events.append("prep")
        return "prepared"

    @task(name="soft_fail", depends_on=[prep], ignore_errors=True, on_failure=diag_ignored)
    async def soft_fail(conn: Connection) -> str:
        events.append("soft_fail")
        raise ValueError("non-critical hiccup")

    @task(name="finish", depends_on=[soft_fail])
    async def finish(conn: Connection) -> str:
        events.append("finish")
        return "done"

    flow_soft = Flow("soft_fail_flow", tasks=[finish])
    async with Connection.from_uri("local://") as conn:
        rep_soft = await flow_soft.run(conn)

    assert rep_soft.ok is True
    assert rep_soft.rolled_back is False
    assert "undo_prep" not in events
    assert any(e.startswith("on_failure_ignored:") and "prepared" in e for e in events)
    assert "finish" in events

    # Теперь критическая ошибка + падающий on_failure НЕ должен ломать Saga-откат upstream-задач
    crit_events: list[str] = []

    async def undo_step1(conn: Connection, ctx: FlowContext) -> None:
        crit_events.append("undo_step1")

    async def crashing_on_failure(conn: Connection, ctx: FlowContext) -> None:
        crit_events.append("crashing_on_failure")
        raise RuntimeError("diagnostics failed too")

    @task(name="s1", compensate=undo_step1)
    async def s1(conn: Connection) -> str:
        crit_events.append("s1")
        return "ok"

    @task(name="s2", depends_on=[s1], on_failure=crashing_on_failure)
    async def s2(conn: Connection) -> str:
        crit_events.append("s2")
        raise RuntimeError("hard crash")

    flow_hard = Flow("hard_fail_flow", tasks=[s2])
    async with Connection.from_uri("local://") as conn:
        rep_hard = await flow_hard.run(conn)

    assert rep_hard.ok is False
    assert rep_hard.rolled_back is True
    assert rep_hard.rollback_ok is True
    assert crit_events == ["s1", "s2", "crashing_on_failure", "undo_step1"]


async def test_best_effort_rollback_continues_when_compensators_fail() -> None:
    """Ошибка или неуспешный Result/EnsureResult в compensate не прерывает откат остальных шагов."""
    order: list[str] = []

    async def undo_1(conn: Connection, ctx: FlowContext) -> Result:
        order.append("t1")
        return Result(command="undo1", exit_code=0, stdout="ok", stderr="", duration=0.01)

    async def undo_2(conn: Connection, ctx: FlowContext) -> None:
        order.append("t2")
        raise RuntimeError("t2 compensate exploded")

    async def undo_3(conn: Connection, ctx: FlowContext) -> Result:
        order.append("t3")
        return Result(command="undo3", exit_code=1, stdout="", stderr="undo3 failed", duration=0.01)

    async def undo_4(conn: Connection, ctx: FlowContext) -> EnsureResult:
        order.append("t4")
        return EnsureResult(
            target="cfg",
            state="present",
            changed=False,
            ok=False,
            details="ensure undo failed",
        )

    @task(name="t1", compensate=undo_1)
    async def t1(conn: Connection) -> str:
        return "1"

    @task(name="t2", depends_on=[t1], compensate=undo_2)
    async def t2(conn: Connection) -> str:
        return "2"

    @task(name="t3", depends_on=[t2], compensate=undo_3)
    async def t3(conn: Connection) -> str:
        return "3"

    @task(name="t4", depends_on=[t3], compensate=undo_4)
    async def t4(conn: Connection) -> str:
        return "4"

    @task(name="t5", depends_on=[t4])
    async def t5(conn: Connection) -> str:
        raise RuntimeError("t5 failed")

    flow = Flow("best_effort", tasks=[t5])
    async with Connection.from_uri("local://") as conn:
        report = await flow.run(conn)

    assert order == ["t4", "t3", "t2", "t1"]
    assert report.rolled_back is True
    assert report.rollback_ok is False

    host_key = next(iter(report.rollbacks))
    results = report.rollbacks[host_key]
    assert [(r.task_name, r.status) for r in results] == [
        ("t4", "failed"),
        ("t3", "failed"),
        ("t2", "failed"),
        ("t1", "success"),
    ]
    assert results[0].error == "ensure undo failed"
    assert results[1].error == "undo3 failed"
    assert results[2].error is not None and "t2 compensate exploded" in results[2].error
    assert results[3].error is None


async def test_rollback_on_failure_flag_and_runtime_override() -> None:
    """rollback_on_failure=False отключает Saga-откат, а runtime-аргумент run()/run_flow() переопределяет его."""
    undone: list[str] = []
    failed_hooks: list[str] = []

    @task(name="step_1", compensate=lambda conn, ctx: undone.append("step_1"))
    async def step_1(conn: Connection) -> str:
        return "v1"

    @task(name="step_2", depends_on=[step_1], on_failure=lambda conn, ctx: failed_hooks.append("step_2"))
    async def step_2(conn: Connection) -> str:
        raise RuntimeError("boom")

    flow_no_rb = Flow("no_rb", tasks=[step_2], rollback_on_failure=False)
    async with Connection.from_uri("local://") as conn:
        r1 = await flow_no_rb.run(conn)
        assert r1.rolled_back is False
        assert undone == []
        assert failed_hooks == ["step_2"]

        # Runtime override: включить откат
        r2 = await flow_no_rb.run(conn, rollback_on_failure=True)
        assert r2.rolled_back is True
        assert undone == ["step_1"]

        # Runtime override через conn.run_flow: выключить откат на Flow(rollback_on_failure=True)
        undone.clear()
        flow_with_rb = Flow("with_rb", tasks=[step_2], rollback_on_failure=True)
        r3 = await conn.run_flow(flow_with_rb, rollback_on_failure=False)
        assert r3.rolled_back is False
        assert undone == []


def test_sync_flow_and_sync_connection_and_sync_pool_saga_parity() -> None:
    """SyncFlow, SyncConnection.run_flow и SyncConnectionPool.run_flow поддерживают sync compensate и rollback_on_failure."""
    log: list[str] = []

    def sync_undo(conn: Any, ctx: FlowContext) -> str:
        host = conn.config.host or "local"
        log.append(f"undo:{host}:{ctx.outputs['step_1']}")
        return "restored"

    @task(name="step_1", compensate=sync_undo)
    def step_1(conn: Any) -> str:
        return f"data-{conn.config.host or 'local'}"

    @task(name="step_2", depends_on=[step_1])
    def step_2(conn: Any) -> str:
        raise RuntimeError("sync boom")

    sflow = SyncFlow(Flow("sync_saga", tasks=[step_2], rollback_on_failure=True))
    assert sflow.rollback_on_failure is True

    with SyncConnection.from_uri("local://") as sconn:
        rep = sflow.run(sconn)
        assert rep.ok is False
        assert rep.rolled_back is True
        assert rep.rollback_ok is True
        assert log == ["undo:localhost:data-localhost"]

        log.clear()
        rep_off = sconn.run_flow(sflow, rollback_on_failure=False)
        assert rep_off.rolled_back is False
        assert log == []

    log.clear()
    c1 = Connection.from_uri("local://").with_overrides(host="sync-01")
    c2 = Connection.from_uri("local://").with_overrides(host="sync-02")
    with SyncConnectionPool(ConnectionPool([c1, c2])) as spool:
        rep_pool = spool.run_flow(sflow, rollback_on_failure=True)
    assert rep_pool.rolled_back is True
    assert rep_pool.rollback_ok is True
    assert sorted(log) == ["undo:sync-01:data-sync-01", "undo:sync-02:data-sync-02"]


async def test_dry_run_and_plan_skip_rollback_and_describe_plan_shows_handlers() -> None:
    """В dry_run=True и flow.plan() compensate/on_failure не запускаются, но отображаются в describe_plan()."""
    calls: list[str] = []

    def my_compensator(conn: Connection, ctx: FlowContext) -> None:
        calls.append("compensate")

    def my_fail_hook(conn: Connection, ctx: FlowContext) -> None:
        calls.append("on_failure")

    @task(name="step_1", compensate=my_compensator)
    async def step_1(conn: Connection) -> str:
        return "ok"

    @task(name="step_2", depends_on=[step_1], on_failure=my_fail_hook)
    async def step_2(conn: Connection) -> str:
        raise RuntimeError("simulated error")

    flow = Flow("dry_saga", tasks=[step_2], rollback_on_failure=True)

    plan_text = flow.describe_plan(targets=["node-01"])
    assert "Rollback On Failure: True" in plan_text
    assert "compensate=my_compensator" in plan_text
    assert "on_failure=my_fail_hook" in plan_text

    tree = flow.to_rich_tree()
    assert tree is not None

    async with Connection.from_uri("local://", dry_run=True) as conn:
        rep_dry = await flow.run(conn)
        assert rep_dry.rolled_back is False
        assert calls == []

    async with Connection.from_uri("local://") as conn:
        rep_dry_kw = await flow.run(conn, dry_run=True)
        assert rep_dry_kw.rolled_back is False
        assert calls == []

        # flow.plan() использует dry_run и не запускает rollback/on_failure
        _ = await flow.plan(conn)
        assert calls == []


async def test_fleet_barrier_mode_reverse_layer_rollback_and_host_outputs_isolation() -> None:
    """В barrier-режиме откат идёт строго по обратным слоям по всему флоту с изоляцией ctx.outputs на хост."""
    events: list[tuple[str, str, str]] = []

    async def undo_l0(conn: Connection, ctx: FlowContext) -> None:
        host = conn.config.host or ""
        events.append(("undo_l0", host, str(ctx.outputs["l0"])))

    async def undo_l1(conn: Connection, ctx: FlowContext) -> None:
        host = conn.config.host or ""
        if host == "web-01":
            await asyncio.sleep(0.04)
        events.append(("undo_l1", host, str(ctx.outputs["l1"])))

    @task(name="l0", compensate=undo_l0)
    async def l0(conn: Connection) -> str:
        return f"db-{conn.config.host}"

    @task(name="l1", depends_on=[l0], compensate=undo_l1)
    async def l1(conn: Connection) -> str:
        return f"app-{conn.config.host}"

    @task(name="l2", depends_on=[l1])
    async def l2(conn: Connection) -> str:
        if conn.config.host == "web-02":
            raise RuntimeError("healthcheck failed on web-02")
        return "healthy"

    flow = Flow("barrier_saga", tasks=[l2], mode="barrier", rollback_on_failure=True)
    conns = [
        Connection.from_uri("local://").with_overrides(host="web-01"),
        Connection.from_uri("local://").with_overrides(host="web-02"),
    ]
    async with ConnectionPool(conns) as pool:
        report = await pool.run_flow(flow)

    assert report.ok is False
    assert report.rolled_back is True
    assert report.rollback_ok is True

    # Первые два события отката обязаны быть undo_l1 на обоих хостах, и только потом undo_l0!
    assert [e[0] for e in events] == ["undo_l1", "undo_l1", "undo_l0", "undo_l0"]
    # Проверяем изоляцию ctx.outputs между хостами
    for step, host, val in events:
        expected_prefix = "app-" if step == "undo_l1" else "db-"
        assert val == f"{expected_prefix}{host}"


async def test_fleet_barrier_batch_aborted_rolls_back_only_affected_batch() -> None:
    """При BatchAbortedError в barrier-режиме откатывается ТОЛЬКО затронутый батч, предыдущий остаётся нетронутым."""
    rolled_back_events: list[tuple[str, str]] = []

    async def undo_s1(conn: Connection, ctx: FlowContext) -> None:
        rolled_back_events.append(("s1", conn.config.host or ""))

    async def undo_s2(conn: Connection, ctx: FlowContext) -> None:
        rolled_back_events.append(("s2", conn.config.host or ""))

    @task(name="s1", compensate=undo_s1)
    async def s1(conn: Connection) -> str:
        return f"s1:{conn.config.host}"

    @task(name="s2", depends_on=[s1], compensate=undo_s2)
    async def s2(conn: Connection) -> str:
        if conn.config.host == "node-04":
            raise RuntimeError("node-04 failed at s2")
        return f"s2:{conn.config.host}"

    flow = Flow(
        "batch_barrier_saga",
        tasks=[s2],
        mode="barrier",
        batch_size=2,
        max_fail_ratio=0.0,
        rollback_on_failure=True,
    )
    conns = [
        Connection.from_uri("local://").with_overrides(host="node-01"),
        Connection.from_uri("local://").with_overrides(host="node-02"),
        Connection.from_uri("local://").with_overrides(host="node-03"),
        Connection.from_uri("local://").with_overrides(host="node-04"),
    ]
    async with ConnectionPool(conns) as pool:
        with pytest.raises(BatchAbortedError) as exc_info:
            await pool.run_flow(flow)

    err = exc_info.value
    assert err.batch_index == 1
    assert err.rolled_back is True
    assert err.rollback_ok is True
    assert set(err.rollbacks.keys()) == {"node-03", "node-04"}

    # Батч 0 (node-01, node-02) НЕ откатывался!
    hosts_rolled = {h for _, h in rolled_back_events}
    assert hosts_rolled == {"node-03", "node-04"}
    # В батче 1: s2 (успешная на node-03) откатывается строго раньше s1 (на node-03 и node-04)
    assert rolled_back_events[0] == ("s2", "node-03")
    assert set(rolled_back_events[1:]) == {("s1", "node-03"), ("s1", "node-04")}


async def test_fleet_independent_mode_single_host_and_batch_aborted_no_double_rollback() -> None:
    """В independent-режиме: одиночный сбой откатывает только упавший хост; BatchAborted откатывает весь батч без дублей."""
    rb_log: list[tuple[str, str]] = []

    async def undo_a(conn: Connection, ctx: FlowContext) -> None:
        rb_log.append(("a", conn.config.host or ""))

    async def undo_b(conn: Connection, ctx: FlowContext) -> None:
        rb_log.append(("b", conn.config.host or ""))

    @task(name="a", compensate=undo_a)
    async def a(conn: Connection) -> str:
        return "a"

    @task(name="b", depends_on=[a], compensate=undo_b)
    async def b(conn: Connection) -> str:
        if conn.config.host == "h2":
            raise RuntimeError("h2 boom")
        return "b"

    # Случай 1: без batch_size -> откатывается только h2
    flow_single = Flow("ind_single", tasks=[b], mode="independent")
    conns1 = [
        Connection.from_uri("local://").with_overrides(host="h1"),
        Connection.from_uri("local://").with_overrides(host="h2"),
    ]
    async with ConnectionPool(conns1) as pool:
        rep = await pool.run_flow(flow_single)
    assert rep.rolled_back is True
    assert rep.rollback_ok is True
    assert rb_log == [("a", "h2")]
    assert list(rep.rollbacks.keys()) == ["h2"]

    # Случай 2: batch_size=2, max_fail_ratio=0.0 -> Batch 0 (h0, h1) не тронут, Batch 1 (h2, h3) откачен ровно 1 раз
    rb_log.clear()
    flow_batch = Flow(
        "ind_batch",
        tasks=[b],
        mode="independent",
        batch_size=2,
        max_fail_ratio=0.0,
    )
    conns2 = [
        Connection.from_uri("local://").with_overrides(host="h0"),
        Connection.from_uri("local://").with_overrides(host="h1"),
        Connection.from_uri("local://").with_overrides(host="h2"),
        Connection.from_uri("local://").with_overrides(host="h3"),
    ]
    async with ConnectionPool(conns2) as pool:
        with pytest.raises(BatchAbortedError) as exc_info:
            await pool.run_flow(flow_batch)

    err = exc_info.value
    assert err.batch_index == 1
    assert err.rolled_back is True
    assert err.rollback_ok is True
    assert set(err.rollbacks.keys()) == {"h2", "h3"}
    # h0 и h1 не откатывались; h2 откатила a ровно один раз; h3 откатила b затем a
    assert ("a", "h0") not in rb_log
    assert ("a", "h1") not in rb_log
    assert rb_log.count(("a", "h2")) == 1
    h3_events = [step for step, h in rb_log if h == "h3"]
    assert h3_events == ["b", "a"]


def test_task_validation_rejects_non_callable_compensate_or_on_failure() -> None:
    """Передача не-callable в compensate или on_failure вызывает ConfigurationError."""
    with pytest.raises(ConfigurationError, match="compensate"):
        @task(compensate="not_a_callable")  # type: ignore[arg-type]
        async def bad_comp(conn: Connection) -> None:
            return None

    with pytest.raises(ConfigurationError, match="on_failure"):
        @task(on_failure=12345)  # type: ignore[arg-type]
        async def bad_fail(conn: Connection) -> None:
            return None


async def test_end_to_end_saga_with_ensure_file_backup_restores_original_file(tmp_path: Path) -> None:
    """Интеграция ensure_file(backup=True) + @task(compensate=...) восстанавливает конфиг из backup_path."""
    cfg_file = tmp_path / "app.conf"
    cfg_file.write_text("PORT=8080\nMODE=stable\n", encoding="utf-8")
    cfg_file.chmod(0o600)

    async def restore_cfg(conn: Connection, ctx: FlowContext) -> Result:
        ensure_res: EnsureResult = ctx.outputs["update_cfg"]
        assert ensure_res.backup_path is not None
        return await conn.run(f"mv -f {ensure_res.backup_path} {cfg_file}")

    @task(name="update_cfg", compensate=restore_cfg)
    async def update_cfg(conn: Connection) -> EnsureResult:
        return await conn.state.ensure_file(
            cfg_file,
            content="PORT=9090\nMODE=broken\n",
            backup=True,
        )

    @task(name="healthcheck", depends_on=[update_cfg])
    async def healthcheck(conn: Connection) -> None:
        raise RuntimeError("service failed to start with broken config")

    flow = Flow("safe_config_rollout", tasks=[healthcheck], rollback_on_failure=True)
    async with Connection.from_uri("local://") as conn:
        report = await flow.run(conn)

    assert report.ok is False
    assert report.rolled_back is True
    assert report.rollback_ok is True
    assert cfg_file.read_text(encoding="utf-8") == "PORT=8080\nMODE=stable\n"
    if sys.platform != "win32":
        assert (cfg_file.stat().st_mode & 0o777) == 0o600


async def test_single_param_extra_vars_binding_for_on_failure_and_compensate() -> None:
    """1-аргументные on_failure(error) и compensate(output) получают extra_vars, а не объект Connection."""
    captured_errors: list[Any] = []
    captured_outputs: list[Any] = []

    def handle_err(error: Any) -> None:
        captured_errors.append(error)

    def handle_undo(output: Any) -> None:
        captured_outputs.append(output)

    @task(name="produce", compensate=handle_undo)
    async def produce(conn: Connection) -> str:
        return "artifact-42"

    @task(name="explode", depends_on=[produce], on_failure=handle_err)
    async def explode(conn: Connection) -> None:
        raise RuntimeError("kaboom-99")

    flow = Flow("extra_vars_binding", tasks=[explode])
    async with Connection.from_uri("local://") as conn:
        report = await flow.run(conn)

    assert report.rolled_back is True
    assert captured_outputs == ["artifact-42"]
    assert len(captured_errors) == 1
    assert isinstance(captured_errors[0], RuntimeError)
    assert "kaboom-99" in str(captured_errors[0])


async def test_compensate_notify_handlers_execute_not_swallowed_by_aborted_batch(
    tmp_path: Path,
) -> None:
    """notify внутри compensate выполняется немедленно (а не поглощается отменённым NotificationBatch)."""
    cfg = tmp_path / "service.conf"
    cfg.write_text("v=1\n", encoding="utf-8")
    notify_calls: list[str] = []

    async def restore_with_notify(conn: Connection, ctx: FlowContext) -> EnsureResult:
        return await conn.state.ensure_file(
            cfg,
            content="v=1\n",
            notify=("reload_after_rollback", lambda _c: notify_calls.append("reloaded")),
        )

    @task(name="mutate", compensate=restore_with_notify)
    async def mutate(conn: Connection) -> EnsureResult:
        return await conn.state.ensure_file(
            cfg,
            content="v=2\n",
            notify=("reload_main", lambda _c: notify_calls.append("main_should_not_run")),
        )

    @task(name="fail_after", depends_on=[mutate])
    async def fail_after(conn: Connection) -> None:
        raise RuntimeError("post-deploy check failed")

    # 1. Одиночный хост (batch_notifications=True)
    flow_single = Flow("notify_in_comp_single", tasks=[fail_after], batch_notifications=True)
    async with Connection.from_uri("local://") as conn:
        rep = await flow_single.run(conn)
    assert rep.rolled_back is True
    assert rep.rollback_ok is True
    assert notify_calls == ["reloaded"]

    # 2. Барьерный флот (batch_notifications=True)
    notify_calls.clear()
    cfg_barrier = tmp_path / "barrier.conf"
    cfg_barrier.write_text("v=1\n", encoding="utf-8")

    async def restore_barrier(conn: Connection, ctx: FlowContext) -> EnsureResult:
        host = conn.config.host or ""
        return await conn.state.ensure_file(
            tmp_path / f"{host}.conf",
            content="v=1\n",
            notify=(f"reload_{host}", lambda _c, h=host: notify_calls.append(f"reloaded:{h}")),
        )

    @task(name="b_mutate", compensate=restore_barrier)
    async def b_mutate(conn: Connection) -> EnsureResult:
        host = conn.config.host or ""
        return await conn.state.ensure_file(
            tmp_path / f"{host}.conf",
            content="v=2\n",
            notify=(f"main_{host}", lambda _c: notify_calls.append("main_should_not_run")),
        )

    @task(name="b_fail", depends_on=[b_mutate])
    async def b_fail(conn: Connection) -> None:
        if conn.config.host == "b2":
            raise RuntimeError("b2 failed")

    flow_barrier = Flow(
        "notify_in_comp_barrier",
        tasks=[b_fail],
        mode="barrier",
        batch_notifications=True,
    )
    conns = [
        Connection.from_uri("local://").with_overrides(host="b1"),
        Connection.from_uri("local://").with_overrides(host="b2"),
    ]
    async with ConnectionPool(conns) as pool:
        rep_b = await pool.run_flow(flow_barrier)
    assert rep_b.rolled_back is True
    assert rep_b.rollback_ok is True
    assert sorted(notify_calls) == ["reloaded:b1", "reloaded:b2"]


async def test_barrier_dry_run_does_not_abort_healthy_hosts_for_rollback() -> None:
    """В barrier dry_run сбой на одном хосте не отменяет следующие слои на здоровых хостах."""
    ran_layer2: list[str] = []
    rolled_back: list[str] = []

    @task(name="l1", compensate=lambda conn, ctx: rolled_back.append(conn.config.host or ""))
    async def l1(conn: Connection) -> str:
        if conn.config.host == "bad-01":
            raise RuntimeError("bad host failed")
        return "ok"

    @task(name="l2", depends_on=[l1])
    async def l2(conn: Connection) -> str:
        ran_layer2.append(conn.config.host or "")
        return "l2-ok"

    flow = Flow("barrier_dry", tasks=[l2], mode="barrier", rollback_on_failure=True)
    assert "Rollback On Failure: True (skipped in dry_run)" in flow.describe_plan(dry_run=True)

    conns = [
        Connection.from_uri("local://").with_overrides(host="bad-01"),
        Connection.from_uri("local://").with_overrides(host="good-02"),
    ]
    async with ConnectionPool(conns) as pool:
        rep = await pool.run_flow(flow, dry_run=True)

    assert rep.rolled_back is False
    assert rolled_back == []
    assert ran_layer2 == ["good-02"]


async def test_barrier_early_layer_failure_does_not_flush_notify_on_last_layer(
    tmp_path: Path,
) -> None:
    """Сбой на Layer 0 в barrier-режиме не должен сбрасывать notify здорового хоста на Layer 1 до отката."""
    notify_calls: list[str] = []

    async def undo_l0(conn: Connection, ctx: FlowContext) -> EnsureResult:
        host = conn.config.host or ""
        return await conn.state.ensure_file(
            tmp_path / f"early_{host}.conf",
            content="v=1\n",
            notify=(f"undo_{host}", lambda _c, h=host: notify_calls.append(f"undid:{h}")),
        )

    @task(name="l0", compensate=undo_l0)
    async def l0(conn: Connection) -> EnsureResult:
        host = conn.config.host or ""
        if host == "b2":
            raise RuntimeError("b2 failed at layer 0")
        return await conn.state.ensure_file(
            tmp_path / f"early_{host}.conf",
            content="v=2\n",
            notify=(f"main_{host}", lambda _c: notify_calls.append("main_should_not_run")),
        )

    @task(name="l1", depends_on=[l0])
    async def l1(conn: Connection) -> str:
        return "l1-done"

    flow = Flow("barrier_early_fail", tasks=[l1], mode="barrier", batch_notifications=True)
    conns = [
        Connection.from_uri("local://").with_overrides(host="b1"),
        Connection.from_uri("local://").with_overrides(host="b2"),
    ]
    async with ConnectionPool(conns) as pool:
        rep = await pool.run_flow(flow)

    assert rep.ok is False
    assert rep.rolled_back is True
    assert rep.rollback_ok is True
    assert notify_calls == ["undid:b1"]


