# tests/unit/orchestration/test_fleet_and_sync_flow.py
"""Unit-тесты флотского исполнения (Barrier / Independent), SyncFlow и фильтрации hosts/tags."""

from __future__ import annotations

import asyncio

import pytest

from uniconn import (
    BatchAbortedError,
    Connection,
    ConnectionPool,
    Flow,
    FlowContext,
    SyncConnection,
    task,
)


async def test_fleet_barrier_mode_synchronizes_layers_across_hosts() -> None:
    """В режиме mode='barrier' ни один хост не начинает Слой 2, пока все хосты не завершат Слой 1."""
    events: list[tuple[str, str]] = []

    @task
    async def step_1(conn: Connection) -> str:
        if "slow" in (conn.config.host or ""):
            await asyncio.sleep(0.04)
        events.append(("step_1", conn.config.host or ""))
        return "s1"

    @task(depends_on=[step_1])
    async def step_2(conn: Connection) -> str:
        events.append(("step_2", conn.config.host or ""))
        return "s2"

    flow = Flow("barrier_test", tasks=[step_2], mode="barrier")
    conns = [
        Connection.from_uri("local://").with_overrides(host="fast-01"),
        Connection.from_uri("local://").with_overrides(host="slow-02"),
    ]
    async with ConnectionPool(conns) as pool:
        report = await pool.run_flow(flow)

    assert report.ok is True
    assert report.mode == "barrier"
    # Первые два события должны быть step_1 на обоих хостах, и только потом step_2
    assert [e[0] for e in events] == ["step_1", "step_1", "step_2", "step_2"]


async def test_fleet_independent_mode_allows_fast_host_to_finish_ahead() -> None:
    """В режиме mode='independent' быстрый хост проходит весь граф, не дожидаясь медленного."""
    events: list[tuple[str, str]] = []

    @task
    async def step_1(conn: Connection) -> str:
        if conn.config.host == "slow-02":
            await asyncio.sleep(0.06)
        events.append(("step_1", conn.config.host or ""))
        return "s1"

    @task(depends_on=[step_1])
    async def step_2(conn: Connection) -> str:
        events.append(("step_2", conn.config.host or ""))
        return "s2"

    flow = Flow("independent_test", tasks=[step_2], mode="independent")
    conns = [
        Connection.from_uri("local://").with_overrides(host="fast-01"),
        Connection.from_uri("local://").with_overrides(host="slow-02"),
    ]
    async with ConnectionPool(conns) as pool:
        report = await pool.run_flow(flow)

    assert report.ok is True
    assert report.mode == "independent"
    # fast-01 завершает и step_1, и step_2 раньше, чем slow-02 завершит step_1
    fast_step2_idx = events.index(("step_2", "fast-01"))
    slow_step1_idx = events.index(("step_1", "slow-02"))
    assert fast_step2_idx < slow_step1_idx


async def test_fleet_barrier_batch_size_and_max_fail_ratio_raises_batch_aborted() -> None:
    """При превышении max_fail_ratio в батче выбрасывается BatchAbortedError с частичными результатами."""
    visited_hosts: list[str] = []

    @task
    async def deploy_step(conn: Connection) -> str:
        h = conn.config.host or ""
        visited_hosts.append(h)
        if h == "node-02":
            raise RuntimeError("deploy crashed on node-02")
        return "ok"

    flow = Flow(
        "rollout_abort",
        tasks=[deploy_step],
        mode="barrier",
        batch_size=2,
        max_fail_ratio=0.0,
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
    assert err.batch_index == 0
    assert err.fail_ratio == 0.5
    assert "node-02" in err.failed_hosts
    # Второй батч (node-03, node-04) не должен был запускаться!
    assert "node-03" not in visited_hosts
    assert "node-04" not in visited_hosts
    # Стек батчей уведомлений на активных соединениях пула обязан быть чистым после прерывания
    for c in conns:
        assert c.state._current_batch() is None


async def test_host_and_tag_filtering_in_fleet_flow() -> None:
    """Селектор hosts у @task и фильтр tags в run_flow пропускают нерелевантные шаги и включают post-задачи."""

    @task(tags=["common"])
    async def base_setup(conn: Connection) -> str:
        return "base"

    @task
    async def verify_migration(conn: Connection) -> str:
        return "verified"

    @task(depends_on=[base_setup], post=[verify_migration], hosts=["db-01"], tags=["db"])
    async def migrate_db(conn: Connection) -> str:
        return "migrated"

    @task(depends_on=[base_setup], tags=["monitoring"])
    async def install_agent(conn: Connection) -> str:
        return "agent"

    flow = Flow("filtered_flow", tasks=[migrate_db, install_agent])
    conns = [
        Connection.from_uri("local://").with_overrides(host="db-01"),
        Connection.from_uri("local://").with_overrides(host="web-01"),
    ]
    async with ConnectionPool(conns) as pool:
        # Запускаем только тег "db" (он транзитивно подтянет base_setup и post-задачу verify_migration)
        report = await pool.run_flow(flow, tags=["db"])

    assert report.ok is True
    db_res = {r.task_name: r for r in report.for_host("db-01")}
    web_res = {r.task_name: r for r in report.for_host("web-01")}

    assert db_res["base_setup"].status == "success"
    assert db_res["migrate_db"].status == "success"
    assert db_res["verify_migration"].status == "success"
    assert db_res["install_agent"].status == "skipped"
    assert db_res["install_agent"].skip_reason == "tag_filtered"

    assert web_res["base_setup"].status == "success"
    assert web_res["migrate_db"].status == "skipped"
    assert web_res["migrate_db"].skip_reason == "host_filtered"


def test_sync_flow_and_sync_connection_parity_without_deadlock() -> None:
    """SyncFlow, sync_conn.run_flow и sync_pool.run_flow работают с sync (в т.ч. без аннотаций) и async задачами."""

    @task
    def untyped_sync_task(conn, ctx: FlowContext) -> str:
        # Вызов нескольких синхронных команд подряд без аннотации SyncConnection
        r1 = conn.run("echo part1")
        r2 = conn.run("echo part2")
        combined = f"{r1.text}_{r2.text}"
        ctx.host_set(conn, "greeting", combined)
        return combined

    @task(depends_on=[untyped_sync_task])
    async def async_task(conn: Connection, ctx: FlowContext) -> str:
        prev = ctx.host_get(conn, "greeting")
        res = await conn.run(f"echo {prev}_world")
        return res.text

    flow = Flow("hybrid_sync_async", tasks=[async_task])
    sync_flow = flow.to_sync()

    with SyncConnection.local() as sync_conn:
        report1 = sync_conn.run_flow(flow)
        assert report1.ok is True
        by_name = {r.task_name: r for r in report1.for_host("localhost")}
        assert by_name["untyped_sync_task"].return_value == "part1_part2"
        assert by_name["async_task"].return_value == "part1_part2_world"

        report2 = sync_flow.run(sync_conn)
        assert report2.ok is True

    conns = [
        Connection.from_uri("local://").with_overrides(host="s1"),
        Connection.from_uri("local://").with_overrides(host="s2"),
    ]
    with ConnectionPool(conns).to_sync() as sync_pool:
        pool_report = sync_pool.run_flow(sync_flow)
        assert pool_report.ok is True
        assert set(pool_report.results.keys()) == {"s1", "s2"}


async def test_fleet_barrier_layer_failure_ratio_ignores_prior_layer_ignored_errors() -> None:
    """В режиме barrier с ignore_errors=True ошибка в Слое 0 не должна считаться падением в Слое 1."""

    @task(ignore_errors=True)
    async def layer_0_optional(conn: Connection) -> str:
        if conn.config.host == "node-01":
            raise RuntimeError("non-fatal error in layer 0")
        return "ok"

    @task(depends_on=[layer_0_optional])
    async def layer_1_healthy(conn: Connection) -> str:
        _ = conn
        return "layer_1_ok"

    flow = Flow(
        "barrier_ignored_layer0",
        tasks=[layer_1_healthy],
        mode="barrier",
        batch_size=2,
        max_fail_ratio=0.5,
    )
    conns = [
        Connection.from_uri("local://").with_overrides(host="node-01"),
        Connection.from_uri("local://").with_overrides(host="node-02"),
    ]
    async with ConnectionPool(conns) as pool:
        report = await pool.run_flow(flow)

    assert len(report.for_host("node-01")) == 2
    assert report.for_host("node-01")[1].status == "success"

