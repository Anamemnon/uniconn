# tests/unit/services/test_fleet_plan.py
"""Unit-тесты цикла Plan -> Diff -> Apply (FleetChangePlan) и детектора дрейфа (StateDriftError)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from uniconn import (
    BatchAbortedError,
    Connection,
    ConnectionPool,
    SyncConnection,
    SyncConnectionPool,
)
from uniconn.orchestration import Flow, SyncFlow, task
from uniconn.services.provisioning import FleetChangePlan, PlannedChange, StateDriftError


def _named_local_conn(name: str) -> Connection:
    """Создать локальное подключение с уникальным host-именем для флотских тестов."""
    return Connection.local().copy(host=name)


# ---------------------------------------------------------------------------
# 1. Модель данных FleetChangePlan & PlannedChange
# ---------------------------------------------------------------------------


def test_fleet_change_plan_hash_determinism_serialization_and_rendering() -> None:
    """FleetChangePlan: детерминированный plan_hash, JSON round-trip, diff, summary и Rich Table."""
    ch_a = PlannedChange(
        host="web-01",
        task_name="configure_nginx",
        operation="ensure_file",
        target="/etc/nginx/nginx.conf",
        state="present",
        changed=True,
        actions=("write_content",),
        before_digest="sha256:aaa",
        unified_diff="--- /etc/nginx/nginx.conf\n+++ /etc/nginx/nginx.conf\n@@ -1 +1 @@\n-old\n+new\n",
        details="Would write /etc/nginx/nginx.conf",
    )
    ch_b = PlannedChange(
        host="web-02",
        task_name="configure_nginx",
        operation="ensure_file",
        target="/etc/nginx/nginx.conf",
        state="present",
        changed=False,
        actions=(),
        before_digest="sha256:bbb",
        unified_diff=None,
        details="Already up-to-date",
    )

    plan1 = FleetChangePlan(flow_name="deploy_web")
    plan1.record(ch_a)
    plan1.record(ch_b)

    # Обратный порядок регистрации хостов должен давать точно такой же plan_hash
    plan2 = FleetChangePlan(flow_name="deploy_web")
    plan2.record(ch_b)
    plan2.record(ch_a)

    assert plan1.plan_hash == plan2.plan_hash
    assert len(plan1.plan_hash) == 64
    assert plan1.total_changes == 2
    assert plan1.changed_count == 1
    assert plan1.has_changes is True
    assert plan1.has_drift is True
    assert plan1.ok is True
    assert plan1.changed_hosts == ["web-01"]
    assert plan1.unchanged_hosts == ["web-02"]
    assert plan1.failed_hosts == []
    assert ch_a.diff == ch_a.unified_diff

    # Diff & Summary & Rich Table
    diff_text = plan1.to_diff()
    assert "web-01" in diff_text
    assert "+new" in diff_text
    assert "web-02" not in diff_text
    summary = plan1.to_summary()
    assert "deploy_web" in summary
    assert "1" in summary
    table = plan1.to_rich_table()
    assert table.row_count == 2

    # JSON round-trip полностью сохраняет данные и plan_hash
    raw_json = plan1.to_json()
    restored = FleetChangePlan.from_json(raw_json)
    assert restored.plan_hash == plan1.plan_hash
    assert restored.flow_name == "deploy_web"
    assert restored.changed_count == 1
    assert restored.for_host("web-01")[0].before_digest == "sha256:aaa"


# ---------------------------------------------------------------------------
# 2. conn.state.plan() и conn.state.apply_plan()
# ---------------------------------------------------------------------------


async def test_connection_state_plan_and_apply_clean_lifecycle(tmp_path: Path) -> None:
    """conn.state.plan() снимает реальный unified diff без мутации, apply_plan() применяет и не дрейфует."""
    target_file = tmp_path / "app.conf"
    target_file.write_text("PORT=8080\n", encoding="utf-8", newline="\n")
    notified: list[str] = []

    async with Connection.local() as conn:
        async with conn.state.plan(flow_name="update_app_conf") as plan:
            res_plan = await conn.state.ensure_file(
                str(target_file),
                content="PORT=9090\n",
                notify=("reload", lambda: notified.append("reloaded")),
            )
            assert res_plan.dry_run is True
            assert res_plan.changed is True

        # Во время plan() файл НЕ был изменён и notify НЕ сработал
        assert target_file.read_text(encoding="utf-8") == "PORT=8080\n"
        assert notified == []
        assert plan.has_drift is True
        assert plan.changed_count == 1
        assert "-PORT=8080" in plan.to_diff()
        assert "+PORT=9090" in plan.to_diff()

        # Применение утверждённого плана
        async with conn.state.apply_plan(plan):
            res_apply = await conn.state.ensure_file(
                str(target_file),
                content="PORT=9090\n",
                notify=("reload", lambda: notified.append("reloaded")),
            )
            assert res_apply.dry_run is False
            assert res_apply.changed is True

        assert target_file.read_text(encoding="utf-8") == "PORT=9090\n"
        assert notified == ["reloaded"]

        # Повторное планирование показывает отсутствие дрейфа
        async with conn.state.plan(flow_name="check_converged") as plan_after:
            await conn.state.ensure_file(str(target_file), content="PORT=9090\n")
        assert plan_after.has_drift is False
        assert plan_after.changed_count == 0


async def test_connection_state_apply_plan_detects_external_drift_before_mutation(
    tmp_path: Path,
) -> None:
    """Если файл изменили вручную между plan() и apply_plan(), StateDriftError падает ДО записи."""
    target_file = tmp_path / "nginx.conf"
    target_file.write_text("worker_processes 2;\n", encoding="utf-8", newline="\n")

    async with Connection.local() as conn:
        async with conn.state.plan() as plan:
            await conn.state.ensure_file(str(target_file), content="worker_processes 4;\n")

        # Внешний дрейф: оператор вручную отредактировал файл
        target_file.write_text("worker_processes 8; # hotfix\n", encoding="utf-8", newline="\n")

        with pytest.raises(StateDriftError) as exc_info:
            async with conn.state.apply_plan(plan):
                await conn.state.ensure_file(str(target_file), content="worker_processes 4;\n")

        err = exc_info.value
        assert err.reason == "digest_mismatch"
        assert err.target == str(target_file)
        assert err.expected_digest != err.actual_digest
        # Критично: файл остался в состоянии hotfix — apply НЕ перезаписал его!
        assert target_file.read_text(encoding="utf-8") == "worker_processes 8; # hotfix\n"


async def test_connection_state_apply_plan_strict_vs_non_strict_unexpected_resource(
    tmp_path: Path,
) -> None:
    """Незапланированный ensure_* вызывает StateDriftError при strict=True и разрешается при strict=False."""
    planned_file = tmp_path / "planned.txt"
    extra_file = tmp_path / "extra.txt"

    async with Connection.local() as conn:
        async with conn.state.plan() as plan:
            await conn.state.ensure_file(str(planned_file), content="planned\n")

        # strict=True (по умолчанию) -> StateDriftError(reason="unexpected_resource")
        with pytest.raises(StateDriftError) as exc_info:
            async with conn.state.apply_plan(plan, strict=True):
                await conn.state.ensure_file(str(planned_file), content="planned\n")
                await conn.state.ensure_file(str(extra_file), content="surprise\n")

        assert exc_info.value.reason == "unexpected_resource"
        assert exc_info.value.target == str(extra_file)
        assert not extra_file.exists()

        # Пересоздаём чистый план и применяем с strict=False
        planned_file.unlink()
        async with conn.state.plan() as plan2:
            await conn.state.ensure_file(str(planned_file), content="planned\n")

        async with conn.state.apply_plan(plan2, strict=False):
            await conn.state.ensure_file(str(planned_file), content="planned\n")
            await conn.state.ensure_file(str(extra_file), content="allowed\n")

        assert planned_file.read_text(encoding="utf-8") == "planned\n"
        assert extra_file.read_text(encoding="utf-8") == "allowed\n"


async def test_sequential_same_file_mutations_do_not_false_positive_as_drift(
    tmp_path: Path,
) -> None:
    """Последовательные мутации одного файла внутри одного плана не считаются внешним дрейфом."""
    hosts_file = tmp_path / "hosts.conf"
    hosts_file.write_text("127.0.0.1 localhost\n", encoding="utf-8", newline="\n")

    async with Connection.local() as conn:
        async with conn.state.plan() as plan:
            await conn.state.ensure_line(str(hosts_file), "10.0.0.1 db-01")
            await conn.state.ensure_line(str(hosts_file), "10.0.0.2 cache-01")

        assert len(plan.for_host("localhost")) == 2

        async with conn.state.apply_plan(plan):
            await conn.state.ensure_line(str(hosts_file), "10.0.0.1 db-01")
            await conn.state.ensure_line(str(hosts_file), "10.0.0.2 cache-01")

        content = hosts_file.read_text(encoding="utf-8")
        assert "10.0.0.1 db-01" in content
        assert "10.0.0.2 cache-01" in content


async def test_composite_primitive_records_single_top_level_planned_change(
    tmp_path: Path,
) -> None:
    """Составной примитив ensure_systemd_unit записывается как один PlannedChange без дублирования."""
    unit_dir = tmp_path / "systemd_units"
    unit_content = "[Unit]\nDescription=Demo App\n\n[Service]\nExecStart=/bin/true\n"

    async with Connection.local() as conn:
        async with conn.state.plan() as plan:
            res = await conn.state.ensure_systemd_unit(
                "demo-app.service",
                content=unit_content,
                state="present",
                unit_dir=str(unit_dir),
                daemon_reload=False,
                sudo=False,
            )
            assert res.dry_run is True
            assert res.changed is True

        changes = plan.for_host("localhost")
        assert len(changes) == 1
        assert changes[0].operation == "ensure_systemd_unit"
        assert not (unit_dir / "demo-app.service").exists()

        async with conn.state.apply_plan(plan):
            res_apply = await conn.state.ensure_systemd_unit(
                "demo-app.service",
                content=unit_content,
                state="present",
                unit_dir=str(unit_dir),
                daemon_reload=False,
                sudo=False,
            )
            assert res_apply.changed is True

        assert (unit_dir / "demo-app.service").read_text(encoding="utf-8") == unit_content


# ---------------------------------------------------------------------------
# 3. pool.state.plan() / apply_plan() и Flow.plan() / Flow.run(expected_plan=...)
# ---------------------------------------------------------------------------


async def test_pool_state_plan_and_apply_across_multiple_hosts(tmp_path: Path) -> None:
    """pool.state.plan() и pool.state.apply_plan() агрегируют и проверяют изменения по всему пулу."""
    file_1 = tmp_path / "shared_pool.conf"
    c1 = _named_local_conn("node-01")
    c2 = _named_local_conn("node-02")

    async with ConnectionPool([c1, c2]) as pool:
        async with pool.state.plan(flow_name="pool_cfg") as plan:
            await pool.state.ensure_file(str(file_1), content="CLUSTER=prod\n")

        assert set(plan.hosts) == {"node-01", "node-02"}
        assert plan.changed_count == 2
        assert not file_1.exists()

        # Проверяем на двух отдельных файлах (чтобы избежать гонки на одном локальном файле при apply)
    f1 = tmp_path / "node-01.conf"
    f2 = tmp_path / "node-02.conf"

    @task(name="write_node_cfg")
    async def write_node_cfg(conn: Connection, host: str) -> Any:
        target = f1 if host == "node-01" else f2
        return await conn.state.ensure_file(str(target), content=f"NODE={host}\n")

    flow = Flow(name="pool_node_cfg", tasks=[write_node_cfg])
    async with ConnectionPool([_named_local_conn("node-01"), _named_local_conn("node-02")]) as pool:
        plan = await flow.plan(pool)
        assert set(plan.changed_hosts) == {"node-01", "node-02"}
        assert not f1.exists() and not f2.exists()

        report = await flow.run(pool, expected_plan=plan)
        assert report.ok is True
        assert f1.read_text(encoding="utf-8") == "NODE=node-01\n"
        assert f2.read_text(encoding="utf-8") == "NODE=node-02\n"


async def test_flow_drift_does_not_retry_and_respects_fail_fast_and_max_fail_ratio(
    tmp_path: Path,
) -> None:
    """StateDriftError в Flow: 0 повторов при retries=3, fail_fast на затронутом хосте, max_fail_ratio на флоте."""
    f1 = tmp_path / "web1.conf"
    f2 = tmp_path / "web2.conf"
    f1.write_text("V=1\n", encoding="utf-8", newline="\n")
    f2.write_text("V=1\n", encoding="utf-8", newline="\n")

    attempts_by_host: dict[str, int] = {"web-01": 0, "web-02": 0}
    downstream_hosts: list[str] = []

    @task(name="apply_cfg", retries=3, retry_delay=0.01)
    async def apply_cfg(conn: Connection, host: str) -> Any:
        attempts_by_host[host] += 1
        target = f1 if host == "web-01" else f2
        return await conn.state.ensure_file(str(target), content="V=2\n")

    @task(name="post_step", depends_on=[apply_cfg])
    async def post_step(conn: Connection, host: str) -> str:
        downstream_hosts.append(host)
        return "done"

    # 1. Режим independent с max_fail_ratio=0.5: web-01 падает с дрейфом (1 попытка), web-02 успешно завершается
    flow_ind = Flow(
        name="drift_independent",
        tasks=[post_step],
        mode="independent",
        fail_fast=True,
        max_fail_ratio=0.5,
    )
    async with ConnectionPool([_named_local_conn("web-01"), _named_local_conn("web-02")]) as pool:
        plan = await flow_ind.plan(pool)
        assert plan.changed_count == 2
        attempts_by_host["web-01"] = 0
        attempts_by_host["web-02"] = 0
        downstream_hosts.clear()

        # Внешний дрейф только на web-01
        f1.write_text("V=HOTFIX\n", encoding="utf-8", newline="\n")

        report = await flow_ind.run(pool, expected_plan=plan)
        assert report.ok is False
        # StateDriftError не ретраится, несмотря на retries=3!
        assert attempts_by_host["web-01"] == 1
        assert attempts_by_host["web-02"] == 1
        # На web-01 downstream-задача пропущена (fail_fast), на web-02 выполнена
        assert downstream_hosts == ["web-02"]
        assert f1.read_text(encoding="utf-8") == "V=HOTFIX\n"
        assert f2.read_text(encoding="utf-8") == "V=2\n"

        w1_apply = next(r for r in report.for_host("web-01") if r.task_name == "apply_cfg")
        assert w1_apply.status == "failed"
        assert isinstance(w1_apply.exception, StateDriftError)
        assert w1_apply.attempts == 1

    # 2. Батчевая раскатка с batch_size=1 и max_fail_ratio=0.0 -> BatchAbortedError после падения первого батча
    f1.write_text("V=1\n", encoding="utf-8", newline="\n")
    f2.write_text("V=1\n", encoding="utf-8", newline="\n")
    flow_batch = Flow(
        name="drift_batch",
        tasks=[apply_cfg],
        mode="barrier",
        batch_size=1,
        max_fail_ratio=0.0,
    )
    async with ConnectionPool([_named_local_conn("web-01"), _named_local_conn("web-02")]) as pool:
        plan_b = await flow_batch.plan(pool)
        f1.write_text("V=MANUAL\n", encoding="utf-8", newline="\n")

        with pytest.raises(BatchAbortedError):
            await flow_batch.run(pool, expected_plan=plan_b)

        # Второй хост (второй батч) даже не был затронут!
        assert f2.read_text(encoding="utf-8") == "V=1\n"


async def test_flow_plan_records_host_errors_when_task_fails() -> None:
    """Если задача падает во время flow.plan(), ошибка попадает в plan.errors и plan.ok == False."""

    @task(name="broken_preflight")
    async def broken_preflight(conn: Connection) -> None:
        raise RuntimeError("inventory unreachable")

    flow = Flow(name="broken_flow", tasks=[broken_preflight])
    async with Connection.local() as conn:
        plan = await flow.plan(conn)

    assert plan.ok is False
    assert plan.failed_hosts == ["localhost"]
    assert "inventory unreachable" in plan.host_errors["localhost"]


# ---------------------------------------------------------------------------
# 4. Полный Sync-паритет: SyncConnection, SyncConnectionPool, SyncFlow
# ---------------------------------------------------------------------------


def test_sync_parity_connection_pool_and_flow_plan_apply(tmp_path: Path) -> None:
    """Синхронные фасады SyncConnection.state, SyncConnectionPool.state и SyncFlow поддерживают plan/apply."""
    f_conn = tmp_path / "sync_conn.conf"
    f_flow = tmp_path / "sync_flow.conf"

    with SyncConnection.local() as sconn:
        with sconn.state.plan(flow_name="sync_direct") as plan:
            res = sconn.state.ensure_file(str(f_conn), content="MODE=sync\n")
            assert res.dry_run is True
        assert plan.has_drift is True
        assert not f_conn.exists()

        with sconn.state.apply_plan(plan):
            res_apply = sconn.state.ensure_file(str(f_conn), content="MODE=sync\n")
            assert res_apply.changed is True
        assert f_conn.read_text(encoding="utf-8") == "MODE=sync\n"

    # SyncFlow.plan() & SyncFlow.run(expected_plan=...)
    @task(name="write_sync_flow")
    async def write_sync_flow(conn: Connection) -> Any:
        return await conn.state.ensure_file(str(f_flow), content="SYNC_FLOW=1\n")

    sflow = SyncFlow(Flow(name="sync_flow_demo", tasks=[write_sync_flow]))
    with SyncConnection.local() as sconn:
        fplan = sflow.plan(sconn)
        assert fplan.has_drift is True
        assert not f_flow.exists()

        report = sflow.run(sconn, expected_plan=fplan)
        assert report.ok is True
        assert f_flow.read_text(encoding="utf-8") == "SYNC_FLOW=1\n"

    # SyncConnectionPool.state.plan() / apply_plan()
    f_pool = tmp_path / "sync_pool.conf"
    with ConnectionPool(["local://"]).to_sync() as spool:
        assert isinstance(spool, SyncConnectionPool)
        with spool.state.plan(flow_name="sync_pool_plan") as pplan:
            spool.state.ensure_file(str(f_pool), content="POOL_SYNC=ok\n")
        assert pplan.has_drift is True
        with spool.state.apply_plan(pplan):
            spool.state.ensure_file(str(f_pool), content="POOL_SYNC=ok\n")
        assert f_pool.read_text(encoding="utf-8") == "POOL_SYNC=ok\n"


# ---------------------------------------------------------------------------
# 5. Регрессионные тесты (notify-обработчики, plan_failed, peek-before-pop, коллизии хостов)
# ---------------------------------------------------------------------------


async def test_apply_plan_strict_allows_ensure_inside_inline_and_batched_notify(
    tmp_path: Path,
) -> None:
    """ensure_* внутри notify-обработчиков (inline и batch_notifications) не роняют strict apply_plan."""
    cfg_file = tmp_path / "service.conf"
    marker_inline = tmp_path / "notified_inline.flag"
    marker_batched = tmp_path / "notified_batched.flag"
    cfg_file.write_text("STATE=v1\n", encoding="utf-8", newline="\n")

    async with Connection.local() as conn:
        async def _write_inline_marker() -> Any:
            return await conn.state.ensure_file(str(marker_inline), content="reloaded=inline\n")

        async def _write_batched_marker() -> Any:
            return await conn.state.ensure_file(str(marker_batched), content="reloaded=batched\n")

        # 1. Inline notify handler
        async with conn.state.plan(flow_name="inline_notify_plan") as plan_inline:
            await conn.state.ensure_file(
                str(cfg_file),
                content="STATE=v2\n",
                notify=("mark_inline", _write_inline_marker),
            )
        assert not marker_inline.exists()
        assert len(plan_inline.for_host("localhost")) == 1

        async with conn.state.apply_plan(plan_inline, strict=True):
            await conn.state.ensure_file(
                str(cfg_file),
                content="STATE=v2\n",
                notify=("mark_inline", _write_inline_marker),
            )
        assert cfg_file.read_text(encoding="utf-8") == "STATE=v2\n"
        assert marker_inline.read_text(encoding="utf-8") == "reloaded=inline\n"

        # 2. Batched notify handler (NotificationBatch.flush)
        async with conn.state.plan(flow_name="batched_notify_plan") as plan_batched:
            async with conn.state.batch_notifications():
                await conn.state.ensure_file(
                    str(cfg_file),
                    content="STATE=v3\n",
                    notify=("mark_batched", _write_batched_marker),
                )
        assert not marker_batched.exists()

        async with conn.state.apply_plan(plan_batched, strict=True):
            async with conn.state.batch_notifications():
                await conn.state.ensure_file(
                    str(cfg_file),
                    content="STATE=v3\n",
                    notify=("mark_batched", _write_batched_marker),
                )
        assert cfg_file.read_text(encoding="utf-8") == "STATE=v3\n"
        assert marker_batched.read_text(encoding="utf-8") == "reloaded=batched\n"


async def test_apply_plan_rejects_hosts_with_plan_errors_or_failed_changes(
    tmp_path: Path,
) -> None:
    """PlanApplier блокирует мутацию с reason='plan_failed', если план хоста завершился с ошибкой."""
    target_file = tmp_path / "protected.conf"
    target_file.write_text("SAFE=1\n", encoding="utf-8", newline="\n")

    # Случай 1: host_errors зафиксирован на хосте
    plan_with_host_error = FleetChangePlan(flow_name="broken_host_plan")
    plan_with_host_error.record_host_error("localhost", "preflight failed")

    async with Connection.local() as conn:
        with pytest.raises(StateDriftError) as exc_host:
            async with conn.state.apply_plan(plan_with_host_error, strict=True):
                await conn.state.ensure_file(str(target_file), content="MUTATED=1\n")
        assert exc_host.value.reason == "plan_failed"
        assert target_file.read_text(encoding="utf-8") == "SAFE=1\n"

        # Случай 2: PlannedChange имеет ok=False
        plan_with_failed_change = FleetChangePlan(flow_name="failed_change_plan")
        plan_with_failed_change.record(
            PlannedChange(
                host="localhost",
                operation="ensure_file",
                target=str(target_file),
                state="present",
                changed=False,
                ok=False,
                details="Permission denied during plan",
            )
        )
        with pytest.raises(StateDriftError) as exc_change:
            async with conn.state.apply_plan(plan_with_failed_change, strict=True):
                await conn.state.ensure_file(str(target_file), content="MUTATED=2\n")
        assert exc_change.value.reason == "plan_failed"
        assert target_file.read_text(encoding="utf-8") == "SAFE=1\n"


async def test_plan_applier_preserves_remaining_count_on_digest_mismatch(
    tmp_path: Path,
) -> None:
    """При StateDriftError запись не вынимается из очереди: remaining_count и verified_count остаются точными."""
    target_file = tmp_path / "atomic_peek.conf"
    target_file.write_text("REV=1\n", encoding="utf-8", newline="\n")

    async with Connection.local() as conn:
        async with conn.state.plan() as plan:
            await conn.state.ensure_file(str(target_file), content="REV=2\n")

        target_file.write_text("REV=DRIFT\n", encoding="utf-8", newline="\n")

        applier_ctx = conn.state.apply_plan(plan, strict=True)
        async with applier_ctx as applier:
            assert applier.remaining_count == 1
            assert applier.verified_count == 0
            with pytest.raises(StateDriftError) as exc_info:
                await conn.state.ensure_file(str(target_file), content="REV=2\n")
            assert exc_info.value.reason == "digest_mismatch"
            assert applier.remaining_count == 1
            assert applier.verified_count == 0


async def test_fleet_change_plan_short_host_resolution_avoids_multi_port_collision(
    tmp_path: Path,
) -> None:
    """Неоднозначное короткое имя (один IP, разные порты) не вызывает ложного совпадения хостов."""
    target_file = tmp_path / "app.conf"
    target_file.write_text("PORT=1\n", encoding="utf-8", newline="\n")

    plan = FleetChangePlan(flow_name="multi_port")
    plan.record(
        PlannedChange(
            host="ssh://10.0.0.1:2222",
            operation="ensure_file",
            target=str(target_file),
            state="present",
            changed=True,
            before_digest="sha256:111",
        )
    )
    plan.record(
        PlannedChange(
            host="ssh://10.0.0.1:2223",
            operation="ensure_file",
            target=str(target_file),
            state="present",
            changed=True,
            before_digest="sha256:222",
        )
    )
    plan.record(
        PlannedChange(
            host="ssh://10.0.0.2:22",
            operation="ensure_file",
            target=str(target_file),
            state="present",
            changed=True,
            before_digest="sha256:333",
        )
    )

    # Неоднозначный short-name 10.0.0.1 не должен молча возвращать первый попавшийся порт
    assert plan.for_host("10.0.0.1") == []
    assert len(plan.for_host("ssh://10.0.0.1:2222")) == 1
    assert len(plan.for_host("ssh://10.0.0.1:2223")) == 1
    # Однозначный short-name 10.0.0.2 по-прежнему работает
    assert len(plan.for_host("10.0.0.2")) == 1

    # Незапланированный порт 2224 на том же IP должен падать с plan_host_missing
    async with _named_local_conn("ssh://10.0.0.1:2224") as conn:
        with pytest.raises(StateDriftError) as exc_info:
            async with conn.state.apply_plan(plan, strict=True):
                await conn.state.ensure_file(str(target_file), content="PORT=2\n")
        assert exc_info.value.reason == "plan_host_missing"
        assert target_file.read_text(encoding="utf-8") == "PORT=1\n"


async def test_single_host_plan_rejects_different_explicit_port_and_raw_host_errors(
    tmp_path: Path,
) -> None:
    """Однохостовый план не матчится с другим явным портом, а host_errors блокирует даже при strict=False."""
    target_file = tmp_path / "single.conf"
    target_file.write_text("SAFE=1\n", encoding="utf-8", newline="\n")

    single_port_plan = FleetChangePlan(flow_name="single_port")
    single_port_plan.record(
        PlannedChange(
            host="ssh://10.0.0.1:2222",
            operation="ensure_file",
            target=str(target_file),
            state="present",
            changed=True,
            before_digest="sha256:111",
        )
    )
    assert len(single_port_plan.for_host("10.0.0.1")) == 1
    assert single_port_plan.for_host("ssh://10.0.0.1:2224") == []

    async with _named_local_conn("ssh://10.0.0.1:2224") as wrong_port_conn:
        with pytest.raises(StateDriftError) as exc_port:
            async with wrong_port_conn.state.apply_plan(single_port_plan, strict=True):
                await wrong_port_conn.state.ensure_file(str(target_file), content="BAD=1\n")
        assert exc_port.value.reason == "plan_host_missing"
        assert target_file.read_text(encoding="utf-8") == "SAFE=1\n"

    # План, сконструированный напрямую с host_errors без register_host(), должен падать с plan_failed при strict=False
    raw_err_plan = FleetChangePlan(
        flow_name="raw_err",
        host_errors={"localhost": "connection refused"},
    )
    async with Connection.local() as conn:
        with pytest.raises(StateDriftError) as exc_err:
            async with conn.state.apply_plan(raw_err_plan, strict=False):
                await conn.state.ensure_file(str(target_file), content="BAD=2\n")
        assert exc_err.value.reason == "plan_failed"
        assert target_file.read_text(encoding="utf-8") == "SAFE=1\n"


def test_compute_before_digest_includes_actions_and_to_summary_marks_failed_items() -> None:
    """before_digest учитывает actions (для не-файловых ensure_*), а to_summary помечает ok=False как FAILED."""
    from uniconn.services.provisioning._fleet_plan import compute_before_digest

    d1 = compute_before_digest(
        operation="ensure_service",
        target="nginx",
        state="started",
        changed=True,
        ok=True,
        diff=None,
        actions=("start nginx", "enable nginx"),
        snapshot=None,
    )
    d2 = compute_before_digest(
        operation="ensure_service",
        target="nginx",
        state="started",
        changed=True,
        ok=True,
        diff=None,
        actions=("enable nginx",),
        snapshot=None,
    )
    assert d1 != d2

    plan = FleetChangePlan(flow_name="failed_item_summary")
    plan.record(
        PlannedChange(
            host="web-01",
            operation="ensure_file",
            target="/etc/secret.conf",
            state="present",
            changed=False,
            ok=False,
            details="Permission denied",
        )
    )
    summary = plan.to_summary()
    assert "[FAILED] web-01" in summary
    assert "Permission denied" in summary
    assert "[OK]" not in summary


