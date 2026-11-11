# tests/unit/mcp/test_mcp_flow_tools.py
"""Unit-тесты динамического экспорта сценариев Flow-as-Tool для MCP (Вектор 4.3)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal

import pytest
from pydantic import BaseModel, Field

from uniconn import (
    ActionRiskTier,
    Connection,
    Flow,
    FlowCheckpointStore,
    FlowContext,
    FlowRiskEvaluator,
    FlowSchemaGenerator,
    HITLPolicy,
    MCPFlowRegistry,
    MCPHostEntry,
    MCPHostRegistry,
    MCPSecurityPolicy,
    MCPServer,
    Result,
    normalize_flow_tool_name,
    task,
)
from uniconn.cli.cmd_mcp import build_mcp_client_config

# ---------------------------------------------------------------------------
# 1. Тесты связывания параметров @task и генерации JSON Schema
# ---------------------------------------------------------------------------


async def test_task_parameter_injection_from_flow_context_vars() -> None:
    """Параметры сигнатуры @task должны автоматически подставляться из FlowContext.vars."""
    observed: list[tuple[str, str, int, bool]] = []

    @task(name="deploy_step", tags=["deploy"])
    async def deploy_step(
        conn: Connection,
        ctx: FlowContext,
        host: str,
        version: str,
        replicas: int = 3,
        canary: bool = False,
    ) -> dict[str, Any]:
        observed.append((host, version, replicas, canary))
        ctx.set("deployed_version", version)
        return {"host": host, "version": version, "replicas": replicas, "canary": canary}

    flow = Flow(
        name="inject_demo",
        tasks=[deploy_step],
        description="Demo flow with parameter injection.",
    )

    async with Connection.from_uri("local://") as conn:
        report = await flow.run(conn, vars={"version": "2.4.0", "canary": True})

    assert report.ok is True
    assert len(observed) == 1
    host_val, ver_val, rep_val, can_val = observed[0]
    assert host_val == "localhost"
    assert ver_val == "2.4.0"
    assert rep_val == 3
    assert can_val is True


async def test_task_missing_required_parameter_raises_clear_error() -> None:
    """Если обязательный типизированный параметр @task отсутствует в ctx.vars, задача фиксирует ошибку."""

    @task(name="require_version")
    async def require_version(conn: Connection, version: str) -> str:
        return version

    flow = Flow(name="missing_var_flow", tasks=[require_version])
    async with Connection.from_uri("local://") as conn:
        report = await flow.run(conn, vars={})

    assert report.ok is False
    host_res = report.for_host("localhost")
    assert len(host_res) == 1
    assert host_res[0].status == "failed"
    assert "missing required flow variable 'version'" in (host_res[0].error or "")


def test_flow_schema_generator_introspects_tasks_and_docstrings() -> None:
    """FlowSchemaGenerator должен извлекать типы, дефолты, Literal и описания из docstring."""

    @task(name="preflight", tags=["safe"])
    async def preflight(conn: Connection, check_disk: bool = True) -> None:
        """Run preflight checks.

        Args:
            check_disk: Verify free disk space before rollout.
        """

    @task(name="rollout", depends_on=[preflight], tags=["deploy"])
    async def rollout(
        conn: Connection,
        ctx: FlowContext,
        version: str,
        strategy: Literal["blue-green", "canary", "rolling"] = "rolling",
        batch_wait: float = 1.5,
        notes: str | None = None,
    ) -> None:
        """Roll out new release across target nodes.

        :param version: Semantic release version tag (e.g. v1.4.2).
        :param strategy: Deployment rollout strategy.
        """

    flow = Flow(
        name="Zero-Downtime Deploy",
        tasks=[rollout],
        description="Zero-downtime application deployment.",
    )

    assert normalize_flow_tool_name(flow.name) == "flow_zero_downtime_deploy"
    tool_def = FlowSchemaGenerator.generate_tool_definition(flow)
    assert tool_def.name == "flow_zero_downtime_deploy"
    assert "Zero-downtime application deployment." in tool_def.description
    assert "Wave 1: [preflight] -> Wave 2: [rollout]" in tool_def.description

    schema = tool_def.input_schema
    props = schema["properties"]
    assert props["version"]["type"] == "string"
    assert "Semantic release version tag" in props["version"]["description"]
    assert props["strategy"] == {
        "type": "string",
        "enum": ["blue-green", "canary", "rolling"],
        "description": "Deployment rollout strategy.",
        "default": "rolling",
    }
    assert props["check_disk"]["type"] == "boolean"
    assert props["check_disk"]["default"] is True
    assert "Verify free disk space" in props["check_disk"]["description"]
    assert props["batch_wait"]["type"] == "number"
    assert props["batch_wait"]["default"] == 1.5
    assert schema["required"] == ["version"]


def test_flow_schema_generator_with_pydantic_and_dataclass_models() -> None:
    """FlowSchemaGenerator должен поддерживать Pydantic BaseModel и dataclass в params_model."""

    class DeployParams(BaseModel):
        image_tag: str = Field(description="Container image tag")
        workers: int = Field(default=4, description="Gunicorn worker count")

    @task(name="apply_container")
    async def apply_container(conn: Connection, image_tag: str, workers: int = 4) -> str:
        return f"{image_tag}:{workers}"

    flow_pydantic = Flow(
        name="container_deploy",
        tasks=[apply_container],
        params_model=DeployParams,
    )
    props, req = FlowSchemaGenerator.extract_user_parameters(flow_pydantic)
    assert "image_tag" in props
    assert props["workers"]["default"] == 4
    assert req == ["image_tag"]

    validated = FlowSchemaGenerator.extract_and_validate_vars(
        flow_pydantic,
        {"image_tag": "v3.1.0", "workers": "6"},
    )
    assert validated == {"image_tag": "v3.1.0", "workers": 6}

    @dataclass
    class BackupParams:
        retention_days: int = 14
        bucket: str = "s3://backups"

    @task(name="run_backup")
    async def run_backup(conn: Connection, retention_days: int, bucket: str) -> str:
        return f"{bucket}:{retention_days}"

    flow_dc = Flow(
        name="db_backup",
        tasks=[run_backup],
        params_model=BackupParams,
    )
    dc_props, dc_req = FlowSchemaGenerator.extract_user_parameters(flow_dc)
    assert dc_req == []
    assert dc_props["retention_days"]["default"] == 14
    assert dc_props["bucket"]["default"] == "s3://backups"


# ---------------------------------------------------------------------------
# 2. Тесты оценки риска FlowRiskEvaluator и ASCII DAG-плана
# ---------------------------------------------------------------------------


def test_flow_risk_evaluator_and_plan_preview() -> None:
    """FlowRiskEvaluator должен учитывать теги задач, prod_groups и режим dry_run."""

    @task(name="check_status", tags=["safe", "readonly"])
    async def check_status(conn: Connection) -> None:
        pass

    @task(name="restart_db", depends_on=[check_status], tags=["restart", "mutating"])
    async def restart_db(conn: Connection, graceful: bool = True) -> None:
        pass

    flow = Flow(name="db_maintenance", tasks=[restart_db])
    staging_entry = MCPHostEntry(
        name="stg-db-01",
        uri="local://",
        masked_uri="local://",
        transport="local",
        host="stg-db-01",
        groups=("staging",),
    )
    prod_entry = MCPHostEntry(
        name="prod-db-01",
        uri="local://",
        masked_uri="local://",
        transport="local",
        host="prod-db-01",
        groups=("prod",),
    )
    policy = HITLPolicy(enabled=True)

    # 1. Полный запуск на staging -> TIER_1_MUTATING
    assess_stg, plan_stg = FlowRiskEvaluator.evaluate(
        flow,
        entries=[staging_entry],
        vars={"graceful": True},
        policy=policy,
    )
    assert assess_stg.risk_tier == ActionRiskTier.TIER_1_MUTATING
    assert assess_stg.requires_approval is True
    assert "Wave 1 (parallel=1):" in plan_stg
    assert "Wave 2 (parallel=1):" in plan_stg
    assert "restart_db <- [check_status]" in plan_stg

    # 2. Запуск на prod -> эскалация до TIER_2_DESTRUCTIVE
    assess_prod, _ = FlowRiskEvaluator.evaluate(
        flow,
        entries=[prod_entry],
        vars={"graceful": True},
        policy=policy,
    )
    assert assess_prod.risk_tier == ActionRiskTier.TIER_2_DESTRUCTIVE
    assert assess_prod.requires_approval is True
    assert any("production" in r.lower() for r in assess_prod.reasons)

    # 3. Фильтрация только по тегу safe -> TIER_0_SAFE (без подтверждения)
    assess_safe_tag, _ = FlowRiskEvaluator.evaluate(
        flow,
        entries=[prod_entry],
        tags=["safe"],
        policy=policy,
    )
    assert assess_safe_tag.risk_tier == ActionRiskTier.TIER_0_SAFE
    assert assess_safe_tag.requires_approval is False

    # 4. Запуск с dry_run=True -> всегда TIER_0_SAFE
    assess_dry, _ = FlowRiskEvaluator.evaluate(
        flow,
        entries=[prod_entry],
        dry_run=True,
        policy=policy,
    )
    assert assess_dry.risk_tier == ActionRiskTier.TIER_0_SAFE
    assert assess_dry.requires_approval is False


# ---------------------------------------------------------------------------
# 3. Тесты экспорта в MCPServer, двухфазного HITL 4.2, диагностики 4.1 и резюма
# ---------------------------------------------------------------------------


async def test_mcp_server_flow_as_tool_two_phase_hitl_and_execution(tmp_path: Path) -> None:
    """MCPServer должен экспортировать flow_<name>, требовать HITL с планом DAG в diff и исполнять Flow после approve."""
    execution_log: list[str] = []

    @task(name="verify_config", tags=["preflight", "safe"])
    async def verify_config(conn: Connection, app_version: str) -> str:
        execution_log.append(f"verify:{app_version}")
        return f"verified {app_version}"

    @task(name="apply_release", depends_on=[verify_config], tags=["deploy", "mutating"])
    async def apply_release(
        conn: Connection,
        ctx: FlowContext,
        app_version: str,
        workers: int = 2,
    ) -> Result:
        execution_log.append(f"apply:{app_version}:{workers}")
        return await conn.run(f"echo deploying {app_version} with {workers} workers")

    deploy_flow = Flow(
        name="release_app",
        tasks=[apply_release],
        description="Deploy application release with preflight verification.",
    )

    store_file = tmp_path / "approvals.json"
    policy = MCPSecurityPolicy(
        hitl=HITLPolicy(enabled=True, store_path=str(store_file)),
    )
    registry = MCPHostRegistry.from_sources(include_local=True, policy=policy)
    server = MCPServer(registry=registry, flows=[deploy_flow])

    # Проверяем tools/list
    tools_resp = await server.handle_message(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    )
    assert isinstance(tools_resp, dict)
    tool_names = {t["name"] for t in tools_resp["result"]["tools"]}
    assert "flow_release_app" in tool_names
    assert "uniconn_list_flows" in tool_names
    assert "uniconn_inspect_flow" in tool_names
    assert "uniconn_run_flow" in tool_names
    assert "uniconn_resume_flow" in tool_names

    # Проверяем uniconn_inspect_flow
    inspect_resp = await server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "uniconn_inspect_flow",
                "arguments": {
                    "flow_name": "release_app",
                    "vars": {"app_version": "1.5.0"},
                },
            },
        }
    )
    assert isinstance(inspect_resp, dict)
    inspect_data = json.loads(inspect_resp["result"]["content"][0]["text"])
    assert inspect_data["flow_name"] == "release_app"
    assert inspect_data["tool_name"] == "flow_release_app"
    assert "Wave 1" in inspect_data["plan_preview"]
    assert "apply_release <- [verify_config]" in inspect_data["plan_preview"]

    # Фаза 1: вызов динамического тула flow_release_app -> должен вернуть PENDING_APPROVAL с DAG-планом
    call_phase1 = await server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "flow_release_app",
                "arguments": {
                    "targets": ["local"],
                    "app_version": "1.5.0",
                    "workers": 4,
                },
            },
        }
    )
    assert isinstance(call_phase1, dict)
    p1_data = json.loads(call_phase1["result"]["content"][0]["text"])
    assert p1_data["status"] == "PENDING_APPROVAL"
    assert p1_data["requires_approval"] is True
    assert p1_data["flow_name"] == "release_app"
    assert "Wave 1" in p1_data["diff"]
    assert "app_version='1.5.0'" in p1_data["diff"]
    approval_id = p1_data["approval_id"]
    assert execution_log == []

    # Одобряем заявку оператором
    await server.approval_manager.approve(
        approval_id,
        decided_by="sre_lead",
        reason="Rollout window approved",
    )

    # Попытка подмены параметра app_version при повторном вызове должна быть заблокирована HMAC
    tampered_call = await server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "flow_release_app",
                "arguments": {
                    "targets": ["local"],
                    "app_version": "9.9.9-hacked",
                    "workers": 4,
                    "approval_id": approval_id,
                },
            },
        }
    )
    assert isinstance(tampered_call, dict)
    assert tampered_call["result"]["isError"] is True
    tampered_err = json.loads(tampered_call["result"]["content"][0]["text"])
    assert tampered_err["error"] == "ApprovalTamperingError"
    assert execution_log == []

    # Фаза 2: повторный вызов с неизменёнными параметрами и approval_id -> успешное выполнение
    call_phase2 = await server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "flow_release_app",
                "arguments": {
                    "targets": ["local"],
                    "app_version": "1.5.0",
                    "workers": 4,
                    "approval_id": approval_id,
                },
            },
        }
    )
    assert isinstance(call_phase2, dict)
    assert call_phase2["result"]["isError"] is False
    p2_data = json.loads(call_phase2["result"]["content"][0]["text"])
    assert p2_data["ok"] is True
    assert p2_data["status"] == "COMPLETED"
    assert p2_data["summary"]["succeeded_count"] == 2
    assert p2_data["approval"]["approved_by"] == "sre_lead"
    assert execution_log == ["verify:1.5.0", "apply:1.5.0:4"]


async def test_mcp_flow_failure_attaches_diagnostic_and_resumes_from_checkpoint(
    tmp_path: Path,
) -> None:
    """При сбое задачи внутри Flow возвращается DiagnosticSummary (4.1) и run_id, по которому возможен резюм."""
    step_counts = {"step1": 0, "step2": 0, "step3": 0}
    should_fail_step2 = True

    @task(name="step1_prepare", tags=["safe"])
    async def step1_prepare(conn: Connection, env_name: str = "staging") -> Result:
        step_counts["step1"] += 1
        return await conn.run(f"echo preparing {env_name}")

    @task(name="step2_migrate", depends_on=[step1_prepare], tags=["safe"])
    async def step2_migrate(conn: Connection) -> Result:
        step_counts["step2"] += 1
        if should_fail_step2:
            return await conn.run(
                "sh -c 'echo \"permission denied: /etc/shadow\" >&2; exit 13'",
                raise_on_error=False,
            )
        return await conn.run("echo migration_ok")

    @task(name="step3_finalize", depends_on=[step2_migrate], tags=["safe"])
    async def step3_finalize(conn: Connection) -> Result:
        step_counts["step3"] += 1
        return await conn.run("echo finalized")

    migration_flow = Flow(
        name="db_migration",
        tasks=[step3_finalize],
        risk_tier="safe",
    )

    cp_store = FlowCheckpointStore(store_path=tmp_path / "checkpoints.json")
    registry = MCPHostRegistry.from_sources(include_local=True)
    server = MCPServer(
        registry=registry,
        flows=[migration_flow],
        checkpoint_store=cp_store,
    )

    # Запуск 1: падает на step2_migrate
    resp1 = await server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "flow_db_migration",
                "arguments": {"targets": ["local"], "env_name": "staging"},
            },
        }
    )
    assert isinstance(resp1, dict)
    data1 = json.loads(resp1["result"]["content"][0]["text"])
    assert data1["ok"] is False
    assert data1["status"] == "FAILED"
    assert data1["can_resume"] is True
    run_id = data1["run_id"]
    assert run_id.startswith("run_")
    assert step_counts == {"step1": 1, "step2": 1, "step3": 0}

    # Проверяем, что в failed_tasks прикреплён DiagnosticSummary (Вектор 4.1)
    assert len(data1["failed_tasks"]) == 1
    failed_item = data1["failed_tasks"][0]
    assert failed_item["task_name"] == "step2_migrate"
    assert "diagnostic" in failed_item
    assert failed_item["diagnostic"]["exit_code"] == 13
    assert "permission denied" in failed_item["diagnostic"]["stderr_tail"].lower()

    # Проверяем ресурс uniconn://flows — должен содержать resumable_checkpoints
    res_read = await server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "resources/read",
            "params": {"uri": "uniconn://flows"},
        }
    )
    assert isinstance(res_read, dict)
    flows_res_payload = json.loads(res_read["result"]["contents"][0]["text"])
    assert any(
        cp["run_id"] == run_id for cp in flows_res_payload["resumable_checkpoints"]
    )

    # Устраняем проблему и запускаем uniconn_resume_flow(run_id=...)
    should_fail_step2 = False
    resp2 = await server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {
                "name": "uniconn_resume_flow",
                "arguments": {"run_id": run_id},
            },
        }
    )
    assert isinstance(resp2, dict)
    data2 = json.loads(resp2["result"]["content"][0]["text"])
    assert data2["ok"] is True
    assert data2["status"] == "COMPLETED"
    assert data2["resumed_from"] == run_id
    # step1_prepare НЕ должен был выполняться повторно (пропущен по чекпоинту)!
    assert step_counts == {"step1": 1, "step2": 2, "step3": 1}
    host_results = data2["results"]["local"]
    step1_res = next(r for r in host_results if r["task_name"] == "step1_prepare")
    assert step1_res["status"] == "skipped"
    assert step1_res["skip_reason"] == "checkpoint_completed"


async def test_mcp_flow_registry_loads_from_python_file_and_cli_config(
    tmp_path: Path,
) -> None:
    """MCPFlowRegistry должен загружать сценарии Flow из .py файла, а CLI формировать конфиг с --flows."""
    flow_file = tmp_path / "custom_flows.py"
    flow_file.write_text(
        "from uniconn import Flow, task\n\n"
        "@task(name='ping_step', tags=['safe'])\n"
        "async def ping_step(conn, label: str = 'ok'):\n"
        "    return await conn.run(f'echo {label}')\n\n"
        "health_flow = Flow(name='fleet_health', tasks=[ping_step], description='Check fleet health')\n",
        encoding="utf-8",
    )

    flow_reg = MCPFlowRegistry.from_sources(specs=[str(flow_file)])
    flows = flow_reg.list_flows()
    assert len(flows) == 1
    assert flows[0].name == "fleet_health"

    cfg = build_mcp_client_config(
        local=True,
        hitl=True,
        flows=(str(flow_file),),
    )
    args = cfg["mcpServers"]["uniconn"]["args"]
    assert "--flows" in args
    assert str(flow_file) in args


async def test_annotated_types_tag_filtered_validation_and_checkpoint_outputs(
    tmp_path: Path,
) -> None:
    """Проверка typing.Annotated, валидации по активным тегам, expose_as_tool=False и восстановления return_value."""

    @task(name="preflight_step", tags=["preflight", "safe"])
    async def preflight_step(
        conn: Connection,
        workers: Annotated[int, "Worker pool concurrency"] = 4,
    ) -> dict[str, Any]:
        return {"artifact_id": f"art-{workers}", "workers": workers}

    @task(name="deploy_step", depends_on=[preflight_step], tags=["deploy"])
    async def deploy_step(
        conn: Connection,
        ctx: FlowContext,
        version: Annotated[str, Field(description="Target release version")],
    ) -> str:
        upstream = ctx.get_result("preflight_step")
        art_id = upstream["artifact_id"] if isinstance(upstream, dict) else "missing"
        return f"deployed:{version}:{art_id}"

    flow = Flow(name="annotated_pipeline", tasks=[deploy_step], risk_tier="safe")

    # 1. typing.Annotated распаковывается в корректные JSON Schema типы и описания
    props, req = FlowSchemaGenerator.extract_user_parameters(flow)
    assert props["workers"]["type"] == "integer"
    assert props["workers"]["description"] == "Worker pool concurrency"
    assert props["workers"]["default"] == 4
    assert props["version"]["type"] == "string"
    assert props["version"]["description"] == "Target release version"
    assert req == ["version"]

    # 2. При фильтрации tags=['preflight'] параметр 'version' из отфильтрованной задачи deploy_step не требуется
    vars_preflight = FlowSchemaGenerator.extract_and_validate_vars(
        flow,
        {"tags": ["preflight"]},
    )
    assert vars_preflight == {"workers": 4}

    # Без фильтра тегов отсутствие 'version' вызывает ValueError
    with pytest.raises(ValueError, match="version"):
        FlowSchemaGenerator.extract_and_validate_vars(flow, {})

    # 3. При возобновлении с чекпоинта (checkpoint_outputs_by_host) ctx.get_result() возвращает сохранённый результат
    async with Connection.from_uri("local://") as conn:
        resumed_report = await flow.run(
            conn,
            vars={"version": "v2.0.0"},
            completed_tasks_by_host={"localhost": ["preflight_step"]},
            checkpoint_outputs_by_host={
                "localhost": {"preflight_step": {"artifact_id": "art-from-cp", "workers": 8}}
            },
            run_id="run_test_cp",
            resumed_from="run_prev_cp",
        )
    assert resumed_report.ok is True
    host_res = resumed_report.results["localhost"]
    deploy_res = next(r for r in host_res if r.task_name == "deploy_step")
    assert deploy_res.return_value == "deployed:v2.0.0:art-from-cp"

    # 4. expose_as_tool=False скрывает сценарий из MCPFlowRegistry
    hidden_flow = Flow(
        name="internal_only",
        tasks=[preflight_step],
        expose_as_tool=False,
    )
    reg = MCPFlowRegistry(flows=[flow, hidden_flow])
    assert [f.name for f in reg.list_flows()] == ["annotated_pipeline"]
    with pytest.raises(KeyError):
        reg.get_flow("internal_only")
    with pytest.raises(KeyError):
        reg.get_flow("flow_internal_only")
