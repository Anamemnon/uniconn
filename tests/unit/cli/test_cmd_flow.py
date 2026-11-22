# tests/unit/cli/test_cmd_flow.py
"""Unit-тесты CLI-команд оркестрации: uniconn flow list, flow inspect, flow run."""

from __future__ import annotations

import json
from pathlib import Path

from uniconn.cli import CliRunner, create_cli_app


def _write_sample_flow_file(tmp_path: Path) -> Path:
    flow_file = tmp_path / "sample_deploy.py"
    flow_file.write_text(
        """
from dataclasses import dataclass
from uniconn import Connection, Flow, FlowContext, task

@dataclass
class DeployMeta:
    service: str = "api"

@task(tags=["init"])
async def check_host(conn: Connection, ctx: FlowContext):
    meta = DeployMeta()
    env_name = ctx.get("env", "dev")
    return await conn.run(f"echo service={meta.service} env={env_name}")

@task(always_run=True)
async def post_cleanup(conn: Connection):
    return await conn.run("echo cleanup")

@task(depends_on=[check_host], post=[post_cleanup], tags=["deploy"])
async def apply_app(conn: Connection):
    return await conn.run("echo deployed")

deploy_flow = Flow(name="sample_deploy_flow", tasks=[apply_app], mode="barrier")
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return flow_file


def test_cli_flow_list_table_and_json(tmp_path: Path) -> None:
    """Команда uniconn flow list выводит все Flow и @task из файла."""
    flow_file = _write_sample_flow_file(tmp_path)
    app = create_cli_app()
    runner = CliRunner()

    res_table = runner.invoke(app, ["flow", "list", str(flow_file)])
    assert res_table.exit_code == 0
    assert "sample_deploy_flow" in res_table.output
    assert "check_host" in res_table.output
    assert "apply_app" in res_table.output

    res_json = runner.invoke(app, ["flow", "list", str(flow_file), "--format", "json"])
    assert res_json.exit_code == 0
    data = json.loads(res_json.stdout)
    assert len(data["flows"]) == 1
    assert data["flows"][0]["name"] == "sample_deploy_flow"
    assert {t["name"] for t in data["tasks"]} == {"check_host", "apply_app", "post_cleanup"}


def test_cli_flow_inspect_tree_and_json(tmp_path: Path) -> None:
    """Команда uniconn flow inspect (и алиас flow-info) проверяет граф и выводит слои, включая post-рёбра."""
    flow_file = _write_sample_flow_file(tmp_path)
    app = create_cli_app()
    runner = CliRunner()

    res_tree = runner.invoke(app, ["flow", "inspect", f"{flow_file}:deploy_flow"])
    assert res_tree.exit_code == 0
    assert "Layer 1" in res_tree.output
    assert "Layer 2" in res_tree.output
    assert "Layer 3" in res_tree.output

    res_json = runner.invoke(
        app, ["flow-info", f"{flow_file}:deploy_flow", "--format", "json"]
    )
    assert res_json.exit_code == 0
    data = json.loads(res_json.stdout)
    assert data["flow_name"] == "sample_deploy_flow"
    assert data["layers"] == [["check_host"], ["apply_app"], ["post_cleanup"]]
    assert data["tasks"]["post_cleanup"]["depends_on"] == ["apply_app"]


def test_cli_flow_run_single_and_multi_host(tmp_path: Path) -> None:
    """Команда uniconn flow run (и run-flow) исполняет граф на local:// с передачей --var и --format json."""
    flow_file = _write_sample_flow_file(tmp_path)
    app = create_cli_app()
    runner = CliRunner()

    res = runner.invoke(
        app,
        [
            "flow",
            "run",
            f"{flow_file}:deploy_flow",
            "local://",
            "--var",
            "env=production",
            "--format",
            "json",
        ],
    )
    assert res.exit_code == 0
    payload = json.loads(res.stdout)
    assert payload["ok"] is True
    assert payload["succeeded_count"] == 3
    host_items = payload["results"]["localhost"]
    assert "env=production" in host_items[0]["return_value"]["stdout"]

    # Табличный вывод через алиас run-flow на нескольких URI
    res_multi = runner.invoke(
        app,
        [
            "run-flow",
            str(flow_file),
            "local://",
            "local://",
            "--mode",
            "independent",
            "--dry-run",
        ],
    )
    assert res_multi.exit_code == 0
    assert "SUCCESS" in res_multi.output


def _write_stateful_flow_file(tmp_path: Path, target_file: Path, extra_file: Path | None = None) -> Path:
    flow_file = tmp_path / "stateful_deploy.py"
    extra_block = ""
    if extra_file is not None:
        extra_block = (
            f"    if ctx.get('with_extra', False):\n"
            f"        await conn.state.ensure_file({str(extra_file)!r}, content='EXTRA=1\\n')\n"
        )
    flow_file.write_text(
        f"""
from uniconn import Connection, Flow, FlowContext, task

@task(name="apply_cfg", tags=["deploy"])
async def apply_cfg(conn: Connection, ctx: FlowContext):
    val = ctx.get("value", "v2")
    res = await conn.state.ensure_file({str(target_file)!r}, content=f"VAL={{val}}\\n")
{extra_block}    return res

state_flow = Flow(name="stateful_deploy_flow", tasks=[apply_cfg])
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return flow_file


def test_cli_flow_plan_check_drift_formats_and_out_file(tmp_path: Path) -> None:
    """uniconn flow plan: --format json/diff/table, --out сохраняет JSON, --check-drift отдаёт код 2 и 0."""
    target_file = tmp_path / "cli_app.conf"
    target_file.write_text("VAL=v1\n", encoding="utf-8", newline="\n")
    flow_file = _write_stateful_flow_file(tmp_path, target_file)
    plan_out = tmp_path / "saved_plan.json"

    app = create_cli_app()
    runner = CliRunner()

    # 1. --check-drift при наличии расхождений возвращает код 2 и сохраняет план в --out
    res_drift = runner.invoke(
        app,
        [
            "flow",
            "plan",
            f"{flow_file}:state_flow",
            "local://",
            "--var",
            "value=v2",
            "--check-drift",
            "--out",
            str(plan_out),
            "--format",
            "json",
        ],
    )
    assert res_drift.exit_code == 2
    assert plan_out.exists()
    plan_data = json.loads(res_drift.stdout)
    assert plan_data["has_drift"] is True
    assert plan_data["changed_count"] == 1
    assert len(plan_data["plan_hash"]) == 64
    # Файл не был изменён во время plan!
    assert target_file.read_text(encoding="utf-8") == "VAL=v1\n"

    # 2. Форматы diff и table (через алиас plan-flow)
    res_diff = runner.invoke(
        app,
        ["plan-flow", f"{flow_file}:state_flow", "local://", "--format", "diff"],
    )
    assert res_diff.exit_code == 0
    assert "-VAL=v1" in res_diff.stdout
    assert "+VAL=v2" in res_diff.stdout

    res_table = runner.invoke(
        app,
        ["flow", "plan", f"{flow_file}:state_flow", "local://", "--format", "table"],
    )
    assert res_table.exit_code == 0
    assert "stateful_deploy_flow" in res_table.output

    # 3. После приведения файла в целевое состояние --check-drift возвращает 0
    target_file.write_text("VAL=v2\n", encoding="utf-8", newline="\n")
    res_clean = runner.invoke(
        app,
        [
            "flow",
            "plan",
            f"{flow_file}:state_flow",
            "local://",
            "--check-drift",
            "--format",
            "json",
        ],
    )
    assert res_clean.exit_code == 0
    assert json.loads(res_clean.stdout)["has_drift"] is False


def test_cli_flow_run_with_plan_apply_drift_guard_and_strict_toggle(tmp_path: Path) -> None:
    """uniconn flow run --plan применяет чистый план, падает при внешнем дрейфе и уважает --no-strict-plan."""
    target_file = tmp_path / "run_app.conf"
    extra_file = tmp_path / "extra_app.conf"
    target_file.write_text("VAL=v1\n", encoding="utf-8", newline="\n")
    flow_file = _write_stateful_flow_file(tmp_path, target_file, extra_file=extra_file)
    plan_file = tmp_path / "apply_plan.json"

    app = create_cli_app()
    runner = CliRunner()

    # Генерируем план
    res_plan = runner.invoke(
        app,
        ["flow", "plan", f"{flow_file}:state_flow", "local://", "--out", str(plan_file)],
    )
    assert res_plan.exit_code == 0

    # 1. Внешний дрейф -> flow run --plan падает с exit_code=1, не перезаписывая hotfix
    target_file.write_text("VAL=HOTFIX\n", encoding="utf-8", newline="\n")
    res_drifted = runner.invoke(
        app,
        [
            "flow",
            "run",
            f"{flow_file}:state_flow",
            "local://",
            "--plan",
            str(plan_file),
            "--format",
            "json",
        ],
    )
    assert res_drifted.exit_code == 1
    assert json.loads(res_drifted.stdout)["ok"] is False
    assert target_file.read_text(encoding="utf-8") == "VAL=HOTFIX\n"

    # 2. Восстанавливаем исходное состояние и применяем план успешно
    target_file.write_text("VAL=v1\n", encoding="utf-8", newline="\n")
    res_apply = runner.invoke(
        app,
        [
            "flow",
            "run",
            f"{flow_file}:state_flow",
            "local://",
            "--plan",
            str(plan_file),
            "--format",
            "json",
        ],
    )
    assert res_apply.exit_code == 0
    assert json.loads(res_apply.stdout)["ok"] is True
    assert target_file.read_text(encoding="utf-8") == "VAL=v2\n"

    # 3. Незапланированный ресурс (with_extra=true) с --no-strict-plan разрешается
    target_file.write_text("VAL=v1\n", encoding="utf-8", newline="\n")
    res_non_strict = runner.invoke(
        app,
        [
            "flow",
            "run",
            f"{flow_file}:state_flow",
            "local://",
            "--plan",
            str(plan_file),
            "--no-strict-plan",
            "--var",
            "with_extra=true",
            "--format",
            "json",
        ],
    )
    assert res_non_strict.exit_code == 0
    assert extra_file.read_text(encoding="utf-8") == "EXTRA=1\n"


def test_cli_flow_mode_override_preserves_flow_metadata(tmp_path: Path) -> None:
    """Переопределение --mode в CLI не теряет params_model, connection_window и метаданные Flow."""
    from uniconn.cli.cmd_flow import resolve_flow_spec
    from uniconn.orchestration.scheduler import coerce_to_flow

    flow_file = tmp_path / "meta_flow.py"
    flow_file.write_text(
        """
from pydantic import BaseModel
from uniconn import Flow, task

class Params(BaseModel):
    tag: str = "v1"

@task(name="echo_tag")
async def echo_tag(conn, ctx):
    return ctx.vars["tag"]

meta_flow = Flow(
    name="meta_demo",
    tasks=[echo_tag],
    mode="barrier",
    connection_window=2,
    description="Preserve metadata on mode override",
    params_model=Params,
    risk_tier="low",
    expose_as_tool=True,
)
""",
        encoding="utf-8",
    )

    spec = f"{flow_file}:meta_flow"
    overridden = coerce_to_flow(resolve_flow_spec(spec), mode="independent")
    assert overridden.mode == "independent"
    assert overridden.connection_window == 2
    assert overridden.description == "Preserve metadata on mode override"
    assert overridden.params_model is not None
    assert overridden.risk_tier == "low"
    assert overridden.expose_as_tool is True

    app = create_cli_app()
    runner = CliRunner()
    res = runner.invoke(
        app,
        [
            "flow",
            "run",
            spec,
            "local://",
            "--mode",
            "independent",
            "--var",
            "tag=override_ok",
            "--format",
            "json",
        ],
    )
    assert res.exit_code == 0
    payload = json.loads(res.stdout)
    assert payload["ok"] is True
    assert payload["flow_name"] == "meta_demo"

    res_plan = runner.invoke(
        app,
        [
            "flow",
            "plan",
            spec,
            "local://",
            "--mode",
            "independent",
            "--var",
            "tag=plan_ok",
            "--format",
            "json",
        ],
    )
    assert res_plan.exit_code == 0
    assert json.loads(res_plan.stdout)["flow_name"] == "meta_demo"



