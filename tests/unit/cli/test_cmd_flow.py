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
