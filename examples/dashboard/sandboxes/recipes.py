"""Interactive Quickstart & Recipe Wizard sandbox for the uniconn web dashboard."""

from __future__ import annotations

import asyncio
import os
import tempfile
import time
from pathlib import Path
from typing import Any


def _inspect_runtime_rpc(multiplier: int) -> dict[str, int]:
    """Self-contained RPC helper executed inside RemotePythonWorker."""
    import os

    cpus = os.cpu_count() or 1
    return {
        "pid": os.getpid(),
        "cpu_count": cpus,
        "computed_workers": cpus * multiplier,
    }


def _execute_recipe_sandbox(payload: dict[str, Any]) -> dict[str, Any]:
    """Execute a curated onboarding recipe in-process and return code snippets + live output."""
    recipe_id = str(payload.get("recipe_id") or "parse_auto").strip().lower()
    target_uri = str(payload.get("uri") or "ssh://admin:env://SSH_PASS@prod-web-01").strip()
    custom_cmd = str(payload.get("command") or "").strip()

    try:
        from uniconn import (
            Cassette,
            CommandASTParser,
            Connection,
            ConnectionPool,
            Flow,
            FlowContext,
            PolicyGuardrailConfig,
            RecordedExecInteraction,
            build_auth_context,
            create_policy_engine,
            task,
        )

        async def _run() -> dict[str, Any]:
            t0 = time.monotonic()

            if recipe_id == "run_python_rpc":
                async with Connection.local() as conn:
                    kernel_rel = await conn.run_python(lambda: os.uname().release if hasattr(os, "uname") else "nt")
                    worker_stats = await conn.run_python(_inspect_runtime_rpc, 2)
                dur_ms = round((time.monotonic() - t0) * 1000, 2)
                return {
                    "status": "ok",
                    "recipe_id": "run_python_rpc",
                    "duration_ms": dur_ms,
                    "target_uri_preview": target_uri,
                    "kernel_release": kernel_rel,
                    "worker_stats": worker_stats,
                }

            if recipe_id == "idempotent_state":
                with tempfile.TemporaryDirectory(prefix="uniconn_recipe_state_") as tmp:
                    conf_path = Path(tmp) / "nginx.conf"
                    conf_path.write_text("worker_processes 1;\n", encoding="utf-8")
                    reload_calls: list[str] = []

                    async def _reload_handler() -> str:
                        reload_calls.append("nginx_reloaded")
                        return "reloaded"

                    async with Connection.local() as conn:
                        notify_spec = ("reload_nginx", _reload_handler)
                        async with conn.state.batch_notifications() as batch:
                            pass1 = await conn.state.ensure_file(
                                str(conf_path),
                                content="worker_processes auto;\nevents { worker_connections 1024; }\n",
                                atomic=True,
                                notify=notify_spec,
                            )
                            pass2 = await conn.state.ensure_file(
                                str(conf_path),
                                content="worker_processes auto;\nevents { worker_connections 1024; }\n",
                                atomic=True,
                                notify=notify_spec,
                            )
                    dur_ms = round((time.monotonic() - t0) * 1000, 2)
                    return {
                        "status": "ok",
                        "recipe_id": "idempotent_state",
                        "duration_ms": dur_ms,
                        "first_pass_changed": pass1.changed,
                        "second_pass_changed": pass2.changed,
                        "unified_diff": pass1.diff,
                        "notifications_triggered": batch.triggered_count,
                        "notifications_executed": batch.executed_count,
                        "reload_calls": reload_calls,
                    }

            if recipe_id == "remote_path_sync":
                with tempfile.TemporaryDirectory(prefix="uniconn_recipe_path_") as tmp:
                    src_dir = Path(tmp) / "build"
                    dst_dir = Path(tmp) / "remote_www"
                    src_dir.mkdir()
                    (src_dir / "index.html").write_text("<h1>uniconn v0.19</h1>\n", encoding="utf-8")
                    (src_dir / "app.js").write_text("console.log('ready');\n", encoding="utf-8")

                    async with Connection.local() as conn:
                        sync_res = await conn.files.sync_dir(src_dir, dst_dir, delete=True, checksum_check=True)
                        remote_root = conn.path(str(dst_dir))
                        discovered: list[dict[str, Any]] = []
                        async for item in remote_root.glob("*"):
                            st = await item.stat()
                            discovered.append({"name": item.name, "size": st.st_size})
                    dur_ms = round((time.monotonic() - t0) * 1000, 2)
                    return {
                        "status": "ok",
                        "recipe_id": "remote_path_sync",
                        "duration_ms": dur_ms,
                        "sync_result": sync_res.to_dict(),
                        "remote_path_glob": discovered,
                    }

            if recipe_id == "dag_flow":
                @task(name="preflight", tags=["preflight"])
                async def preflight(conn: Connection, ctx: FlowContext) -> Any:
                    facts = await conn.gather_facts()
                    ctx.host_set(conn, "os_family", facts.os_family)
                    return {"os_family": facts.os_family, "arch": facts.arch}

                @task(name="cleanup", always_run=True)
                async def cleanup(conn: Connection) -> str:
                    res = await conn.run("echo cleanup-ok")
                    return res.text

                @task(name="deploy_release", depends_on=[preflight], post=[cleanup])
                async def deploy_release(conn: Connection, ctx: FlowContext, version: str = "2.4.0") -> dict[str, Any]:
                    os_fam = ctx.host_get(conn, "os_family")
                    res = await conn.run(f"echo deploying-{version}-on-{os_fam}")
                    return {"output": res.text, "version": version}

                flow = Flow(
                    name="canary_release_flow",
                    tasks=[deploy_release],
                    mode="barrier",
                    batch_size=2,
                    max_fail_ratio=0.0,
                    batch_notifications=True,
                )
                async with ConnectionPool(["local://?host=web-01", "local://?host=web-02"], max_concurrent=2) as pool:
                    report = await pool.run_flow(flow, vars={"version": "2.4.0"})
                dur_ms = round((time.monotonic() - t0) * 1000, 2)
                return {
                    "status": "ok",
                    "recipe_id": "dag_flow",
                    "duration_ms": dur_ms,
                    "flow_ok": report.ok,
                    "plan_ascii": flow.describe_plan(targets=["web-01", "web-02"], vars={"version": "2.4.0"}),
                    "report": report.to_dict(),
                }

            if recipe_id == "cassette_contract":
                with tempfile.TemporaryDirectory(prefix="uniconn_recipe_cass_") as tmp:
                    cass_file = Path(tmp) / "contract.yaml"
                    cass = Cassette(
                        transport="ssh",
                        host="prod-web-01",
                        interactions=[
                            RecordedExecInteraction(
                                command="nginx -v",
                                exit_code=0,
                                stdout="nginx version: nginx/1.26.2\n",
                            ),
                            RecordedExecInteraction(
                                command="uptime",
                                exit_code=0,
                                stdout=" 10:15:00 up 90 days, 2 users, load average: 0.05, 0.03, 0.01\n",
                            ),
                        ],
                    )
                    cass.save(cass_file)
                    replay_uri = f"replay://prod-web-01?cassette={cass_file}&mode=none"
                    async with Connection.from_uri(replay_uri) as conn:
                        r1 = await conn.run("nginx -v")
                        r2 = await conn.run("uptime")
                    diff_rep = cass.diff(Cassette.load(cass_file))
                dur_ms = round((time.monotonic() - t0) * 1000, 2)
                return {
                    "status": "ok",
                    "recipe_id": "cassette_contract",
                    "duration_ms": dur_ms,
                    "replayed_outputs": {"nginx_v": r1.text, "uptime": r2.text},
                    "cassette_diff": diff_rep.to_dict(),
                }

            if recipe_id == "mcp_policy_guard":
                cmd_to_eval = custom_cmd or "echo cm0gLXJmIC8= | base64 -d | sh"
                ast = CommandASTParser.parse(cmd_to_eval)
                engine = create_policy_engine(PolicyGuardrailConfig(enabled=True, preset="prod-guard"))
                auth_ctx = build_auth_context(
                    agent_id="recipe-explorer-agent",
                    role="operator",
                    host_name="prod-db-01",
                    environment="prod",
                    is_production=True,
                    tool_name="uniconn_run",
                    command=cmd_to_eval,
                    ast=ast,
                    sudo=True,
                )
                eval_res = await engine.evaluate(auth_ctx)
                dur_ms = round((time.monotonic() - t0) * 1000, 2)
                return {
                    "status": "ok",
                    "recipe_id": "mcp_policy_guard",
                    "duration_ms": dur_ms,
                    "command": cmd_to_eval,
                    "decision": eval_res.decision.value,
                    "allowed": eval_res.allowed,
                    "ast_is_obfuscated": ast.is_obfuscated,
                    "extracted_verbs": list(ast.verbs),
                    "policy_details": eval_res.to_dict(),
                }

            # Default: "parse_auto" (Semantic Auto-Parsing & Diagnostics)
            async with Connection.local() as conn:
                res = await conn.run(
                    custom_cmd
                    or 'python3 -c \'import json; print(json.dumps([{"filesystem":"/dev/sda1","mounted_on":"/","use_pct":42}]))\'',
                    parse="auto",
                )
                facts = await conn.gather_facts()
            dur_ms = round((time.monotonic() - t0) * 1000, 2)
            return {
                "status": "ok",
                "recipe_id": "parse_auto",
                "duration_ms": dur_ms,
                "command": res.command,
                "exit_code": res.exit_code,
                "parsed": res.parsed,
                "host_facts_summary": {
                    "os_family": facts.os_family,
                    "kernel": facts.kernel,
                    "arch": facts.arch,
                    "cpu_count": facts.cpu_count,
                },
            }

        return asyncio.run(_run())
    except Exception as exc:
        return {
            "status": "error",
            "recipe_id": recipe_id,
            "error": {"type": type(exc).__name__, "message": str(exc)},
        }
