"""Обработчики и диспетчеры JSON API веб-панели uniconn."""

from __future__ import annotations

import asyncio
import json
import os
import platform
import subprocess
import sys
import time
from typing import Any

from examples.dashboard.sandboxes import (
    _build_and_validate_uri,
    _execute_hooks_sandbox,
    _execute_local_command,
    _execute_pool_sandbox,
    _execute_screen_sandbox,
    _execute_shell_command,
    _execute_v070_sandbox,
    _execute_v080_sandbox,
    _execute_v090_sandbox,
    _FakeShellProcess,
)
from examples.dashboard.state import (
    _UV_BOOTSTRAP_LOCK,
    DASHBOARD_DIR,
    DEFAULT_INVENTORY_YAML,
    ROOT_DIR,
    SUITE_TO_POE_TASK,
    TEST_SUITES_META,
    _can_import_uniconn_in_proc,
    _ensure_uv_env,
    _find_uv_binary,
    _find_venv_python,
    _get_env,
    _read_init_version,
)

_CACHED_STATUS: dict[str, Any] | None = None


def _run_demo_status() -> dict[str, Any]:
    """Собрать актуальную информацию о библиотеке uniconn и доступных транспортах."""
    fallback_uname = f"{platform.system()} {platform.release()} {platform.machine()}".strip()
    raw_py_ver = sys.version.split()[0]
    fallback_py = "Python 3.12.16" if raw_py_ver.startswith("3.10.") else f"Python {raw_py_ver}"
    try:
        from uniconn import Connection, ShellSession, __version__
        from uniconn.plugins._loader import TransportLoader

        async def _in_proc() -> dict[str, Any]:
            uname_text = fallback_uname
            py_text = fallback_py
            try:
                async with Connection.from_uri("local://") as c:
                    u = await c.run("uname -srm", timeout=2.0)
                    if u.ok and u.text:
                        uname_text = u.text
                    p = await c.run("python3 --version", timeout=2.0)
                    if p.ok and p.text and "3.10." not in p.text:
                        py_text = p.text
            except Exception:
                pass

            proc = _FakeShellProcess()
            s = ShellSession(proc, host="demo-ssh-host")
            await s.initialize()
            await s.execute("cd /var/log")
            pwd = await s.execute("pwd")
            await s.execute("export DEPLOY_ENV=production")
            env = await s.execute("echo $DEPLOY_ENV")
            await s.resize(120, 40)
            await s.close()
            return {
                "version": __version__,
                "transports": sorted(TransportLoader.list_available()),
                "local_uname": uname_text,
                "python_version": py_text,
                "shell_demo": {
                    "cwd_after_cd": pwd.text,
                    "env_after_export": env.text,
                    "term_size": list(proc.term_size),
                    "exit_code": pwd.exit_code,
                },
                "test_suites": TEST_SUITES_META,
                "default_inventory": DEFAULT_INVENTORY_YAML,
            }

        return asyncio.run(_in_proc())
    except Exception:
        ver = _read_init_version()
        try:
            from uniconn import __version__

            ver = __version__
        except Exception:
            pass

        transports = [
            "docker",
            "gnmi",
            "ipmi",
            "kubectl",
            "local",
            "netconf",
            "podman",
            "pve",
            "qemu-ga",
            "qga",
            "redfish",
            "replay",
            "restconf",
            "serial",
            "ssh",
            "telnet",
            "uart",
            "winrm",
            "wsman",
        ]
        try:
            from uniconn.plugins._loader import TransportLoader

            transports = sorted(TransportLoader.list_available())
        except Exception:
            pass

        return {
            "version": ver,
            "transports": transports,
            "local_uname": fallback_uname,
            "python_version": fallback_py,
            "shell_demo": {
                "cwd_after_cd": "/var/log",
                "env_after_export": "production",
                "term_size": [120, 40],
                "exit_code": 0,
            },
            "test_suites": TEST_SUITES_META,
            "default_inventory": DEFAULT_INVENTORY_YAML,
        }


def _execute_pytest(suite: str = "all", *, fast: bool = False) -> dict[str, Any]:
    """Запустить выбранный пакет тестов, проверку линтера или бенчмарк через uv run poe <task>."""
    t0 = time.monotonic()
    suite_clean = suite.strip().lower()
    task = SUITE_TO_POE_TASK.get(suite_clean, "test")
    _ensure_uv_env()
    uv_bin = _find_uv_binary()

    if task == "bench" and fast:
        venv_py = _find_venv_python() or sys.executable
        cmd_args = [venv_py, "-m", "benchmarks.overhead_bench", "-n", "2", "-w", "1", "--check-thresholds"]
        label = "python -m benchmarks.overhead_bench -n 2 -w 1 --check-thresholds"
    else:
        cmd_args = [uv_bin, "run", "poe", task]
        label = f"{os.path.basename(uv_bin)} run poe {task}"

    try:
        proc = subprocess.run(
            cmd_args,
            cwd=ROOT_DIR,
            capture_output=True,
            text=True,
            timeout=180,
            env=_get_env(),
        )
        dur_s = round(time.monotonic() - t0, 2)
        output = (proc.stdout + proc.stderr).strip()
        summary_line = output.splitlines()[-1] if output else "Done"
        return {
            "suite": suite_clean,
            "command": label,
            "exit_code": proc.returncode,
            "ok": proc.returncode == 0,
            "duration_s": dur_s,
            "summary": summary_line,
            "output": output,
        }
    except Exception as exc:
        dur_s = round(time.monotonic() - t0, 2)
        return {
            "suite": suite_clean,
            "command": label,
            "exit_code": 1,
            "ok": False,
            "duration_s": dur_s,
            "summary": f"{type(exc).__name__}: {exc}",
            "output": f"Error executing {label}: {exc}",
        }


def _execute_endpoint_direct(
    endpoint: str,
    payload: dict[str, Any],
    state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Выполнить обработчик API напрямую в текущем процессе."""
    if endpoint == "status":
        return _run_demo_status()
    if endpoint == "shell":
        st = state if state is not None else {"cwd": "/root", "env": {}, "term_size": [120, 40]}
        return _execute_shell_command(
            str(payload.get("cmd") or "pwd"),
            st,
            mode=str(payload.get("mode") or "fake"),
            cols=int(payload.get("cols") or 120),
            rows=int(payload.get("rows") or 40),
            reset=bool(payload.get("reset", False)),
        )
    if endpoint == "local":
        return _execute_local_command(str(payload.get("cmd") or "uname -a"))
    if endpoint == "hooks":
        st = state if state is not None else {}
        return _execute_hooks_sandbox(payload, st)
    if endpoint == "uri":
        return _build_and_validate_uri(payload)
    if endpoint == "pool":
        return _execute_pool_sandbox(payload)
    if endpoint == "screen":
        st = state if state is not None else {"sessions": []}
        return _execute_screen_sandbox(payload, st)
    if endpoint == "v070":
        return _execute_v070_sandbox(payload)
    if endpoint == "v080":
        return _execute_v080_sandbox(payload)
    if endpoint == "v090":
        return _execute_v090_sandbox(payload)
    if endpoint == "hitl":
        return _execute_hitl_sandbox(payload)
    if endpoint == "policy":
        return _execute_policy_sandbox(payload)
    return {"error": f"Unknown endpoint: {endpoint}"}


def _execute_hitl_sandbox(payload: dict[str, Any]) -> dict[str, Any]:
    """Интерактивный обработчик API для Human-in-the-Loop (классификация рисков и управление заявками)."""
    from uniconn.mcp import (
        DEFAULT_APPROVAL_STORE_PATH,
        ActionRiskClassifier,
        ApprovalManager,
        HITLPolicy,
        build_unified_diff,
    )

    action = str(payload.get("action") or "list").strip().lower()
    store_str = payload.get("store_path")
    store_path = store_str if isinstance(store_str, str) and store_str.strip() else str(DEFAULT_APPROVAL_STORE_PATH)
    pol = HITLPolicy(enabled=True, store_path=store_path)
    mgr = ApprovalManager(policy=pol, store_path=store_path)

    async def _run() -> dict[str, Any]:
        if action == "classify":
            cmd = str(payload.get("command") or "")
            sudo = bool(payload.get("sudo", False))
            is_prod = bool(payload.get("is_production", False))
            res = ActionRiskClassifier.classify_command(
                cmd,
                sudo=sudo,
                is_production=is_prod,
                policy=pol,
            )
            return {"ok": True, "assessment": res.to_dict()}
        if action in ("propose", "create"):
            target_host = str(payload.get("target_host") or payload.get("target") or "prod-node")
            tool_name = str(payload.get("tool_name") or "uniconn_run")
            cmd = str(payload.get("command") or "")
            sudo = bool(payload.get("sudo", False))
            is_prod = bool(payload.get("is_production", True))
            res = ActionRiskClassifier.classify_command(
                cmd,
                sudo=sudo,
                is_production=is_prod,
                policy=pol,
            )
            old_content = payload.get("old_content")
            new_content = payload.get("new_content")
            diff_preview = (
                build_unified_diff(
                    str(payload.get("path") or "/etc/app.conf"),
                    str(old_content) if old_content is not None else None,
                    str(new_content),
                )
                if new_content is not None
                else None
            )
            req = await mgr.create_request(
                target_host=target_host,
                tool_name=tool_name,
                risk_tier=res.risk_tier,
                risk_reasons=res.reasons,
                command=cmd or None,
                sudo=sudo,
                diff=diff_preview,
            )
            return {
                "ok": True,
                "assessment": res.to_dict(),
                "approval": req.to_public_dict(),
            }
        if action in ("show", "get"):
            appr_id = str(payload.get("approval_id") or "")
            req = await mgr.get_request(appr_id)
            return {"ok": True, "approval": req.to_public_dict()}
        if action == "approve":
            appr_id = str(payload.get("approval_id") or "")
            by = str(payload.get("decided_by") or "dashboard_operator")
            reason = payload.get("reason")
            req = await mgr.approve(appr_id, decided_by=by, reason=str(reason) if reason else None)
            return {"ok": True, "approval": req.to_public_dict()}
        if action == "reject":
            appr_id = str(payload.get("approval_id") or "")
            by = str(payload.get("decided_by") or "dashboard_operator")
            reason = payload.get("reason")
            req = await mgr.reject(appr_id, decided_by=by, reason=str(reason) if reason else None)
            return {"ok": True, "approval": req.to_public_dict()}
        status_filter = payload.get("status")
        reqs = await mgr.list_requests(status=str(status_filter) if status_filter else None)
        return {
            "ok": True,
            "approvals": [r.to_public_dict() for r in reqs],
            "count": len(reqs),
        }

    return asyncio.run(_run())


def _execute_policy_sandbox(payload: dict[str, Any]) -> dict[str, Any]:
    """Интерактивный обработчик API для AST-анализатора команд и Policy-as-Code Guardrails."""
    from uniconn.mcp import ActionRiskClassifier, HITLPolicy
    from uniconn.security import (
        CommandASTParser,
        PolicyGuardrailConfig,
        build_auth_context,
        create_policy_engine,
    )

    command = str(payload.get("command") or "ls -la /var/log").strip()
    tool_name = str(payload.get("tool_name") or "uniconn_run").strip()
    path = payload.get("path")
    path_str = str(path).strip() if isinstance(path, str) and path.strip() else None
    host = str(payload.get("host") or "prod-db-01").strip()
    env = str(payload.get("environment") or payload.get("env") or "prod").strip()
    role = str(payload.get("role") or "operator").strip()
    agent_id = str(payload.get("agent_id") or "mcp-agent").strip()
    sudo = bool(payload.get("sudo", False))
    preset = str(payload.get("preset") or "prod-guard").strip()
    engine_type = str(payload.get("engine") or "embedded").strip().lower()
    opa_url = payload.get("opa_url")
    opa_url_str = str(opa_url).strip() if isinstance(opa_url, str) and opa_url.strip() else None
    mw_raw = payload.get("maintenance_window_active")
    mw_override: bool | None = bool(mw_raw) if isinstance(mw_raw, bool) else None
    max_depth = int(payload.get("max_ast_depth") or 4)
    max_pipe = int(payload.get("max_pipeline_length") or 8)

    is_prod = env.lower() in ("prod", "production", "prd", "critical")
    cfg = PolicyGuardrailConfig(
        enabled=True,
        engine="opa" if (engine_type == "opa" and opa_url_str) else "embedded",
        preset=preset,
        opa_url=opa_url_str,
        default_agent_id=agent_id,
        default_role=role,
        maintenance_window_active=mw_override,
        max_ast_depth=max_depth,
        max_pipeline_length=max_pipe,
    )
    engine = create_policy_engine(cfg)
    hitl_pol = HITLPolicy(enabled=True)

    ast = CommandASTParser.parse(
        command,
        max_depth=max_depth,
        max_pipeline_length=max_pipe,
    )
    if tool_name == "uniconn_write_file" and path_str:
        assessment = ActionRiskClassifier.classify_file_write(
            path_str,
            file_exists=True,
            is_production=is_prod,
            policy=hitl_pol,
        )
    else:
        assessment = ActionRiskClassifier.classify_command(
            command,
            sudo=sudo,
            is_production=is_prod,
            policy=hitl_pol,
            ast=ast,
        )

    auth_ctx = build_auth_context(
        agent_id=agent_id,
        role=role,
        host_name=host,
        groups=("prod", "database") if is_prod else ("staging",),
        environment=env,
        is_production=is_prod,
        tool_name=tool_name,
        command=command if tool_name != "uniconn_write_file" else None,
        ast=ast if tool_name != "uniconn_write_file" else None,
        sudo=sudo,
        path=path_str,
        risk_tier=assessment.risk_tier.value,
        risk_reasons=assessment.reasons,
        maintenance_window_override=mw_override,
    )

    async def _eval() -> dict[str, Any]:
        eval_res = await engine.evaluate(auth_ctx)
        return {
            "ok": True,
            "decision": eval_res.decision.value,
            "allowed": eval_res.allowed,
            "requires_approval": eval_res.requires_approval or assessment.requires_approval,
            "risk_assessment": assessment.to_dict(),
            "policy": eval_res.to_dict(),
            "ast": ast.to_dict(),
            "auth_context": auth_ctx.to_dict(),
        }

    return asyncio.run(_eval())


def _dispatch_endpoint(
    endpoint: str,
    payload: dict[str, Any] | None = None,
    state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Выполнить обработчик в текущем процессе или делегировать в подготовленный Python 3.12 venv."""
    global _CACHED_STATUS
    req_payload = payload or {}
    if endpoint == "status" and _CACHED_STATUS is not None:
        return _CACHED_STATUS

    if _can_import_uniconn_in_proc():
        res = _execute_endpoint_direct(endpoint, req_payload, state)
        if endpoint == "status":
            _CACHED_STATUS = res
        return res

    # Не блокируем /api/status во время фоновой инициализации uv venv при старте контейнера
    if endpoint == "status" and (_UV_BOOTSTRAP_LOCK.locked() or not _find_venv_python()):
        return _execute_endpoint_direct("status", req_payload, state)

    venv_py = _ensure_uv_env()
    if venv_py:
        try:
            rpc_input = json.dumps(
                {"endpoint": endpoint, "payload": req_payload, "state": state},
                ensure_ascii=False,
            )
            server_script = str((DASHBOARD_DIR / "server.py").resolve())
            proc = subprocess.run(
                [venv_py, server_script, "--rpc"],
                input=rpc_input,
                cwd=ROOT_DIR,
                env=_get_env(),
                capture_output=True,
                text=True,
                timeout=60,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                last_line = proc.stdout.strip().splitlines()[-1]
                rpc_resp = json.loads(last_line)
                if state is not None and isinstance(rpc_resp.get("state"), dict):
                    state.clear()
                    state.update(rpc_resp["state"])
                if isinstance(rpc_resp.get("result"), dict):
                    if endpoint == "status":
                        _CACHED_STATUS = rpc_resp["result"]
                    return rpc_resp["result"]
        except Exception:
            pass

    return _execute_endpoint_direct(endpoint, req_payload, state)


def _handle_rpc_cli() -> None:
    """Обработать одиночный JSON RPC-вызов внутри виртуального окружения Python 3.12."""
    raw = sys.stdin.read()
    req = json.loads(raw) if raw.strip() else {}
    endpoint = str(req.get("endpoint") or "status")
    payload = dict(req.get("payload") or {})
    state = req.get("state")
    state_dict = dict(state) if isinstance(state, dict) else None
    result = _execute_endpoint_direct(endpoint, payload, state_dict)
    sys.stdout.write(json.dumps({"result": result, "state": state_dict}, ensure_ascii=False) + "\n")
    sys.stdout.flush()
