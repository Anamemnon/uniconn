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


def _run_demo_status() -> dict[str, Any]:
    """Собрать актуальную информацию о библиотеке uniconn и доступных транспортах."""
    fallback_uname = f"{platform.system()} {platform.release()} {platform.machine()}".strip()
    fallback_py = f"Python {sys.version.split()[0]}"
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
            "ipmi",
            "kubectl",
            "local",
            "podman",
            "redfish",
            "replay",
            "serial",
            "ssh",
            "telnet",
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
    return {"error": f"Unknown endpoint: {endpoint}"}


def _dispatch_endpoint(
    endpoint: str,
    payload: dict[str, Any] | None = None,
    state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Выполнить обработчик в текущем процессе или делегировать в подготовленный Python 3.12 venv."""
    req_payload = payload or {}
    if _can_import_uniconn_in_proc():
        return _execute_endpoint_direct(endpoint, req_payload, state)

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
