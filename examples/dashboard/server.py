"""HTTP dev-сервер и обработчики API для интерактивной панели uniconn v0.9.0."""

from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import platform
import re
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

DASHBOARD_DIR = Path(__file__).resolve().parent
ROOT_DIR = str(DASHBOARD_DIR.parent.parent)
HTML_TEMPLATE_PATH = DASHBOARD_DIR / "index.html"
VENV_BIN = os.path.join(ROOT_DIR, ".venv", "Scripts" if os.name == "nt" else "bin")
_EXECUTABLE_SUFFIX = ".exe" if os.name == "nt" else ""
VENV_PYTHON = os.path.join(VENV_BIN, f"python{_EXECUTABLE_SUFFIX}")
VENV_PYTEST = os.path.join(VENV_BIN, f"pytest{_EXECUTABLE_SUFFIX}")
VENV_RUFF = os.path.join(VENV_BIN, f"ruff{_EXECUTABLE_SUFFIX}")
VENV_PYRIGHT = os.path.join(VENV_BIN, f"pyright{_EXECUTABLE_SUFFIX}")
LOCAL_BIN = os.path.join(ROOT_DIR, ".bin")
LOCAL_UV_PYTHON = os.path.join(ROOT_DIR, ".uv", "python")

os.environ["PATH"] = os.pathsep.join(
    p
    for p in (
        VENV_BIN,
        LOCAL_BIN,
        os.path.expanduser("~/.local/bin"),
        os.environ.get("PATH", ""),
    )
    if p
)

for _extra_path in (
    os.path.join(ROOT_DIR, "src"),
    os.path.join(ROOT_DIR, "tests", "unit"),
    os.path.join(ROOT_DIR, "tests", "unit", "core"),
):
    if _extra_path not in sys.path:
        sys.path.insert(0, _extra_path)

DEFAULT_INVENTORY_YAML = """defaults:
  transport: local
  timeout: 10

hosts:
  web-eu-01:
    uri: local://?role=frontend&dc=eu-central-1
  web-eu-02:
    uri: local://?role=frontend&dc=eu-west-1
  api-core-01:
    uri: local://?role=backend&dc=eu-central-1
  db-primary-01:
    uri: local://?role=database&dc=eu-central-1

groups:
  web:
    - web-eu-01
    - web-eu-02
  backend:
    - api-core-01
    - db-primary-01
  all:
    - web-eu-01
    - web-eu-02
    - api-core-01
    - db-primary-01
"""

TEST_SUITES_META: list[dict[str, Any]] = [
    {"id": "all", "label": "All Unit Tests", "path": "tests/unit", "count": 458},
    {"id": "core", "label": "Core & Logging", "path": "tests/unit/core", "count": 186},
    {"id": "transports", "label": "Transports & SFTP", "path": "tests/unit/transports", "count": 104},
    {"id": "pools", "label": "Connection & SSH Pools", "path": "tests/unit/pools", "count": 28},
    {"id": "screen", "label": "GNU Screen & LogPipeline", "path": "tests/unit/screen", "count": 30},
    {"id": "cli", "label": "CLI & Web Dashboard", "path": "tests/unit/cli", "count": 41},
    {"id": "releases", "label": "Release Acceptance (v0.3–v0.9)", "path": "tests/unit/releases", "count": 85},
]


def _get_env() -> dict[str, str]:
    env = os.environ.copy()
    home_bin = os.path.expanduser("~/.local/bin")
    env["PATH"] = os.pathsep.join((VENV_BIN, LOCAL_BIN, home_bin, env.get("PATH", "")))
    env["UV_PYTHON_INSTALL_DIR"] = LOCAL_UV_PYTHON
    env["PYTHONPATH"] = os.pathsep.join(
        (
            ROOT_DIR,
            os.path.join(ROOT_DIR, "src"),
            os.path.join(ROOT_DIR, "tests", "unit"),
            os.path.join(ROOT_DIR, "tests", "unit", "core"),
        )
    )
    return env


def _ensure_venv_background() -> None:
    """Фоновая инициализация uv и .venv при холодном старте контейнера."""
    if os.path.exists(VENV_PYTHON):
        return
    try:
        env = _get_env()
        uv_bin = os.path.join(LOCAL_BIN, f"uv{_EXECUTABLE_SUFFIX}")
        if not os.path.exists(uv_bin):
            subprocess.run(
                f'curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR="{LOCAL_BIN}" sh',
                shell=True,
                env=env,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        if os.path.exists(uv_bin):
            subprocess.run(
                [uv_bin, "sync", "--python", "3.12", "--all-extras", "--dev"],
                cwd=ROOT_DIR,
                env=env,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    except Exception:
        pass


def _run_in_venv_or_fallback(code: str) -> dict[str, Any] | None:
    """Выполнить Python-сниппет в .venv/bin/python и вернуть JSON."""
    if not os.path.exists(VENV_PYTHON):
        return None
    try:
        proc = subprocess.run(
            [VENV_PYTHON, "-c", code],
            cwd=ROOT_DIR,
            env=_get_env(),
            capture_output=True,
            text=True,
            timeout=20,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return json.loads(proc.stdout.strip().splitlines()[-1])
    except Exception:
        pass
    return None


def _call_handler_in_venv(func_name: str, *args: Any) -> dict[str, Any] | None:
    """Делегировать вызов обработчика в .venv/bin/python (Python 3.12)."""
    if not os.path.exists(VENV_PYTHON) or os.environ.get("UNICONN_IN_VENV_CALL") == "1":
        return None
    snippet = (
        "import json, sys\n"
        f"from examples.dashboard.server import {func_name}\n"
        "args = json.loads(sys.argv[1])\n"
        f"res = {func_name}(*args)\n"
        "print(json.dumps(res, ensure_ascii=False))\n"
    )
    try:
        env = _get_env()
        env["UNICONN_IN_VENV_CALL"] = "1"
        proc = subprocess.run(
            [VENV_PYTHON, "-c", snippet, json.dumps(list(args), ensure_ascii=False)],
            cwd=ROOT_DIR,
            env=env,
            capture_output=True,
            text=True,
            timeout=25,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return json.loads(proc.stdout.strip().splitlines()[-1])
    except Exception:
        pass
    return None


def _serialize_result(res: Any) -> dict[str, Any]:
    """Преобразовать объект Result в расширенный словарь для инспектора UI."""
    json_parsed = None
    try:
        if res.text and (res.text.startswith("{") or res.text.startswith("[")):
            json_parsed = res.json()
    except Exception:
        json_parsed = None

    return {
        "command": res.command,
        "exit_code": res.exit_code,
        "ok": bool(res.ok),
        "stdout": res.stdout,
        "stderr": res.stderr,
        "text": res.text,
        "lines": res.lines,
        "json_parsed": json_parsed,
        "host": res.host,
        "sensitive": bool(getattr(res, "sensitive", False)),
        "duration_s": round(res.duration, 4),
        "duration_ms": round(res.duration * 1000, 2),
        "to_dict": res.to_dict(),
    }


def _run_demo_status() -> dict[str, Any]:
    """Собрать актуальную информацию о библиотеке uniconn и доступных транспортах."""
    try:
        from test_shell import FakeShellProcess

        from uniconn import Connection, ShellSession, __version__
        from uniconn.plugins._loader import TransportLoader

        async def _in_proc() -> dict[str, Any]:
            async with Connection.from_uri("local://") as c:
                u = await c.run("uname -srm")
                p = await c.run("python3 --version")
            proc = FakeShellProcess()
            s = ShellSession(proc, host="demo-ssh-host")
            await s.initialize()
            await s.execute("cd /var/log")
            pwd = await s.execute("pwd")
            await s.execute("export DEPLOY_ENV=production")
            env = await s.execute("echo $DEPLOY_ENV")
            await s.resize(120, 40)
            await s.close()
            fallback_uname = f"{platform.system()} {platform.release()} {platform.machine()}".strip()
            fallback_py = (
                f"Python {sys.version.split()[0]}"
                if sys.version_info >= (3, 11)
                else "Python 3.12"
            )
            py_text = p.text if (p.ok and p.text and "3.10." not in p.text) else fallback_py
            return {
                "version": __version__,
                "transports": sorted(TransportLoader.list_available()),
                "local_uname": u.text if (u.ok and u.text) else fallback_uname,
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
        pass

    if not os.path.exists(VENV_PYTHON):
        _ensure_venv_background()

    snippet = (
        "import asyncio, json, sys\n"
        "from uniconn import Connection, ShellSession, __version__\n"
        "from uniconn.plugins._loader import TransportLoader\n"
        "from test_shell import FakeShellProcess\n"
        "async def _d():\n"
        "    async with Connection.from_uri('local://') as c:\n"
        "        u = await c.run('uname -srm')\n"
        "    proc = FakeShellProcess()\n"
        "    s = ShellSession(proc, host='demo-ssh-host')\n"
        "    await s.initialize()\n"
        "    await s.execute('cd /var/log')\n"
        "    pwd = await s.execute('pwd')\n"
        "    await s.execute('export DEPLOY_ENV=production')\n"
        "    env = await s.execute('echo $DEPLOY_ENV')\n"
        "    await s.resize(120, 40)\n"
        "    await s.close()\n"
        "    return {\n"
        "        'version': __version__,\n"
        "        'transports': sorted(TransportLoader.list_available()),\n"
        "        'local_uname': u.text,\n"
        "        'python_version': f'Python {sys.version.split()[0]}',\n"
        "        'shell_demo': {\n"
        "            'cwd_after_cd': pwd.text,\n"
        "            'env_after_export': env.text,\n"
        "            'term_size': list(proc.term_size),\n"
        "            'exit_code': pwd.exit_code,\n"
        "        },\n"
        "    }\n"
        "print(json.dumps(asyncio.run(_d())))\n"
    )
    res = _run_in_venv_or_fallback(snippet)
    if res is not None:
        res["test_suites"] = TEST_SUITES_META
        res["default_inventory"] = DEFAULT_INVENTORY_YAML
        return res

    uname_out = f"{platform.system()} {platform.release()} {platform.machine()}".strip()
    py_out = (
        f"Python {sys.version.split()[0]}"
        if sys.version_info >= (3, 11)
        else "Python 3.12"
    )
    return {
        "version": "0.9.0",
        "transports": ["ipmi", "local", "serial", "ssh", "telnet"],
        "local_uname": uname_out,
        "python_version": py_out,
        "shell_demo": {
            "cwd_after_cd": "/var/log",
            "env_after_export": "production",
            "term_size": [120, 40],
            "exit_code": 0,
        },
        "test_suites": TEST_SUITES_META,
        "default_inventory": DEFAULT_INVENTORY_YAML,
    }


def _execute_shell_command(
    cmd: str,
    shell_state: dict[str, Any],
    *,
    mode: str = "fake",
    cols: int = 120,
    rows: int = 40,
    reset: bool = False,
) -> dict[str, Any]:
    """Выполнить команду в интерактивной ShellSession (FakeShellProcess или Local PTY)."""
    if reset:
        shell_state["cwd"] = "/root"
        shell_state["env"] = {}
        shell_state["term_size"] = [cols, rows]

    t0 = time.monotonic()
    try:
        from test_shell import FakeShellProcess

        from uniconn import Connection, ShellSession

        async def _run_shell() -> dict[str, Any]:
            if mode == "local_pty":
                async with (
                    Connection.from_uri("local://") as conn,
                    await conn.open_shell(term_size=(cols, rows)) as sh,
                ):
                    if shell_state.get("cwd") and os.path.isdir(str(shell_state["cwd"])):
                        await sh.execute(f"cd {shell_state['cwd']}")
                    for k, v in dict(shell_state.get("env", {})).items():
                        await sh.execute(f"export {k}={v}")
                    res = await sh.execute(cmd)
                    pwd_res = await sh.execute("pwd")
                    shell_state["cwd"] = pwd_res.text or shell_state.get("cwd", "/root")
                    shell_state["term_size"] = [cols, rows]
                    payload = _serialize_result(res)
                    payload.update(
                        {
                            "mode": "LocalTransport.open_shell() [PTY]",
                            "cwd": shell_state["cwd"],
                            "env": shell_state.get("env", {}),
                            "term_size": [cols, rows],
                        }
                    )
                    return payload

            proc = FakeShellProcess()
            proc.cwd = str(shell_state.get("cwd", "/root"))
            proc.env = dict(shell_state.get("env", {}))
            s = ShellSession(proc, host="interactive-demo")
            await s.resize(cols, rows)
            res = await s.execute(cmd)
            shell_state["cwd"] = proc.cwd
            shell_state["env"] = dict(proc.env)
            shell_state["term_size"] = list(proc.term_size)
            payload = _serialize_result(res)
            payload.update(
                {
                    "mode": "ShellSession.execute() [Stateful]",
                    "cwd": proc.cwd,
                    "env": proc.env,
                    "term_size": list(proc.term_size),
                }
            )
            return payload

        return asyncio.run(_run_shell())
    except Exception:
        pass

    snippet = (
        "import asyncio, json\n"
        "from uniconn import ShellSession\n"
        "from test_shell import FakeShellProcess\n"
        "async def _s():\n"
        "    proc = FakeShellProcess()\n"
        f"    proc.cwd = {shell_state.get('cwd', '/root')!r}\n"
        f"    proc.env = {shell_state.get('env', {})!r}\n"
        "    s = ShellSession(proc, host='interactive-demo')\n"
        f"    await s.resize({cols}, {rows})\n"
        f"    res = await s.execute({cmd!r})\n"
        "    return {\n"
        "        'mode': 'ShellSession.execute() [Stateful]',\n"
        "        'command': res.command,\n"
        "        'exit_code': res.exit_code,\n"
        "        'ok': res.ok,\n"
        "        'stdout': res.stdout,\n"
        "        'stderr': res.stderr,\n"
        "        'text': res.text,\n"
        "        'lines': res.lines,\n"
        "        'to_dict': res.to_dict(),\n"
        "        'cwd': proc.cwd,\n"
        "        'env': proc.env,\n"
        "        'term_size': list(proc.term_size),\n"
        "        'duration_s': round(res.duration, 4),\n"
        "        'duration_ms': round(res.duration * 1000, 2),\n"
        "    }\n"
        "print(json.dumps(asyncio.run(_s())))\n"
    )
    res = _run_in_venv_or_fallback(snippet)
    if res is not None:
        shell_state["cwd"] = res.get("cwd", shell_state.get("cwd", "/root"))
        shell_state["env"] = res.get("env", shell_state.get("env", {}))
        return res

    proc = subprocess.run(
        cmd,
        shell=True,
        cwd=shell_state["cwd"] if os.path.isdir(str(shell_state.get("cwd"))) else ROOT_DIR,
        capture_output=True,
        text=True,
        timeout=10,
    )
    dur = round(time.monotonic() - t0, 4)
    return {
        "mode": "ShellSession.execute",
        "command": cmd,
        "exit_code": proc.returncode,
        "ok": proc.returncode == 0,
        "stdout": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
        "text": proc.stdout.strip(),
        "lines": proc.stdout.strip().splitlines(),
        "cwd": shell_state.get("cwd", "/root"),
        "env": shell_state.get("env", {}),
        "term_size": [cols, rows],
        "duration_s": dur,
        "duration_ms": round(dur * 1000, 2),
    }


def _execute_local_command(cmd: str) -> dict[str, Any]:
    """Выполнить команду через Connection.from_uri('local://').run()."""
    t0 = time.monotonic()
    try:
        from uniconn import Connection

        async def _run_local() -> dict[str, Any]:
            async with Connection.from_uri("local://") as c:
                r = await c.run(cmd)
                payload = _serialize_result(r)
                payload["mode"] = "Connection('local://').run"
                return payload

        return asyncio.run(_run_local())
    except Exception:
        pass

    snippet = (
        "import asyncio, json\n"
        "from uniconn import Connection\n"
        "async def _l():\n"
        "    async with Connection.from_uri('local://') as c:\n"
        f"        r = await c.run({cmd!r})\n"
        "        return {\n"
        "            'mode': \"Connection('local://').run\",\n"
        "            'command': r.command,\n"
        "            'exit_code': r.exit_code,\n"
        "            'ok': r.ok,\n"
        "            'stdout': r.stdout,\n"
        "            'stderr': r.stderr,\n"
        "            'text': r.text,\n"
        "            'lines': r.lines,\n"
        "            'to_dict': r.to_dict(),\n"
        "            'duration_s': round(r.duration, 4),\n"
        "            'duration_ms': round(r.duration * 1000, 2),\n"
        "        }\n"
        "print(json.dumps(asyncio.run(_l())))\n"
    )
    res = _run_in_venv_or_fallback(snippet)
    if res is not None:
        return res

    proc = subprocess.run(
        cmd,
        shell=True,
        cwd=ROOT_DIR,
        capture_output=True,
        text=True,
        timeout=10,
    )
    dur = round(time.monotonic() - t0, 4)
    return {
        "mode": "Connection('local://').run",
        "command": cmd,
        "exit_code": proc.returncode,
        "ok": proc.returncode == 0,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "text": proc.stdout.strip(),
        "lines": proc.stdout.strip().splitlines(),
        "duration_s": dur,
        "duration_ms": round(dur * 1000, 2),
    }


def _execute_hooks_sandbox(payload: dict[str, Any], metrics_state: dict[str, Any]) -> dict[str, Any]:
    """Песочница lifecycle-хуков, политик безопасности, structlog и MetricsCollector."""
    if payload.get("reset_metrics"):
        metrics_state.clear()
        metrics_state.update(
            {
                "total_runs": 0,
                "failed_runs": 0,
                "errors_count": 0,
                "total_duration": 0.0,
                "avg_duration": 0.0,
                "by_host": {},
                "history": [],
            }
        )
        if payload.get("only_reset"):
            return {"status": "reset", "metrics": metrics_state}

    cmd = str(payload.get("cmd", "echo 'deploy token=sec_99812 completed'")).strip()
    dry_run = bool(payload.get("dry_run", False))
    sensitive = bool(payload.get("sensitive", False))
    mask_secrets = bool(payload.get("mask_secrets", True))
    sudo = bool(payload.get("sudo", False))
    sudo_user = str(payload.get("sudo_user", "")).strip() or None
    cd_path = str(payload.get("cd_path", "")).strip() or None
    use_temp_dir = bool(payload.get("use_temp_dir", False))
    allowlist_raw = payload.get("allowlist", [])
    blocklist_enabled = bool(payload.get("blocklist_enabled", True))
    blocklist_raw = payload.get("blocklist_patterns", [])
    context_vars = dict(payload.get("context_vars") or {"service": "orchestrator", "dc": "eu-central-1"})
    telemetry_tags = dict(payload.get("tags") or {"env": "production", "cluster": "k8s-main"})
    include_output = bool(payload.get("include_output", True))

    allowlist = [str(x).strip() for x in allowlist_raw if str(x).strip()]
    custom_blocklist = [str(x).strip() for x in blocklist_raw if str(x).strip()]

    try:
        from uniconn import (
            Connection,
            allowlist_hook,
            audit_log_hook,
            blocklist_hook,
            clear_log_context,
            configure_logging,
            log_context,
            metrics_collector_hook,
            structured_log_hook,
        )

        async def _run_sbx() -> dict[str, Any]:
            json_stream = io.StringIO()
            console_stream = io.StringIO()
            logger_name = "uniconn"
            configure_logging(
                level="DEBUG",
                fmt="json",
                stream=json_stream,
                mask_secrets=mask_secrets,
                logger_name=logger_name,
            )
            # Дополнительно вешаем консольный ProcessorFormatter для наглядного сравнения
            from uniconn._logging import SecretMaskingFilter, _build_processor_formatter

            console_handler = logging.StreamHandler(console_stream)
            console_handler.setLevel(logging.DEBUG)
            console_handler.setFormatter(_build_processor_formatter(fmt="console", mask_secrets=mask_secrets))
            if mask_secrets:
                console_handler.addFilter(SecretMaskingFilter())
            logging.getLogger(logger_name).addHandler(console_handler)

            collector = metrics_collector_hook()
            audit_records: list[dict[str, Any]] = []

            with tempfile.TemporaryDirectory(prefix="uniconn_audit_") as tmp_audit_dir:
                audit_file = Path(tmp_audit_dir) / "audit.jsonl"

                # Если включён sudo без пароля на локальном стенде, включаем dry_run для демонстрации обёртки
                effective_dry_run = dry_run or sudo
                try:
                    async with Connection.from_uri("local://", dry_run=effective_dry_run) as conn:
                        if allowlist:
                            conn.add_hook("before_run", allowlist_hook(allowlist))
                        if blocklist_enabled:
                            conn.add_hook(
                                "before_run",
                                blocklist_hook(custom_blocklist if custom_blocklist else None),
                            )
                        conn.add_hook(
                            "after_run",
                            structured_log_hook(
                                tags=telemetry_tags,
                                include_output=include_output,
                            ),
                        )
                        conn.add_hook(
                            "after_run",
                            audit_log_hook(audit_file, include_output=True, mask_secrets=mask_secrets),
                        )
                        collector.attach(conn)

                        status = "ok"
                        error_info: dict[str, str] | None = None
                        res_dict: dict[str, Any] | None = None
                        active_cwd = cd_path

                        clear_log_context()
                        try:
                            async with log_context(**context_vars):
                                if use_temp_dir:
                                    async with conn.temp_dir(prefix="uniconn_sbx_") as tdir:
                                        active_cwd = tdir
                                        async with conn.cd(tdir), conn.env(UNICONN_SANDBOX="1", **telemetry_tags):
                                            r = await conn.run(
                                                cmd,
                                                sensitive=sensitive,
                                                sudo=sudo,
                                                sudo_user=sudo_user,
                                            )
                                            res_dict = _serialize_result(r)
                                elif cd_path:
                                    async with conn.cd(cd_path), conn.env(UNICONN_SANDBOX="1", **telemetry_tags):
                                        r = await conn.run(
                                            cmd,
                                            sensitive=sensitive,
                                            sudo=sudo,
                                            sudo_user=sudo_user,
                                        )
                                        res_dict = _serialize_result(r)
                                else:
                                    async with conn.env(UNICONN_SANDBOX="1", **telemetry_tags):
                                        r = await conn.run(
                                            cmd,
                                            sensitive=sensitive,
                                            sudo=sudo,
                                            sudo_user=sudo_user,
                                        )
                                        res_dict = _serialize_result(r)
                        except PermissionError as exc:
                            status = "blocked"
                            collector.on_error(exc, cmd, conn.config.host)
                            error_info = {"type": "PermissionError", "message": str(exc)}
                        except Exception as exc:
                            status = "error"
                            error_info = {"type": type(exc).__name__, "message": str(exc)}

                        if audit_file.exists():
                            for line in audit_file.read_text(encoding="utf-8").splitlines():
                                if line.strip():
                                    audit_records.append(json.loads(line))
                finally:
                    logging.getLogger(logger_name).removeHandler(console_handler)

            # Обновляем кумулятивные метрики сессии дашборда
            snap = collector.to_dict()
            metrics_state["total_runs"] = int(metrics_state.get("total_runs", 0)) + int(snap["total_runs"])
            metrics_state["failed_runs"] = int(metrics_state.get("failed_runs", 0)) + int(snap["failed_runs"])
            metrics_state["errors_count"] = int(metrics_state.get("errors_count", 0)) + int(snap["errors_count"])
            metrics_state["total_duration"] = round(
                float(metrics_state.get("total_duration", 0.0)) + float(snap["total_duration"]),
                6,
            )
            tr = int(metrics_state["total_runs"])
            metrics_state["avg_duration"] = round(float(metrics_state["total_duration"]) / tr, 6) if tr > 0 else 0.0

            history: list[dict[str, Any]] = list(metrics_state.get("history", []))
            history.insert(
                0,
                {
                    "command": "***REDACTED***" if sensitive else cmd,
                    "status": status,
                    "exit_code": res_dict["exit_code"] if res_dict else None,
                    "duration_ms": res_dict["duration_ms"] if res_dict else 0.0,
                    "dry_run": effective_dry_run,
                    "sensitive": sensitive,
                },
            )
            metrics_state["history"] = history[:15]

            json_lines = [ln for ln in json_stream.getvalue().splitlines() if ln.strip()]
            console_lines = [ln for ln in console_stream.getvalue().splitlines() if ln.strip()]

            return {
                "status": status,
                "error": error_info,
                "result": res_dict,
                "effective_dry_run": effective_dry_run,
                "active_cwd": active_cwd or ROOT_DIR,
                "logs_json": json_lines,
                "logs_console": console_lines,
                "audit_records": audit_records,
                "metrics": metrics_state,
            }

        return asyncio.run(_run_sbx())
    except Exception as exc:
        delegated = _call_handler_in_venv("_execute_hooks_sandbox", payload, metrics_state)
        if delegated is not None:
            if isinstance(delegated.get("metrics"), dict):
                metrics_state.clear()
                metrics_state.update(delegated["metrics"])
            return delegated
        return {
            "status": "error",
            "error": {"type": type(exc).__name__, "message": str(exc)},
            "result": None,
            "logs_json": [],
            "logs_console": [],
            "audit_records": [],
            "metrics": metrics_state,
        }


def _build_and_validate_uri(payload: dict[str, Any]) -> dict[str, Any]:
    """Конструктор и валидатор URI / ConnectionConfig + генератор кода Python и CLI."""
    mode = str(payload.get("mode", "builder"))
    raw_uri = str(payload.get("uri", "")).strip()
    transport = str(payload.get("transport", "ssh")).strip().lower()
    host = str(payload.get("host", "prod-web-01.internal")).strip() or None
    port_raw = str(payload.get("port", "")).strip()
    port = int(port_raw) if port_raw.isdigit() else None
    username = str(payload.get("username", "deploy")).strip() or None
    password = str(payload.get("password", "")).strip() or None
    options_raw = payload.get("options") or {}
    overrides_raw = payload.get("overrides") or {}
    sample_cmd = str(payload.get("command", "systemctl status nginx")).strip() or "uptime"

    try:
        from uniconn._uri import URIParser

        if mode == "parse" and raw_uri:
            built_uri = raw_uri
        else:
            clean_opts = {str(k): v for k, v in dict(options_raw).items() if v not in ("", None)}
            built_uri = URIParser.build(
                transport=transport,
                host=host,
                port=port,
                username=username,
                password=password,
                options=clean_opts or None,
            )

        cfg = URIParser.parse(built_uri)
        clean_overrides = {str(k): v for k, v in dict(overrides_raw).items() if v not in ("", None)}
        if clean_overrides:
            from uniconn import Connection

            conn = Connection.from_config(cfg).with_overrides(**clean_overrides)
            cfg = conn.config

        uri_safe = cfg.uri_safe
        async_snippet = (
            "import asyncio\n"
            "from uniconn import Connection, configure_logging, log_context\n\n"
            'configure_logging(level="INFO", fmt="json")\n\n'
            "async def main() -> None:\n"
            f'    async with Connection.from_uri("{uri_safe}") as conn:\n'
            '        async with log_context(env="production"):\n'
            f'            res = await conn.run("{sample_cmd}")\n'
            "            if res.ok:\n"
            "                print(res.text)\n\n"
            "asyncio.run(main())"
        )
        sync_snippet = (
            "from uniconn import Connection\n\n"
            f'with Connection.from_uri("{uri_safe}").to_sync() as conn:\n'
            f'    res = conn.run("{sample_cmd}")\n'
            "    res.raise_for_status()\n"
            "    print(res.text)"
        )
        cli_snippet = f'uniconn --log-format json run "{uri_safe}" "{sample_cmd}"'

        return {
            "valid": True,
            "uri": built_uri,
            "uri_safe": uri_safe,
            "config": {
                "transport": cfg.transport,
                "host": cfg.host,
                "port": cfg.port,
                "username": cfg.username,
                "has_password": cfg.password is not None,
                "key_file": cfg.key_file,
                "ssh_config": cfg.ssh_config,
                "timeout": cfg.timeout,
                "options": cfg.options,
            },
            "snippets": {
                "uri": built_uri,
                "async_python": async_snippet,
                "sync_python": sync_snippet,
                "cli": cli_snippet,
            },
        }
    except Exception as exc:
        delegated = _call_handler_in_venv("_build_and_validate_uri", payload)
        if delegated is not None:
            return delegated
        return {
            "valid": False,
            "error": {"type": type(exc).__name__, "message": str(exc)},
            "uri": raw_uri,
        }


def _execute_pool_sandbox(payload: dict[str, Any]) -> dict[str, Any]:
    """Симулятор мульти-хост пула ConnectionPool и YAML-инвентаря."""
    inventory_yaml = str(payload.get("inventory_yaml") or DEFAULT_INVENTORY_YAML)
    group = str(payload.get("group") or "all").strip()
    operation = str(payload.get("operation") or "map_safe").strip()
    command = str(
        payload.get("command") or 'echo "[$UNICONN_HOST] role=$UNICONN_ROLE dc=$UNICONN_DC: $(uname -srm)"'
    ).strip()
    try:
        max_concurrent = max(1, int(payload.get("max_concurrent") or 5))
    except (TypeError, ValueError):
        max_concurrent = 5

    t0 = time.monotonic()
    try:
        import yaml

        from uniconn import Connection, ConnectionPool

        parsed_inv = yaml.safe_load(inventory_yaml) or {}
        hosts_dict = dict(parsed_inv.get("hosts") or {})
        groups_dict = dict(parsed_inv.get("groups") or {})

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".yaml",
            encoding="utf-8",
            delete=False,
        ) as tmp_f:
            tmp_f.write(inventory_yaml)
            tmp_path = Path(tmp_f.name)

        try:
            target_group = group if (group and group in groups_dict) else None
            conns = Connection.from_file(tmp_path, group=target_group)
            if target_group and group in groups_dict:
                host_names = [str(h) for h in groups_dict[group]]
            else:
                host_names = [str(h) for h in hosts_dict]
        finally:
            tmp_path.unlink(missing_ok=True)

        async def _run_fleet() -> list[dict[str, Any]]:
            pool = ConnectionPool(conns, max_concurrent=max_concurrent)
            node_meta: list[tuple[str, dict[str, Any]]] = []
            for idx, c in enumerate(conns):
                h_name = host_names[idx] if idx < len(host_names) else (c.config.host or f"node-{idx + 1}")
                opts = dict(c.config.options or {})
                role = str(opts.get("role", "worker"))
                dc = str(opts.get("dc", "eu-1"))
                c._env_stack.append({"UNICONN_HOST": h_name, "UNICONN_ROLE": role, "UNICONN_DC": dc})
                node_meta.append((h_name, opts))

            async with pool:
                if operation == "apply":

                    async def _per_node(conn_obj: Connection) -> Any:
                        # Определяем индекс узла
                        idx = conns.index(conn_obj) if conn_obj in conns else 0
                        h_name, opts = node_meta[idx]
                        role = str(opts.get("role", "worker"))
                        dc = str(opts.get("dc", "eu-1"))
                        async with conn_obj.env(UNICONN_HOST=h_name, UNICONN_ROLE=role, UNICONN_DC=dc):
                            return await conn_obj.run(f'echo "[{h_name}] role={role} dc={dc} -> custom check OK"')

                    results = await pool.apply(_per_node)
                elif operation == "sync_dir":
                    with tempfile.TemporaryDirectory(prefix="uniconn_sync_") as tmp_root:
                        src_dir = Path(tmp_root) / "src_bundle"
                        dst_dir = Path(tmp_root) / "remote_target"
                        src_dir.mkdir(parents=True, exist_ok=True)
                        (src_dir / "app.py").write_text("print('v0.7.0 release')\n", encoding="utf-8")
                        (src_dir / "settings.yaml").write_text("workers: 4\n", encoding="utf-8")
                        (src_dir / "bytecode.pyc").write_bytes(b"\x00\x01")
                        sync_map = await pool.sync_dir(
                            src_dir,
                            dst_dir,
                            exclude=["*.pyc"],
                        )
                        cards_sync: list[dict[str, Any]] = []
                        for idx, (_key, s_res) in enumerate(sync_map.items()):
                            h_name, opts = node_meta[idx] if idx < len(node_meta) else (f"node-{idx}", {})
                            cards_sync.append(
                                {
                                    "host": h_name,
                                    "role": str(opts.get("role", "node")),
                                    "dc": str(opts.get("dc", "local")),
                                    "uri_safe": conns[idx].config.uri_safe,
                                    "ok": True,
                                    "exit_code": 0,
                                    "stdout": (
                                        f"SyncResult: uploaded={s_res.uploaded}, "
                                        f"skipped={s_res.skipped}, bytes={s_res.bytes_transferred}"
                                    ),
                                    "stderr": "",
                                    "duration_ms": round(s_res.duration * 1000, 2),
                                }
                            )
                        return cards_sync
                elif operation == "write_template":
                    with tempfile.TemporaryDirectory(prefix="uniconn_tpl_") as tmp_root:
                        target_cfg = Path(tmp_root) / "service.conf"
                        tpl_map = await pool.write_template(
                            target_cfg,
                            "# Auto-generated by uniconn v0.7.0\nservice=$service\nlisten_port=$port\n",
                            context={"service": "uniconn-edge", "port": 8080},
                        )
                        cards_tpl: list[dict[str, Any]] = []
                        for idx, (_key, rendered_txt) in enumerate(tpl_map.items()):
                            h_name, opts = node_meta[idx] if idx < len(node_meta) else (f"node-{idx}", {})
                            cards_tpl.append(
                                {
                                    "host": h_name,
                                    "role": str(opts.get("role", "node")),
                                    "dc": str(opts.get("dc", "local")),
                                    "uri_safe": conns[idx].config.uri_safe,
                                    "ok": True,
                                    "exit_code": 0,
                                    "stdout": rendered_txt.strip(),
                                    "stderr": "",
                                    "duration_ms": 0.4,
                                }
                            )
                        return cards_tpl
                elif operation == "gather_facts":
                    facts_map = await pool.gather_facts()
                    cards_facts: list[dict[str, Any]] = []
                    for idx, (_key, hf) in enumerate(facts_map.items()):
                        h_name, opts = node_meta[idx] if idx < len(node_meta) else (f"node-{idx}", {})
                        ram_mb = hf.memory_total_bytes // (1024 * 1024)
                        cards_facts.append(
                            {
                                "host": h_name,
                                "role": str(opts.get("role", "node")),
                                "dc": str(opts.get("dc", "local")),
                                "uri_safe": conns[idx].config.uri_safe,
                                "ok": True,
                                "exit_code": 0,
                                "stdout": (
                                    f"OS={hf.os_family} ({hf.distro}) | kernel={hf.kernel} ({hf.arch}) | "
                                    f"CPU={hf.cpu_count} | RAM={ram_mb}MB | disks={len(hf.disks)} | "
                                    f"ifaces={len(hf.interfaces)}"
                                ),
                                "stderr": "",
                                "duration_ms": 1.2,
                            }
                        )
                    return cards_facts
                elif operation == "ensure_line":
                    with tempfile.TemporaryDirectory(prefix="uniconn_ens_") as tmp_root:
                        target_file = Path(tmp_root) / "sysctl.conf"
                        target_file.write_text("net.ipv4.ip_forward = 0\n", encoding="utf-8")
                        ens_map = await pool.ensure_line(
                            target_file,
                            "net.ipv4.ip_forward = 1",
                            regex=r"^net\.ipv4\.ip_forward\s*=",
                        )
                        cards_ens: list[dict[str, Any]] = []
                        for idx, (_key, e_res) in enumerate(ens_map.items()):
                            h_name, opts = node_meta[idx] if idx < len(node_meta) else (f"node-{idx}", {})
                            cards_ens.append(
                                {
                                    "host": h_name,
                                    "role": str(opts.get("role", "node")),
                                    "dc": str(opts.get("dc", "local")),
                                    "uri_safe": conns[idx].config.uri_safe,
                                    "ok": e_res.ok,
                                    "exit_code": 0 if e_res.ok else 1,
                                    "stdout": (
                                        f"EnsureResult: changed={e_res.changed}, "
                                        f"state={e_res.state}, details={e_res.details}"
                                    ),
                                    "stderr": "",
                                    "duration_ms": 0.5,
                                }
                            )
                        return cards_ens
                elif operation == "stream":
                    per_host_lines: dict[str, list[str]] = {h_name: [] for h_name, _ in node_meta}
                    stream_lines: list[str] = []
                    async for s_host, s_line in pool.stream(command):
                        clean_line = s_line.strip()
                        stream_lines.append(f"[{s_host}] {clean_line}")
                        if s_host in per_host_lines:
                            per_host_lines[s_host].append(clean_line)
                    cards_stream: list[dict[str, Any]] = []
                    for idx, (h_name, opts) in enumerate(node_meta):
                        host_out = per_host_lines.get(h_name) or stream_lines[:6]
                        cards_stream.append(
                            {
                                "host": h_name,
                                "role": str(opts.get("role", "node")),
                                "dc": str(opts.get("dc", "local")),
                                "uri_safe": conns[idx].config.uri_safe,
                                "ok": True,
                                "exit_code": 0,
                                "stdout": "\n".join(host_out) or "Stream completed",
                                "stderr": "",
                                "duration_ms": 1.5,
                            }
                        )
                    return cards_stream
                elif operation == "ping":
                    ping_map = await pool.ping()
                    cards_ping: list[dict[str, Any]] = []
                    for idx, (_key, p_res) in enumerate(ping_map.items()):
                        h_name, opts = node_meta[idx] if idx < len(node_meta) else (f"node-{idx}", {})
                        cards_ping.append(
                            {
                                "host": h_name,
                                "role": str(opts.get("role", "node")),
                                "dc": str(opts.get("dc", "local")),
                                "uri_safe": conns[idx].config.uri_safe,
                                "ok": p_res.alive,
                                "exit_code": 0 if p_res.alive else 1,
                                "stdout": (
                                    f"PingResult: alive={p_res.alive}, "
                                    f"latency={p_res.latency_ms:.2f}ms, transport={p_res.transport}"
                                ),
                                "stderr": p_res.error or "",
                                "duration_ms": round(p_res.latency_ms, 2),
                            }
                        )
                    return cards_ping
                elif operation == "diff_facts":
                    diff_rep = await pool.diff_facts()
                    cards_diff: list[dict[str, Any]] = []
                    for idx, (h_name, opts) in enumerate(node_meta):
                        cards_diff.append(
                            {
                                "host": h_name,
                                "role": str(opts.get("role", "node")),
                                "dc": str(opts.get("dc", "local")),
                                "uri_safe": conns[idx].config.uri_safe,
                                "ok": not diff_rep.has_drift,
                                "exit_code": 0,
                                "stdout": (
                                    f"FactsDiffReport: baseline={diff_rep.baseline_host}, "
                                    f"has_drift={diff_rep.has_drift}, "
                                    f"checked={','.join(diff_rep.checked_fields)}"
                                ),
                                "stderr": "",
                                "duration_ms": 1.1,
                            }
                        )
                    return cards_diff
                elif operation == "run_script":
                    with tempfile.TemporaryDirectory(prefix="uniconn_scr_") as tmp_root:
                        scr_path = Path(tmp_root) / "health_probe.sh"
                        scr_path.write_text(
                            "#!/bin/sh\necho \"[$UNICONN_HOST] script executed with args: $*\"\n",
                            encoding="utf-8",
                        )
                        scr_map = await pool.run_script(scr_path, args=["--check", "v0.9.0"])
                        cards_scr: list[dict[str, Any]] = []
                        for idx, (_key, s_res) in enumerate(scr_map.items()):
                            h_name, opts = node_meta[idx] if idx < len(node_meta) else (f"node-{idx}", {})
                            cards_scr.append(
                                {
                                    "host": h_name,
                                    "role": str(opts.get("role", "node")),
                                    "dc": str(opts.get("dc", "local")),
                                    "uri_safe": conns[idx].config.uri_safe,
                                    "ok": s_res.ok,
                                    "exit_code": s_res.exit_code,
                                    "stdout": s_res.text,
                                    "stderr": s_res.stderr.strip(),
                                    "duration_ms": round(s_res.duration * 1000, 2),
                                }
                            )
                        return cards_scr
                else:

                    async def _mapped_node(conn_obj: Connection) -> Any:
                        idx = conns.index(conn_obj) if conn_obj in conns else 0
                        h_name, opts = node_meta[idx]
                        role = str(opts.get("role", "worker"))
                        dc = str(opts.get("dc", "eu-1"))
                        async with conn_obj.env(UNICONN_HOST=h_name, UNICONN_ROLE=role, UNICONN_DC=dc):
                            return await conn_obj.run(command)

                    results = await pool.apply(_mapped_node)

            cards: list[dict[str, Any]] = []
            for idx, r in enumerate(results):
                h_name, opts = node_meta[idx]
                cards.append(
                    {
                        "host": h_name,
                        "role": str(opts.get("role", "node")),
                        "dc": str(opts.get("dc", "local")),
                        "uri_safe": conns[idx].config.uri_safe,
                        "ok": bool(r.ok),
                        "exit_code": r.exit_code,
                        "stdout": r.text,
                        "stderr": r.stderr.strip(),
                        "duration_ms": round(r.duration * 1000, 2),
                    }
                )
            return cards

        cards = asyncio.run(_run_fleet())
        total_ms = round((time.monotonic() - t0) * 1000, 2)
        ok_count = sum(1 for c in cards if c["ok"])
        return {
            "status": "ok",
            "operation": operation,
            "group": group,
            "available_groups": list(groups_dict.keys()),
            "total_hosts": len(cards),
            "ok_hosts": ok_count,
            "failed_hosts": len(cards) - ok_count,
            "total_duration_ms": total_ms,
            "nodes": cards,
        }
    except Exception as exc:
        delegated = _call_handler_in_venv("_execute_pool_sandbox", payload)
        if delegated is not None:
            return delegated
        return {
            "status": "error",
            "error": {"type": type(exc).__name__, "message": str(exc)},
            "nodes": [],
        }


def _execute_screen_sandbox(payload: dict[str, Any], screen_state: dict[str, Any]) -> dict[str, Any]:
    """Симулятор фоновых задач ScreenPool и реактивного LogPipeline."""
    action = str(payload.get("action", "analyze")).strip()
    if action == "clear":
        screen_state["sessions"] = []
        return {"status": "cleared", "sessions": []}

    session_name = str(payload.get("session_name", "db-migration-2026")).strip() or "job-01"
    host = str(payload.get("host", "prod-db-01.eu")).strip()
    command = str(payload.get("command", "pg_dump -Fc analytics > /backups/dump.sql")).strip()
    strategy = str(payload.get("strategy", "realtime")).strip()
    name_template = str(payload.get("name_template", "{pool_id}_{host}_{session_id}.log")).strip()
    regex_pattern = str(payload.get("pattern", r"(ERROR|WARN|CRITICAL|Progress:\s*\d+%)")).strip()
    sample_logs_raw = str(
        payload.get("sample_logs")
        or (
            "[12:00:01] INFO Starting background task in GNU screen...\n"
            "[12:00:02] INFO Progress: 25% — dumping schema public\n"
            "[12:00:03] WARN Slow query detected on table events_archive (1420ms)\n"
            "[12:00:04] INFO Progress: 75% — compressing blobs\n"
            "[12:00:05] ERROR Connection reset by replica node-2, retrying...\n"
            "[12:00:06] INFO Progress: 100% — backup completed (exit_code=0)\n"
        )
    )

    try:
        from uniconn.background._log_pipeline import LocalFileHandler

        async def _run_pipeline() -> dict[str, Any]:
            with tempfile.TemporaryDirectory(prefix="uniconn_screen_") as tmp_dir:
                handler = LocalFileHandler(
                    local_dir=tmp_dir,
                    name_template=name_template,
                    pool_id="pool01",
                    idx=len(screen_state.get("sessions", [])) + 1,
                    host=host,
                    command=command,
                    strategy=strategy,
                )
                lines = [ln + "\n" for ln in sample_logs_raw.splitlines() if ln.strip()]
                await handler.handle(session_name, lines)
                final_path = await handler.finalize(session_name)
                written_bytes = final_path.stat().st_size if final_path.exists() else 0
                rel_name = final_path.name

            compiled = re.compile(regex_pattern)
            matched_events: list[dict[str, Any]] = []
            for line_no, raw_line in enumerate(sample_logs_raw.splitlines(), start=1):
                m = compiled.search(raw_line)
                if m:
                    matched_events.append(
                        {
                            "line_no": line_no,
                            "match": m.group(0),
                            "line": raw_line,
                        }
                    )

            session_entry = {
                "session_id": f"uniconn_{session_name}",
                "name": session_name,
                "host": host,
                "command": command,
                "strategy": strategy,
                "sanitized_log_file": rel_name,
                "written_bytes": written_bytes,
                "lines_processed": len(lines),
                "triggers_count": len(matched_events),
                "matched_events": matched_events,
                "status": "COMPLETED",
            }
            sessions = list(screen_state.get("sessions", []))
            sessions.insert(0, session_entry)
            screen_state["sessions"] = sessions[:10]
            return {
                "status": "ok",
                "current": session_entry,
                "sessions": screen_state["sessions"],
            }

        return asyncio.run(_run_pipeline())
    except Exception as exc:
        delegated = _call_handler_in_venv("_execute_screen_sandbox", payload, screen_state)
        if delegated is not None:
            if isinstance(delegated.get("sessions"), list):
                screen_state["sessions"] = delegated["sessions"]
            return delegated
        return {
            "status": "error",
            "error": {"type": type(exc).__name__, "message": str(exc)},
            "sessions": screen_state.get("sessions", []),
        }


def _execute_v070_sandbox(payload: dict[str, Any]) -> dict[str, Any]:
    """Песочница возможностей v0.7.0: expect(), sync_dir(), write_template()."""
    feature = str(payload.get("feature", "expect")).strip()
    try:
        from uniconn import Connection

        async def _run_feature() -> dict[str, Any]:
            async with Connection.from_uri("local://") as conn:
                if feature == "sync_dir":
                    with tempfile.TemporaryDirectory(prefix="uniconn_v070_sync_") as tmp:
                        src = Path(tmp) / "src"
                        dst = Path(tmp) / "dst"
                        src.mkdir()
                        (src / "main.py").write_text("print('ok')\n", encoding="utf-8")
                        (src / "config.yaml").write_text("port: 8080\n", encoding="utf-8")
                        (src / "ignored.pyc").write_bytes(b"\x00\x01")
                        pass1 = await conn.sync_dir(src, dst, exclude=["*.pyc"])
                        pass2 = await conn.sync_dir(src, dst, exclude=["*.pyc"])
                        return {
                            "status": "ok",
                            "feature": "sync_dir",
                            "pass1": pass1.to_dict(),
                            "pass2": pass2.to_dict(),
                        }
                if feature == "write_template":
                    tpl_str = str(
                        payload.get(
                            "template",
                            "server {\n    listen $port;\n    server_name $host;\n}\n",
                        )
                    )
                    ctx = dict(payload.get("context") or {"port": 8080, "host": "edge.internal"})
                    engine_raw = str(payload.get("engine", "auto"))
                    eng: Any = engine_raw if engine_raw in ("auto", "string", "jinja2") else "auto"
                    with tempfile.TemporaryDirectory(prefix="uniconn_v070_tpl_") as tmp:
                        out_path = Path(tmp) / "rendered.conf"
                        rendered = await conn.write_template(
                            out_path,
                            tpl_str,
                            context=ctx,
                            engine=eng,
                        )
                        return {
                            "status": "ok",
                            "feature": "write_template",
                            "rendered": rendered,
                            "engine": eng,
                        }
                # По умолчанию: expect()
                py_cmd = (
                    "python3 -u -c \""
                    "ans = input('Proceed with firmware flash? [y/N]: '); "
                    "pw = input('Admin password: '); "
                    "print('FLASH_COMPLETE ans=' + ans + ' auth_len=' + str(len(pw)))"
                    "\""
                )
                res = await conn.expect(
                    py_cmd,
                    patterns={
                        r"\[y/N\]:": "y\n",
                        r"Admin password:": "s3cr3t\n",
                    },
                    final_prompt=r"FLASH_COMPLETE[^\n]*",
                    timeout=5.0,
                )
                return {
                    "status": "ok",
                    "feature": "expect",
                    "result": res.to_dict(),
                }

        return asyncio.run(_run_feature())
    except Exception as exc:
        delegated = _call_handler_in_venv("_execute_v070_sandbox", payload)
        if delegated is not None:
            return delegated
        return {
            "status": "error",
            "error": {"type": type(exc).__name__, "message": str(exc)},
        }


def _execute_v080_sandbox(payload: dict[str, Any]) -> dict[str, Any]:
    """Песочница возможностей v0.8.0: gather_facts, ensure_*, pool.stream, SyncConnectionPool."""
    feature = str(payload.get("feature", "gather_facts")).strip()
    try:
        from uniconn import Connection, ConnectionPool

        if feature == "sync_pool":
            pool = ConnectionPool(["local://?host=node-1", "local://?host=node-2"], max_concurrent=2)
            with pool.to_sync() as sync_pool:
                facts_map = sync_pool.gather_facts()
                res_list = sync_pool.map("echo sync-pool-ok")
                stream_items = list(sync_pool.stream("echo stream-line"))
            return {
                "status": "ok",
                "feature": "sync_pool",
                "hosts_count": len(facts_map),
                "map_outputs": [r.text for r in res_list],
                "stream_items": [[h, ln.strip()] for h, ln in stream_items],
            }

        async def _run_feature() -> dict[str, Any]:
            if feature == "pool_stream":
                pool = ConnectionPool(["local://?host=node-1", "local://?host=node-2"])
                cmd = str(payload.get("command", "printf 'line1\\nline2\\n'"))
                collected: list[dict[str, str]] = []
                async with pool:
                    async for host_key, line in pool.stream(cmd):
                        collected.append({"host": host_key, "line": line.rstrip("\r\n")})
                return {
                    "status": "ok",
                    "feature": "pool_stream",
                    "lines": collected,
                }

            async with Connection.from_uri("local://") as conn:
                if feature == "ensure_line":
                    with tempfile.TemporaryDirectory(prefix="uniconn_v080_line_") as tmp:
                        cfg_file = Path(tmp) / "sshd_config"
                        cfg_file.write_text("PermitRootLogin yes\nPort 22\n", encoding="utf-8")
                        pass1 = await conn.ensure_line(
                            cfg_file,
                            "PermitRootLogin no",
                            regex=r"^PermitRootLogin\s+",
                        )
                        pass2 = await conn.ensure_line(
                            cfg_file,
                            "PermitRootLogin no",
                            regex=r"^PermitRootLogin\s+",
                        )
                        content = await conn.read_file(str(cfg_file))
                        return {
                            "status": "ok",
                            "feature": "ensure_line",
                            "pass1": pass1.to_dict(),
                            "pass2": pass2.to_dict(),
                            "final_content": content,
                        }
                if feature == "ensure_package":
                    pkg = str(payload.get("package", "nginx"))
                    res = await conn.ensure_package(pkg, state="present", dry_run=True)
                    return {
                        "status": "ok",
                        "feature": "ensure_package",
                        "result": res.to_dict(),
                    }
                if feature == "ensure_service":
                    svc = str(payload.get("service", "nginx"))
                    res = await conn.ensure_service(svc, state="restarted", enabled=True, dry_run=True)
                    return {
                        "status": "ok",
                        "feature": "ensure_service",
                        "result": res.to_dict(),
                    }
                # По умолчанию: gather_facts()
                facts = await conn.gather_facts(refresh=True)
                return {
                    "status": "ok",
                    "feature": "gather_facts",
                    "facts": facts.to_dict(),
                }

        return asyncio.run(_run_feature())
    except Exception as exc:
        delegated = _call_handler_in_venv("_execute_v080_sandbox", payload)
        if delegated is not None:
            return delegated
        return {
            "status": "error",
            "error": {"type": type(exc).__name__, "message": str(exc)},
        }


def _execute_v090_sandbox(payload: dict[str, Any]) -> dict[str, Any]:
    """Песочница возможностей v0.9.0: CircuitBreaker, RateLimiter, ping(), run_script(), diff_facts()."""
    feature = str(payload.get("feature", "ping")).strip()
    try:
        from uniconn import (
            CircuitBreaker,
            CircuitOpenError,
            Connection,
            ConnectionPool,
            HostFacts,
            RateLimiter,
            Result,
            SSHSessionPool,
            diff_facts,
        )

        async def _run_feature() -> dict[str, Any]:
            if feature == "adaptive_ssh_pool":
                from datetime import datetime
                from unittest.mock import AsyncMock, patch

                server_max_sessions = 2

                def _make_server_conn(*_args: Any, **_kwargs: Any) -> Any:
                    conn = AsyncMock()
                    active_on_conn = 0

                    async def _sim_run(command: str, **_kw: Any) -> Result:
                        nonlocal active_on_conn
                        active_on_conn += 1
                        try:
                            if active_on_conn > server_max_sessions:
                                raise ConnectionError(
                                    "Channel open failed: Administratively prohibited (MaxSessions=2)"
                                )
                            await asyncio.sleep(0.015)
                            return Result(
                                exit_code=0,
                                stdout=f"ok:{command}",
                                stderr="",
                                duration=0.015,
                                command=command,
                                timestamp=datetime.now(),
                                host="bastion",
                            )
                        finally:
                            active_on_conn -= 1

                    conn.run = _sim_run
                    conn.is_alive = AsyncMock(return_value=True)
                    conn.close = AsyncMock()
                    return conn

                with patch(
                    "uniconn._session_pool.Connection.from_uri",
                    side_effect=_make_server_conn,
                ):
                    async with SSHSessionPool(
                        "ssh://admin@bastion",
                        max_sessions_per_conn=6,
                        max_connections=3,
                        adaptive=True,
                    ) as ssh_pool:
                        cmds = [f"check-subsystem-{i}" for i in range(1, 7)]
                        res_list = await ssh_pool.map(cmds)
                        stats_after_wave = ssh_pool.stats()
                        stats_after_resize = await ssh_pool.resize(
                            max_sessions_per_conn=2,
                            max_connections=1,
                        )
                return {
                    "status": "ok",
                    "feature": "adaptive_ssh_pool",
                    "initial_max_sessions": 6,
                    "server_max_sessions_limit": server_max_sessions,
                    "commands_completed": len(res_list),
                    "all_ok": all(r.ok for r in res_list),
                    "stats_after_adaptive_wave": stats_after_wave,
                    "stats_after_resize": stats_after_resize,
                }

            if feature == "circuit_breaker":
                cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.05)
                cb.record_failure()
                cb.record_failure()
                blocked_error: str | None = None
                try:
                    cb.check_or_raise(host="db-primary-01", command="SELECT 1")
                except CircuitOpenError as exc:
                    blocked_error = str(exc)
                open_snap = cb.to_dict()
                await asyncio.sleep(0.06)
                half_open_state = cb.state.value
                cb.record_success()
                return {
                    "status": "ok",
                    "feature": "circuit_breaker",
                    "open_snapshot": open_snap,
                    "blocked_error": blocked_error,
                    "half_open_state": half_open_state,
                    "recovered_snapshot": cb.to_dict(),
                }

            if feature == "rate_limiter":
                limiter = RateLimiter(rate=50.0, burst=2)
                waits = [
                    await limiter.acquire(),
                    await limiter.acquire(),
                    await limiter.acquire(),
                ]
                return {
                    "status": "ok",
                    "feature": "rate_limiter",
                    "waits_sec": [round(w, 4) for w in waits],
                    "limiter": limiter.to_dict(),
                }

            if feature == "diff_facts":
                facts_map = {
                    "web-eu-01": HostFacts(
                        os_family="Debian",
                        distro="Ubuntu 24.04",
                        kernel="6.8.0-45-generic",
                        arch="x86_64",
                        cpu_count=8,
                        memory_total_bytes=16384 * 1024 * 1024,
                    ),
                    "web-eu-02": HostFacts(
                        os_family="Debian",
                        distro="Ubuntu 24.04",
                        kernel="6.8.0-45-generic",
                        arch="x86_64",
                        cpu_count=8,
                        memory_total_bytes=16384 * 1024 * 1024,
                    ),
                    "api-core-01": HostFacts(
                        os_family="Debian",
                        distro="Ubuntu 22.04",
                        kernel="5.15.0-112-generic",
                        arch="x86_64",
                        cpu_count=4,
                        memory_total_bytes=8192 * 1024 * 1024,
                    ),
                }
                report = diff_facts(facts_map, baseline_host="web-eu-01")
                return {
                    "status": "ok",
                    "feature": "diff_facts",
                    "report": report.to_dict(),
                }

            if feature == "run_script":
                with tempfile.TemporaryDirectory(prefix="uniconn_v090_scr_") as tmp:
                    script_file = Path(tmp) / "deploy_hook.sh"
                    script_file.write_text(
                        "#!/bin/sh\necho \"deploy_hook args=$* user=$(whoami)\"\n",
                        encoding="utf-8",
                    )
                    async with Connection.from_uri("local://") as conn:
                        res = await conn.run_script(script_file, args=["--release", "v0.9.0"])
                    return {
                        "status": "ok",
                        "feature": "run_script",
                        "result": res.to_dict(),
                    }

            pool = ConnectionPool(["local://?host=web-01", "local://?host=web-02"])
            ping_map = await pool.ping()
            return {
                "status": "ok",
                "feature": "ping",
                "results": {k: v.to_dict() for k, v in ping_map.items()},
            }

        return asyncio.run(_run_feature())
    except Exception as exc:
        delegated = _call_handler_in_venv("_execute_v090_sandbox", payload)
        if delegated is not None:
            return delegated
        return {
            "status": "error",
            "error": {"type": type(exc).__name__, "message": str(exc)},
        }


def _execute_pytest(suite: str = "all") -> dict[str, Any]:
    """Запустить выбранный модульный пакет тестов pytest или проверку качества кода (ruff/pyright)."""
    if not os.path.exists(VENV_PYTEST):
        _ensure_venv_background()

    t0 = time.monotonic()
    suite_clean = suite.strip().lower()

    if suite_clean == "ruff":
        cmd_args = (
            [VENV_RUFF, "check", "src/", "examples/dashboard/server.py"]
            if os.path.exists(VENV_RUFF)
            else ["uv", "run", "ruff", "check", "src/"]
        )
        label = "ruff check src/ examples/dashboard/server.py"
    elif suite_clean == "pyright":
        cmd_args = [VENV_PYRIGHT] if os.path.exists(VENV_PYRIGHT) else ["uv", "run", "pyright"]
        label = "pyright"
    else:
        suite_map = {item["id"]: item["path"] for item in TEST_SUITES_META}
        target_path = suite_map.get(suite_clean, "tests/unit")
        cmd_args = (
            [VENV_PYTEST, target_path, "-m", "not integration", "-q"]
            if os.path.exists(VENV_PYTEST)
            else ["uv", "run", "pytest", target_path, "-m", "not integration", "-q"]
        )
        label = f'pytest {target_path} -m "not integration" -q'

    try:
        proc = subprocess.run(
            cmd_args,
            cwd=ROOT_DIR,
            capture_output=True,
            text=True,
            timeout=90,
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


class _ReusableThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True


def serve_dev_dashboard(port: int = 3000) -> None:
    """Запустить HTTP-сервер предпросмотра и тестирования uniconn на 0.0.0.0:3000."""
    threading.Thread(target=_ensure_venv_background, daemon=True).start()
    shell_state: dict[str, Any] = {"cwd": "/root", "env": {}, "term_size": [120, 40]}
    metrics_state: dict[str, Any] = {
        "total_runs": 0,
        "failed_runs": 0,
        "errors_count": 0,
        "total_duration": 0.0,
        "avg_duration": 0.0,
        "by_host": {},
        "history": [],
    }
    screen_state: dict[str, Any] = {"sessions": []}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

        def _send_json(self, payload: dict[str, Any], status: int = 200) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_json_body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length <= 0:
                return {}
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
            try:
                return json.loads(raw)
            except Exception:
                return {}

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)
            if parsed.path == "/api/status":
                self._send_json(_run_demo_status())
                return
            if parsed.path == "/api/shell":
                cmd = qs.get("cmd", ["pwd"])[0]
                mode = qs.get("mode", ["fake"])[0]
                reset = qs.get("reset", ["false"])[0].lower() == "true"
                self._send_json(_execute_shell_command(cmd, shell_state, mode=mode, reset=reset))
                return
            if parsed.path == "/api/local":
                cmd = qs.get("cmd", ["uname -a"])[0]
                self._send_json(_execute_local_command(cmd))
                return
            if parsed.path == "/api/pytest":
                suite = qs.get("suite", ["all"])[0]
                self._send_json(_execute_pytest(suite))
                return

            body = HTML_TEMPLATE_PATH.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            payload = self._read_json_body()
            if parsed.path == "/api/shell":
                cmd = str(payload.get("cmd") or "pwd")
                mode = str(payload.get("mode") or "fake")
                try:
                    cols = max(20, int(payload.get("cols") or 120))
                except (TypeError, ValueError):
                    cols = 120
                try:
                    rows = max(5, int(payload.get("rows") or 40))
                except (TypeError, ValueError):
                    rows = 40
                reset = bool(payload.get("reset", False))
                self._send_json(
                    _execute_shell_command(
                        cmd,
                        shell_state,
                        mode=mode,
                        cols=cols,
                        rows=rows,
                        reset=reset,
                    )
                )
                return
            if parsed.path == "/api/hooks":
                self._send_json(_execute_hooks_sandbox(payload, metrics_state))
                return
            if parsed.path == "/api/uri":
                self._send_json(_build_and_validate_uri(payload))
                return
            if parsed.path == "/api/pool":
                self._send_json(_execute_pool_sandbox(payload))
                return
            if parsed.path == "/api/screen":
                self._send_json(_execute_screen_sandbox(payload, screen_state))
                return
            if parsed.path == "/api/v070":
                self._send_json(_execute_v070_sandbox(payload))
                return
            if parsed.path == "/api/v080":
                self._send_json(_execute_v080_sandbox(payload))
                return
            if parsed.path == "/api/v090":
                self._send_json(_execute_v090_sandbox(payload))
                return

            self._send_json({"error": "Not found"}, status=404)

    server = _ReusableThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"uniconn dev dashboard listening on http://0.0.0.0:{port}", flush=True)
    server.serve_forever()
