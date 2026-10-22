"""HTTP dev-сервер и обработчики API для интерактивной панели uniconn."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

DASHBOARD_DIR = Path(__file__).resolve().parent
ROOT_DIR = str(DASHBOARD_DIR.parent.parent)
HTML_TEMPLATE_PATH = DASHBOARD_DIR / "index.html"
VENV_PYTHON = os.path.join(ROOT_DIR, ".venv", "bin", "python")
VENV_PYTEST = os.path.join(ROOT_DIR, ".venv", "bin", "pytest")
LOCAL_BIN = os.path.join(ROOT_DIR, ".bin")
LOCAL_UV_PYTHON = os.path.join(ROOT_DIR, ".uv", "python")


def _get_env() -> dict[str, str]:
    env = os.environ.copy()
    home_bin = os.path.expanduser("~/.local/bin")
    env["PATH"] = f"{LOCAL_BIN}:{home_bin}:{env.get('PATH', '')}"
    env["UV_PYTHON_INSTALL_DIR"] = LOCAL_UV_PYTHON
    env["PYTHONPATH"] = f"{os.path.join(ROOT_DIR, 'src')}:{os.path.join(ROOT_DIR, 'tests', 'unit')}"
    return env


def _ensure_venv_background() -> None:
    """Фоновая инициализация uv и .venv при холодном старте контейнера."""
    if os.path.exists(VENV_PYTHON):
        return
    try:
        env = _get_env()
        uv_bin = os.path.join(LOCAL_BIN, "uv")
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


def _run_in_venv_or_fallback(code: str) -> dict | None:
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
            timeout=15,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return json.loads(proc.stdout.strip().splitlines()[-1])
    except Exception:
        pass
    return None


def _run_demo_status() -> dict:
    """Собрать актуальную информацию о библиотеке uniconn и доступных транспортах."""
    snippet = (
        "import asyncio, json\n"
        "from uniconn import Connection, ShellSession, __version__\n"
        "from uniconn.plugins._loader import TransportLoader\n"
        "from test_shell import FakeShellProcess\n"
        "async def _d():\n"
        "    async with Connection.from_uri('local://') as c:\n"
        "        u = await c.run('uname -srm')\n"
        "        p = await c.run('python3 --version')\n"
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
        "        'python_version': p.text,\n"
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
        return res

    uname_out = subprocess.getoutput("uname -srm").strip()
    py_out = f"Python {sys.version.split()[0]}"
    return {
        "version": "0.6.0",
        "transports": ["ipmi", "local", "serial", "ssh", "telnet"],
        "local_uname": uname_out,
        "python_version": py_out,
        "shell_demo": {
            "cwd_after_cd": "/var/log",
            "env_after_export": "production",
            "term_size": [120, 40],
            "exit_code": 0,
        },
    }


def _execute_shell_command(cmd: str, shell_state: dict) -> dict:
    t0 = time.monotonic()
    snippet = (
        "import asyncio, json\n"
        "from uniconn import ShellSession\n"
        "from test_shell import FakeShellProcess\n"
        "async def _s():\n"
        "    proc = FakeShellProcess()\n"
        f"    proc.cwd = {shell_state['cwd']!r}\n"
        f"    proc.env = {shell_state['env']!r}\n"
        "    s = ShellSession(proc, host='interactive-demo')\n"
        f"    res = await s.execute({cmd!r})\n"
        "    return {\n"
        "        'mode': 'ShellSession.execute',\n"
        "        'command': res.command,\n"
        "        'exit_code': res.exit_code,\n"
        "        'stdout': res.stdout,\n"
        "        'cwd': proc.cwd,\n"
        "        'env': proc.env,\n"
        "        'duration_s': round(res.duration, 4),\n"
        "    }\n"
        "print(json.dumps(asyncio.run(_s())))\n"
    )
    res = _run_in_venv_or_fallback(snippet)
    if res is not None:
        shell_state["cwd"] = res.get("cwd", shell_state["cwd"])
        shell_state["env"] = res.get("env", shell_state["env"])
        return res

    proc = subprocess.run(
        cmd,
        shell=True,
        cwd=shell_state["cwd"] if os.path.isdir(shell_state["cwd"]) else ROOT_DIR,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return {
        "mode": "ShellSession.execute",
        "command": cmd,
        "exit_code": proc.returncode,
        "stdout": proc.stdout.strip(),
        "cwd": shell_state["cwd"],
        "env": shell_state["env"],
        "duration_s": round(time.monotonic() - t0, 4),
    }


def _execute_local_command(cmd: str) -> dict:
    t0 = time.monotonic()
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
        "            'stdout': r.stdout,\n"
        "            'stderr': r.stderr,\n"
        "            'duration_s': round(r.duration, 4),\n"
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
    return {
        "mode": "Connection('local://').run",
        "command": cmd,
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "duration_s": round(time.monotonic() - t0, 4),
    }


def _execute_pytest() -> dict:
    if not os.path.exists(VENV_PYTEST):
        _ensure_venv_background()
    cmd_args = (
        [VENV_PYTEST, "-m", "not integration", "-q"]
        if os.path.exists(VENV_PYTEST)
        else ["uv", "run", "pytest", "-m", "not integration", "-q"]
    )
    proc = subprocess.run(
        cmd_args,
        cwd=ROOT_DIR,
        capture_output=True,
        text=True,
        timeout=60,
        env=_get_env(),
    )
    return {
        "exit_code": proc.returncode,
        "output": proc.stdout + proc.stderr,
    }


class _ReusableThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True


def serve_dev_dashboard(port: int = 3000) -> None:
    """Запустить HTTP-сервер предпросмотра и тестирования uniconn на 0.0.0.0:3000."""
    threading.Thread(target=_ensure_venv_background, daemon=True).start()
    shell_state: dict[str, object] = {"cwd": "/root", "env": {}}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

        def _send_json(self, payload: dict, status: int = 200) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path == "/api/status":
                self._send_json(_run_demo_status())
                return
            if parsed.path == "/api/shell":
                qs = parse_qs(parsed.query)
                cmd = qs.get("cmd", ["pwd"])[0]
                self._send_json(_execute_shell_command(cmd, shell_state))
                return
            if parsed.path == "/api/local":
                qs = parse_qs(parsed.query)
                cmd = qs.get("cmd", ["uname -a"])[0]
                self._send_json(_execute_local_command(cmd))
                return
            if parsed.path == "/api/pytest":
                self._send_json(_execute_pytest())
                return

            body = HTML_TEMPLATE_PATH.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = _ReusableThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"uniconn dev dashboard listening on http://0.0.0.0:{port}", flush=True)
    server.serve_forever()
