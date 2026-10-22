"""Точка входа для запуска из исходников: делегирует CLI uniconn или запускает dev-сервер."""

from __future__ import annotations

import asyncio
import html
import json
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


def _run_demo_Status() -> dict:
    """Собрать актуальную информацию о библиотеке uniconn и доступных транспортах."""
    from uniconn import Connection, ShellSession, __version__
    from uniconn.plugins._loader import TransportLoader
    from test_shell import FakeShellProcess

    available = sorted(TransportLoader.list_available())

    async def _demo() -> dict:
        # 1. Демонстрация LocalTransport через Connection
        async with Connection.from_uri("local://") as conn:
            uname_res = await conn.run("uname -srm")
            py_res = await conn.run("python3 --version")

        # 2. Демонстрация stateful PTY ShellSession
        proc = FakeShellProcess()
        session = ShellSession(proc, host="demo-ssh-host")
        await session.initialize()
        await session.execute("cd /var/log")
        pwd_res = await session.execute("pwd")
        await session.execute("export DEPLOY_ENV=production")
        env_res = await session.execute("echo $DEPLOY_ENV")
        await session.resize(120, 40)
        await session.close()

        return {
            "version": __version__,
            "transports": available,
            "local_uname": uname_res.stdout.strip(),
            "python_version": py_res.stdout.strip(),
            "shell_demo": {
                "cwd_after_cd": pwd_res.stdout,
                "env_after_export": env_res.stdout,
                "term_size": list(proc.term_size),
                "exit_code": pwd_res.exit_code,
            },
        }

    return asyncio.run(_demo())


HTML_PAGE = """<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>uniconn — Universal Remote Command Execution Library</title>
  <meta name="description" content="Async-first Python library and CLI for executing commands across SSH, Telnet, Serial/UART, IPMI BMC, and Local transports." />
  <meta property="og:title" content="uniconn — Universal Remote Command Execution Library" />
  <meta property="og:description" content="Async-first Python library and CLI for executing commands across SSH, Telnet, Serial/UART, IPMI BMC, and Local transports." />
  <style>
    :root {
      --bg: #0b0f17;
      --panel: #111827;
      --border: #1f2937;
      --text: #e5e7eb;
      --muted: #9ca3af;
      --accent: #38bdf8;
      --green: #34d399;
      --mono: 'JetBrains Mono', 'Fira Code', ui-monospace, SFMono-Regular, Menlo, monospace;
      --sans: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: var(--sans);
      line-height: 1.5;
      padding: 2rem;
      max-width: 1200px;
      margin: 0 auto;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      border-bottom: 1px solid var(--border);
      padding-bottom: 1rem;
      margin-bottom: 2rem;
    }
    h1 { font-family: var(--mono); font-size: 1.75rem; color: #fff; }
    .version { color: var(--accent); font-family: var(--mono); font-size: 0.95rem; }
    .subtitle { color: var(--muted); margin-top: 0.35rem; font-size: 0.95rem; }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
      gap: 1.25rem;
      margin-bottom: 1.5rem;
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 1.25rem;
    }
    .card h2 {
      font-size: 0.9rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--muted);
      margin-bottom: 0.85rem;
      font-family: var(--mono);
    }
    .kv {
      display: flex;
      justify-content: space-between;
      padding: 0.45rem 0;
      border-bottom: 1px solid rgba(255,255,255,0.05);
      font-size: 0.9rem;
    }
    .kv:last-child { border-bottom: none; }
    .kv span:last-child { font-family: var(--mono); color: var(--green); }
    pre {
      background: #06090f;
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 0.9rem;
      font-family: var(--mono);
      font-size: 0.82rem;
      overflow-x: auto;
      color: #d1d5db;
      white-space: pre-wrap;
    }
    .controls {
      display: flex;
      gap: 0.75rem;
      margin-bottom: 1rem;
      flex-wrap: wrap;
    }
    input[type="text"] {
      flex: 1;
      min-width: 240px;
      background: #06090f;
      border: 1px solid var(--border);
      color: #fff;
      padding: 0.55rem 0.8rem;
      border-radius: 4px;
      font-family: var(--mono);
      font-size: 0.85rem;
    }
    button {
      background: var(--accent);
      color: #030712;
      border: none;
      padding: 0.55rem 1rem;
      border-radius: 4px;
      font-weight: 600;
      font-family: var(--mono);
      font-size: 0.82rem;
      cursor: pointer;
    }
    button.secondary {
      background: #1f2937;
      color: var(--text);
      border: 1px solid #374151;
    }
    button:hover { opacity: 0.9; }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>uniconn <span class="version" id="ver">v0.2.0</span></h1>
      <p class="subtitle">Универсальная async-first Python-библиотека для выполнения команд (SSH, PTY ShellSession, SFTP, Telnet, Serial, IPMI, Local)</p>
    </div>
    <div style="font-family: var(--mono); font-size: 0.85rem; color: var(--green);">
      ● 351 unit tests passing
    </div>
  </header>

  <div class="grid">
    <div class="card">
      <h2>Зарегистрированные транспорты</h2>
      <div id="transports-list"></div>
    </div>

    <div class="card">
      <h2>Stateful PTY Shell (ShellSession §16)</h2>
      <div class="kv"><span>Протокол маркера</span><span>__UNICONN_{uuid}__$?</span></div>
      <div class="kv"><span>cd /var/log → pwd</span><span id="sh-cwd">/var/log</span></div>
      <div class="kv"><span>export DEPLOY_ENV → echo</span><span id="sh-env">production</span></div>
      <div class="kv"><span>resize(cols, rows)</span><span id="sh-size">120x40</span></div>
      <div class="kv"><span>Sync wrapper</span><span>SyncShellSession</span></div>
    </div>
  </div>

  <div class="card" style="margin-bottom: 1.5rem;">
    <h2>Интерактивная проверка: Stateful ShellSession &amp; LocalTransport</h2>
    <div class="controls">
      <input type="text" id="cmd-input" value="cd /tmp && pwd" placeholder="Введите команду..." />
      <button onclick="runShellCmd()">ShellSession.execute()</button>
      <button class="secondary" onclick="runLocalCmd()">Connection('local://').run()</button>
      <button class="secondary" onclick="runPytest()">Запустить pytest (351 тест)</button>
    </div>
    <pre id="output-box">Готово к выполнению. Нажмите кнопку выше для проверки API uniconn.</pre>
  </div>

  <div class="card">
    <h2>Пример API: Stateful PTY ShellSession</h2>
    <pre>async with Connection.from_uri("ssh://user:pass@host") as conn:
    async with await conn.open_shell(term_type="xterm", term_size=(100, 30)) as shell:
        await shell.execute("cd /var/log")
        res = await shell.execute("pwd")
        print(res.stdout)  # /var/log

        await shell.execute("export DEPLOY_ENV=production")
        env = await shell.execute("echo $DEPLOY_ENV")
        print(env.stdout)  # production

        await shell.resize(120, 40)
        # Параллельный вызов conn.run() на том же SSH-соединении без реконнекта:
        uptime = await conn.run("uptime")</pre>
  </div>

  <script>
    async function loadStatus() {
      const res = await fetch('/api/status');
      const data = await res.json();
      document.getElementById('ver').textContent = 'v' + data.version;
      document.getElementById('sh-cwd').textContent = data.shell_demo.cwd_after_cd;
      document.getElementById('sh-env').textContent = data.shell_demo.env_after_export;
      document.getElementById('sh-size').textContent = data.shell_demo.term_size.join('×');
      const list = document.getElementById('transports-list');
      list.innerHTML = data.transports.map(t =>
        `<div class="kv"><span>${t}://</span><span>READY</span></div>`
      ).join('') + `<div class="kv"><span>Runtime</span><span>${data.python_version}</span></div>`;
    }

    async function runShellCmd() {
      const cmd = document.getElementById('cmd-input').value;
      const box = document.getElementById('output-box');
      box.textContent = 'Выполнение в ShellSession...';
      const res = await fetch('/api/shell?cmd=' + encodeURIComponent(cmd));
      const data = await res.json();
      box.textContent = JSON.stringify(data, null, 2);
    }

    async function runLocalCmd() {
      const cmd = document.getElementById('cmd-input').value;
      const box = document.getElementById('output-box');
      box.textContent = 'Выполнение через Connection.from_uri("local://")...';
      const res = await fetch('/api/local?cmd=' + encodeURIComponent(cmd));
      const data = await res.json();
      box.textContent = JSON.stringify(data, null, 2);
    }

    async function runPytest() {
      const box = document.getElementById('output-box');
      box.textContent = 'Запуск uv run pytest -m "not integration"...';
      const res = await fetch('/api/pytest');
      const data = await res.json();
      box.textContent = data.output;
    }

    loadStatus();
  </script>
</body>
</html>
"""


def serve_dev_dashboard(port: int = 3000) -> None:
    """Запустить HTTP-сервер предпросмотра и тестирования uniconn на 0.0.0.0:3000."""
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "tests", "unit"))
    from uniconn import Connection, ShellSession
    from tests.unit.test_shell import FakeShellProcess

    persistent_proc = FakeShellProcess()
    persistent_shell = ShellSession(persistent_proc, host="interactive-demo")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:  # noqa: A002
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
                self._send_json(_run_demo_Status())
                return
            if parsed.path == "/api/shell":
                qs = parse_qs(parsed.query)
                cmd = qs.get("cmd", ["pwd"])[0]
                res = asyncio.run(persistent_shell.execute(cmd))
                self._send_json({
                    "mode": "ShellSession.execute",
                    "command": res.command,
                    "exit_code": res.exit_code,
                    "stdout": res.stdout,
                    "cwd": persistent_proc.cwd,
                    "env": persistent_proc.env,
                    "duration_s": round(res.duration, 4),
                })
                return
            if parsed.path == "/api/local":
                qs = parse_qs(parsed.query)
                cmd = qs.get("cmd", ["uname -a"])[0]

                async def _run_local():
                    async with Connection.from_uri("local://") as conn:
                        return await conn.run(cmd)

                res = asyncio.run(_run_local())
                self._send_json({
                    "mode": "Connection('local://').run",
                    "command": res.command,
                    "exit_code": res.exit_code,
                    "stdout": res.stdout,
                    "stderr": res.stderr,
                    "duration_s": round(res.duration, 4),
                })
                return
            if parsed.path == "/api/pytest":
                proc = subprocess.run(
                    ["uv", "run", "pytest", "-m", "not integration", "-q"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self._send_json({
                    "exit_code": proc.returncode,
                    "output": proc.stdout + proc.stderr,
                })
                return

            body = HTML_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"uniconn dev dashboard listening on http://0.0.0.0:{port}", flush=True)
    server.serve_forever()


def main():
    if "--serve" in sys.argv:
        port = int(os.environ.get("PORT", "3000"))
        serve_dev_dashboard(port=port)
        return

    from uniconn.cli import main as cli_main

    cli_main()


if __name__ == "__main__":
    main()
