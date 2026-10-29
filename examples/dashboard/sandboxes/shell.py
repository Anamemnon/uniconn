"""Песочницы интерактивных сессий ShellSession, локального выполнения и конструктора URI."""

from __future__ import annotations

import asyncio
import os
import re
import subprocess
import time
from typing import Any

from examples.dashboard.state import ROOT_DIR, _serialize_result


class _FakeShellProcess:
    """Фейковый asyncssh PTY-процесс с эмуляцией stateful оболочки для дашборда."""

    def __init__(self, echo_commands: bool = False) -> None:
        self.cwd = "/home/user"
        self.env: dict[str, str] = {}
        self.echo_commands = echo_commands
        self.returncode: int | None = None
        self.exit_status: int | None = None
        self.terminated = False
        self.closed = False
        self.term_size = (80, 24)
        self.written_chunks: list[str] = []
        self._out_queue: asyncio.Queue[str] = asyncio.Queue()

        self.stdin = type("StdinMock", (), {})()
        self.stdin.write = self._on_stdin_write

        async def _drain() -> None:
            pass

        self.stdin.drain = _drain

        self.stdout = type("StdoutMock", (), {})()
        self.stdout.read = self._on_stdout_read

    def _on_stdin_write(self, text: str) -> None:
        self.written_chunks.append(text)
        stripped = text.strip()
        if stripped in ("", "\x03", "exit", "export PS1=''; stty -echo"):
            return

        m = re.match(r'^(.*);\s*echo\s+"\\n(__UNICONN_[a-f0-9]+__)\$\?"$', stripped)
        if not m:
            return
        cmd, marker_prefix = m.group(1).strip(), m.group(2)

        output, exit_code = self._eval_command(cmd)
        prefix = f"{stripped}\r\n" if self.echo_commands else ""
        payload = f"{prefix}{output}\n{marker_prefix}{exit_code}\n"
        self._out_queue.put_nowait(payload)

    def _eval_command(self, cmd: str) -> tuple[str, int]:
        if cmd.startswith("cd "):
            target = cmd[3:].strip()
            self.cwd = target
            return "", 0
        if cmd == "pwd":
            return self.cwd, 0
        if cmd.startswith("export "):
            assignment = cmd[7:].strip()
            if "=" in assignment:
                k, v = assignment.split("=", 1)
                self.env[k.strip()] = v.strip().strip("'\"")
            return "", 0
        if cmd.startswith("echo $"):
            var_name = cmd[6:].strip()
            return self.env.get(var_name, ""), 0
        if cmd.startswith("echo "):
            return cmd[5:].strip().strip("'\""), 0
        if cmd == "false":
            return "error occurred", 127
        return f"ran:{cmd}", 0

    async def _on_stdout_read(self, _n: int = 4096) -> str:
        if self.returncode is not None:
            return ""
        return await self._out_queue.get()

    def change_terminal_size(self, cols: int, rows: int) -> None:
        self.term_size = (cols, rows)

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15

    def close(self) -> None:
        self.closed = True


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

            proc = _FakeShellProcess()
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
        from uniconn.config.uri import URIParser

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
        return {
            "valid": False,
            "error": {"type": type(exc).__name__, "message": str(exc)},
            "uri": raw_uri,
        }
