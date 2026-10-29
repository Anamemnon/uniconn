"""Песочницы релизных возможностей v0.7.0, v0.8.0 и v0.9.0."""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from typing import Any


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
                        pass1 = await conn.files.sync_dir(src, dst, exclude=["*.pyc"])
                        pass2 = await conn.files.sync_dir(src, dst, exclude=["*.pyc"])
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
                        rendered = await conn.files.write_template(
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
                        pass1 = await conn.state.ensure_line(
                            cfg_file,
                            "PermitRootLogin no",
                            regex=r"^PermitRootLogin\s+",
                        )
                        pass2 = await conn.state.ensure_line(
                            cfg_file,
                            "PermitRootLogin no",
                            regex=r"^PermitRootLogin\s+",
                        )
                        content = await conn.files.read_file(str(cfg_file))
                        return {
                            "status": "ok",
                            "feature": "ensure_line",
                            "pass1": pass1.to_dict(),
                            "pass2": pass2.to_dict(),
                            "final_content": content,
                        }
                if feature == "ensure_package":
                    pkg = str(payload.get("package", "nginx"))
                    res = await conn.state.ensure_package(pkg, state="present", dry_run=True)
                    return {
                        "status": "ok",
                        "feature": "ensure_package",
                        "result": res.to_dict(),
                    }
                if feature == "ensure_service":
                    svc = str(payload.get("service", "nginx"))
                    res = await conn.state.ensure_service(svc, state="restarted", enabled=True, dry_run=True)
                    return {
                        "status": "ok",
                        "feature": "ensure_service",
                        "result": res.to_dict(),
                    }
                facts = await conn.gather_facts(refresh=True)
                return {
                    "status": "ok",
                    "feature": "gather_facts",
                    "facts": facts.to_dict(),
                }

        return asyncio.run(_run_feature())
    except Exception as exc:
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
        return {
            "status": "error",
            "error": {"type": type(exc).__name__, "message": str(exc)},
        }
