"""Песочница мульти-хост пула ConnectionPool и групповых операций."""

from __future__ import annotations

import asyncio
import os
import tempfile
import time
from pathlib import Path
from typing import Any

from examples.dashboard.state import DEFAULT_INVENTORY_YAML


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
                        sync_map = await pool.files.sync_dir(
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
                        tpl_map = await pool.files.write_template(
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
                        ens_map = await pool.state.ensure_line(
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
                        if os.name == "nt":
                            scr_path = Path(tmp_root) / "health_probe.bat"
                            scr_path.write_text(
                                "@echo off\necho [%UNICONN_HOST%] script executed with args: %*\n",
                                encoding="utf-8",
                            )
                        else:
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
                            cmd_to_run = command
                            if os.name == "nt":
                                cmd_to_run = (
                                    cmd_to_run.replace("$UNICONN_HOST", h_name)
                                    .replace("$UNICONN_ROLE", role)
                                    .replace("$UNICONN_DC", dc)
                                )
                            return await conn_obj.run(cmd_to_run)

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
        return {
            "status": "error",
            "error": {"type": type(exc).__name__, "message": str(exc)},
            "nodes": [],
        }
