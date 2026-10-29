"""Песочницы lifecycle-хуков, телеметрии structlog и реактивного LogPipeline."""

from __future__ import annotations

import asyncio
import io
import json
import logging
import re
import tempfile
from pathlib import Path
from typing import Any

from examples.dashboard.state import ROOT_DIR, _serialize_result


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
        return {
            "status": "error",
            "error": {"type": type(exc).__name__, "message": str(exc)},
            "result": None,
            "logs_json": [],
            "logs_console": [],
            "audit_records": [],
            "metrics": metrics_state,
        }


def _execute_screen_sandbox(payload: dict[str, Any], screen_state: dict[str, Any]) -> dict[str, Any]:
    """Симулятор фоновых задач BackgroundPool и реактивного LogPipeline."""
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
            "[12:00:01] INFO Starting background task (backend=auto)...\n"
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
        return {
            "status": "error",
            "error": {"type": type(exc).__name__, "message": str(exc)},
            "sessions": screen_state.get("sessions", []),
        }
