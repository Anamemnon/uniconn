# src/uniconn/cli/cmd_mcp.py
"""CLI-команды запуска официального MCP-сервера (uniconn mcp) и управления HITL-заявками (uniconn approval)."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sys
from pathlib import Path
from typing import Annotated, Any

from ..mcp import (
    DEFAULT_APPROVAL_STORE_PATH,
    ApprovalManager,
    HITLPolicy,
    MCPHostRegistry,
    MCPSecurityPolicy,
    MCPServer,
)
from .renderers import CLIOutputRenderer, Panel, Parameter, Table, box, cyclopts, print_json


def _split_csv(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(item.strip() for item in value.split(",") if item.strip())


def build_mcp_client_config(
    *,
    inventory: str | None = None,
    uris: tuple[str, ...] = (),
    group: str | None = None,
    host: str | None = None,
    local: bool = False,
    allow_write: bool = False,
    allow_sudo: bool = False,
    allow_dynamic_uri: bool = False,
    dry_run: bool = False,
    allowlist: str | None = None,
    blocklist: str | None = None,
    audit_log: str | None = None,
    max_read_bytes: int = 65536,
    hitl: bool = False,
    hitl_store: str | None = None,
    hitl_timeout: float = 300.0,
    hitl_wait: bool = False,
    hitl_webhook_url: str | None = None,
    flows: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Сформировать готовый JSON-конфиг ``mcpServers`` для Claude Desktop / Cursor."""
    args: list[str] = ["--from", "uniconn[cli]", "uniconn", "mcp"]
    if inventory:
        args.extend(["--inventory", str(Path(inventory).resolve())])
    for u in uris:
        args.extend(["--uri", u])
    if group:
        args.extend(["--group", group])
    if host:
        args.extend(["--host", host])
    if local:
        args.append("--local")
    if allow_write:
        args.append("--allow-write")
    if allow_sudo:
        args.append("--allow-sudo")
    if allow_dynamic_uri:
        args.append("--allow-dynamic-uri")
    if dry_run:
        args.append("--dry-run")
    if allowlist:
        args.extend(["--allowlist", allowlist])
    if blocklist:
        args.extend(["--blocklist", blocklist])
    if audit_log:
        args.extend(["--audit-log", audit_log])
    if max_read_bytes != 65536:
        args.extend(["--max-read-bytes", str(max_read_bytes)])
    if hitl:
        args.append("--hitl")
    if hitl_store:
        args.extend(["--hitl-store", str(Path(hitl_store).resolve())])
    if hitl_timeout != 300.0:
        args.extend(["--hitl-timeout", str(hitl_timeout)])
    if hitl_wait:
        args.append("--hitl-wait")
    if hitl_webhook_url:
        args.extend(["--hitl-webhook-url", hitl_webhook_url])
    if flows:
        args.extend(["--flows", ",".join(flows)])

    return {
        "mcpServers": {
            "uniconn": {
                "command": "uvx",
                "args": args,
            }
        }
    }


def _resolve_cli_store_path(store: str | None) -> Path:
    if store and store.strip():
        return Path(store.strip()).expanduser()
    env_store = os.environ.get("UNICONN_APPROVAL_STORE")
    if env_store and env_store.strip():
        return Path(env_store.strip()).expanduser()
    return DEFAULT_APPROVAL_STORE_PATH


def register_mcp_commands(app: Any, console: Any, renderer: CLIOutputRenderer) -> None:
    """Зарегистрировать команду ``mcp`` и подгруппу ``approval`` в Cyclopts-приложении."""

    @app.command(name="mcp")
    def mcp_command(
        inventory: Annotated[
            str | None,
            Parameter(
                name=["--inventory", "-i"],
                help="Path to inventory file (YAML/TOML/JSON)",
            ),
        ] = None,
        uri: Annotated[
            str | None,
            Parameter(
                name=["--uri", "-u"],
                help="Comma-separated target connection URI(s)",
            ),
        ] = None,
        group: Annotated[
            str | None,
            Parameter(
                name=["--group", "-g"],
                help="Filter inventory hosts by group name",
            ),
        ] = None,
        host: Annotated[
            str | None,
            Parameter(
                name=["--host", "-H"],
                help="Filter inventory by specific host alias",
            ),
        ] = None,
        local: Annotated[
            bool,
            Parameter(
                name=["--local"],
                negative="",
                help="Register local:// transport host in the MCP registry",
            ),
        ] = False,
        allow_write: Annotated[
            bool,
            Parameter(
                name=["--allow-write"],
                negative="",
                help="Enable file write operations (uniconn_write_file)",
            ),
        ] = False,
        allow_sudo: Annotated[
            bool,
            Parameter(
                name=["--allow-sudo"],
                negative="",
                help="Allow privileged command execution (sudo=True)",
            ),
        ] = False,
        allow_dynamic_uri: Annotated[
            bool,
            Parameter(
                name=["--allow-dynamic-uri"],
                negative="",
                help="Allow AI agents to connect to arbitrary URIs not in the registry",
            ),
        ] = False,
        dry_run: Annotated[
            bool,
            Parameter(
                name=["--dry-run"],
                negative="",
                help="Enforce dry-run mode on all executed commands and file writes",
            ),
        ] = False,
        allowlist: Annotated[
            str | None,
            Parameter(
                name=["--allowlist"],
                help="Comma-separated list of permitted command prefixes",
            ),
        ] = None,
        blocklist: Annotated[
            str | None,
            Parameter(
                name=["--blocklist"],
                help="Comma-separated list of additional blocked regex patterns",
            ),
        ] = None,
        audit_log: Annotated[
            str | None,
            Parameter(
                name=["--audit-log"],
                help="Path to JSONL audit log file (with automatic secret masking)",
            ),
        ] = None,
        max_read_bytes: Annotated[
            int,
            Parameter(
                name=["--max-read-bytes"],
                help="Maximum bytes returned by uniconn_read_file (default: 65536)",
            ),
        ] = 65536,
        hitl: Annotated[
            bool,
            Parameter(
                name=["--hitl"],
                negative="",
                help="Enable Human-in-the-Loop (HITL) two-phase approvals for destructive actions",
            ),
        ] = False,
        hitl_store: Annotated[
            str | None,
            Parameter(
                name=["--hitl-store"],
                help="Path to JSON approval store file for IPC with 'uniconn approval'",
            ),
        ] = None,
        hitl_timeout: Annotated[
            float,
            Parameter(
                name=["--hitl-timeout"],
                help="Expiration timeout in seconds for pending HITL approvals (default: 300.0)",
            ),
        ] = 300.0,
        hitl_wait: Annotated[
            bool,
            Parameter(
                name=["--hitl-wait"],
                negative="",
                help="Wait synchronously for operator decision before returning PENDING_APPROVAL",
            ),
        ] = False,
        hitl_webhook_url: Annotated[
            str | None,
            Parameter(
                name=["--hitl-webhook-url"],
                help="Webhook URL to notify on pending HITL approval requests",
            ),
        ] = None,
        flows: Annotated[
            str | None,
            Parameter(
                name=["--flows", "-F"],
                help="Comma-separated Python files, directories, or module[:attr] specs to export as MCP Flow tools",
            ),
        ] = None,
        print_config: Annotated[
            bool,
            Parameter(
                name=["--print-config"],
                negative="",
                help="Print mcpServers JSON configuration for Claude Desktop / Cursor and exit",
            ),
        ] = False,
    ) -> None:
        """Start the official uniconn Model Context Protocol (MCP) server over JSON-RPC 2.0 stdio."""
        parsed_uris = _split_csv(uri)
        parsed_flows = _split_csv(flows)

        if print_config:
            cfg_snippet = build_mcp_client_config(
                inventory=inventory,
                uris=parsed_uris,
                group=group,
                host=host,
                local=local,
                allow_write=allow_write,
                allow_sudo=allow_sudo,
                allow_dynamic_uri=allow_dynamic_uri,
                dry_run=dry_run,
                allowlist=allowlist,
                blocklist=blocklist,
                audit_log=audit_log,
                max_read_bytes=max_read_bytes,
                hitl=hitl,
                hitl_store=hitl_store,
                hitl_timeout=hitl_timeout,
                hitl_wait=hitl_wait,
                hitl_webhook_url=hitl_webhook_url,
                flows=parsed_flows,
            )
            sys.stdout.write(json.dumps(cfg_snippet, ensure_ascii=False, indent=2) + "\n")
            sys.stdout.flush()
            return

        if inventory is not None and not Path(inventory).is_file():
            sys.stderr.write(f"ERROR: Inventory file not found: {inventory}\n")
            sys.exit(1)

        try:
            allow_tuple = _split_csv(allowlist)
            block_tuple = _split_csv(blocklist) if blocklist else None
            effective_store = (
                str(_resolve_cli_store_path(hitl_store))
                if (hitl or hitl_store)
                else None
            )
            channels: list[str] = ["cli", "dashboard"]
            if hitl_webhook_url:
                channels.append("webhook")
            hitl_policy = HITLPolicy(
                enabled=hitl,
                timeout_seconds=hitl_timeout,
                wait_for_approval=hitl_wait,
                channels=tuple(channels),
                store_path=effective_store,
                webhook_url=hitl_webhook_url,
                audit_log_path=audit_log,
            )
            policy = MCPSecurityPolicy(
                allow_write=allow_write,
                allow_sudo=allow_sudo,
                allow_dynamic_uri=allow_dynamic_uri,
                dry_run=dry_run,
                allowlist=allow_tuple,
                blocklist=block_tuple,
                audit_log_path=audit_log,
                max_read_bytes=max_read_bytes,
                hitl=hitl_policy,
            )
            registry = MCPHostRegistry.from_sources(
                inventory=inventory,
                uris=parsed_uris,
                group=group,
                host=host,
                include_local=local,
                default_to_local=True,
                policy=policy,
            )
            server = MCPServer(registry=registry, flow_specs=parsed_flows)
        except Exception as exc:
            renderer.print_error_and_exit(exc, title="MCP Server Configuration Error")
            return

        with contextlib.suppress(KeyboardInterrupt):
            asyncio.run(server.serve_stdio())

    approval_app = cyclopts.App(
        name="approval",
        help="Inspect, approve, and reject Human-in-the-Loop (HITL) requests for AI agents",
    )

    @approval_app.command(name="list")
    def approval_list(
        status: Annotated[
            str | None,
            Parameter(
                name=["--status", "-s"],
                help="Filter by status: PENDING, APPROVED, CONSUMED, REJECTED, EXPIRED",
            ),
        ] = None,
        store: Annotated[
            str | None,
            Parameter(
                name=["--store"],
                help="Path to JSON approval store file",
            ),
        ] = None,
        output_format: Annotated[
            str,
            Parameter(
                name=["--format", "-f"],
                help="Output format: table, json",
            ),
        ] = "table",
    ) -> None:
        """List Human-in-the-Loop approval requests."""
        store_path = _resolve_cli_store_path(store)
        mgr = ApprovalManager(store_path=store_path)
        try:
            reqs = asyncio.run(mgr.list_requests(status=status))
        except Exception as exc:
            renderer.print_error_and_exit(exc, title="Approval List Error")
            return

        if output_format == "json":
            print_json(console, {"approvals": [r.to_public_dict() for r in reqs], "count": len(reqs)})
            return

        if not reqs:
            console.print("[dim]No approval requests found.[/dim]")
            return

        tbl = Table(
            title="Human-in-the-Loop Approval Requests",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
        )
        tbl.add_column("ID", style="bold white", width=18)
        tbl.add_column("Status", width=11)
        tbl.add_column("Risk", width=12)
        tbl.add_column("Host", style="cyan", width=16)
        tbl.add_column("Tool / Command", style="white")
        tbl.add_column("TTL / Decided By", width=18)

        for r in reqs:
            detail = r.command or r.parameters.get("path") or r.tool_name
            detail_str = str(detail)
            if len(detail_str) > 48:
                detail_str = detail_str[:45] + "..."
            info_col = (
                f"{r.remaining_seconds():.0f}s left"
                if r.status.value == "PENDING"
                else (r.decided_by or r.status.value)
            )
            tbl.add_row(
                r.approval_id,
                r.status.value,
                r.risk_tier.value,
                r.target_host,
                detail_str,
                str(info_col),
            )
        console.print(tbl)

    @approval_app.command(name="show")
    def approval_show(
        approval_id: Annotated[str, Parameter(help="Approval request ID (e.g. appr_...)")],
        store: Annotated[
            str | None,
            Parameter(
                name=["--store"],
                help="Path to JSON approval store file",
            ),
        ] = None,
        output_format: Annotated[
            str,
            Parameter(
                name=["--format", "-f"],
                help="Output format: panel, json",
            ),
        ] = "panel",
    ) -> None:
        """Show detailed information and unified diff for a specific approval request."""
        store_path = _resolve_cli_store_path(store)
        mgr = ApprovalManager(store_path=store_path)
        try:
            req = asyncio.run(mgr.get_request(approval_id))
        except Exception as exc:
            renderer.print_error_and_exit(exc, title="Approval Show Error")
            return

        if output_format == "json":
            print_json(console, req.to_public_dict())
            return

        lines = [
            f"[bold]Approval ID[/bold] : {req.approval_id}",
            f"[bold]Status[/bold]      : {req.status.value}",
            f"[bold]Target Host[/bold] : {req.target_host}",
            f"[bold]Tool[/bold]        : {req.tool_name}",
            f"[bold]Risk Tier[/bold]   : {req.risk_tier.value}",
            f"[bold]Reasons[/bold]     : {'; '.join(req.risk_reasons) or '-'}",
        ]
        if req.command:
            lines.append(f"[bold]Command[/bold]     : {req.command}")
        if req.sudo:
            lines.append("[bold]Sudo[/bold]        : True")
        if req.decided_by:
            lines.append(f"[bold]Decided By[/bold]  : {req.decided_by} ({req.decision_reason or 'no comment'})")
        if req.diff:
            lines.append(f"\n[bold]Diff[/bold]:\n{req.diff}")
        console.print(
            Panel(
                "\n".join(lines),
                title=f"Approval Request {req.approval_id}",
                border_style="cyan",
            )
        )

    @approval_app.command(name="approve")
    def approval_approve(
        approval_id: Annotated[str, Parameter(help="Approval request ID to approve (e.g. appr_...)")],
        by: Annotated[
            str | None,
            Parameter(
                name=["--by", "-b"],
                help="Operator username or identifier",
            ),
        ] = None,
        reason: Annotated[
            str | None,
            Parameter(
                name=["--reason", "--comment", "-r", "-m"],
                help="Approval comment or justification",
            ),
        ] = None,
        store: Annotated[
            str | None,
            Parameter(
                name=["--store"],
                help="Path to JSON approval store file",
            ),
        ] = None,
        output_format: Annotated[
            str,
            Parameter(
                name=["--format", "-f"],
                help="Output format: panel, json",
            ),
        ] = "panel",
    ) -> None:
        """Approve a pending Human-in-the-Loop request."""
        store_path = _resolve_cli_store_path(store)
        operator = by or os.environ.get("USER") or os.environ.get("USERNAME") or "cli_operator"
        mgr = ApprovalManager(store_path=store_path)
        try:
            req = asyncio.run(mgr.approve(approval_id, decided_by=operator, reason=reason))
        except Exception as exc:
            renderer.print_error_and_exit(exc, title="Approval Error")
            return

        if output_format == "json":
            print_json(console, req.to_public_dict())
            return

        console.print(
            Panel(
                f"[bold green]APPROVED[/bold green] {req.approval_id}\n"
                f"[dim]Host:[/dim] {req.target_host} | [dim]Tool:[/dim] {req.tool_name} | "
                f"[dim]Approved by:[/dim] {req.decided_by}",
                title="HITL Approval",
                border_style="green",
            )
        )

    @approval_app.command(name="reject")
    def approval_reject(
        approval_id: Annotated[str, Parameter(help="Approval request ID to reject (e.g. appr_...)")],
        by: Annotated[
            str | None,
            Parameter(
                name=["--by", "-b"],
                help="Operator username or identifier",
            ),
        ] = None,
        reason: Annotated[
            str | None,
            Parameter(
                name=["--reason", "--comment", "-r", "-m"],
                help="Rejection reason or explanation",
            ),
        ] = None,
        store: Annotated[
            str | None,
            Parameter(
                name=["--store"],
                help="Path to JSON approval store file",
            ),
        ] = None,
        output_format: Annotated[
            str,
            Parameter(
                name=["--format", "-f"],
                help="Output format: panel, json",
            ),
        ] = "panel",
    ) -> None:
        """Reject a pending Human-in-the-Loop request."""
        store_path = _resolve_cli_store_path(store)
        operator = by or os.environ.get("USER") or os.environ.get("USERNAME") or "cli_operator"
        mgr = ApprovalManager(store_path=store_path)
        try:
            req = asyncio.run(mgr.reject(approval_id, decided_by=operator, reason=reason))
        except Exception as exc:
            renderer.print_error_and_exit(exc, title="Rejection Error")
            return

        if output_format == "json":
            print_json(console, req.to_public_dict())
            return

        console.print(
            Panel(
                f"[bold red]REJECTED[/bold red] {req.approval_id}\n"
                f"[dim]Host:[/dim] {req.target_host} | [dim]Tool:[/dim] {req.tool_name} | "
                f"[dim]Rejected by:[/dim] {req.decided_by} ({req.decision_reason or 'no reason'})",
                title="HITL Rejection",
                border_style="red",
            )
        )

    app.command(approval_app)

