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
    ActionRiskClassifier,
    ApprovalManager,
    HITLPolicy,
    MCPHostRegistry,
    MCPSecurityPolicy,
    MCPServer,
)
from ..security import (
    CommandASTParser,
    PolicyGuardrailConfig,
    build_auth_context,
    create_policy_engine,
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
    policy_engine: str = "embedded",
    policy_preset: str = "default",
    policy_file: str | None = None,
    opa_url: str | None = None,
    agent_role: str = "operator",
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
    if policy_engine != "embedded":
        args.extend(["--policy-engine", policy_engine])
    if policy_preset != "default":
        args.extend(["--policy-preset", policy_preset])
    if policy_file:
        args.extend(["--policy-file", str(Path(policy_file).resolve())])
    if opa_url:
        args.extend(["--opa-url", opa_url])
    if agent_role != "operator":
        args.extend(["--agent-role", agent_role])

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
        policy_engine: Annotated[
            str,
            Parameter(
                name=["--policy-engine"],
                help="Policy-as-Code backend engine: 'embedded' or 'opa' (default: embedded)",
            ),
        ] = "embedded",
        policy_preset: Annotated[
            str,
            Parameter(
                name=["--policy-preset"],
                help="Built-in Policy-as-Code preset: default, prod-guard, least-privilege, strict",
            ),
        ] = "default",
        policy_file: Annotated[
            str | None,
            Parameter(
                name=["--policy-file"],
                help="Optional YAML/JSON declarative policy rules file",
            ),
        ] = None,
        opa_url: Annotated[
            str | None,
            Parameter(
                name=["--opa-url"],
                help="Open Policy Agent (OPA) REST endpoint URL (enables OPA evaluation)",
            ),
        ] = None,
        agent_role: Annotated[
            str,
            Parameter(
                name=["--agent-role"],
                help="Default RBAC/ABAC role for AI agent calls (default: operator)",
            ),
        ] = "operator",
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
                policy_engine=policy_engine,
                policy_preset=policy_preset,
                policy_file=policy_file,
                opa_url=opa_url,
                agent_role=agent_role,
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
            eff_engine = "opa" if (policy_engine == "opa" or opa_url) else "embedded"
            guardrails_cfg = PolicyGuardrailConfig(
                enabled=True,
                engine="opa" if eff_engine == "opa" else "embedded",
                preset=policy_preset,
                policy_file=policy_file,
                opa_url=opa_url,
                default_role=agent_role,
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
                guardrails=guardrails_cfg,
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

    policy_app = cyclopts.App(
        name="policy",
        help="AST command verification and Policy-as-Code evaluation for AI agents",
    )

    @policy_app.command(name="parse")
    def policy_parse(
        command: Annotated[str, Parameter(help="Shell command string to decompose into AST")],
        max_depth: Annotated[
            int,
            Parameter(
                name=["--max-depth"],
                help="Maximum recursive subshell/wrapper AST depth (default: 4)",
            ),
        ] = 4,
        max_pipeline: Annotated[
            int,
            Parameter(
                name=["--max-pipeline"],
                help="Maximum atomic commands in pipeline/chain (default: 8)",
            ),
        ] = 8,
        output_format: Annotated[
            str,
            Parameter(
                name=["--format", "-f"],
                help="Output format: panel, json",
            ),
        ] = "panel",
    ) -> None:
        """Parse a shell command into an AST and inspect atomic verbs, wrappers, and obfuscation."""
        ast = CommandASTParser.parse(
            command,
            max_depth=max_depth,
            max_pipeline_length=max_pipeline,
        )
        if output_format == "json":
            print_json(console, ast.to_dict())
            return

        status_badge = (
            "[bold red]OBFUSCATED / OPAQUE[/bold red]"
            if (ast.is_obfuscated or ast.complexity_exceeded)
            else "[bold green]CLEAN AST[/bold green]"
        )
        lines = [
            f"[bold]Raw Command[/bold]      : {ast.raw_command}",
            f"[bold]AST Status[/bold]       : {status_badge}",
            f"[bold]Verbs[/bold]            : {', '.join(ast.verbs) or '-'}",
            f"[bold]Pipeline Length[/bold]  : {ast.pipeline_length} (Max Depth: {ast.max_depth})",
            f"[bold]Destructive Verbs[/bold]: {ast.has_destructive_verbs}",
        ]
        if ast.obfuscation_reasons:
            lines.append(
                f"[bold red]Obfuscation[/bold red]      : {'; '.join(ast.obfuscation_reasons)}"
            )
        console.print(
            Panel(
                "\n".join(lines),
                title="Command AST Verification",
                border_style="red" if ast.is_obfuscated else "cyan",
            )
        )
        if ast.commands:
            tbl = Table(
                title="Decomposed Atomic Commands",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold cyan",
            )
            tbl.add_column("#", width=4)
            tbl.add_column("Executable", style="bold white", width=16)
            tbl.add_column("Args", style="white")
            tbl.add_column("Flags", style="yellow", width=14)
            tbl.add_column("Wrappers", style="magenta", width=18)
            tbl.add_column("Depth", width=6)
            for idx, atom in enumerate(ast.commands, start=1):
                tbl.add_row(
                    str(idx),
                    atom.executable,
                    " ".join(atom.args) or "-",
                    " ".join(atom.flags) or "-",
                    ", ".join(atom.wrappers) or "-",
                    str(atom.subshell_depth),
                )
            console.print(tbl)

    @policy_app.command(name="eval")
    def policy_eval(
        command: Annotated[str, Parameter(help="Shell command string to evaluate against Policy-as-Code")],
        host: Annotated[
            str,
            Parameter(
                name=["--host", "-H"],
                help="Target host alias for ABAC resource context (default: local)",
            ),
        ] = "local",
        env: Annotated[
            str,
            Parameter(
                name=["--env", "-e"],
                help="Target environment tag: default, staging, prod (default: default)",
            ),
        ] = "default",
        role: Annotated[
            str,
            Parameter(
                name=["--role", "-r"],
                help="Agent RBAC/ABAC role: operator, readonly, junior-ai, sre (default: operator)",
            ),
        ] = "operator",
        agent_id: Annotated[
            str,
            Parameter(
                name=["--agent-id"],
                help="Agent identifier (default: mcp-agent)",
            ),
        ] = "mcp-agent",
        sudo: Annotated[
            bool,
            Parameter(
                name=["--sudo"],
                negative="",
                help="Evaluate command with sudo=True",
            ),
        ] = False,
        preset: Annotated[
            str,
            Parameter(
                name=["--preset", "-p"],
                help="Built-in policy preset: default, prod-guard, least-privilege, strict",
            ),
        ] = "default",
        policy_file: Annotated[
            str | None,
            Parameter(
                name=["--policy-file"],
                help="Path to declarative YAML/JSON policy rules file",
            ),
        ] = None,
        opa_url: Annotated[
            str | None,
            Parameter(
                name=["--opa-url"],
                help="Open Policy Agent (OPA) REST URL",
            ),
        ] = None,
        maintenance_window: Annotated[
            bool | None,
            Parameter(
                name=["--maintenance-window"],
                help="Explicitly override maintenance_window_active (true/false)",
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
        """Evaluate a command against CommandASTParser, ActionRiskClassifier, and PolicyEngine."""
        try:
            cfg = PolicyGuardrailConfig(
                enabled=True,
                engine="opa" if opa_url else "embedded",
                preset=preset,
                policy_file=policy_file,
                opa_url=opa_url,
                default_agent_id=agent_id,
                default_role=role,
                maintenance_window_active=maintenance_window,
            )
            engine = create_policy_engine(cfg)
            ast = CommandASTParser.parse(
                command,
                max_depth=cfg.max_ast_depth,
                max_pipeline_length=cfg.max_pipeline_length,
            )
            is_prod = env.strip().lower() in ("prod", "production", "prd", "critical")
            hitl_pol = HITLPolicy(enabled=True)
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
                groups=("prod",) if is_prod else ("default",),
                environment=env,
                is_production=is_prod,
                tool_name="uniconn_run",
                command=command,
                ast=ast,
                sudo=sudo,
                risk_tier=assessment.risk_tier.value,
                risk_reasons=assessment.reasons,
                maintenance_window_override=maintenance_window,
            )
            eval_res = asyncio.run(engine.evaluate(auth_ctx))
        except Exception as exc:
            renderer.print_error_and_exit(exc, title="Policy Evaluation Error")
            return

        payload = {
            "decision": eval_res.decision.value,
            "allowed": eval_res.allowed,
            "requires_approval": eval_res.requires_approval or assessment.requires_approval,
            "risk_assessment": assessment.to_dict(),
            "policy": eval_res.to_dict(),
            "ast": ast.to_dict(),
            "auth_context": auth_ctx.to_dict(),
        }
        if output_format == "json":
            print_json(console, payload)
            return

        dec = eval_res.decision.value
        color = "green" if dec == "ALLOW" else ("yellow" if dec == "REQUIRE_APPROVAL" else "red")
        lines = [
            f"[bold]Decision[/bold]     : [bold {color}]{dec}[/bold {color}]",
            f"[bold]Risk Tier[/bold]    : {assessment.risk_tier.value}",
            f"[bold]Preset/Engine[/bold]: {cfg.preset} ({eval_res.engine})",
            f"[bold]Subject[/bold]      : {agent_id} (role={role})",
            f"[bold]Resource[/bold]     : {host} (env={env}, prod={is_prod})",
            f"[bold]AST Verbs[/bold]    : {', '.join(ast.verbs) or '-'}",
        ]
        if eval_res.reasons:
            lines.append(f"[bold]Policy Reasons[/bold]: {'; '.join(eval_res.reasons)}")
        if eval_res.remediation_hint:
            lines.append(f"[bold cyan]Remediation[/bold cyan]  : {eval_res.remediation_hint}")
        console.print(
            Panel(
                "\n".join(lines),
                title="Policy-as-Code Evaluation Result",
                border_style=color,
            )
        )

    app.command(policy_app)

