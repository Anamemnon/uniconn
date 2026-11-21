# src/uniconn/cli/cmd_mcp.py
"""CLI-команды запуска официального MCP-сервера (uniconn mcp) и управления HITL-заявками (uniconn approval)."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sys
from pathlib import Path
from typing import Annotated, Any, Literal, cast

from ..mcp import (
    DEFAULT_STATE_DB_PATH,
    ActionRiskClassifier,
    ApprovalManager,
    HITLPolicy,
    InMemoryStateStore,
    MCPAuthConfig,
    MCPHostRegistry,
    MCPHttpConfig,
    MCPSecurityPolicy,
    MCPServer,
    MTLSConfig,
    OAuth2OIDCConfig,
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


def _parse_tenant_inventories(raw: str | None) -> dict[str, str]:
    """Разобрать строку ``tenant=path,tenant2=path2`` в словарь путей к инвентарям."""
    if not raw or not raw.strip():
        return {}
    result: dict[str, str] = {}
    for item in raw.split(","):
        token = item.strip()
        if not token:
            continue
        if "=" not in token:
            raise ValueError(
                f"Invalid --tenant-inventory item {token!r}; expected 'tenant_id=/path/to/inventory.yaml'"
            )
        tenant_id, inv_path = token.split("=", 1)
        tenant_id = tenant_id.strip()
        inv_path = inv_path.strip()
        if not tenant_id or not inv_path:
            raise ValueError(f"Invalid --tenant-inventory item {token!r}; tenant_id and path must be non-empty")
        result[tenant_id] = inv_path
    return result


def _build_network_auth_and_http_configs(
    *,
    bind: str,
    port: int,
    mcp_path: str,
    allowed_origins: str | None,
    allowed_hosts: str | None,
    stateless: bool,
    session_ttl: float,
    max_sessions_per_tenant: int,
    auth_mode: str,
    oidc_issuer: str | None,
    oidc_jwks_url: str | None,
    oidc_audience: str | None,
    role_claim: str,
    tenant_claim: str,
    agent_id_claim: str,
    required_scopes: str | None,
    resource_url: str | None,
    oidc_allow_private_network: bool,
    tls_cert: str | None,
    tls_key: str | None,
    tls_client_ca: str | None,
    mtls_role_source: str,
    mtls_tenant_source: str,
    trusted_proxy_cidrs: str | None,
    require_tenant: bool,
    agent_role: str | None = None,
) -> tuple[MCPAuthConfig, MCPHttpConfig]:
    """Собрать fail-closed конфигурации ``MCPAuthConfig`` и ``MCPHttpConfig`` из флагов CLI."""
    mode_norm = auth_mode.strip().lower()
    if mode_norm not in ("oauth2", "mtls", "either", "both"):
        raise ValueError(f"Unsupported --auth-mode {auth_mode!r}; expected one of: oauth2, mtls, either, both")

    oauth2_cfg: OAuth2OIDCConfig | None = None
    if mode_norm in ("oauth2", "both") or oidc_issuer or oidc_jwks_url:
        aud_items = _split_csv(oidc_audience)
        eff_audience: str | tuple[str, ...] | None = (
            aud_items[0] if len(aud_items) == 1 else (aud_items if aud_items else None)
        )
        oauth2_cfg = OAuth2OIDCConfig(
            issuer=oidc_issuer,
            jwks_url=oidc_jwks_url,
            audience=eff_audience,
            role_claim=role_claim,
            tenant_claim=tenant_claim,
            agent_id_claim=agent_id_claim,
            required_scopes=_split_csv(required_scopes),
            resource_url=resource_url,
            allow_private_network=oidc_allow_private_network,
        )

    mtls_cfg: MTLSConfig | None = None
    proxy_cidrs = _split_csv(trusted_proxy_cidrs)
    if mode_norm in ("mtls", "both") or tls_client_ca or proxy_cidrs:
        valid_role_sources = ("ou", "san_uri", "cn", "static_map", "spiffe_sa")
        valid_tenant_sources = ("o", "ou", "spiffe_ns", "san_dns", "cn", "static_map")
        r_src = mtls_role_source.strip().lower()
        t_src = mtls_tenant_source.strip().lower()
        if r_src not in valid_role_sources:
            raise ValueError(
                f"Unsupported --mtls-role-source {mtls_role_source!r}; expected one of: {', '.join(valid_role_sources)}"
            )
        if t_src not in valid_tenant_sources:
            raise ValueError(
                f"Unsupported --mtls-tenant-source {mtls_tenant_source!r}; "
                f"expected one of: {', '.join(valid_tenant_sources)}"
            )
        mtls_cfg = MTLSConfig(
            ca_cert_path=tls_client_ca,
            role_source=cast(Literal["ou", "san_uri", "cn", "static_map", "spiffe_sa"], r_src),
            tenant_source=cast(Literal["o", "ou", "spiffe_ns", "san_dns", "cn", "static_map"], t_src),
            trusted_proxy_cidrs=proxy_cidrs,
        )

    auth_cfg = MCPAuthConfig(
        mode=cast(Literal["oauth2", "mtls", "either", "both"], mode_norm),
        oauth2=oauth2_cfg,
        mtls=mtls_cfg,
        require_tenant=require_tenant,
        default_role=agent_role,
    )
    http_cfg = MCPHttpConfig(
        host=bind,
        port=port,
        mcp_path=mcp_path,
        allowed_origins=_split_csv(allowed_origins),
        allowed_hosts=_split_csv(allowed_hosts),
        session_ttl_seconds=session_ttl,
        max_sessions_per_tenant=max_sessions_per_tenant,
        tls_cert_path=tls_cert,
        tls_key_path=tls_key,
        tls_client_ca_path=tls_client_ca if (tls_cert and tls_key) else None,
        stateless_mode=stateless,
    )
    return auth_cfg, http_cfg


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
    transport: str = "stdio",
    bind: str = "127.0.0.1",
    port: int = 8080,
    mcp_path: str = "/mcp",
    auth_mode: str = "oauth2",
    resource_url: str | None = None,
    tls_cert: str | None = None,
) -> dict[str, Any]:
    """Сформировать готовый JSON-конфиг ``mcpServers`` для Claude Desktop / Cursor."""
    if transport.strip().lower() == "http":
        scheme = "https" if tls_cert else "http"
        norm_path = mcp_path if mcp_path.startswith("/") else f"/{mcp_path}"
        url = resource_url or f"{scheme}://{bind}:{port}{norm_path}"
        entry: dict[str, Any] = {
            "type": "streamable-http",
            "url": url,
        }
        if auth_mode.strip().lower() in ("oauth2", "either", "both"):
            entry["headers"] = {"Authorization": "Bearer ${UNICONN_MCP_TOKEN}"}
        return {"mcpServers": {"uniconn": entry}}

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
        norm_hitl_store = hitl_store.strip()
        resolved_hitl_store = (
            ":memory:" if norm_hitl_store == ":memory:" else str(Path(norm_hitl_store).resolve())
        )
        args.extend(["--hitl-store", resolved_hitl_store])
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
    env_state = os.environ.get("UNICONN_STATE_DB") or os.environ.get("UNICONN_APPROVAL_STORE")
    if env_state and env_state.strip():
        return Path(env_state.strip()).expanduser()
    return DEFAULT_STATE_DB_PATH


def _build_mcp_server_from_args(
    *,
    inventory: str | None,
    parsed_uris: tuple[str, ...],
    group: str | None,
    host: str | None,
    local: bool,
    allow_write: bool,
    allow_sudo: bool,
    allow_dynamic_uri: bool,
    dry_run: bool,
    allowlist: str | None,
    blocklist: str | None,
    audit_log: str | None,
    max_read_bytes: int,
    hitl: bool,
    hitl_store: str | None,
    hitl_timeout: float,
    hitl_wait: bool,
    hitl_webhook_url: str | None,
    parsed_flows: tuple[str, ...],
    policy_engine: str,
    policy_preset: str,
    policy_file: str | None,
    opa_url: str | None,
    agent_role: str,
    tenant_inventories: dict[str, str] | None = None,
    allow_shared_hosts: bool = False,
    auth_config: MCPAuthConfig | None = None,
    http_config: MCPHttpConfig | None = None,
    stateless: bool = False,
    checkpoint_secret: str | None = None,
) -> MCPServer:
    allow_tuple = _split_csv(allowlist)
    block_tuple = _split_csv(blocklist) if blocklist else None
    raw_store = hitl_store.strip() if isinstance(hitl_store, str) and hitl_store.strip() else None
    force_in_memory = False
    if raw_store == ":memory:":
        effective_store: str | None = None
        force_in_memory = True
    elif stateless and raw_store is None:
        effective_store = None
        force_in_memory = True
    elif hitl or raw_store is not None:
        effective_store = str(_resolve_cli_store_path(raw_store))
    else:
        effective_store = None
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
    has_tenant_regs = bool(tenant_inventories)
    registry = MCPHostRegistry.from_sources(
        inventory=inventory,
        uris=parsed_uris,
        group=group,
        host=host,
        include_local=local,
        default_to_local=not has_tenant_regs,
        policy=policy,
    )
    tenant_regs: dict[str, MCPHostRegistry] = {}
    if tenant_inventories:
        for tid, inv_path in tenant_inventories.items():
            tenant_regs[tid] = MCPHostRegistry.from_sources(
                inventory=inv_path,
                include_local=False,
                default_to_local=False,
                policy=policy,
            )
    return MCPServer(
        registry=registry,
        tenant_registries=tenant_regs or None,
        allow_shared_hosts=allow_shared_hosts,
        auth_config=auth_config,
        http_config=http_config,
        state_store=InMemoryStateStore() if force_in_memory else None,
        flow_specs=parsed_flows,
        checkpoint_secret=checkpoint_secret,
    )


def _render_approval_list(console: Any, reqs: list[Any], output_format: str) -> None:
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
        detail = str(r.command or r.parameters.get("path") or r.tool_name)
        if len(detail) > 48:
            detail = detail[:45] + "..."
        info_col = (
            f"{r.remaining_seconds():.0f}s left"
            if r.status.value == "PENDING"
            else (r.decided_by or r.status.value)
        )
        tbl.add_row(r.approval_id, r.status.value, r.risk_tier.value, r.target_host, detail, str(info_col))
    console.print(tbl)


def _render_approval_detail(console: Any, req: Any, output_format: str) -> None:
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
    console.print(Panel("\n".join(lines), title=f"Approval Request {req.approval_id}", border_style="cyan"))


def _render_policy_ast(console: Any, ast: Any, output_format: str) -> None:
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
        lines.append(f"[bold red]Obfuscation[/bold red]      : {'; '.join(ast.obfuscation_reasons)}")
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


def _exec_policy_eval(
    console: Any,
    renderer: CLIOutputRenderer,
    *,
    command: str,
    host: str,
    env: str,
    role: str,
    agent_id: str,
    sudo: bool,
    preset: str,
    policy_file: str | None,
    opa_url: str | None,
    maintenance_window: bool | None,
    output_format: str,
) -> None:
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

    if output_format == "json":
        print_json(
            console,
            {
                "decision": eval_res.decision.value,
                "allowed": eval_res.allowed,
                "requires_approval": eval_res.requires_approval or assessment.requires_approval,
                "risk_assessment": assessment.to_dict(),
                "policy": eval_res.to_dict(),
                "ast": ast.to_dict(),
                "auth_context": auth_ctx.to_dict(),
            },
        )
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
    console.print(Panel("\n".join(lines), title="Policy-as-Code Evaluation Result", border_style=color))


def _register_approval_subcommands(app: Any, console: Any, renderer: CLIOutputRenderer) -> None:
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
                name=["--store", "--state-db"],
                help="Path to SQLite WAL state database (default: ~/.uniconn/state.db)",
            ),
        ] = None,
        output_format: Annotated[
            str,
            Parameter(name=["--format", "-f"], help="Output format: table, json"),
        ] = "table",
    ) -> None:
        """List Human-in-the-Loop approval requests."""

        async def _op() -> list[Any]:
            async with ApprovalManager(store_path=_resolve_cli_store_path(store)) as mgr:
                return await mgr.list_requests(status=status)

        try:
            reqs = asyncio.run(_op())
        except Exception as exc:
            renderer.print_error_and_exit(exc, title="Approval List Error")
            return
        _render_approval_list(console, reqs, output_format)

    @approval_app.command(name="show")
    def approval_show(
        approval_id: Annotated[str, Parameter(help="Approval request ID (e.g. appr_...)")],
        store: Annotated[
            str | None,
            Parameter(
                name=["--store", "--state-db"],
                help="Path to SQLite WAL state database (default: ~/.uniconn/state.db)",
            ),
        ] = None,
        output_format: Annotated[
            str,
            Parameter(name=["--format", "-f"], help="Output format: panel, json"),
        ] = "panel",
    ) -> None:
        """Show detailed information and unified diff for a specific approval request."""

        async def _op() -> Any:
            async with ApprovalManager(store_path=_resolve_cli_store_path(store)) as mgr:
                return await mgr.get_request(approval_id)

        try:
            req = asyncio.run(_op())
        except Exception as exc:
            renderer.print_error_and_exit(exc, title="Approval Show Error")
            return
        _render_approval_detail(console, req, output_format)

    @approval_app.command(name="approve")
    def approval_approve(
        approval_id: Annotated[str, Parameter(help="Approval request ID to approve (e.g. appr_...)")],
        by: Annotated[
            str | None,
            Parameter(name=["--by", "-b"], help="Operator username or identifier"),
        ] = None,
        reason: Annotated[
            str | None,
            Parameter(name=["--reason", "--comment", "-r", "-m"], help="Approval comment or justification"),
        ] = None,
        store: Annotated[
            str | None,
            Parameter(
                name=["--store", "--state-db"],
                help="Path to SQLite WAL state database (default: ~/.uniconn/state.db)",
            ),
        ] = None,
        output_format: Annotated[
            str,
            Parameter(name=["--format", "-f"], help="Output format: panel, json"),
        ] = "panel",
    ) -> None:
        """Approve a pending Human-in-the-Loop request."""
        operator = by or os.environ.get("USER") or os.environ.get("USERNAME") or "cli_operator"

        async def _op() -> Any:
            async with ApprovalManager(store_path=_resolve_cli_store_path(store)) as mgr:
                return await mgr.approve(approval_id, decided_by=operator, reason=reason)

        try:
            req = asyncio.run(_op())
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
            Parameter(name=["--by", "-b"], help="Operator username or identifier"),
        ] = None,
        reason: Annotated[
            str | None,
            Parameter(name=["--reason", "--comment", "-r", "-m"], help="Rejection reason or explanation"),
        ] = None,
        store: Annotated[
            str | None,
            Parameter(
                name=["--store", "--state-db"],
                help="Path to SQLite WAL state database (default: ~/.uniconn/state.db)",
            ),
        ] = None,
        output_format: Annotated[
            str,
            Parameter(name=["--format", "-f"], help="Output format: panel, json"),
        ] = "panel",
    ) -> None:
        """Reject a pending Human-in-the-Loop request."""
        operator = by or os.environ.get("USER") or os.environ.get("USERNAME") or "cli_operator"

        async def _op() -> Any:
            async with ApprovalManager(store_path=_resolve_cli_store_path(store)) as mgr:
                return await mgr.reject(approval_id, decided_by=operator, reason=reason)

        try:
            req = asyncio.run(_op())
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


def _register_policy_subcommands(app: Any, console: Any, renderer: CLIOutputRenderer) -> None:
    policy_app = cyclopts.App(
        name="policy",
        help="AST command verification and Policy-as-Code evaluation for AI agents",
    )

    @policy_app.command(name="parse")
    def policy_parse(
        command: Annotated[str, Parameter(help="Shell command string to decompose into AST")],
        max_depth: Annotated[
            int,
            Parameter(name=["--max-depth"], help="Maximum recursive subshell/wrapper AST depth (default: 4)"),
        ] = 4,
        max_pipeline: Annotated[
            int,
            Parameter(name=["--max-pipeline"], help="Maximum atomic commands in pipeline/chain (default: 8)"),
        ] = 8,
        output_format: Annotated[
            str,
            Parameter(name=["--format", "-f"], help="Output format: panel, json"),
        ] = "panel",
    ) -> None:
        """Parse a shell command into an AST and inspect atomic verbs, wrappers, and obfuscation."""
        ast = CommandASTParser.parse(command, max_depth=max_depth, max_pipeline_length=max_pipeline)
        _render_policy_ast(console, ast, output_format)

    @policy_app.command(name="eval")
    def policy_eval(
        command: Annotated[str, Parameter(help="Shell command string to evaluate against Policy-as-Code")],
        host: Annotated[
            str,
            Parameter(name=["--host", "-H"], help="Target host alias for ABAC resource context (default: local)"),
        ] = "local",
        env: Annotated[
            str,
            Parameter(name=["--env", "-e"], help="Target environment tag: default, staging, prod (default: default)"),
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
            Parameter(name=["--agent-id"], help="Agent identifier (default: mcp-agent)"),
        ] = "mcp-agent",
        sudo: Annotated[
            bool,
            Parameter(name=["--sudo"], negative="", help="Evaluate command with sudo=True"),
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
            Parameter(name=["--policy-file"], help="Path to declarative YAML/JSON policy rules file"),
        ] = None,
        opa_url: Annotated[
            str | None,
            Parameter(name=["--opa-url"], help="Open Policy Agent (OPA) REST URL"),
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
            Parameter(name=["--format", "-f"], help="Output format: panel, json"),
        ] = "panel",
    ) -> None:
        """Evaluate a command against CommandASTParser, ActionRiskClassifier, and PolicyEngine."""
        _exec_policy_eval(
            console,
            renderer,
            command=command,
            host=host,
            env=env,
            role=role,
            agent_id=agent_id,
            sudo=sudo,
            preset=preset,
            policy_file=policy_file,
            opa_url=opa_url,
            maintenance_window=maintenance_window,
            output_format=output_format,
        )

    app.command(policy_app)


def register_mcp_commands(app: Any, console: Any, renderer: CLIOutputRenderer) -> None:
    """Зарегистрировать команду ``mcp`` и подгруппы ``approval``, ``policy`` в Cyclopts-приложении."""

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
                name=["--hitl-store", "--state-db"],
                help="Path to SQLite WAL state DB for HITL approvals and Flow checkpoints (or ':memory:')",
            ),
        ] = None,
        checkpoint_secret: Annotated[
            str | None,
            Parameter(
                name=["--checkpoint-secret"],
                help="Shared HMAC secret for stateless signed Flow checkpoint tokens (or UNICONN_CHECKPOINT_SECRET)",
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
        transport: Annotated[
            str,
            Parameter(
                name=["--transport", "-t"],
                help="MCP transport mode: 'stdio' (default) or 'http' (Streamable HTTP / SSE)",
            ),
        ] = "stdio",
        bind: Annotated[
            str,
            Parameter(
                name=["--bind"],
                help="Bind host for --transport http (default: 127.0.0.1)",
            ),
        ] = "127.0.0.1",
        port: Annotated[
            int,
            Parameter(
                name=["--port", "-p"],
                help="Bind port for --transport http (default: 8080)",
            ),
        ] = 8080,
        mcp_path: Annotated[
            str,
            Parameter(
                name=["--mcp-path"],
                help="HTTP endpoint path for Streamable HTTP MCP (default: /mcp)",
            ),
        ] = "/mcp",
        allowed_origins: Annotated[
            str | None,
            Parameter(
                name=["--allowed-origins"],
                help="Comma-separated allowed Origin headers for anti-DNS-rebinding",
            ),
        ] = None,
        allowed_hosts: Annotated[
            str | None,
            Parameter(
                name=["--allowed-hosts"],
                help="Comma-separated allowed Host headers for anti-DNS-rebinding",
            ),
        ] = None,
        stateless: Annotated[
            bool,
            Parameter(
                name=["--stateless"],
                negative="",
                help="Run in 100% stateless mode (no Mcp-Session-Id and pure InMemoryStateStore unless --state-db set)",
            ),
        ] = False,
        session_ttl: Annotated[
            float,
            Parameter(
                name=["--session-ttl"],
                help="Idle TTL in seconds for HTTP MCP sessions (default: 1800.0)",
            ),
        ] = 1800.0,
        max_sessions_per_tenant: Annotated[
            int,
            Parameter(
                name=["--max-sessions-per-tenant"],
                help="Maximum concurrent HTTP MCP sessions per tenant (default: 100)",
            ),
        ] = 100,
        auth_mode: Annotated[
            str,
            Parameter(
                name=["--auth-mode"],
                help="Network auth mode for --transport http: oauth2, mtls, either, both (default: oauth2)",
            ),
        ] = "oauth2",
        oidc_issuer: Annotated[
            str | None,
            Parameter(
                name=["--oidc-issuer"],
                help="OAuth 2.1 / OIDC issuer URL for discovery and iss claim verification",
            ),
        ] = None,
        oidc_jwks_url: Annotated[
            str | None,
            Parameter(
                name=["--oidc-jwks-url"],
                help="Explicit JWKS URL for JWT signature verification",
            ),
        ] = None,
        oidc_audience: Annotated[
            str | None,
            Parameter(
                name=["--oidc-audience"],
                help="Expected JWT audience (comma-separated for multiple allowed audiences)",
            ),
        ] = None,
        role_claim: Annotated[
            str,
            Parameter(
                name=["--role-claim"],
                help="JWT claim path for RBAC role extraction (default: role)",
            ),
        ] = "role",
        tenant_claim: Annotated[
            str,
            Parameter(
                name=["--tenant-claim"],
                help="JWT claim path for tenant_id extraction (default: tenant_id)",
            ),
        ] = "tenant_id",
        agent_id_claim: Annotated[
            str,
            Parameter(
                name=["--agent-id-claim"],
                help="JWT claim path for agent_id extraction (default: sub)",
            ),
        ] = "sub",
        required_scopes: Annotated[
            str | None,
            Parameter(
                name=["--required-scopes"],
                help="Comma-separated OAuth 2.1 scopes required on every MCP request",
            ),
        ] = None,
        resource_url: Annotated[
            str | None,
            Parameter(
                name=["--resource-url"],
                help="Canonical MCP Resource URL advertised in RFC 9728 Protected Resource Metadata",
            ),
        ] = None,
        oidc_allow_private_network: Annotated[
            bool,
            Parameter(
                name=["--oidc-allow-private-network"],
                negative="",
                help="Allow OIDC discovery / JWKS fetches to private/loopback networks",
            ),
        ] = False,
        tls_cert: Annotated[
            str | None,
            Parameter(
                name=["--tls-cert"],
                help="Path to server TLS certificate PEM file",
            ),
        ] = None,
        tls_key: Annotated[
            str | None,
            Parameter(
                name=["--tls-key"],
                help="Path to server TLS private key PEM file",
            ),
        ] = None,
        tls_client_ca: Annotated[
            str | None,
            Parameter(
                name=["--tls-client-ca"],
                help="Path to CA bundle PEM file for verifying mTLS client certificates",
            ),
        ] = None,
        mtls_role_source: Annotated[
            str,
            Parameter(
                name=["--mtls-role-source"],
                help="X.509 field for RBAC role: ou, san_uri, cn, static_map, spiffe_sa (default: ou)",
            ),
        ] = "ou",
        mtls_tenant_source: Annotated[
            str,
            Parameter(
                name=["--mtls-tenant-source"],
                help="X.509 field for tenant_id: spiffe_ns, o, ou, san_dns, cn, static_map (default: spiffe_ns)",
            ),
        ] = "spiffe_ns",
        trusted_proxy_cidrs: Annotated[
            str | None,
            Parameter(
                name=["--trusted-proxy-cidrs"],
                help="Comma-separated CIDRs of reverse proxies trusted to pass client certificate headers",
            ),
        ] = None,
        tenant_inventory: Annotated[
            str | None,
            Parameter(
                name=["--tenant-inventory"],
                help="Comma-separated tenant=path pairs for isolated per-tenant registries",
            ),
        ] = None,
        allow_shared_hosts: Annotated[
            bool,
            Parameter(
                name=["--allow-shared-hosts"],
                negative="",
                help="Allow tenants to access untagged hosts in a shared inventory (default: false)",
            ),
        ] = False,
        require_tenant: Annotated[
            bool,
            Parameter(
                name=["--require-tenant"],
                help="Require non-empty tenant_id on authenticated network MCP calls (default: true)",
            ),
        ] = True,
        print_config: Annotated[
            bool,
            Parameter(
                name=["--print-config"],
                negative="",
                help="Print mcpServers JSON configuration for Claude Desktop / Cursor and exit",
            ),
        ] = False,
    ) -> None:
        """Start the official uniconn Model Context Protocol (MCP) server (stdio or Streamable HTTP/SSE)."""
        parsed_uris = _split_csv(uri)
        parsed_flows = _split_csv(flows)
        transport_norm = transport.strip().lower()
        if transport_norm not in ("stdio", "http"):
            sys.stderr.write(f"ERROR: Unsupported --transport {transport!r}; expected 'stdio' or 'http'\n")
            sys.exit(1)

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
                transport=transport_norm,
                bind=bind,
                port=port,
                mcp_path=mcp_path,
                auth_mode=auth_mode,
                resource_url=resource_url,
                tls_cert=tls_cert,
            )
            sys.stdout.write(json.dumps(cfg_snippet, ensure_ascii=False, indent=2) + "\n")
            sys.stdout.flush()
            return

        if inventory is not None and not Path(inventory).is_file():
            sys.stderr.write(f"ERROR: Inventory file not found: {inventory}\n")
            sys.exit(1)

        try:
            parsed_tenant_invs = _parse_tenant_inventories(tenant_inventory)
            for tid, inv_path in parsed_tenant_invs.items():
                if not Path(inv_path).is_file():
                    raise FileNotFoundError(f"Tenant {tid!r} inventory file not found: {inv_path}")

            auth_cfg: MCPAuthConfig | None = None
            http_cfg: MCPHttpConfig | None = None
            if transport_norm == "http":
                auth_cfg, http_cfg = _build_network_auth_and_http_configs(
                    bind=bind,
                    port=port,
                    mcp_path=mcp_path,
                    allowed_origins=allowed_origins,
                    allowed_hosts=allowed_hosts,
                    stateless=stateless,
                    session_ttl=session_ttl,
                    max_sessions_per_tenant=max_sessions_per_tenant,
                    auth_mode=auth_mode,
                    oidc_issuer=oidc_issuer,
                    oidc_jwks_url=oidc_jwks_url,
                    oidc_audience=oidc_audience,
                    role_claim=role_claim,
                    tenant_claim=tenant_claim,
                    agent_id_claim=agent_id_claim,
                    required_scopes=required_scopes,
                    resource_url=resource_url,
                    oidc_allow_private_network=oidc_allow_private_network,
                    tls_cert=tls_cert,
                    tls_key=tls_key,
                    tls_client_ca=tls_client_ca,
                    mtls_role_source=mtls_role_source,
                    mtls_tenant_source=mtls_tenant_source,
                    trusted_proxy_cidrs=trusted_proxy_cidrs,
                    require_tenant=require_tenant,
                    agent_role=None,
                )

            server = _build_mcp_server_from_args(
                inventory=inventory,
                parsed_uris=parsed_uris,
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
                parsed_flows=parsed_flows,
                policy_engine=policy_engine,
                policy_preset=policy_preset,
                policy_file=policy_file,
                opa_url=opa_url,
                agent_role=agent_role,
                tenant_inventories=parsed_tenant_invs,
                allow_shared_hosts=allow_shared_hosts,
                auth_config=auth_cfg,
                http_config=http_cfg,
                stateless=stateless,
                checkpoint_secret=checkpoint_secret,
            )
        except Exception as exc:
            renderer.print_error_and_exit(exc, title="MCP Server Configuration Error")
            return

        async def _serve_and_close() -> None:
            try:
                if transport_norm == "http":
                    await server.serve_http(auth_config=auth_cfg, http_config=http_cfg)
                else:
                    await server.serve_stdio()
            finally:
                await server.close()

        with contextlib.suppress(KeyboardInterrupt):
            asyncio.run(_serve_and_close())

    _register_approval_subcommands(app, console, renderer)
    _register_policy_subcommands(app, console, renderer)

