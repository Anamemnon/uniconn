# src/uniconn/cli/cmd_mcp.py
"""CLI-команда запуска официального MCP-сервера (Model Context Protocol): uniconn mcp."""

from __future__ import annotations

import asyncio
import contextlib
import json
import sys
from pathlib import Path
from typing import Annotated, Any

from ..mcp import MCPHostRegistry, MCPSecurityPolicy, MCPServer
from .renderers import CLIOutputRenderer, Parameter


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

    return {
        "mcpServers": {
            "uniconn": {
                "command": "uvx",
                "args": args,
            }
        }
    }


def register_mcp_commands(app: Any, console: Any, renderer: CLIOutputRenderer) -> None:
    """Зарегистрировать команду ``mcp`` в Cyclopts-приложении."""

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
            policy = MCPSecurityPolicy(
                allow_write=allow_write,
                allow_sudo=allow_sudo,
                allow_dynamic_uri=allow_dynamic_uri,
                dry_run=dry_run,
                allowlist=allow_tuple,
                blocklist=block_tuple,
                audit_log_path=audit_log,
                max_read_bytes=max_read_bytes,
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
            server = MCPServer(registry=registry)
        except Exception as exc:
            renderer.print_error_and_exit(exc, title="MCP Server Configuration Error")
            return

        with contextlib.suppress(KeyboardInterrupt):
            asyncio.run(server.serve_stdio())
