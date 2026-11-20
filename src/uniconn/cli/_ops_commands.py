# src/uniconn/cli/_ops_commands.py
"""Регистрация CLI-команд провижининга, ожидания и обнаружения портов."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Annotated, Any

from .._logging import get_logger
from ._ops_exec import (
    _default_host_uris,
    _exec_wait_for,
    _render_ensure_results,
    _render_serial_ports,
)
from .renderers import CLIOutputRenderer, Parameter, build_cli_pool


def register_provisioning_and_wait_commands(
    app: Any,
    console: Any,
    renderer: CLIOutputRenderer,
    cli_pkg: Any,
) -> None:
    """Зарегистрировать команды ensure-user/authorized-key/unit/sysctl, wait-for и serial-ports."""

    @app.command(name="ensure-user")
    def ensure_user_cmd(
        username: Annotated[str, Parameter(help="Target system username")],
        *uris: Annotated[str, Parameter(help="Target connection URIs")],
        state: Annotated[
            str,
            Parameter(name=["--state", "-s"], help="Desired state: present, absent"),
        ] = "present",
        uid: Annotated[
            int | None, Parameter(name="--uid", help="Explicit numeric UID")
        ] = None,
        groups: Annotated[
            str | None,
            Parameter(name="--groups", help="Comma-separated supplementary groups"),
        ] = None,
        shell: Annotated[
            str | None, Parameter(name="--shell", help="Login shell path")
        ] = None,
        home: Annotated[
            str | None, Parameter(name="--home", help="Home directory path")
        ] = None,
        create_home: Annotated[
            bool,
            Parameter(name="--create-home", help="Create home directory when adding user"),
        ] = True,
        system: Annotated[
            bool,
            Parameter(name="--system", negative="", help="Create as a system account"),
        ] = False,
        sudo: Annotated[
            bool,
            Parameter(name="--sudo", negative="", help="Execute with sudo privileges"),
        ] = False,
        dry_run: Annotated[
            bool,
            Parameter(name="--dry-run", negative="", help="Check without applying changes"),
        ] = False,
        inventory: Annotated[
            str | None,
            Parameter(name=["--inventory", "-i"], help="Inventory file (.yaml/.json)"),
        ] = None,
        group: Annotated[
            str | None,
            Parameter(name=["--group", "-g"], help="Host group name in inventory"),
        ] = None,
        max_concurrent: Annotated[
            int,
            Parameter(name=["--max-concurrent", "-j"], help="Max concurrent connections"),
        ] = 10,
        batch_size: Annotated[
            int | None,
            Parameter(name="--batch-size", help="Rollout wave/batch size"),
        ] = None,
        max_fail_ratio: Annotated[
            float,
            Parameter(
                name="--max-fail-ratio",
                help="Maximum allowed failure ratio per batch (0.0..1.0)",
            ),
        ] = 0.0,
        output_format: Annotated[
            str,
            Parameter(name=["--format", "-f"], help="Output format: table, json"),
        ] = "table",
        verbose: Annotated[
            bool, Parameter(name=["--verbose", "-v"], negative="", help="Verbose output")
        ] = False,
    ) -> None:
        """Idempotently ensure a user account and its attributes across hosts."""
        host_uris = _default_host_uris(uris, inventory)
        group_list = [g.strip() for g in groups.split(",") if g.strip()] if groups else None

        async def _execute() -> None:
            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            try:
                pool = build_cli_pool(
                    cli_pkg,
                    host_uris,
                    inventory,
                    group,
                    max_concurrent,
                    logger,
                    batch_size=batch_size,
                    max_fail_ratio=max_fail_ratio,
                )
                res_map = await pool.state.ensure_user(
                    username,
                    state=state,
                    uid=uid,
                    groups=group_list,
                    shell=shell,
                    home=home,
                    create_home=create_home,
                    system=system,
                    sudo=sudo,
                    dry_run=dry_run,
                )
                _render_ensure_results(console, "Ensure User Report", res_map, output_format)
            except Exception as e:
                renderer.print_error_and_exit(e, title="Ensure User Error")

        asyncio.run(_execute())

    @app.command(name="ensure-authorized-key")
    def ensure_authorized_key_cmd(
        user: Annotated[str, Parameter(help="Target system username")],
        key: Annotated[str, Parameter(help="SSH public key string")],
        *uris: Annotated[str, Parameter(help="Target connection URIs")],
        state: Annotated[
            str,
            Parameter(name=["--state", "-s"], help="Desired state: present, absent"),
        ] = "present",
        sudo: Annotated[
            bool,
            Parameter(name="--sudo", negative="", help="Execute with sudo privileges"),
        ] = False,
        dry_run: Annotated[
            bool,
            Parameter(name="--dry-run", negative="", help="Check without applying changes"),
        ] = False,
        inventory: Annotated[
            str | None,
            Parameter(name=["--inventory", "-i"], help="Inventory file (.yaml/.json)"),
        ] = None,
        group: Annotated[
            str | None,
            Parameter(name=["--group", "-g"], help="Host group name in inventory"),
        ] = None,
        max_concurrent: Annotated[
            int,
            Parameter(name=["--max-concurrent", "-j"], help="Max concurrent connections"),
        ] = 10,
        batch_size: Annotated[
            int | None,
            Parameter(name="--batch-size", help="Rollout wave/batch size"),
        ] = None,
        max_fail_ratio: Annotated[
            float,
            Parameter(
                name="--max-fail-ratio",
                help="Maximum allowed failure ratio per batch (0.0..1.0)",
            ),
        ] = 0.0,
        output_format: Annotated[
            str,
            Parameter(name=["--format", "-f"], help="Output format: table, json"),
        ] = "table",
        verbose: Annotated[
            bool, Parameter(name=["--verbose", "-v"], negative="", help="Verbose output")
        ] = False,
    ) -> None:
        """Idempotently manage an SSH public key in ~/.ssh/authorized_keys across hosts."""
        host_uris = _default_host_uris(uris, inventory)

        async def _execute() -> None:
            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            try:
                pool = build_cli_pool(
                    cli_pkg,
                    host_uris,
                    inventory,
                    group,
                    max_concurrent,
                    logger,
                    batch_size=batch_size,
                    max_fail_ratio=max_fail_ratio,
                )
                res_map = await pool.state.ensure_authorized_key(
                    user,
                    key,
                    state=state,
                    sudo=sudo,
                    dry_run=dry_run,
                )
                _render_ensure_results(
                    console, "Ensure Authorized Key Report", res_map, output_format
                )
            except Exception as e:
                renderer.print_error_and_exit(e, title="Ensure Authorized Key Error")

        asyncio.run(_execute())

    @app.command(name="ensure-unit")
    def ensure_unit_cmd(
        name: Annotated[str, Parameter(help="Systemd unit name (e.g. myapp.service)")],
        *uris: Annotated[str, Parameter(help="Target connection URIs")],
        content: Annotated[
            str | None,
            Parameter(name=["--content", "-c"], help="Inline unit file content"),
        ] = None,
        unit_file: Annotated[
            str | None,
            Parameter(name="--file", help="Local path to systemd unit file"),
        ] = None,
        state: Annotated[
            str,
            Parameter(
                name=["--state", "-s"],
                help="Desired state: started, stopped, restarted, absent",
            ),
        ] = "started",
        enabled: Annotated[
            bool,
            Parameter(name="--enabled", help="Enable unit on boot"),
        ] = True,
        sudo: Annotated[
            bool,
            Parameter(name="--sudo", negative="", help="Execute with sudo privileges"),
        ] = False,
        dry_run: Annotated[
            bool,
            Parameter(name="--dry-run", negative="", help="Check without applying changes"),
        ] = False,
        inventory: Annotated[
            str | None,
            Parameter(name=["--inventory", "-i"], help="Inventory file (.yaml/.json)"),
        ] = None,
        group: Annotated[
            str | None,
            Parameter(name=["--group", "-g"], help="Host group name in inventory"),
        ] = None,
        max_concurrent: Annotated[
            int,
            Parameter(name=["--max-concurrent", "-j"], help="Max concurrent connections"),
        ] = 10,
        batch_size: Annotated[
            int | None,
            Parameter(name="--batch-size", help="Rollout wave/batch size"),
        ] = None,
        max_fail_ratio: Annotated[
            float,
            Parameter(
                name="--max-fail-ratio",
                help="Maximum allowed failure ratio per batch (0.0..1.0)",
            ),
        ] = 0.0,
        output_format: Annotated[
            str,
            Parameter(name=["--format", "-f"], help="Output format: table, json"),
        ] = "table",
        verbose: Annotated[
            bool, Parameter(name=["--verbose", "-v"], negative="", help="Verbose output")
        ] = False,
    ) -> None:
        """Idempotently deploy a systemd unit file, reload daemon if changed, and manage state."""
        host_uris = _default_host_uris(uris, inventory)

        async def _execute() -> None:
            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            try:
                unit_content = Path(unit_file).read_text(encoding="utf-8") if unit_file else content
                pool = build_cli_pool(
                    cli_pkg,
                    host_uris,
                    inventory,
                    group,
                    max_concurrent,
                    logger,
                    batch_size=batch_size,
                    max_fail_ratio=max_fail_ratio,
                )
                res_map = await pool.state.ensure_systemd_unit(
                    name,
                    content=unit_content,
                    state=state,
                    enabled=enabled,
                    sudo=sudo,
                    dry_run=dry_run,
                )
                _render_ensure_results(
                    console, "Ensure Systemd Unit Report", res_map, output_format
                )
            except Exception as e:
                renderer.print_error_and_exit(e, title="Ensure Systemd Unit Error")

        asyncio.run(_execute())

    @app.command(name="ensure-sysctl")
    def ensure_sysctl_cmd(
        key: Annotated[str, Parameter(help="Kernel sysctl parameter name")],
        value: Annotated[str, Parameter(help="Desired sysctl parameter value")],
        *uris: Annotated[str, Parameter(help="Target connection URIs")],
        state: Annotated[
            str,
            Parameter(name=["--state", "-s"], help="Desired state: present, absent"),
        ] = "present",
        reload: Annotated[
            bool,
            Parameter(name="--reload", help="Apply sysctl setting immediately via sysctl -w"),
        ] = True,
        config_file: Annotated[
            str,
            Parameter(
                name="--config-file",
                help="Sysctl persistence file path",
            ),
        ] = "/etc/sysctl.d/99-uniconn.conf",
        sudo: Annotated[
            bool,
            Parameter(name="--sudo", negative="", help="Execute with sudo privileges"),
        ] = False,
        dry_run: Annotated[
            bool,
            Parameter(name="--dry-run", negative="", help="Check without applying changes"),
        ] = False,
        inventory: Annotated[
            str | None,
            Parameter(name=["--inventory", "-i"], help="Inventory file (.yaml/.json)"),
        ] = None,
        group: Annotated[
            str | None,
            Parameter(name=["--group", "-g"], help="Host group name in inventory"),
        ] = None,
        max_concurrent: Annotated[
            int,
            Parameter(name=["--max-concurrent", "-j"], help="Max concurrent connections"),
        ] = 10,
        batch_size: Annotated[
            int | None,
            Parameter(name="--batch-size", help="Rollout wave/batch size"),
        ] = None,
        max_fail_ratio: Annotated[
            float,
            Parameter(
                name="--max-fail-ratio",
                help="Maximum allowed failure ratio per batch (0.0..1.0)",
            ),
        ] = 0.0,
        output_format: Annotated[
            str,
            Parameter(name=["--format", "-f"], help="Output format: table, json"),
        ] = "table",
        verbose: Annotated[
            bool, Parameter(name=["--verbose", "-v"], negative="", help="Verbose output")
        ] = False,
    ) -> None:
        """Idempotently set a runtime and persistent kernel sysctl parameter across hosts."""
        host_uris = _default_host_uris(uris, inventory)

        async def _execute() -> None:
            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            try:
                pool = build_cli_pool(
                    cli_pkg,
                    host_uris,
                    inventory,
                    group,
                    max_concurrent,
                    logger,
                    batch_size=batch_size,
                    max_fail_ratio=max_fail_ratio,
                )
                res_map = await pool.state.ensure_sysctl(
                    key,
                    value,
                    state=state,
                    config_file=config_file,
                    reload=reload,
                    sudo=sudo,
                    dry_run=dry_run,
                )
                _render_ensure_results(console, "Ensure Sysctl Report", res_map, output_format)
            except Exception as e:
                renderer.print_error_and_exit(e, title="Ensure Sysctl Error")

        asyncio.run(_execute())

    @app.command(name="wait-for")
    def wait_for_cmd(
        kind: Annotated[
            str,
            Parameter(help="Condition type: connection, port, path"),
        ],
        *args: Annotated[
            str,
            Parameter(help="Target port/path (for port/path) followed by connection URIs"),
        ],
        host: Annotated[
            str | None,
            Parameter(name="--host", help="Target host for TCP port check"),
        ] = None,
        state: Annotated[
            str | None,
            Parameter(
                name=["--state", "-s"],
                help="Desired state: open/closed (port) or present/absent (path)",
            ),
        ] = None,
        check_from: Annotated[
            str,
            Parameter(
                name="--check-from",
                help="Where to run TCP port probe: remote or local",
            ),
        ] = "remote",
        regex: Annotated[
            str | None,
            Parameter(
                name=["--regex", "-r"],
                help="Regular expression to match in file content (for path)",
            ),
        ] = None,
        timeout: Annotated[
            float, Parameter(name=["--timeout", "-t"], help="Timeout in seconds")
        ] = 60.0,
        interval: Annotated[
            float, Parameter(name="--interval", help="Polling interval in seconds")
        ] = 1.0,
        delay: Annotated[
            float, Parameter(name="--delay", help="Initial delay in seconds")
        ] = 0.0,
        sudo: Annotated[
            bool,
            Parameter(name="--sudo", negative="", help="Run remote path check with sudo"),
        ] = False,
        inventory: Annotated[
            str | None,
            Parameter(name=["--inventory", "-i"], help="Inventory file (.yaml/.json)"),
        ] = None,
        group: Annotated[
            str | None,
            Parameter(name=["--group", "-g"], help="Host group name in inventory"),
        ] = None,
        max_concurrent: Annotated[
            int,
            Parameter(name=["--max-concurrent", "-j"], help="Max concurrent connections"),
        ] = 10,
        batch_size: Annotated[
            int | None,
            Parameter(name="--batch-size", help="Rollout wave/batch size"),
        ] = None,
        max_fail_ratio: Annotated[
            float,
            Parameter(
                name="--max-fail-ratio",
                help="Maximum allowed failure ratio per batch (0.0..1.0)",
            ),
        ] = 0.0,
        output_format: Annotated[
            str,
            Parameter(name=["--format", "-f"], help="Output format: table, json"),
        ] = "table",
        verbose: Annotated[
            bool, Parameter(name=["--verbose", "-v"], negative="", help="Verbose output")
        ] = False,
    ) -> None:
        """Wait for host connection, TCP port state, or filesystem path/content across hosts."""
        kind_lower = kind.lower()
        if kind_lower not in ("connection", "port", "path"):
            console.print(
                f"[red]ERROR:[/red] unknown wait-for kind {kind!r}, expected connection, port, or path"
            )
            sys.exit(1)

        if kind_lower == "connection":
            target_arg = ""
            raw_uris = list(args)
        else:
            if not args:
                console.print(f"[red]ERROR:[/red] wait-for {kind_lower} requires a target argument")
                sys.exit(1)
            target_arg = args[0]
            raw_uris = list(args[1:])

        host_uris = raw_uris or (["local://"] if not inventory else [])
        asyncio.run(
            _exec_wait_for(
                cli_pkg,
                console,
                renderer,
                kind_lower,
                target_arg,
                host_uris,
                inventory,
                group,
                host,
                state,
                check_from,
                regex,
                timeout,
                interval,
                delay,
                sudo,
                max_concurrent,
                batch_size,
                max_fail_ratio,
                output_format,
                verbose,
            )
        )

    @app.command(name="serial-ports")
    def serial_ports_cmd(
        *,
        output_format: Annotated[
            str,
            Parameter(name=["--format", "-f"], help="Output format: table, json"),
        ] = "table",
    ) -> None:
        """List available local serial/UART ports (COM / /dev/tty)."""
        _render_serial_ports(console, output_format)


__all__ = ["register_provisioning_and_wait_commands"]
