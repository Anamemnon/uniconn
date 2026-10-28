# src/uniconn/cli/cmd_ops.py
"""Операционные и диагностические команды CLI: ping, facts, tail, bmc."""

from __future__ import annotations

import asyncio
import json
import shlex
import sys
from typing import Annotated, Any

from .._logging import get_logger
from ..services.facts_models import diff_facts
from .renderers import CLIOutputRenderer, Panel, Parameter, Table, box, build_cli_pool


def register_ops_commands(app: Any, console: Any, renderer: CLIOutputRenderer) -> None:
    """Зарегистрировать команды инспекции и мониторинга (ping, facts, tail, bmc)."""
    import uniconn.cli as cli_pkg

    @app.command(name="ping")
    def ping_cmd(
        *uris: Annotated[str, Parameter(help="Target connection URIs")],
        inventory: Annotated[
            str | None,
            Parameter(name=["--inventory", "-i"], help="Inventory file (.yaml/.json)"),
        ] = None,
        group: Annotated[
            str | None,
            Parameter(name=["--group", "-g"], help="Host group name in inventory"),
        ] = None,
        timeout: Annotated[
            float, Parameter(name=["--timeout", "-t"], help="Timeout in seconds")
        ] = 5.0,
        max_concurrent: Annotated[
            int,
            Parameter(name=["--max-concurrent", "-j"], help="Max concurrent connections"),
        ] = 20,
        output_format: Annotated[
            str,
            Parameter(name=["--format", "-f"], help="Output format: table, json"),
        ] = "table",
        verbose: Annotated[
            bool, Parameter(name=["--verbose", "-v"], negative="", help="Verbose output")
        ] = False,
    ) -> None:
        """Parallel host availability and latency check across URIs or inventory."""
        host_uris = list(uris)
        if not host_uris and not inventory:
            host_uris = ["local://"]

        async def _execute() -> None:
            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            try:
                pool = build_cli_pool(
                    cli_pkg, host_uris, inventory, group, max_concurrent, logger
                )
                ping_map = await pool.ping(timeout=timeout)
                dead_count = sum(1 for r in ping_map.values() if not r.alive)

                if output_format == "json":
                    payload = {k: v.to_dict() for k, v in ping_map.items()}
                    console.print(json.dumps(payload, indent=2))
                    if dead_count > 0:
                        sys.exit(1)
                    return

                table = Table(
                    title=f"Ping Latency Report ({len(ping_map)} host(s))",
                    box=box.ROUNDED,
                    show_header=True,
                    header_style="bold cyan",
                )
                table.add_column("Host", style="cyan")
                table.add_column("Status", style="bold")
                table.add_column("Transport", style="magenta")
                table.add_column("Latency (ms)", justify="right")
                table.add_column("Details")

                for host_key, pr in ping_map.items():
                    status_str = "[green]ALIVE[/green]" if pr.alive else "[red]DEAD[/red]"
                    lat_str = f"{pr.latency_ms:.2f} ms"
                    details_str = pr.error or "OK"
                    table.add_row(
                        host_key,
                        status_str,
                        pr.transport,
                        lat_str,
                        details_str,
                    )
                console.print(table)
                if dead_count > 0:
                    console.print(
                        f"\n[red]Unreachable hosts: {dead_count}/{len(ping_map)}[/red]"
                    )
                    sys.exit(1)
            except SystemExit:
                raise
            except Exception as e:
                renderer.print_error_and_exit(e, title="Ping Error")

        asyncio.run(_execute())

    @app.command
    def bmc(
        uri: Annotated[
            str,
            Parameter(help="BMC URI (redfish://admin:pass@bmc or ipmi://admin:pass@bmc)"),
        ],
        operation: Annotated[str, Parameter(help="Operation")],
        *,
        timeout: Annotated[
            float, Parameter(name=["--timeout", "-t"], help="Timeout in seconds")
        ] = 30.0,
        output_format: Annotated[
            str,
            Parameter(name=["--format", "-f"], help="Output format: panel, json"),
        ] = "panel",
        verbose: Annotated[
            bool, Parameter(name=["--verbose", "-v"], negative="", help="Verbose output")
        ] = False,
    ) -> None:
        """BMC (Baseboard Management Controller) management."""

        async def _execute() -> None:
            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            try:
                async with cli_pkg.Connection.from_uri(uri, logger=logger) as conn:
                    result = await conn.run(operation, timeout=timeout)

                    if output_format == "json":
                        console.print(json.dumps(result.to_dict(), indent=2))
                        return

                    console.print(
                        Panel(
                            f"[green]OK[/green] Operation completed\n"
                            f"[dim]Time:[/dim] {result.duration:.2f}s",
                            title="BMC Result",
                            border_style="green",
                        )
                    )
                    if result.stdout:
                        console.print(result.stdout)
            except Exception as e:
                renderer.print_error_and_exit(e, title="Exception")

        asyncio.run(_execute())

    @app.command(name="facts")
    def facts_cmd(
        *uris: Annotated[str, Parameter(help="Target connection URIs")],
        inventory: Annotated[
            str | None,
            Parameter(name=["--inventory", "-i"], help="Inventory file (.yaml/.json)"),
        ] = None,
        group: Annotated[
            str | None,
            Parameter(name=["--group", "-g"], help="Host group name in inventory"),
        ] = None,
        diff: Annotated[
            bool,
            Parameter(
                name=["--diff", "-d"],
                negative="",
                help="Compare facts across hosts and highlight configuration drift",
            ),
        ] = False,
        baseline: Annotated[
            str | None,
            Parameter(
                name="--baseline",
                help="Baseline host key for --diff comparison",
            ),
        ] = None,
        spec: Annotated[
            str | None,
            Parameter(
                name=["--spec", "-s"],
                help="FactSpec file (.yaml/.json/.toml) with custom commands, files, and tools",
            ),
        ] = None,
        max_concurrent: Annotated[
            int,
            Parameter(name=["--max-concurrent", "-j"], help="Max concurrent connections"),
        ] = 10,
        output_format: Annotated[
            str,
            Parameter(name=["--format", "-f"], help="Output format: table, json"),
        ] = "table",
        verbose: Annotated[
            bool, Parameter(name=["--verbose", "-v"], negative="", help="Verbose output")
        ] = False,
    ) -> None:
        """Gather structured system facts (OS, kernel, CPU, RAM, disks, network) from hosts."""
        host_uris = list(uris)
        if not host_uris and not inventory:
            host_uris = ["local://"]

        async def _execute() -> None:
            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            try:
                pool = build_cli_pool(
                    cli_pkg, host_uris, inventory, group, max_concurrent, logger
                )
                if spec is not None:
                    facts_map = await pool.gather_facts(spec=spec)
                else:
                    facts_map = await pool.gather_facts()
                if diff:
                    report = diff_facts(facts_map, baseline_host=baseline)
                    if output_format == "json":
                        console.print(json.dumps(report.to_dict(), indent=2))
                        return

                    if not report.has_drift:
                        console.print(
                            Panel(
                                f"[green]OK[/green] All {len(report.in_sync_hosts)} host(s) "
                                f"match baseline [bold cyan]{report.baseline_host}[/bold cyan]",
                                title="Facts Drift Report",
                                border_style="green",
                            )
                        )
                        return

                    diff_table = Table(
                        title=(
                            f"Facts Drift Report (baseline: {report.baseline_host}, "
                            f"drifted: {len(report.drifted_hosts)})"
                        ),
                        box=box.ROUNDED,
                        show_header=True,
                        header_style="bold yellow",
                    )
                    diff_table.add_column("Host", style="cyan")
                    diff_table.add_column("Field", style="magenta")
                    diff_table.add_column("Expected (Baseline)", style="green")
                    diff_table.add_column("Actual", style="red")

                    for drifted_host, fields_diff in report.drifted_hosts.items():
                        for fld, vals in fields_diff.items():
                            diff_table.add_row(
                                drifted_host,
                                fld,
                                str(vals["expected"]),
                                str(vals["actual"]),
                            )
                    console.print(diff_table)
                    return

                if output_format == "json":
                    payload = {k: v.to_dict() for k, v in facts_map.items()}
                    console.print(json.dumps(payload, indent=2))
                    return

                table = Table(
                    title=f"Host Facts ({len(facts_map)} host(s))",
                    box=box.ROUNDED,
                    show_header=True,
                    header_style="bold cyan",
                )
                table.add_column("Host", style="cyan")
                table.add_column("Hostname", style="green")
                table.add_column("OS Family / Distro")
                table.add_column("Kernel / Arch")
                table.add_column("CPU", justify="right")
                table.add_column("RAM (Avail/Total)", justify="right")
                table.add_column("Disks", justify="right")
                table.add_column("Interfaces")

                for host_key, hf in facts_map.items():
                    ram_tot_mb = hf.memory_total_bytes // (1024 * 1024)
                    ram_avl_mb = hf.memory_available_bytes // (1024 * 1024)
                    if_names = ", ".join(
                        f"{iface.name}({','.join(iface.ipv4)})"
                        if iface.ipv4
                        else iface.name
                        for iface in hf.interfaces[:3]
                    )
                    table.add_row(
                        host_key,
                        hf.hostname,
                        f"{hf.os_family} ({hf.distro})",
                        f"{hf.kernel} ({hf.arch})",
                        str(hf.cpu_count),
                        f"{ram_avl_mb}/{ram_tot_mb} MB",
                        str(len(hf.disks)),
                        if_names or "-",
                    )
                console.print(table)
            except Exception as e:
                renderer.print_error_and_exit(e, title="Facts Error")

        asyncio.run(_execute())

    @app.command(name="tail")
    def tail_cmd(
        target_or_cmd: Annotated[
            str, Parameter(help="Log file path or command to stream across hosts")
        ],
        *uris: Annotated[str, Parameter(help="Target connection URIs")],
        inventory: Annotated[
            str | None,
            Parameter(name=["--inventory", "-i"], help="Inventory file (.yaml/.json)"),
        ] = None,
        group: Annotated[
            str | None,
            Parameter(name=["--group", "-g"], help="Host group name in inventory"),
        ] = None,
        lines: Annotated[
            int,
            Parameter(
                name=["--lines", "-n"],
                help="Initial number of lines when tailing a file",
            ),
        ] = 10,
        follow: Annotated[
            bool,
            Parameter(
                name=["--follow", "-f"],
                negative="",
                help="Follow file growth (tail -f)",
            ),
        ] = False,
        raw_command: Annotated[
            bool,
            Parameter(
                name=["--command", "-c"],
                negative="",
                help="Treat first argument as raw command instead of file path",
            ),
        ] = False,
        max_lines: Annotated[
            int,
            Parameter(
                name="--max-lines",
                help="Stop automatically after receiving N total lines (0 = unlimited)",
            ),
        ] = 0,
        max_concurrent: Annotated[
            int,
            Parameter(name=["--max-concurrent", "-j"], help="Max concurrent connections"),
        ] = 10,
        output_format: Annotated[
            str, Parameter(name="--format", help="Output format: console, json")
        ] = "console",
        verbose: Annotated[
            bool, Parameter(name=["--verbose", "-v"], negative="", help="Verbose output")
        ] = False,
    ) -> None:
        """Stream multiplexed output or log files from multiple hosts in real time."""
        host_uris = list(uris)
        if not host_uris and not inventory:
            host_uris = ["local://"]

        if raw_command:
            stream_cmd = target_or_cmd
        else:
            follow_flag = "-f " if follow else ""
            stream_cmd = f"tail -n {lines} {follow_flag}{shlex.quote(target_or_cmd)}"

        palette = [
            "cyan",
            "green",
            "magenta",
            "yellow",
            "blue",
            "bright_cyan",
            "bright_green",
        ]

        async def _execute() -> None:
            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            try:
                pool = build_cli_pool(
                    cli_pkg, host_uris, inventory, group, max_concurrent, logger
                )
                host_colors: dict[str, str] = {}
                collected: list[dict[str, str]] = []
                count = 0

                async for host_key, line in pool.stream(stream_cmd):
                    clean = line.rstrip("\r\n")
                    count += 1
                    if output_format == "json":
                        collected.append({"host": host_key, "line": clean})
                    else:
                        color = host_colors.setdefault(
                            host_key, palette[len(host_colors) % len(palette)]
                        )
                        console.print(
                            f"[bold {color}][{host_key}][/bold {color}] {clean}"
                        )
                    if max_lines > 0 and count >= max_lines:
                        break

                if output_format == "json":
                    console.print(
                        json.dumps(
                            {
                                "command": stream_cmd,
                                "count": len(collected),
                                "lines": collected,
                            },
                            indent=2,
                        )
                    )
            except Exception as e:
                renderer.print_error_and_exit(e, title="Tail Stream Error")

        asyncio.run(_execute())

    def _render_ensure_results(
        title: str,
        results_map: dict[str, Any],
        output_format: str,
    ) -> None:
        if output_format == "json":
            payload = {k: v.to_dict() for k, v in results_map.items()}
            console.print(json.dumps(payload, indent=2))
            return

        table = Table(
            title=f"{title} ({len(results_map)} host(s))",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Host", style="cyan")
        table.add_column("Resource", style="magenta")
        table.add_column("State")
        table.add_column("Changed", style="bold")
        table.add_column("Details")

        for host_key, er in results_map.items():
            changed_str = "[yellow]CHANGED[/yellow]" if er.changed else "[green]OK[/green]"
            table.add_row(
                host_key,
                er.target,
                er.state,
                changed_str,
                er.details or "-",
            )
        console.print(table)
        for host_key, er in results_map.items():
            if er.diff:
                console.print(
                    Panel(
                        er.diff.rstrip(),
                        title=f"Diff ({host_key}: {er.target})",
                        border_style="yellow",
                    )
                )

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
        host_uris = list(uris)
        if not host_uris and not inventory:
            host_uris = ["local://"]
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
                _render_ensure_results("Ensure User Report", res_map, output_format)
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
        host_uris = list(uris)
        if not host_uris and not inventory:
            host_uris = ["local://"]

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
                    "Ensure Authorized Key Report", res_map, output_format
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
        host_uris = list(uris)
        if not host_uris and not inventory:
            host_uris = ["local://"]

        async def _execute() -> None:
            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            try:
                from pathlib import Path

                unit_content = content
                if unit_file:
                    unit_content = Path(unit_file).read_text(encoding="utf-8")
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
                _render_ensure_results("Ensure Systemd Unit Report", res_map, output_format)
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
        host_uris = list(uris)
        if not host_uris and not inventory:
            host_uris = ["local://"]

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
                _render_ensure_results("Ensure Sysctl Report", res_map, output_format)
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
            host_uris = list(args)
        else:
            if not args:
                console.print(
                    f"[red]ERROR:[/red] wait-for {kind_lower} requires a target argument"
                )
                sys.exit(1)
            target_arg = args[0]
            host_uris = list(args[1:])

        if not host_uris and not inventory:
            host_uris = ["local://"]

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
                if kind_lower == "connection":
                    ping_map = await pool.wait_for_connection(
                        timeout=timeout, interval=interval, delay=delay
                    )
                    if output_format == "json":
                        payload = {k: v.to_dict() for k, v in ping_map.items()}
                        console.print(json.dumps(payload, indent=2))
                        return
                    table = Table(
                        title=f"Wait For Connection ({len(ping_map)} host(s))",
                        box=box.ROUNDED,
                        show_header=True,
                        header_style="bold cyan",
                    )
                    table.add_column("Host", style="cyan")
                    table.add_column("Status", style="green")
                    table.add_column("Latency (ms)", justify="right")
                    for hk, pr in ping_map.items():
                        table.add_row(
                            hk,
                            "[green]ALIVE[/green]" if pr.alive else "[red]DEAD[/red]",
                            f"{pr.latency_ms:.2f} ms",
                        )
                    console.print(table)
                elif kind_lower == "port":
                    port_num = int(target_arg)
                    port_state: Any = (
                        state if state in ("open", "closed") else "open"
                    )
                    check_from_val: Any = (
                        check_from if check_from in ("remote", "local") else "remote"
                    )
                    elapsed_map = await pool.wait_for_port(
                        port_num,
                        host=host,
                        state=port_state,
                        check_from=check_from_val,
                        timeout=timeout,
                        interval=interval,
                        delay=delay,
                    )
                    if output_format == "json":
                        console.print(
                            json.dumps(
                                {
                                    "kind": "port",
                                    "port": port_num,
                                    "state": port_state,
                                    "elapsed": elapsed_map,
                                },
                                indent=2,
                            )
                        )
                        return
                    table = Table(
                        title=f"Wait For Port {port_num} ({port_state})",
                        box=box.ROUNDED,
                        show_header=True,
                        header_style="bold cyan",
                    )
                    table.add_column("Host", style="cyan")
                    table.add_column("Port", justify="right")
                    table.add_column("State", style="green")
                    table.add_column("Elapsed (s)", justify="right")
                    for hk, el in elapsed_map.items():
                        table.add_row(hk, str(port_num), port_state, f"{el:.2f}s")
                    console.print(table)
                else:
                    path_state: Any = (
                        state if state in ("present", "absent") else "present"
                    )
                    elapsed_map = await pool.wait_for_path(
                        target_arg,
                        state=path_state,
                        content_regex=regex,
                        timeout=timeout,
                        interval=interval,
                        delay=delay,
                        sudo=sudo,
                    )
                    if output_format == "json":
                        console.print(
                            json.dumps(
                                {
                                    "kind": "path",
                                    "path": target_arg,
                                    "state": path_state,
                                    "elapsed": elapsed_map,
                                },
                                indent=2,
                            )
                        )
                        return
                    table = Table(
                        title=f"Wait For Path {target_arg} ({path_state})",
                        box=box.ROUNDED,
                        show_header=True,
                        header_style="bold cyan",
                    )
                    table.add_column("Host", style="cyan")
                    table.add_column("Path", style="magenta")
                    table.add_column("State", style="green")
                    table.add_column("Elapsed (s)", justify="right")
                    for hk, el in elapsed_map.items():
                        table.add_row(hk, target_arg, path_state, f"{el:.2f}s")
                    console.print(table)
            except Exception as e:
                renderer.print_error_and_exit(e, title="Wait-For Error")

        asyncio.run(_execute())


