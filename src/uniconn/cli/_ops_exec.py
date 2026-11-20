# src/uniconn/cli/_ops_exec.py
"""Асинхронные исполнители и рендереры для операционных команд CLI."""

from __future__ import annotations

import dataclasses
import sys
from typing import Any

from .._logging import get_logger
from ..services.facts_models import diff_facts
from .renderers import (
    CLIOutputRenderer,
    Panel,
    Table,
    box,
    build_cli_pool,
    print_json,
)


def _default_host_uris(uris: tuple[str, ...], inventory: str | None) -> list[str]:
    host_uris = list(uris)
    if not host_uris and not inventory:
        host_uris = ["local://"]
    return host_uris


async def _exec_ping(
    cli_pkg: Any,
    console: Any,
    renderer: CLIOutputRenderer,
    host_uris: list[str],
    inventory: str | None,
    group: str | None,
    timeout: float,
    max_concurrent: int,
    output_format: str,
    verbose: bool,
) -> None:
    logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
    try:
        pool = build_cli_pool(cli_pkg, host_uris, inventory, group, max_concurrent, logger)
        ping_map = await pool.ping(timeout=timeout)
        dead_count = sum(1 for r in ping_map.values() if not r.alive)

        if output_format == "json":
            print_json(console, {k: v.to_dict() for k, v in ping_map.items()})
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
            table.add_row(host_key, status_str, pr.transport, f"{pr.latency_ms:.2f} ms", pr.error or "OK")
        console.print(table)
        if dead_count > 0:
            console.print(f"\n[red]Unreachable hosts: {dead_count}/{len(ping_map)}[/red]")
            sys.exit(1)
    except SystemExit:
        raise
    except Exception as e:
        renderer.print_error_and_exit(e, title="Ping Error")


async def _exec_bmc(
    cli_pkg: Any,
    console: Any,
    renderer: CLIOutputRenderer,
    uri: str,
    operation: str,
    timeout: float,
    output_format: str,
    verbose: bool,
) -> None:
    logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
    try:
        async with cli_pkg.Connection.from_uri(uri, logger=logger) as conn:
            result = await conn.run(operation, timeout=timeout)
            if output_format == "json":
                print_json(console, result.to_dict())
                return
            console.print(
                Panel(
                    f"[green]OK[/green] Operation completed\n[dim]Time:[/dim] {result.duration:.2f}s",
                    title="BMC Result",
                    border_style="green",
                )
            )
            if result.stdout:
                console.print(result.stdout)
    except Exception as e:
        renderer.print_error_and_exit(e, title="Exception")


def _render_facts_diff(console: Any, report: Any, output_format: str) -> None:
    if output_format == "json":
        print_json(console, report.to_dict())
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
            diff_table.add_row(drifted_host, fld, str(vals["expected"]), str(vals["actual"]))
    console.print(diff_table)


def _render_facts_table(console: Any, facts_map: dict[str, Any], output_format: str) -> None:
    if output_format == "json":
        print_json(console, {k: v.to_dict() for k, v in facts_map.items()})
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
            f"{iface.name}({','.join(iface.ipv4)})" if iface.ipv4 else iface.name
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


async def _exec_facts(
    cli_pkg: Any,
    console: Any,
    renderer: CLIOutputRenderer,
    host_uris: list[str],
    inventory: str | None,
    group: str | None,
    diff: bool,
    baseline: str | None,
    spec: str | None,
    max_concurrent: int,
    output_format: str,
    verbose: bool,
) -> None:
    logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
    try:
        pool = build_cli_pool(cli_pkg, host_uris, inventory, group, max_concurrent, logger)
        facts_map = await (pool.gather_facts(spec=spec) if spec is not None else pool.gather_facts())
        if diff:
            report = diff_facts(facts_map, baseline_host=baseline)
            _render_facts_diff(console, report, output_format)
            return
        _render_facts_table(console, facts_map, output_format)
    except Exception as e:
        renderer.print_error_and_exit(e, title="Facts Error")


async def _exec_tail(
    cli_pkg: Any,
    console: Any,
    renderer: CLIOutputRenderer,
    host_uris: list[str],
    inventory: str | None,
    group: str | None,
    stream_cmd: str,
    max_lines: int,
    max_concurrent: int,
    output_format: str,
    verbose: bool,
) -> None:
    palette = ["cyan", "green", "magenta", "yellow", "blue", "bright_cyan", "bright_green"]
    logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
    try:
        pool = build_cli_pool(cli_pkg, host_uris, inventory, group, max_concurrent, logger)
        host_colors: dict[str, str] = {}
        collected: list[dict[str, str]] = []
        count = 0

        async for host_key, line in pool.stream(stream_cmd):
            clean = line.rstrip("\r\n")
            count += 1
            if output_format == "json":
                collected.append({"host": host_key, "line": clean})
            else:
                color = host_colors.setdefault(host_key, palette[len(host_colors) % len(palette)])
                console.print(f"[bold {color}][{host_key}][/bold {color}] {clean}")
            if max_lines > 0 and count >= max_lines:
                break

        if output_format == "json":
            print_json(console, {"command": stream_cmd, "count": len(collected), "lines": collected})
    except Exception as e:
        renderer.print_error_and_exit(e, title="Tail Stream Error")


def _render_ensure_results(
    console: Any,
    title: str,
    results_map: dict[str, Any],
    output_format: str,
) -> None:
    if output_format == "json":
        print_json(console, {k: v.to_dict() for k, v in results_map.items()})
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
        table.add_row(host_key, er.target, er.state, changed_str, er.details or "-")
    console.print(table)
    for host_key, er in results_map.items():
        if er.diff:
            console.print(
                Panel(er.diff.rstrip(), title=f"Diff ({host_key}: {er.target})", border_style="yellow")
            )


async def _exec_wait_for(
    cli_pkg: Any,
    console: Any,
    renderer: CLIOutputRenderer,
    kind_lower: str,
    target_arg: str,
    host_uris: list[str],
    inventory: str | None,
    group: str | None,
    host: str | None,
    state: str | None,
    check_from: str,
    regex: str | None,
    timeout: float,
    interval: float,
    delay: float,
    sudo: bool,
    max_concurrent: int,
    batch_size: int | None,
    max_fail_ratio: float,
    output_format: str,
    verbose: bool,
) -> None:
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
            ping_map = await pool.wait_for_connection(timeout=timeout, interval=interval, delay=delay)
            if output_format == "json":
                print_json(console, {k: v.to_dict() for k, v in ping_map.items()})
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
            return

        if kind_lower == "port":
            port_num = int(target_arg)
            port_state: Any = state if state in ("open", "closed") else "open"
            check_from_val: Any = check_from if check_from in ("remote", "local") else "remote"
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
                print_json(
                    console,
                    {"kind": "port", "port": port_num, "state": port_state, "elapsed": elapsed_map},
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
            return

        path_state: Any = state if state in ("present", "absent") else "present"
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
            print_json(
                console,
                {"kind": "path", "path": target_arg, "state": path_state, "elapsed": elapsed_map},
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


def _render_serial_ports(console: Any, output_format: str) -> None:
    from ..transports._serial import list_serial_ports

    ports = list_serial_ports()
    if output_format.lower() == "json":
        print_json(console, [dataclasses.asdict(p) for p in ports])
        return

    if not ports:
        console.print("[dim]No serial ports detected on the local system.[/dim]")
        return

    table = Table(
        title="Available Serial (UART) Ports",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Device", style="cyan")
    table.add_column("Description", style="green")
    table.add_column("VID:PID", style="yellow")
    table.add_column("Manufacturer", style="magenta")
    table.add_column("Serial Number", style="dim")

    for p in ports:
        table.add_row(
            p.device,
            p.description or "-",
            p.vid_pid_hex or "-",
            p.manufacturer or "-",
            p.serial_number or "-",
        )
    console.print(table)


__all__ = [
    "_default_host_uris",
    "_exec_bmc",
    "_exec_facts",
    "_exec_ping",
    "_exec_tail",
    "_exec_wait_for",
    "_render_ensure_results",
    "_render_facts_diff",
    "_render_facts_table",
    "_render_serial_ports",
]
