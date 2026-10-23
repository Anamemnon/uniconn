# src/uniconn/cli/cmd_ops.py
"""Операционные и диагностические команды CLI: facts, tail, bmc."""

from __future__ import annotations

import asyncio
import json
import shlex
from typing import Annotated, Any

from .._logging import get_logger
from .renderers import CLIOutputRenderer, Panel, Parameter, Table, box, build_cli_pool


def register_ops_commands(app: Any, console: Any, renderer: CLIOutputRenderer) -> None:
    """Зарегистрировать команды инспекции и мониторинга (facts, tail, bmc)."""
    import uniconn.cli as cli_pkg

    @app.command
    def bmc(
        uri: Annotated[str, Parameter(help="BMC URI (ipmi://admin:pass@bmc)")],
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
                facts_map = await pool.gather_facts()
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
