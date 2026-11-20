# src/uniconn/cli/cmd_ops.py
"""Операционные и диагностические команды CLI: ping, facts, tail, bmc, ensure-*, wait-for."""

from __future__ import annotations

import asyncio
import shlex
from typing import Annotated, Any

from ._ops_commands import register_provisioning_and_wait_commands
from ._ops_exec import (
    _default_host_uris,
    _exec_bmc,
    _exec_facts,
    _exec_ping,
    _exec_tail,
    _exec_wait_for,
    _render_ensure_results,
    _render_facts_diff,
    _render_facts_table,
    _render_serial_ports,
)
from .renderers import CLIOutputRenderer, Parameter


def register_ops_commands(app: Any, console: Any, renderer: CLIOutputRenderer) -> None:
    """Зарегистрировать команды инспекции, мониторинга, провижининга и ожидания."""
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
        asyncio.run(
            _exec_ping(
                cli_pkg,
                console,
                renderer,
                _default_host_uris(uris, inventory),
                inventory,
                group,
                timeout,
                max_concurrent,
                output_format,
                verbose,
            )
        )

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
        asyncio.run(
            _exec_bmc(cli_pkg, console, renderer, uri, operation, timeout, output_format, verbose)
        )

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
        asyncio.run(
            _exec_facts(
                cli_pkg,
                console,
                renderer,
                _default_host_uris(uris, inventory),
                inventory,
                group,
                diff,
                baseline,
                spec,
                max_concurrent,
                output_format,
                verbose,
            )
        )

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
        if raw_command:
            stream_cmd = target_or_cmd
        else:
            follow_flag = "-f " if follow else ""
            stream_cmd = f"tail -n {lines} {follow_flag}{shlex.quote(target_or_cmd)}"
        asyncio.run(
            _exec_tail(
                cli_pkg,
                console,
                renderer,
                _default_host_uris(uris, inventory),
                inventory,
                group,
                stream_cmd,
                max_lines,
                max_concurrent,
                output_format,
                verbose,
            )
        )

    register_provisioning_and_wait_commands(app, console, renderer, cli_pkg)


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
    "register_ops_commands",
]
