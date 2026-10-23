# src/uniconn/cli/cmd_exec.py
"""Команды выполнения: version, transports, run, run-multi, shell, expect."""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Annotated, Any

from .._logging import get_logger
from ..plugins._loader import TransportLoader
from .renderers import CLIOutputRenderer, Panel, Parameter, Table, box, build_cli_pool


def register_exec_commands(app: Any, console: Any, renderer: CLIOutputRenderer) -> None:
    """Зарегистрировать базовые команды выполнения в Cyclopts-приложении."""
    import uniconn.cli as cli_pkg

    @app.command
    def version() -> None:
        """Show uniconn version."""
        console.print(
            f"[bold blue]uniconn[/bold blue] version [green]{cli_pkg.__version__}[/green]"
        )

    @app.command
    def transports() -> None:
        """List available transports."""
        table = Table(
            title="Available Transports",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Transport", style="cyan")
        table.add_column("Description", style="green")
        table.add_column("Dependencies", style="yellow")

        transport_info = {
            "local": ("Local command execution", "-"),
            "ssh": ("SSH connection", "asyncssh"),
            "telnet": ("Telnet protocol", "telnetlib3"),
            "serial": ("Serial/UART ports", "pyserial-asyncio"),
            "ipmi": ("IPMI BMC management", "pyghmi"),
        }

        available = TransportLoader.list_available()

        for name, (desc, deps) in transport_info.items():
            status = "OK" if name in available else "--"
            name_col = (
                f"[green]{status}[/green] {name}"
                if name in available
                else f"[dim]{status} {name}[/dim]"
            )
            table.add_row(name_col, desc, deps)

        console.print(table)
        console.print("\n[dim]To install additional transports:[/dim]")
        console.print("[dim]  pip install uniconn[ssh,telnet,serial,bmc][/dim]")

    @app.command
    def run(
        uri: Annotated[str, Parameter(help="Connection URI (ssh://user:pass@host)")],
        command: Annotated[str, Parameter(help="Command to execute")],
        *,
        timeout: Annotated[
            float, Parameter(name=["--timeout", "-t"], help="Timeout in seconds")
        ] = 30.0,
        sudo: Annotated[
            bool, Parameter(name=["--sudo", "-s"], negative="", help="Execute with sudo")
        ] = False,
        output_format: Annotated[
            str,
            Parameter(name=["--format", "-f"], help="Output format: panel, json, plain"),
        ] = "panel",
        verbose: Annotated[
            bool, Parameter(name=["--verbose", "-v"], negative="", help="Verbose output")
        ] = False,
        raise_on_error: Annotated[
            bool, Parameter(name=["--raise", "-e"], negative="", help="Exit on error")
        ] = False,
    ) -> None:
        """Execute command on remote host."""

        async def _execute() -> None:
            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            try:
                async with cli_pkg.Connection.from_uri(uri, logger=logger) as conn:
                    result = await conn.run(
                        command,
                        timeout=timeout,
                        sudo=sudo,
                        raise_on_error=raise_on_error,
                    )
                    renderer.render_single_result(result, output_format=output_format)
            except Exception as e:
                renderer.print_error_and_exit(e, title="Exception")

        asyncio.run(_execute())

    @app.command(name="run-multi")
    def run_multi(
        *uris: Annotated[str, Parameter(help="Connection URIs")],
        command: Annotated[
            str, Parameter(name=["--command", "-c"], help="Command to execute")
        ],
        inventory: Annotated[
            str | None,
            Parameter(name=["--inventory", "-i"], help="Inventory file (.yaml/.json)"),
        ] = None,
        group: Annotated[
            str | None,
            Parameter(name=["--group", "-g"], help="Host group name in inventory"),
        ] = None,
        sudo: Annotated[
            bool, Parameter(name=["--sudo", "-s"], negative="", help="Execute with sudo")
        ] = False,
        max_concurrent: Annotated[
            int,
            Parameter(name=["--max-concurrent", "-j"], help="Max concurrent connections"),
        ] = 10,
        timeout: Annotated[
            float, Parameter(name=["--timeout", "-t"], help="Timeout in seconds")
        ] = 30.0,
        verbose: Annotated[
            bool, Parameter(name=["--verbose", "-v"], negative="", help="Verbose output")
        ] = False,
        output_format: Annotated[
            str,
            Parameter(name=["--format", "-f"], help="Output format: table, json, plain"),
        ] = "table",
    ) -> None:
        """Execute command on multiple hosts in parallel (from URIs or inventory)."""
        host_uris = list(uris)
        if not host_uris and not inventory:
            console.print("[red]ERROR:[/red] specify at least one URI or --inventory/-i")
            sys.exit(1)

        async def _execute() -> None:
            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            pool = build_cli_pool(
                cli_pkg, host_uris, inventory, group, max_concurrent, logger
            )
            target_labels = [pool._target_key(t) for t in pool._uris]
            if output_format != "json":
                console.print(f"[dim]Executing on {len(target_labels)} hosts...[/dim]\n")

            try:
                results = await pool.map(
                    command,
                    timeout=timeout,
                    sudo=sudo,
                    raise_on_error=False,
                )

                if output_format == "json":
                    output = [
                        {
                            "host": label,
                            "exit_code": result.exit_code,
                            "stdout": result.stdout,
                            "stderr": result.stderr,
                            "duration": result.duration,
                        }
                        for label, result in zip(target_labels, results, strict=False)
                    ]
                    console.print(json.dumps(output, indent=2))
                elif output_format == "plain":
                    for label, result in zip(target_labels, results, strict=False):
                        status = "OK" if result.ok else "FAIL"
                        console.print(f"[{status}] {label}: {result.stdout.strip()}")
                else:
                    table = Table(
                        title=f"Results: {command}",
                        box=box.ROUNDED,
                        show_header=True,
                        header_style="bold cyan",
                    )
                    table.add_column("Host", style="cyan", no_wrap=True)
                    table.add_column("Status", style="bold")
                    table.add_column("Time", style="dim")
                    table.add_column("Output", style="green")

                    for label, result in zip(target_labels, results, strict=False):
                        if result.ok:
                            status = "[green]OK[/green]"
                            out_text = result.stdout.strip()[:50]
                            if len(result.stdout.strip()) > 50:
                                out_text += "..."
                        else:
                            status = "[red]FAIL[/red]"
                            out_text = (
                                result.stderr.strip()[:50]
                                or f"Exit code: {result.exit_code}"
                            )
                            if len(result.stderr.strip()) > 50:
                                out_text += "..."

                        table.add_row(
                            label,
                            status,
                            f"{result.duration:.2f}s",
                            out_text,
                        )
                    console.print(table)

                failed = sum(1 for r in results if not r.ok)
                if failed > 0:
                    if output_format != "json":
                        console.print(f"\n[red]Failed: {failed}/{len(target_labels)}[/red]")
                    sys.exit(1)
                elif output_format != "json":
                    console.print(
                        f"\n[green]All {len(target_labels)} hosts successful[/green]"
                    )
            except Exception as e:
                renderer.print_error_and_exit(e, title="Exception")

        asyncio.run(_execute())

    @app.command
    def shell(
        uri: Annotated[str, Parameter(help="Connection URI")],
        *,
        prompt: Annotated[
            str, Parameter(name=["--prompt", "-p"], help="Shell prompt")
        ] = "> ",
    ) -> None:
        """Interactive stateful PTY shell for remote host."""

        async def _interactive() -> None:
            console.print(f"[dim]Connecting to {uri}...[/dim]\n")
            try:
                async with (
                    cli_pkg.Connection.from_uri(uri) as conn,
                    await conn.open_shell() as session,
                ):
                    console.print("[green]Connected[/green]")
                    console.print("[dim]Type 'exit' or 'quit' to quit[/dim]\n")

                    while True:
                        try:
                            cmd = console.input(f"[bold cyan]{prompt}[/bold cyan]")
                            if cmd.lower() in ("exit", "quit"):
                                break
                            if not cmd.strip():
                                continue
                            result = await session.execute(cmd)
                            if result.stdout:
                                console.print(result.stdout)
                            if result.stderr:
                                console.print(f"[red]{result.stderr}[/red]")
                        except KeyboardInterrupt:
                            console.print("\n[dim]Use 'exit' to quit[/dim]")
                            continue
                        except EOFError:
                            break

                    console.print("\n[dim]Disconnecting...[/dim]")
            except Exception as e:
                console.print(
                    Panel(
                        f"[red]Connection error:[/red] {e}",
                        border_style="red",
                    )
                )
                sys.exit(1)

        asyncio.run(_interactive())

    @app.command(name="expect")
    def expect_cmd(
        uri: Annotated[str, Parameter(help="Connection URI")],
        command: Annotated[str, Parameter(help="Interactive command to run")],
        *,
        pattern: Annotated[
            list[str] | None,
            Parameter(
                name=["--pattern", "-p"],
                help="Pattern rule REGEX=RESPONSE (repeatable)",
            ),
        ] = None,
        final_prompt: Annotated[
            str | None,
            Parameter(name="--final-prompt", help="Regex for final prompt completion"),
        ] = None,
        timeout: Annotated[
            float, Parameter(name=["--timeout", "-t"], help="Timeout in seconds")
        ] = 30.0,
        output_format: Annotated[
            str,
            Parameter(name=["--format", "-f"], help="Output format: panel, json, plain"),
        ] = "panel",
        verbose: Annotated[
            bool, Parameter(name=["--verbose", "-v"], negative="", help="Verbose output")
        ] = False,
    ) -> None:
        """Run interactive CLI dialog using declarative regex patterns."""
        patterns_dict: dict[str, str] = {}
        for item in pattern or []:
            sep = "=" if "=" in item else ":"
            if sep not in item:
                console.print(
                    f"[red]ERROR:[/red] invalid --pattern {item!r}, expected REGEX=RESPONSE"
                )
                sys.exit(1)
            pat_str, resp_str = item.split(sep, 1)
            resp_unescaped = resp_str.replace("\\n", "\n").replace("\\r", "\r")
            patterns_dict[pat_str] = resp_unescaped

        async def _execute() -> None:
            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            try:
                async with cli_pkg.Connection.from_uri(uri, logger=logger) as conn:
                    res = await conn.expect(
                        command=command,
                        patterns=patterns_dict,
                        final_prompt=final_prompt,
                        timeout=timeout,
                    )
                    if output_format == "json":
                        console.print(json.dumps(res.to_dict(), indent=2))
                    elif output_format == "plain":
                        if res.stdout:
                            console.print(res.stdout.rstrip())
                    else:
                        console.print(
                            Panel(
                                f"[green]OK[/green] Interactive expect completed in "
                                f"{res.duration:.2f}s",
                                title="Expect Result",
                                border_style="green",
                            )
                        )
                        if res.stdout:
                            console.print(res.stdout)
            except Exception as e:
                renderer.print_error_and_exit(e, title="Expect Error")

        asyncio.run(_execute())
