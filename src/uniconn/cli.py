# src/uniconn/cli.py
"""CLI интерфейс для uniconn.

Предоставляет командную строку для выполнения команд на удалённых хостах
через различные транспорты: SSH, Telnet, Serial, IPMI, Redfish и локальный.

Примеры использования:
    # Выполнить команду по SSH
    uniconn run "ssh://user:pass@host" "uptime"

    # Выполнить на нескольких хостах
    uniconn run-multi "ssh://host1" "ssh://host2" --command "uptime"

    # Управление BMC через Redfish
    uniconn bmc "redfish://admin:pass@bmc" power status

    # Список доступных транспортов
    uniconn transports
"""

import asyncio
import sys

try:
    import typer
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.table import Table
    HAVE_CLI_DEPS = True
except ImportError:
    HAVE_CLI_DEPS = False

from . import Connection, ConnectionPool, __version__
from ._logging import get_logger
from .plugins._loader import TransportLoader


def check_cli_deps():
    """Проверить наличие CLI зависимостей."""
    if not HAVE_CLI_DEPS:
        print(
            "CLI dependencies not installed. "
            "Install: pip install uniconn[cli]",
            file=sys.stderr
        )
        sys.exit(1)


def main():
    """Точка входа для CLI."""
    check_cli_deps()

    app = typer.Typer(
        name="uniconn",
        help="Universal CLI for remote command execution",
        add_completion=True,
    )
    console = Console()

    @app.callback()
    def callback():
        """Uniconn - Universal library for remote command execution."""
        pass

    @app.command()
    def version():
        """Show uniconn version."""
        console.print(f"[bold blue]uniconn[/bold blue] version [green]{__version__}[/green]")

    @app.command()
    def transports():
        """List available transports."""
        table = Table(
            title="Available Transports",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan"
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
            "redfish": ("Redfish REST API", "aiohttp"),
        }

        available = TransportLoader.list_available()

        for name, (desc, deps) in transport_info.items():
            status = "OK" if name in available else "--"
            name_col = f"[green]{status}[/green] {name}" if name in available else f"[dim]{status} {name}[/dim]"
            table.add_row(name_col, desc, deps)

        console.print(table)
        console.print("\n[dim]To install additional transports:[/dim]")
        console.print("[dim]  pip install uniconn[ssh,telnet,serial,bmc][/dim]")

    @app.command()
    def run(
        uri: str = typer.Argument(..., help="Connection URI (ssh://user:pass@host)"),
        command: str = typer.Argument(..., help="Command to execute"),
        timeout: float = typer.Option(30.0, "--timeout", "-t", help="Timeout in seconds"),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
        raise_on_error: bool = typer.Option(False, "--raise", "-e", help="Exit on error"),
    ):
        """Execute command on remote host.

        Examples:
            uniconn run "ssh://user:pass@host" "uptime"
            uniconn run "local://" "echo hello"
            uniconn run "redfish://admin:pass@bmc" "power status"

        """

        async def _execute():
            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")

            try:
                async with Connection.from_uri(uri, logger=logger) as conn:
                    result = await conn.run(
                        command,
                        timeout=timeout,
                        raise_on_error=raise_on_error
                    )

                    # Print result
                    if result.ok:
                        console.print(Panel(
                            f"[green]OK[/green] Command executed successfully\n"
                            f"[dim]Time:[/dim] {result.duration:.2f}s | "
                            f"[dim]Exit code:[/dim] {result.exit_code}",
                            title="Result",
                            border_style="green"
                        ))

                        if result.stdout:
                            console.print("[bold]stdout:[/bold]")
                            console.print(result.stdout)

                        if result.stderr:
                            console.print("[bold red]stderr:[/bold red]")
                            console.print(result.stderr)
                    else:
                        console.print(Panel(
                            f"[red]FAILED[/red] Command failed\n"
                            f"[dim]Time:[/dim] {result.duration:.2f}s | "
                            f"[dim]Exit code:[/dim] {result.exit_code}",
                            title="Error",
                            border_style="red"
                        ))

                        if result.stdout:
                            console.print("[bold]stdout:[/bold]")
                            console.print(result.stdout)

                        if result.stderr:
                            console.print("[bold red]stderr:[/bold red]")
                            console.print(result.stderr)

                        sys.exit(result.exit_code)

            except Exception as e:
                console.print(Panel(
                    f"[red]ERROR:[/red] {e}",
                    title="Exception",
                    border_style="red"
                ))
                sys.exit(1)

        asyncio.run(_execute())

    @app.command("run-multi")
    def run_multi(
        uris: list[str] = typer.Argument(..., help="Connection URIs"),
        command: str = typer.Option(..., "--command", "-c", help="Command to execute"),
        max_concurrent: int = typer.Option(10, "--max-concurrent", "-j", help="Max concurrent connections"),
        timeout: float = typer.Option(30.0, "--timeout", "-t", help="Timeout in seconds"),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
        output_format: str = typer.Option("table", "--format", "-f", help="Output format: table, json, plain"),
    ):
        """Execute command on multiple hosts in parallel.

        Examples:
            uniconn run-multi "ssh://host1" "ssh://host2" -c "uptime"
            uniconn run-multi "ssh://user@host1" "ssh://user@host2" -c "whoami" -j 5

        """

        async def _execute():
            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            pool = ConnectionPool(uris, max_concurrent=max_concurrent, logger=logger)

            console.print(f"[dim]Executing on {len(uris)} hosts...[/dim]\n")

            try:
                results = await pool.map(command, timeout=timeout, raise_on_error=False)

                if output_format == "json":
                    import json
                    output = []
                    for uri, result in zip(uris, results, strict=False):
                        output.append({
                            "host": uri,
                            "exit_code": result.exit_code,
                            "stdout": result.stdout,
                            "stderr": result.stderr,
                            "duration": result.duration,
                        })
                    console.print(json.dumps(output, indent=2))

                elif output_format == "plain":
                    for uri, result in zip(uris, results, strict=False):
                        status = "OK" if result.ok else "FAIL"
                        console.print(f"[{status}] {uri}: {result.stdout.strip()}")

                else:  # table
                    table = Table(
                        title=f"Results: {command}",
                        box=box.ROUNDED,
                        show_header=True,
                        header_style="bold cyan"
                    )
                    table.add_column("Host", style="cyan", no_wrap=True)
                    table.add_column("Status", style="bold")
                    table.add_column("Time", style="dim")
                    table.add_column("Output", style="green")

                    for uri, result in zip(uris, results, strict=False):
                        if result.ok:
                            status = "[green]OK[/green]"
                            output = result.stdout.strip()[:50]
                            if len(result.stdout.strip()) > 50:
                                output += "..."
                        else:
                            status = "[red]FAIL[/red]"
                            output = result.stderr.strip()[:50] or f"Exit code: {result.exit_code}"
                            if len(result.stderr.strip()) > 50:
                                output += "..."

                        table.add_row(
                            uri,
                            status,
                            f"{result.duration:.2f}s",
                            output
                        )

                    console.print(table)

                # Return exit code based on results
                failed = sum(1 for r in results if not r.ok)
                if failed > 0:
                    console.print(f"\n[red]Failed: {failed}/{len(uris)}[/red]")
                    sys.exit(1)
                else:
                    console.print(f"\n[green]All {len(uris)} hosts successful[/green]")

            except Exception as e:
                console.print(Panel(
                    f"[red]ERROR:[/red] {e}",
                    title="Exception",
                    border_style="red"
                ))
                sys.exit(1)

        asyncio.run(_execute())

    @app.command()
    def bmc(
        uri: str = typer.Argument(..., help="BMC URI (redfish://admin:pass@bmc or ipmi://admin:pass@bmc)"),
        operation: str = typer.Argument(
            ...,
            help="Operation",
            case_sensitive=False,
        ),
        timeout: float = typer.Option(30.0, "--timeout", "-t", help="Timeout in seconds"),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    ):
        """BMC (Baseboard Management Controller) management.

        Operations:
            power status    - Server power status
            power on        - Power on server
            power off       - Power off server (graceful)
            power forceoff  - Force power off
            power cycle     - Reboot
            power restart   - Graceful restart
            boot device     - Current boot device
            sensors         - Sensor information
            info            - System information

        Examples:
            uniconn bmc "redfish://admin:pass@idrac.local" power status
            uniconn bmc "ipmi://admin:pass@bmc.local" power on

        """

        async def _execute():
            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")

            try:
                async with Connection.from_uri(uri, logger=logger) as conn:
                    result = await conn.run(operation, timeout=timeout)

                    console.print(Panel(
                        f"[green]OK[/green] Operation completed\n"
                        f"[dim]Time:[/dim] {result.duration:.2f}s",
                        title="BMC Result",
                        border_style="green"
                    ))

                    if result.stdout:
                        console.print(result.stdout)

            except Exception as e:
                console.print(Panel(
                    f"[red]ERROR:[/red] {e}",
                    title="Exception",
                    border_style="red"
                ))
                sys.exit(1)

        asyncio.run(_execute())

    @app.command()
    def shell(
        uri: str = typer.Argument(..., help="Connection URI"),
        prompt: str = typer.Option("> ", "--prompt", "-p", help="Shell prompt"),
    ):
        """Interactive shell for remote host.

        Examples:
            uniconn shell "ssh://user:pass@host"

        """

        async def _interactive():
            console.print(f"[dim]Connecting to {uri}...[/dim]\n")

            try:
                async with Connection.from_uri(uri) as conn:
                    console.print("[green]Connected[/green]")
                    console.print("[dim]Type 'exit' or 'quit' to quit[/dim]\n")

                    while True:
                        try:
                            cmd = console.input(f"[bold cyan]{prompt}[/bold cyan]")

                            if cmd.lower() in ("exit", "quit"):
                                break

                            if not cmd.strip():
                                continue

                            result = await conn.run(cmd, raise_on_error=False)

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
                console.print(Panel(
                    f"[red]Connection error:[/red] {e}",
                    border_style="red"
                ))
                sys.exit(1)

        asyncio.run(_interactive())

    @app.command("screen-run")
    def screen_run(
        uri: str | None = typer.Argument(None, help="Connection URI (ssh://user:pass@host)"),
        config: str | None = typer.Option(None, "--config", "-f", help="ScreenPool config file"),
        command: list[str] | None = typer.Option(  # noqa: B008
            None, "--command", "-c", help="Command to run (repeatable)"
        ),
        instances: int = typer.Option(1, "--instances", "-n", help="Sessions per command"),
        logs: bool = typer.Option(False, "--logs", "-l", help="Stream session logs to console"),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    ):
        """Start commands in background GNU screen sessions.

        Examples:
            uniconn screen-run --config stress_config.yaml -c "stress-ng --cpu 4"
            uniconn screen-run "ssh://user@host" --instances 4 -c "stress-ng --cpu 4" --logs

        """
        if config is None and uri is None:
            console.print("[red]ERROR:[/red] URI argument or --config option is required")
            raise typer.Exit(code=1)

        commands = list(command or [])
        if not commands:
            console.print("[red]ERROR:[/red] at least one --command is required")
            raise typer.Exit(code=1)

        async def _execute():
            # Ленивый импорт: uniconn --help не зависит от background-подсистемы
            from .background import ScreenPool

            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")

            try:
                if config is not None:
                    pool = ScreenPool.from_file(config)
                else:
                    pool = ScreenPool(uri, logger=logger)

                async with pool:
                    started = []
                    for cmd in commands:
                        for _ in range(instances):
                            session = await pool.start(cmd)
                            started.append((session, cmd))

                    table = Table(
                        title=f"Started {len(started)} screen session(s)",
                        box=box.ROUNDED,
                        show_header=True,
                        header_style="bold cyan"
                    )
                    table.add_column("Session ID", style="cyan")
                    table.add_column("Command", style="green")

                    for session, cmd in started:
                        table.add_row(session.session_id, cmd)

                    console.print(table)
                    console.print(
                        "\n[dim]Sessions are detached and keep running after disconnect.[/dim]"
                    )

                    if logs:
                        console.print("[dim]Streaming logs (Ctrl+C to stop)...[/dim]")
                        async for event in pool.poll_logs():
                            console.print(
                                f"[cyan]{event.session_id}[/cyan] {event.line.rstrip()}"
                            )

            except Exception as e:
                console.print(Panel(
                    f"[red]ERROR:[/red] {e}",
                    title="Exception",
                    border_style="red"
                ))
                sys.exit(1)

        asyncio.run(_execute())

    @app.command("screen-logs")
    def screen_logs(
        uri: str = typer.Argument(..., help="Connection URI (ssh://user:pass@host)"),
        session_id: str = typer.Option(..., "--session-id", "-s", help="Screen session ID"),
        follow: bool = typer.Option(False, "--follow", "-f", help="Stream new log data"),
        interval: float = typer.Option(2.0, "--interval", "-i", help="Poll interval (seconds)"),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    ):
        """Read logs of a background screen session.

        Without --follow reads the log once; with --follow polls new chunks
        until the session finishes.

        Examples:
            uniconn screen-logs "ssh://user@host" --session-id uniconn_abc123_0
            uniconn screen-logs "ssh://user@host" --session-id uniconn_abc123_0 --follow

        """
        log_path = f"/tmp/{session_id}.log"

        async def _execute():
            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")

            try:
                async with Connection.from_uri(uri, logger=logger) as conn:
                    if not follow:
                        result = await conn.run(f"cat {log_path}", raise_on_error=False)
                        if result.exit_code != 0:
                            console.print(
                                f"[red]ERROR:[/red] cannot read {log_path}: "
                                f"{result.stderr.strip()}"
                            )
                            sys.exit(1)
                        if result.stdout:
                            console.print(result.stdout)
                        return

                    # Follow-режим: читаем порции по offset, пока сессия жива
                    offset = 0
                    while True:
                        chunk = await conn.run(
                            f"tail -c +{offset + 1} {log_path}",
                            raise_on_error=False
                        )
                        data = chunk.stdout or ""
                        if data:
                            console.print(data, end="")
                            offset += len(data.encode())

                        alive = await conn.run(
                            f"screen -ls | grep {session_id}",
                            raise_on_error=False
                        )
                        if alive.exit_code != 0:
                            break  # сессия завершилась, новых данных больше не будет
                        await asyncio.sleep(interval)

            except Exception as e:
                console.print(Panel(
                    f"[red]ERROR:[/red] {e}",
                    title="Exception",
                    border_style="red"
                ))
                sys.exit(1)

        asyncio.run(_execute())

    @app.command("screen-status")
    def screen_status(
        uri: str = typer.Argument(..., help="Connection URI (ssh://user:pass@host)"),
        pool_id: str | None = typer.Option(None, "--pool-id", "-p", help="Filter by pool ID"),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    ):
        """Show status of background screen sessions on the host.

        Examples:
            uniconn screen-status "ssh://user@host"
            uniconn screen-status "ssh://user@host" --pool-id abc123

        """
        prefix = f"uniconn_{pool_id}" if pool_id else "uniconn_"

        async def _execute():
            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")

            try:
                async with Connection.from_uri(uri, logger=logger) as conn:
                    result = await conn.run("screen -ls", raise_on_error=False)

                sessions = []
                for line in result.stdout.splitlines():
                    if prefix not in line:
                        continue
                    parts = line.strip().split()
                    if not parts:
                        continue
                    pid, _, name = parts[0].partition(".")
                    status = "Unknown"
                    if "(" in line and ")" in line:
                        status = line[line.find("(") + 1:line.rfind(")")]
                    sessions.append((name, pid, status))

                if not sessions:
                    console.print(f"[yellow]No screen sessions matching '{prefix}'[/yellow]")
                    return

                table = Table(
                    title=f"Screen sessions: {prefix}*",
                    box=box.ROUNDED,
                    show_header=True,
                    header_style="bold cyan"
                )
                table.add_column("Session ID", style="cyan")
                table.add_column("PID", style="dim")
                table.add_column("Status", style="green")

                for name, pid, status in sessions:
                    table.add_row(name, pid, status)

                console.print(table)

            except Exception as e:
                console.print(Panel(
                    f"[red]ERROR:[/red] {e}",
                    title="Exception",
                    border_style="red"
                ))
                sys.exit(1)

        asyncio.run(_execute())

    @app.command("screen-kill")
    def screen_kill(
        uri: str = typer.Argument(..., help="Connection URI (ssh://user:pass@host)"),
        session_id: str | None = typer.Option(None, "--session-id", "-s", help="Session ID"),
        pool_id: str | None = typer.Option(None, "--pool-id", "-p", help="Pool ID to kill"),
        all_sessions: bool = typer.Option(False, "--all", help="Kill all sessions of the pool"),
        force: bool = typer.Option(False, "--force", help="Force kill (skip graceful Ctrl+C)"),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    ):
        """Kill background screen session(s).

        Examples:
            uniconn screen-kill "ssh://user@host" --session-id uniconn_abc123_0
            uniconn screen-kill "ssh://user@host" --session-id uniconn_abc123_0 --force
            uniconn screen-kill "ssh://user@host" --pool-id abc123 --all

        """
        if session_id is None and not (pool_id and all_sessions):
            console.print("[red]ERROR:[/red] specify --session-id or --pool-id with --all")
            raise typer.Exit(code=1)

        async def _execute():
            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")

            try:
                async with Connection.from_uri(uri, logger=logger) as conn:
                    targets = [session_id] if session_id else []

                    if pool_id and all_sessions:
                        prefix = f"uniconn_{pool_id}_"
                        result = await conn.run("screen -ls", raise_on_error=False)
                        for line in result.stdout.splitlines():
                            if prefix in line:
                                parts = line.strip().split()
                                if parts:
                                    targets.append(parts[0].partition(".")[2])

                    if not targets:
                        console.print("[yellow]No matching screen sessions found[/yellow]")
                        return

                    for sid in targets:
                        if force:
                            await conn.run(f"screen -S {sid} -X kill", raise_on_error=False)
                            console.print(f"[green]OK[/green] killed {sid}")
                        else:
                            # Graceful: отправляем Ctrl+C в сессию
                            await conn.run(
                                f"screen -S {sid} -X stuff $'\\003'",
                                raise_on_error=False
                            )
                            console.print(f"[green]OK[/green] sent Ctrl+C to {sid}")

            except Exception as e:
                console.print(Panel(
                    f"[red]ERROR:[/red] {e}",
                    title="Exception",
                    border_style="red"
                ))
                sys.exit(1)

        asyncio.run(_execute())

    app()


if __name__ == "__main__":
    main()
