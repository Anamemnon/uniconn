# src/uniconn/cli/cmd_screen.py
"""Команды управления фоновыми сессиями GNU screen: screen-run, screen-logs, screen-status, screen-kill."""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Annotated, Any

from .._logging import get_logger
from .renderers import CLIOutputRenderer, Parameter, Table, box


def register_screen_commands(app: Any, console: Any, renderer: CLIOutputRenderer) -> None:
    """Зарегистрировать команды ``screen-*`` в Cyclopts-приложении."""
    import uniconn.cli as cli_pkg

    @app.command(name="screen-run")
    def screen_run(
        uri: Annotated[
            str | None, Parameter(help="Connection URI (ssh://user:pass@host)")
        ] = None,
        *,
        config: Annotated[
            str | None,
            Parameter(name=["--config", "-f"], help="ScreenPool config file"),
        ] = None,
        command: Annotated[
            list[str] | None,
            Parameter(name=["--command", "-c"], help="Command to run (repeatable)"),
        ] = None,
        instances: Annotated[
            int, Parameter(name=["--instances", "-n"], help="Sessions per command")
        ] = 1,
        logs: Annotated[
            bool,
            Parameter(
                name=["--logs", "-l"],
                negative="",
                help="Stream session logs to console",
            ),
        ] = False,
        verbose: Annotated[
            bool, Parameter(name=["--verbose", "-v"], negative="", help="Verbose output")
        ] = False,
    ) -> None:
        """Start commands in background GNU screen sessions."""
        if config is None and uri is None:
            console.print("[red]ERROR:[/red] URI argument or --config option is required")
            sys.exit(1)

        commands = list(command or [])
        if not commands:
            console.print("[red]ERROR:[/red] at least one --command is required")
            sys.exit(1)

        async def _execute() -> None:
            from ..background import ScreenPool

            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            try:
                if config is not None:
                    pool = ScreenPool.from_file(config)
                else:
                    assert uri is not None
                    pool = ScreenPool(uri, logger=logger)

                started = []
                for cmd in commands:
                    for _ in range(instances):
                        session = await pool.start(cmd)
                        started.append((session, cmd))

                table = Table(
                    title=f"Started {len(started)} screen session(s)",
                    box=box.ROUNDED,
                    show_header=True,
                    header_style="bold cyan",
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

                await pool.disconnect()
            except Exception as e:
                renderer.print_error_and_exit(e, title="Exception")

        asyncio.run(_execute())

    @app.command(name="screen-logs")
    def screen_logs(
        uri: Annotated[str, Parameter(help="Connection URI (ssh://user:pass@host)")],
        *,
        session_id: Annotated[
            str, Parameter(name=["--session-id", "-s"], help="Screen session ID")
        ],
        follow: Annotated[
            bool,
            Parameter(
                name=["--follow", "-f"],
                negative="",
                help="Stream new log data",
            ),
        ] = False,
        interval: Annotated[
            float,
            Parameter(name=["--interval", "-i"], help="Poll interval (seconds)"),
        ] = 2.0,
        verbose: Annotated[
            bool, Parameter(name=["--verbose", "-v"], negative="", help="Verbose output")
        ] = False,
    ) -> None:
        """Read logs of a background screen session."""
        log_path = f"/tmp/{session_id}.log"

        async def _execute() -> None:
            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            try:
                async with cli_pkg.Connection.from_uri(uri, logger=logger) as conn:
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

                    offset = 0
                    while True:
                        chunk = await conn.run(
                            f"tail -c +{offset + 1} {log_path}",
                            raise_on_error=False,
                        )
                        data = chunk.stdout or ""
                        if data:
                            console.print(data, end="")
                            offset += len(data.encode())

                        alive = await conn.run(
                            f"screen -ls | grep {session_id}",
                            raise_on_error=False,
                        )
                        if alive.exit_code != 0:
                            break
                        await asyncio.sleep(interval)
            except Exception as e:
                renderer.print_error_and_exit(e, title="Exception")

        asyncio.run(_execute())

    @app.command(name="screen-status")
    def screen_status(
        uri: Annotated[str, Parameter(help="Connection URI (ssh://user:pass@host)")],
        *,
        pool_id: Annotated[
            str | None,
            Parameter(name=["--pool-id", "-p"], help="Filter by pool ID"),
        ] = None,
        output_format: Annotated[
            str,
            Parameter(name=["--format", "-f"], help="Output format: table, json"),
        ] = "table",
        verbose: Annotated[
            bool, Parameter(name=["--verbose", "-v"], negative="", help="Verbose output")
        ] = False,
    ) -> None:
        """Show status of background screen sessions on the host."""
        prefix = f"uniconn_{pool_id}" if pool_id else "uniconn_"

        async def _execute() -> None:
            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            try:
                async with cli_pkg.Connection.from_uri(uri, logger=logger) as conn:
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
                        status = line[line.find("(") + 1 : line.rfind(")")]
                    sessions.append((name, pid, status))

                if output_format == "json":
                    console.print(
                        json.dumps(
                            [
                                {"session_id": name, "pid": pid, "status": status}
                                for name, pid, status in sessions
                            ],
                            indent=2,
                        )
                    )
                    return

                if not sessions:
                    console.print(
                        f"[yellow]No screen sessions matching '{prefix}'[/yellow]"
                    )
                    return

                table = Table(
                    title=f"Screen sessions: {prefix}*",
                    box=box.ROUNDED,
                    show_header=True,
                    header_style="bold cyan",
                )
                table.add_column("Session ID", style="cyan")
                table.add_column("PID", style="dim")
                table.add_column("Status", style="green")

                for name, pid, status in sessions:
                    table.add_row(name, pid, status)

                console.print(table)
            except Exception as e:
                renderer.print_error_and_exit(e, title="Exception")

        asyncio.run(_execute())

    @app.command(name="screen-kill")
    def screen_kill(
        uri: Annotated[str, Parameter(help="Connection URI (ssh://user:pass@host)")],
        *,
        session_id: Annotated[
            str | None,
            Parameter(name=["--session-id", "-s"], help="Session ID"),
        ] = None,
        pool_id: Annotated[
            str | None,
            Parameter(name=["--pool-id", "-p"], help="Pool ID to kill"),
        ] = None,
        all_sessions: Annotated[
            bool,
            Parameter(
                name="--all",
                negative="",
                help="Kill all sessions of the pool",
            ),
        ] = False,
        force: Annotated[
            bool,
            Parameter(
                name="--force",
                negative="",
                help="Force kill (skip graceful Ctrl+C)",
            ),
        ] = False,
        verbose: Annotated[
            bool, Parameter(name=["--verbose", "-v"], negative="", help="Verbose output")
        ] = False,
    ) -> None:
        """Kill background screen session(s)."""
        if session_id is None and not (pool_id and all_sessions):
            console.print("[red]ERROR:[/red] specify --session-id or --pool-id with --all")
            sys.exit(1)

        async def _execute() -> None:
            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            try:
                async with cli_pkg.Connection.from_uri(uri, logger=logger) as conn:
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
                            await conn.run(
                                f"screen -S {sid} -X kill", raise_on_error=False
                            )
                            console.print(f"[green]OK[/green] killed {sid}")
                        else:
                            await conn.run(
                                f"screen -S {sid} -X stuff $'\\003'",
                                raise_on_error=False,
                            )
                            console.print(f"[green]OK[/green] sent Ctrl+C to {sid}")
            except Exception as e:
                renderer.print_error_and_exit(e, title="Exception")

        asyncio.run(_execute())
