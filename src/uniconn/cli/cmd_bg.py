# src/uniconn/cli/cmd_bg.py
"""Команды управления фоновыми сессиями: bg-run, bg-logs, bg-status, bg-kill."""

from __future__ import annotations

import asyncio
import json
import shlex
import sys
from typing import Annotated, Any, cast

from .._logging import get_logger
from ..background._backends import BackgroundBackendType, resolve_backend
from .renderers import CLIOutputRenderer, Parameter, Table, box


def register_bg_commands(app: Any, console: Any, renderer: CLIOutputRenderer) -> None:
    """Зарегистрировать команды ``bg-*`` в Cyclopts-приложении."""
    import uniconn.cli as cli_pkg

    @app.command(name="bg-run")
    def bg_run(
        uri: Annotated[
            str | None, Parameter(help="Connection URI (ssh://user:pass@host)")
        ] = None,
        *,
        config: Annotated[
            str | None,
            Parameter(name=["--config", "-f"], help="BackgroundPool config file"),
        ] = None,
        command: Annotated[
            list[str] | None,
            Parameter(name=["--command", "-c"], help="Command to run (repeatable)"),
        ] = None,
        backend: Annotated[
            str,
            Parameter(
                name=["--backend", "-b"],
                help="Background backend: auto, tmux, screen, nohup",
            ),
        ] = "auto",
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
        """Start commands in detached background sessions (tmux, screen, or nohup)."""
        if config is None and uri is None:
            console.print("[red]ERROR:[/red] URI argument or --config option is required")
            sys.exit(1)

        commands = list(command or [])
        if not commands:
            console.print("[red]ERROR:[/red] at least one --command is required")
            sys.exit(1)

        async def _execute() -> None:
            from ..background import BackgroundPool

            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            try:
                if config is not None:
                    pool = BackgroundPool.from_file(config, logger=logger)
                else:
                    assert uri is not None
                    pool = BackgroundPool(
                        uri,
                        backend=cast(BackgroundBackendType, backend),
                        logger=logger,
                    )

                started = []
                for cmd in commands:
                    for _ in range(instances):
                        session = await pool.start(cmd)
                        started.append((session, cmd))

                table = Table(
                    title=f"Started {len(started)} background session(s)",
                    box=box.ROUNDED,
                    show_header=True,
                    header_style="bold cyan",
                )
                table.add_column("Session ID", style="cyan")
                table.add_column("Backend", style="magenta")
                table.add_column("Command", style="green")

                for session, cmd in started:
                    table.add_row(session.session_id, session.backend_name, cmd)

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

    @app.command(name="bg-logs")
    def bg_logs(
        uri: Annotated[str, Parameter(help="Connection URI (ssh://user:pass@host)")],
        *,
        session_id: Annotated[
            str, Parameter(name=["--session-id", "-s"], help="Background session ID")
        ],
        backend: Annotated[
            str,
            Parameter(
                name=["--backend", "-b"],
                help="Background backend: auto, tmux, screen, nohup",
            ),
        ] = "auto",
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
        """Read logs of a background session."""
        log_path = f"/tmp/{session_id}.log"

        async def _execute() -> None:
            from ..background import BackgroundSession

            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            try:
                async with cli_pkg.Connection.from_uri(uri, logger=logger) as conn:
                    if not follow:
                        result = await conn.run(
                            f"cat {shlex.quote(log_path)}", raise_on_error=False
                        )
                        if result.exit_code != 0:
                            console.print(
                                f"[red]ERROR:[/red] cannot read {log_path}: "
                                f"{result.stderr.strip()}"
                            )
                            sys.exit(1)
                        if result.stdout:
                            console.print(result.stdout)
                        return

                    session = BackgroundSession(
                        conn,
                        session_id,
                        log_path,
                        backend=cast(BackgroundBackendType, backend),
                    )
                    offset = 0
                    while True:
                        chunk = await conn.run(
                            f"tail -c +{offset + 1} {shlex.quote(log_path)}",
                            raise_on_error=False,
                        )
                        data = chunk.stdout or ""
                        if data:
                            console.print(data, end="")
                            offset += len(data.encode())

                        if not await session.is_alive():
                            break
                        await asyncio.sleep(interval)
            except Exception as e:
                renderer.print_error_and_exit(e, title="Exception")

        asyncio.run(_execute())

    @app.command(name="bg-status")
    def bg_status(
        uri: Annotated[str, Parameter(help="Connection URI (ssh://user:pass@host)")],
        *,
        pool_id: Annotated[
            str | None,
            Parameter(name=["--pool-id", "-p"], help="Filter by pool ID"),
        ] = None,
        backend: Annotated[
            str,
            Parameter(
                name=["--backend", "-b"],
                help="Background backend: auto, tmux, screen, nohup",
            ),
        ] = "auto",
        output_format: Annotated[
            str,
            Parameter(name=["--format", "-f"], help="Output format: table, json"),
        ] = "table",
        verbose: Annotated[
            bool, Parameter(name=["--verbose", "-v"], negative="", help="Verbose output")
        ] = False,
    ) -> None:
        """Show status of background sessions on the host."""
        prefix = f"uniconn_{pool_id}" if pool_id else "uniconn_"

        async def _execute() -> None:
            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            try:
                async with cli_pkg.Connection.from_uri(uri, logger=logger) as conn:
                    strategy = await resolve_backend(
                        conn, cast(BackgroundBackendType, backend)
                    )
                    active_map = await strategy.list_sessions(conn, prefix=prefix)

                sessions = [
                    (name, str(pid), "Running", strategy.name)
                    for name, pid in sorted(active_map.items())
                ]

                if output_format == "json":
                    console.print(
                        json.dumps(
                            [
                                {
                                    "session_id": name,
                                    "pid": pid,
                                    "status": status,
                                    "backend": bname,
                                }
                                for name, pid, status, bname in sessions
                            ],
                            indent=2,
                        )
                    )
                    return

                if not sessions:
                    console.print(
                        f"[yellow]No background sessions matching '{prefix}'[/yellow]"
                    )
                    return

                table = Table(
                    title=f"Background sessions: {prefix}*",
                    box=box.ROUNDED,
                    show_header=True,
                    header_style="bold cyan",
                )
                table.add_column("Session ID", style="cyan")
                table.add_column("PID", style="dim")
                table.add_column("Backend", style="magenta")
                table.add_column("Status", style="green")

                for name, pid, status, bname in sessions:
                    table.add_row(name, pid, bname, status)

                console.print(table)
            except Exception as e:
                renderer.print_error_and_exit(e, title="Exception")

        asyncio.run(_execute())

    @app.command(name="bg-kill")
    def bg_kill(
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
        backend: Annotated[
            str,
            Parameter(
                name=["--backend", "-b"],
                help="Background backend: auto, tmux, screen, nohup",
            ),
        ] = "auto",
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
                help="Force kill (skip graceful interrupt)",
            ),
        ] = False,
        verbose: Annotated[
            bool, Parameter(name=["--verbose", "-v"], negative="", help="Verbose output")
        ] = False,
    ) -> None:
        """Kill background session(s)."""
        if session_id is None and not (pool_id and all_sessions):
            console.print("[red]ERROR:[/red] specify --session-id or --pool-id with --all")
            sys.exit(1)

        async def _execute() -> None:
            from ..background import BackgroundSession

            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            try:
                async with cli_pkg.Connection.from_uri(uri, logger=logger) as conn:
                    strategy = await resolve_backend(
                        conn, cast(BackgroundBackendType, backend)
                    )
                    targets = [session_id] if session_id else []

                    if pool_id and all_sessions:
                        prefix = f"uniconn_{pool_id}_"
                        active_map = await strategy.list_sessions(conn, prefix=prefix)
                        targets.extend(sorted(active_map.keys()))

                    if not targets:
                        console.print(
                            "[yellow]No matching background sessions found[/yellow]"
                        )
                        return

                    for sid in targets:
                        session = BackgroundSession(
                            conn,
                            sid,
                            f"/tmp/{sid}.log",
                            backend=strategy,
                        )
                        if force:
                            await strategy.terminate(conn, sid, session.pid_file_path)
                            console.print(f"[green]OK[/green] killed {sid}")
                        else:
                            await session.send_ctrl_c()
                            console.print(f"[green]OK[/green] sent interrupt to {sid}")
            except Exception as e:
                renderer.print_error_and_exit(e, title="Exception")

        asyncio.run(_execute())
