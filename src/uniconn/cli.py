# src/uniconn/cli.py
"""CLI интерфейс для uniconn.

Предоставляет командную строку для выполнения команд на удалённых хостах
через различные транспорты: SSH, Telnet, Serial, IPMI и локальный.

Примеры использования:
    # Выполнить команду по SSH
    uniconn run "ssh://user:pass@host" "uptime"

    # Выполнить на нескольких хостах
    uniconn run-multi "ssh://host1" "ssh://host2" --command "uptime"

    # Управление BMC через IPMI
    uniconn bmc "ipmi://admin:pass@bmc" power status

    # Список доступных транспортов
    uniconn transports
"""

import asyncio
import shlex
import sys
from typing import Any

try:
    import typer
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    HAVE_CLI_DEPS = True
except ImportError:
    typer: Any = None
    box: Any = None
    Console: Any = None
    Panel: Any = None
    Table: Any = None
    HAVE_CLI_DEPS = False

from . import Connection, ConnectionPool, __version__
from ._logging import configure_logging, get_logger
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
    def callback(
        log_level: str | None = typer.Option(
            None,
            "--log-level",
            help="Log level (DEBUG, INFO, WARNING, ERROR)",
        ),
        log_format: str = typer.Option(
            "console",
            "--log-format",
            help="Structured log format: console or json",
        ),
    ):
        """Uniconn - Universal library for remote command execution."""
        if log_level is not None or log_format != "console":
            fmt_val = "json" if log_format.lower() == "json" else "console"
            configure_logging(
                level=log_level or "INFO",
                fmt=fmt_val,
                stream=sys.stderr,
            )

    @app.command()
    def version():
        """Show uniconn version."""
        console.print(
            f"[bold blue]uniconn[/bold blue] version [green]{__version__}[/green]"
        )

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

    @app.command()
    def run(
        uri: str = typer.Argument(..., help="Connection URI (ssh://user:pass@host)"),
        command: str = typer.Argument(..., help="Command to execute"),
        timeout: float = typer.Option(30.0, "--timeout", "-t", help="Timeout in seconds"),
        sudo: bool = typer.Option(False, "--sudo", "-s", help="Execute with sudo"),
        output_format: str = typer.Option(
            "panel", "--format", "-f", help="Output format: panel, json, plain"
        ),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
        raise_on_error: bool = typer.Option(False, "--raise", "-e", help="Exit on error"),
    ):
        """Execute command on remote host.

        Examples:
            uniconn run "ssh://user:pass@host" "uptime"
            uniconn run "local://" "echo hello" --format json
            uniconn run "ssh://user@host" "systemctl restart nginx" --sudo

        """

        async def _execute():
            import json as json_mod

            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")

            try:
                async with Connection.from_uri(uri, logger=logger) as conn:
                    result = await conn.run(
                        command,
                        timeout=timeout,
                        sudo=sudo,
                        raise_on_error=raise_on_error,
                    )

                    if output_format == "json":
                        console.print(json_mod.dumps(result.to_dict(), indent=2))
                        if not result.ok:
                            sys.exit(result.exit_code)
                        return

                    if output_format == "plain":
                        if result.stdout:
                            console.print(result.stdout.rstrip())
                        if result.stderr:
                            console.print(result.stderr.rstrip(), style="red")
                        if not result.ok:
                            sys.exit(result.exit_code)
                        return

                    # Print result (panel)
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
        uris: list[str] | None = typer.Argument(None, help="Connection URIs"),  # noqa: B008
        command: str = typer.Option(..., "--command", "-c", help="Command to execute"),
        inventory: str | None = typer.Option(
            None, "--inventory", "-i", help="Inventory file (.yaml/.json)"
        ),
        group: str | None = typer.Option(
            None, "--group", "-g", help="Host group name in inventory"
        ),
        sudo: bool = typer.Option(False, "--sudo", "-s", help="Execute with sudo"),
        max_concurrent: int = typer.Option(
            10, "--max-concurrent", "-j", help="Max concurrent connections"
        ),
        timeout: float = typer.Option(30.0, "--timeout", "-t", help="Timeout in seconds"),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
        output_format: str = typer.Option(
            "table", "--format", "-f", help="Output format: table, json, plain"
        ),
    ):
        """Execute command on multiple hosts in parallel (from URIs or inventory).

        Examples:
            uniconn run-multi "ssh://host1" "ssh://host2" -c "uptime"
            uniconn run-multi --inventory hosts.yaml --group web -c "uptime"

        """
        host_uris = list(uris or [])
        if not host_uris and not inventory:
            console.print("[red]ERROR:[/red] specify at least one URI or --inventory/-i")
            raise typer.Exit(code=1)

        async def _execute():
            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            if inventory:
                pool = ConnectionPool.from_file(
                    inventory,
                    group=group,
                    max_concurrent=max_concurrent,
                    logger=logger,
                )
            else:
                pool = ConnectionPool(
                    host_uris,
                    max_concurrent=max_concurrent,
                    logger=logger,
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
                    import json
                    output = []
                    for label, result in zip(target_labels, results, strict=False):
                        output.append({
                            "host": label,
                            "exit_code": result.exit_code,
                            "stdout": result.stdout,
                            "stderr": result.stderr,
                            "duration": result.duration,
                        })
                    console.print(json.dumps(output, indent=2))

                elif output_format == "plain":
                    for label, result in zip(target_labels, results, strict=False):
                        status = "OK" if result.ok else "FAIL"
                        console.print(f"[{status}] {label}: {result.stdout.strip()}")

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

                    for label, result in zip(target_labels, results, strict=False):
                        if result.ok:
                            status = "[green]OK[/green]"
                            output = result.stdout.strip()[:50]
                            if len(result.stdout.strip()) > 50:
                                output += "..."
                        else:
                            status = "[red]FAIL[/red]"
                            output = (
                                result.stderr.strip()[:50]
                                or f"Exit code: {result.exit_code}"
                            )
                            if len(result.stderr.strip()) > 50:
                                output += "..."

                        table.add_row(
                            label,
                            status,
                            f"{result.duration:.2f}s",
                            output
                        )

                    console.print(table)

                # Return exit code based on results
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
                console.print(Panel(
                    f"[red]ERROR:[/red] {e}",
                    title="Exception",
                    border_style="red"
                ))
                sys.exit(1)

        asyncio.run(_execute())

    @app.command()
    def upload(
        local_path: str = typer.Argument(..., help="Local file or directory path"),
        remote_path: str = typer.Argument(..., help="Remote destination path"),
        uris: list[str] | None = typer.Argument(None, help="Target connection URIs"),  # noqa: B008
        inventory: str | None = typer.Option(
            None, "--inventory", "-i", help="Inventory file (.yaml/.json)"
        ),
        group: str | None = typer.Option(
            None, "--group", "-g", help="Host group name in inventory"
        ),
        recurse: bool = typer.Option(
            False, "--recurse", "-r", help="Upload directory recursively"
        ),
        max_concurrent: int = typer.Option(
            10, "--max-concurrent", "-j", help="Max concurrent connections"
        ),
        output_format: str = typer.Option(
            "table", "--format", "-f", help="Output format: table, json"
        ),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    ):
        """Upload file or directory to one or more remote hosts via SFTP.

        Examples:
            uniconn upload ./app.conf /etc/app/app.conf "ssh://user@host"
            uniconn upload ./dist /var/www/app -i hosts.yaml -g web --recurse

        """
        host_uris = list(uris or [])
        if not host_uris and not inventory:
            console.print("[red]ERROR:[/red] specify at least one URI or --inventory/-i")
            raise typer.Exit(code=1)

        async def _execute():
            import json as json_mod

            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            try:
                if inventory:
                    pool = ConnectionPool.from_file(
                        inventory,
                        group=group,
                        max_concurrent=max_concurrent,
                        logger=logger,
                    )
                else:
                    pool = ConnectionPool(
                        host_uris,
                        max_concurrent=max_concurrent,
                        logger=logger,
                    )
                target_labels = [pool._target_key(t) for t in pool._uris]
                await pool.upload(local_path, remote_path, recurse=recurse)

                if output_format == "json":
                    console.print(
                        json_mod.dumps(
                            {
                                "action": "upload",
                                "local_path": local_path,
                                "remote_path": remote_path,
                                "hosts": target_labels,
                                "ok": True,
                            },
                            indent=2,
                        )
                    )
                else:
                    console.print(
                        f"[green]OK[/green] Uploaded [cyan]{local_path}[/cyan] -> "
                        f"[cyan]{remote_path}[/cyan] on {len(target_labels)} host(s)"
                    )
            except Exception as e:
                console.print(Panel(
                    f"[red]ERROR:[/red] {e}",
                    title="Upload Error",
                    border_style="red",
                ))
                sys.exit(1)

        asyncio.run(_execute())

    @app.command()
    def download(
        remote_path: str = typer.Argument(..., help="Remote file or directory path"),
        local_path: str = typer.Argument(..., help="Local destination path or pattern"),
        uris: list[str] | None = typer.Argument(None, help="Target connection URIs"),  # noqa: B008
        inventory: str | None = typer.Option(
            None, "--inventory", "-i", help="Inventory file (.yaml/.json)"
        ),
        group: str | None = typer.Option(
            None, "--group", "-g", help="Host group name in inventory"
        ),
        recurse: bool = typer.Option(
            False, "--recurse", "-r", help="Download directory recursively"
        ),
        max_concurrent: int = typer.Option(
            10, "--max-concurrent", "-j", help="Max concurrent connections"
        ),
        output_format: str = typer.Option(
            "table", "--format", "-f", help="Output format: table, json"
        ),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    ):
        """Download file or directory from one or more remote hosts via SFTP.

        Examples:
            uniconn download /var/log/syslog ./syslog.log "ssh://user@host"
            uniconn download /var/log/syslog "./logs/{host}.log" -i hosts.yaml -g web

        """
        host_uris = list(uris or [])
        if not host_uris and not inventory:
            console.print("[red]ERROR:[/red] specify at least one URI or --inventory/-i")
            raise typer.Exit(code=1)

        async def _execute():
            import json as json_mod

            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            try:
                if inventory:
                    pool = ConnectionPool.from_file(
                        inventory,
                        group=group,
                        max_concurrent=max_concurrent,
                        logger=logger,
                    )
                else:
                    pool = ConnectionPool(
                        host_uris,
                        max_concurrent=max_concurrent,
                        logger=logger,
                    )
                saved = await pool.download(remote_path, local_path, recurse=recurse)

                if output_format == "json":
                    console.print(
                        json_mod.dumps(
                            {
                                "action": "download",
                                "remote_path": remote_path,
                                "saved": saved,
                                "ok": True,
                            },
                            indent=2,
                        )
                    )
                else:
                    for host_key, dest in saved.items():
                        console.print(
                            f"[green]OK[/green] {host_key}: [cyan]{remote_path}[/cyan] -> "
                            f"[cyan]{dest}[/cyan]"
                        )
            except Exception as e:
                console.print(Panel(
                    f"[red]ERROR:[/red] {e}",
                    title="Download Error",
                    border_style="red",
                ))
                sys.exit(1)

        asyncio.run(_execute())

    @app.command()
    def bmc(
        uri: str = typer.Argument(..., help="BMC URI (ipmi://admin:pass@bmc)"),
        operation: str = typer.Argument(
            ...,
            help="Operation",
            case_sensitive=False,
        ),
        timeout: float = typer.Option(30.0, "--timeout", "-t", help="Timeout in seconds"),
        output_format: str = typer.Option(
            "panel", "--format", "-f", help="Output format: panel, json"
        ),
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
            uniconn bmc "ipmi://admin:pass@bmc.local" power status
            uniconn bmc "ipmi://admin:pass@bmc.local" power status --format json

        """

        async def _execute():
            import json as json_mod

            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")

            try:
                async with Connection.from_uri(uri, logger=logger) as conn:
                    result = await conn.run(operation, timeout=timeout)

                    if output_format == "json":
                        console.print(json_mod.dumps(result.to_dict(), indent=2))
                        return

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
        """Interactive stateful PTY shell for remote host.

        Examples:
            uniconn shell "ssh://user:pass@host"

        """

        async def _interactive():
            console.print(f"[dim]Connecting to {uri}...[/dim]\n")

            try:
                async with (
                    Connection.from_uri(uri) as conn,
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
                    assert uri is not None
                    pool = ScreenPool(uri, logger=logger)

                # НЕ используем `async with pool`: __aexit__ вызывает
                # cleanup() → stop_all() и убил бы только что запущенные
                # сессии. Вместо этого в конце — disconnect(): отключение
                # от SSH с сохранением detached screen-сессий на хосте.
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

                # Отключаемся от SSH, сессии продолжают работать на хосте
                await pool.disconnect()

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
        output_format: str = typer.Option(
            "table", "--format", "-f", help="Output format: table, json"
        ),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    ):
        """Show status of background screen sessions on the host.

        Examples:
            uniconn screen-status "ssh://user@host"
            uniconn screen-status "ssh://user@host" --pool-id abc123 --format json

        """
        prefix = f"uniconn_{pool_id}" if pool_id else "uniconn_"

        async def _execute():
            import json as json_mod

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

                if output_format == "json":
                    console.print(
                        json_mod.dumps(
                            [
                                {"session_id": name, "pid": pid, "status": status}
                                for name, pid, status in sessions
                            ],
                            indent=2,
                        )
                    )
                    return

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

    @app.command("sync")
    def sync(
        local_dir: str = typer.Argument(..., help="Local source directory"),
        remote_dir: str = typer.Argument(..., help="Remote destination directory"),
        uris: list[str] | None = typer.Argument(None, help="Target connection URIs"),  # noqa: B008
        inventory: str | None = typer.Option(
            None, "--inventory", "-i", help="Inventory file (.yaml/.json)"
        ),
        group: str | None = typer.Option(
            None, "--group", "-g", help="Host group name in inventory"
        ),
        delete: bool = typer.Option(
            False, "--delete", help="Delete remote files missing locally"
        ),
        exclude: list[str] | None = typer.Option(  # noqa: B008
            None, "--exclude", "-x", help="Exclude glob pattern (repeatable)"
        ),
        dry_run: bool = typer.Option(
            False, "--dry-run", "-n", help="Preview changes without modifying remote"
        ),
        max_concurrent: int = typer.Option(
            10, "--max-concurrent", "-j", help="Max concurrent connections"
        ),
        output_format: str = typer.Option(
            "table", "--format", "-f", help="Output format: table, json"
        ),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    ):
        """Incrementally synchronize local directory to one or more hosts.

        Examples:
            uniconn sync ./app /opt/app "ssh://user@host" --exclude "*.pyc" --exclude ".git"
            uniconn sync ./configs /etc/app -i hosts.yaml -g web --delete

        """
        host_uris = list(uris or [])
        if not host_uris and not inventory:
            console.print("[red]ERROR:[/red] specify at least one URI or --inventory/-i")
            raise typer.Exit(code=1)

        async def _execute():
            import json as json_mod

            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            try:
                if inventory:
                    pool = ConnectionPool.from_file(
                        inventory,
                        group=group,
                        max_concurrent=max_concurrent,
                        logger=logger,
                    )
                else:
                    pool = ConnectionPool(
                        host_uris,
                        max_concurrent=max_concurrent,
                        logger=logger,
                    )
                results = await pool.sync_dir(
                    local_dir=local_dir,
                    remote_dir=remote_dir,
                    delete=delete,
                    exclude=list(exclude or []),
                    dry_run=dry_run,
                )

                if output_format == "json":
                    console.print(
                        json_mod.dumps(
                            {k: v.to_dict() for k, v in results.items()},
                            indent=2,
                        )
                    )
                else:
                    table = Table(
                        title=f"Directory Sync: {local_dir} -> {remote_dir}",
                        box=box.ROUNDED,
                        show_header=True,
                        header_style="bold cyan",
                    )
                    table.add_column("Host", style="cyan")
                    table.add_column("Uploaded", style="green")
                    table.add_column("Skipped", style="dim")
                    table.add_column("Deleted", style="yellow")
                    table.add_column("Bytes", style="blue")
                    for host_key, res in results.items():
                        table.add_row(
                            host_key,
                            str(len(res.uploaded)),
                            str(len(res.skipped)),
                            str(len(res.deleted)),
                            str(res.bytes_transferred),
                        )
                    console.print(table)
            except Exception as e:
                console.print(
                    Panel(
                        f"[red]ERROR:[/red] {e}",
                        title="Sync Error",
                        border_style="red",
                    )
                )
                sys.exit(1)

        asyncio.run(_execute())

    @app.command("template")
    def template(
        template_path: str = typer.Argument(..., help="Template file path or inline string"),
        remote_path: str = typer.Argument(..., help="Remote destination file path"),
        uris: list[str] | None = typer.Argument(None, help="Target connection URIs"),  # noqa: B008
        var: list[str] | None = typer.Option(  # noqa: B008
            None, "--var", "-D", help="Template variable KEY=VALUE (repeatable)"
        ),
        engine: str = typer.Option(
            "auto", "--engine", "-e", help="Template engine: auto, string, jinja2"
        ),
        mode: str = typer.Option(
            "0644", "--mode", "-m", help="File permissions in octal (e.g., 0644)"
        ),
        inventory: str | None = typer.Option(
            None, "--inventory", "-i", help="Inventory file (.yaml/.json)"
        ),
        group: str | None = typer.Option(
            None, "--group", "-g", help="Host group name in inventory"
        ),
        max_concurrent: int = typer.Option(
            10, "--max-concurrent", "-j", help="Max concurrent connections"
        ),
        output_format: str = typer.Option(
            "panel", "--format", "-f", help="Output format: panel, json"
        ),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    ):
        """Render configuration template and write to one or more remote hosts.

        Examples:
            uniconn template ./nginx.conf.j2 /etc/nginx/nginx.conf "ssh://user@host" -D port=8080

        """
        host_uris = list(uris or [])
        if not host_uris and not inventory:
            console.print("[red]ERROR:[/red] specify at least one URI or --inventory/-i")
            raise typer.Exit(code=1)

        ctx: dict[str, Any] = {}
        for item in var or []:
            if "=" not in item:
                console.print(f"[red]ERROR:[/red] invalid --var {item!r}, expected KEY=VALUE")
                raise typer.Exit(code=1)
            k, v = item.split("=", 1)
            ctx[k.strip()] = v

        mode_int = int(mode, 8)
        eng_val: Any = engine if engine in ("auto", "string", "jinja2") else "auto"

        async def _execute():
            import json as json_mod

            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            try:
                if inventory:
                    pool = ConnectionPool.from_file(
                        inventory,
                        group=group,
                        max_concurrent=max_concurrent,
                        logger=logger,
                    )
                else:
                    pool = ConnectionPool(
                        host_uris,
                        max_concurrent=max_concurrent,
                        logger=logger,
                    )
                rendered_map = await pool.write_template(
                    remote_path=remote_path,
                    template_str_or_path=template_path,
                    context=ctx,
                    mode=mode_int,
                    engine=eng_val,
                )

                if output_format == "json":
                    console.print(
                        json_mod.dumps(
                            {
                                "action": "template",
                                "remote_path": remote_path,
                                "hosts": list(rendered_map.keys()),
                                "rendered": next(iter(rendered_map.values()), ""),
                                "ok": True,
                            },
                            indent=2,
                        )
                    )
                else:
                    console.print(
                        f"[green]OK[/green] Rendered template to [cyan]{remote_path}[/cyan] "
                        f"on {len(rendered_map)} host(s)"
                    )
            except Exception as e:
                console.print(
                    Panel(
                        f"[red]ERROR:[/red] {e}",
                        title="Template Error",
                        border_style="red",
                    )
                )
                sys.exit(1)

        asyncio.run(_execute())

    @app.command("expect")
    def expect_cmd(
        uri: str = typer.Argument(..., help="Connection URI"),
        command: str = typer.Argument(..., help="Interactive command to run"),
        pattern: list[str] | None = typer.Option(  # noqa: B008
            None, "--pattern", "-p", help="Pattern rule REGEX=RESPONSE (repeatable)"
        ),
        final_prompt: str | None = typer.Option(
            None, "--final-prompt", help="Regex for final prompt completion"
        ),
        timeout: float = typer.Option(30.0, "--timeout", "-t", help="Timeout in seconds"),
        output_format: str = typer.Option(
            "panel", "--format", "-f", help="Output format: panel, json, plain"
        ),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    ):
        r"""Run interactive CLI dialog using declarative regex patterns.

        Examples:
            uniconn expect "local://" "python3 ask.py" -p "Continue\?:yes\n"

        """
        patterns_dict: dict[str, str] = {}
        for item in pattern or []:
            sep = "=" if "=" in item else ":"
            if sep not in item:
                console.print(
                    f"[red]ERROR:[/red] invalid --pattern {item!r}, expected REGEX=RESPONSE"
                )
                raise typer.Exit(code=1)
            pat_str, resp_str = item.split(sep, 1)
            resp_unescaped = resp_str.replace("\\n", "\n").replace("\\r", "\r")
            patterns_dict[pat_str] = resp_unescaped

        async def _execute():
            import json as json_mod

            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            try:
                async with Connection.from_uri(uri, logger=logger) as conn:
                    res = await conn.expect(
                        command=command,
                        patterns=patterns_dict,
                        final_prompt=final_prompt,
                        timeout=timeout,
                    )
                    if output_format == "json":
                        console.print(json_mod.dumps(res.to_dict(), indent=2))
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
                console.print(
                    Panel(
                        f"[red]ERROR:[/red] {e}",
                        title="Expect Error",
                        border_style="red",
                    )
                )
                sys.exit(1)

        asyncio.run(_execute())

    @app.command("facts")
    def facts_cmd(
        uris: list[str] | None = typer.Argument(None, help="Target connection URIs"),  # noqa: B008
        inventory: str | None = typer.Option(
            None, "--inventory", "-i", help="Inventory file (.yaml/.json)"
        ),
        group: str | None = typer.Option(
            None, "--group", "-g", help="Host group name in inventory"
        ),
        max_concurrent: int = typer.Option(
            10, "--max-concurrent", "-j", help="Max concurrent connections"
        ),
        output_format: str = typer.Option(
            "table", "--format", "-f", help="Output format: table, json"
        ),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    ):
        """Gather structured system facts (OS, kernel, CPU, RAM, disks, network) from hosts.

        Examples:
            uniconn facts "local://"
            uniconn facts -i inventory.yaml -g web --format json

        """
        host_uris = list(uris or [])
        if not host_uris and not inventory:
            host_uris = ["local://"]

        async def _execute():
            import json as json_mod

            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            try:
                if inventory:
                    pool = ConnectionPool.from_file(
                        inventory,
                        group=group,
                        max_concurrent=max_concurrent,
                        logger=logger,
                    )
                else:
                    pool = ConnectionPool(
                        host_uris,
                        max_concurrent=max_concurrent,
                        logger=logger,
                    )

                facts_map = await pool.gather_facts()
                if output_format == "json":
                    payload = {k: v.to_dict() for k, v in facts_map.items()}
                    console.print(json_mod.dumps(payload, indent=2))
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
            except Exception as e:
                console.print(
                    Panel(
                        f"[red]ERROR:[/red] {e}",
                        title="Facts Error",
                        border_style="red",
                    )
                )
                sys.exit(1)

        asyncio.run(_execute())

    @app.command("tail")
    def tail_cmd(
        target_or_cmd: str = typer.Argument(
            ..., help="Log file path or command to stream across hosts"
        ),
        uris: list[str] | None = typer.Argument(None, help="Target connection URIs"),  # noqa: B008
        inventory: str | None = typer.Option(
            None, "--inventory", "-i", help="Inventory file (.yaml/.json)"
        ),
        group: str | None = typer.Option(
            None, "--group", "-g", help="Host group name in inventory"
        ),
        lines: int = typer.Option(
            10, "--lines", "-n", help="Initial number of lines when tailing a file"
        ),
        follow: bool = typer.Option(
            False, "--follow", "-f", help="Follow file growth (tail -f)"
        ),
        raw_command: bool = typer.Option(
            False, "--command", "-c", help="Treat first argument as raw command instead of file path"
        ),
        max_lines: int = typer.Option(
            0, "--max-lines", help="Stop automatically after receiving N total lines (0 = unlimited)"
        ),
        max_concurrent: int = typer.Option(
            10, "--max-concurrent", "-j", help="Max concurrent connections"
        ),
        output_format: str = typer.Option(
            "console", "--format", help="Output format: console, json"
        ),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    ):
        """Stream multiplexed output or log files from multiple hosts in real time.

        Examples:
            uniconn tail /var/log/syslog "ssh://node1" "ssh://node2" -f
            uniconn tail -c "journalctl -n 20" -i inventory.yaml -g web

        """
        host_uris = list(uris or [])
        if not host_uris and not inventory:
            host_uris = ["local://"]

        if raw_command:
            stream_cmd = target_or_cmd
        else:
            follow_flag = "-f " if follow else ""
            stream_cmd = f"tail -n {lines} {follow_flag}{shlex.quote(target_or_cmd)}"

        palette = ["cyan", "green", "magenta", "yellow", "blue", "bright_cyan", "bright_green"]

        async def _execute():
            import json as json_mod

            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            try:
                if inventory:
                    pool = ConnectionPool.from_file(
                        inventory,
                        group=group,
                        max_concurrent=max_concurrent,
                        logger=logger,
                    )
                else:
                    pool = ConnectionPool(
                        host_uris,
                        max_concurrent=max_concurrent,
                        logger=logger,
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
                        console.print(f"[bold {color}][{host_key}][/bold {color}] {clean}")
                    if max_lines > 0 and count >= max_lines:
                        break

                if output_format == "json":
                    console.print(
                        json_mod.dumps(
                            {"command": stream_cmd, "count": len(collected), "lines": collected},
                            indent=2,
                        )
                    )
            except Exception as e:
                console.print(
                    Panel(
                        f"[red]ERROR:[/red] {e}",
                        title="Tail Stream Error",
                        border_style="red",
                    )
                )
                sys.exit(1)

        asyncio.run(_execute())

    app()


if __name__ == "__main__":
    main()

