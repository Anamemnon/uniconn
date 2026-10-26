# src/uniconn/cli/cmd_cassette.py
"""Команды записи, воспроизведения и управления кассетами: record, replay, cassette."""

from __future__ import annotations

import asyncio
import json
import re
import shlex
import sys
from pathlib import Path
from typing import Annotated, Any

from .._logging import get_logger
from ..core.connection import Connection
from ..transports.replay.models import Cassette, RecordMode
from .renderers import CLIOutputRenderer, Panel, Parameter, Table, box, cyclopts


def _format_command(command: list[str] | None, command_args: tuple[str, ...]) -> str | None:
    """Объединить команду из опции --command и позиционных аргументов."""
    parts: list[str] = []
    if command:
        parts.extend(command)
    if command_args:
        parts.extend(command_args)
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]
    return shlex.join(parts)


def _render_cassette_info(cass: Cassette, cassette_path: str | Path, console: Any) -> None:
    """Отрендерить сводку метаданных и таблицу взаимодействий кассеты."""
    path_obj = Path(cassette_path)
    size_bytes = path_obj.stat().st_size if path_obj.exists() else 0
    size_str = f"{size_bytes / 1024:.1f} KB" if size_bytes >= 1024 else f"{size_bytes} B"

    meta_table = Table(
        title="Cassette Metadata",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
    )
    meta_table.add_column("Property", style="cyan", width=18)
    meta_table.add_column("Value", style="green")

    meta_table.add_row("File Path", str(path_obj.resolve()))
    meta_table.add_row("Format Version", cass.version)
    meta_table.add_row("Original Transport", cass.transport)
    meta_table.add_row("Target Host", cass.host or "Unknown")
    meta_table.add_row("Capabilities", ", ".join(cass.capabilities))
    meta_table.add_row("Recorded At", cass.recorded_at)
    meta_table.add_row("File Size", size_str)
    meta_table.add_row(
        "Interactions",
        f"[bold]{cass.total_interactions}[/bold] (exec: {cass.exec_count}, stream: {cass.stream_count}, "
        f"fs: {cass.fs_count}, shell: {cass.shell_count})",
    )
    console.print(meta_table)

    if not cass.interactions:
        console.print("[dim]No interactions recorded in this cassette.[/dim]\n")
        return

    items_table = Table(
        title="Recorded Interactions",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
    )
    items_table.add_column("#", style="dim", width=4)
    items_table.add_column("Kind", style="magenta", width=8)
    items_table.add_column("Details / Command / Path", style="white")
    items_table.add_column("Status / Exit", style="cyan", width=14)
    items_table.add_column("Duration", style="yellow", width=10)

    for idx, it in enumerate(cass.interactions, 1):
        if it.kind == "exec":
            cmd_preview = it.command if len(it.command) <= 50 else it.command[:47] + "..."
            status = f"[green]exit {it.exit_code}[/green]" if it.exit_code == 0 else f"[red]exit {it.exit_code}[/red]"
            dur = f"{it.duration * 1000:.1f}ms"
            items_table.add_row(str(idx), "exec", cmd_preview, status, dur)
        elif it.kind == "stream":
            cmd_preview = f"stream: {it.command}"
            if len(cmd_preview) > 50:
                cmd_preview = cmd_preview[:47] + "..."
            status = f"[green]{len(it.lines)} lines[/green]"
            items_table.add_row(str(idx), "stream", cmd_preview, status, "-")
        elif it.kind == "fs":
            fs_detail = f"{it.operation} {it.path}"
            if len(fs_detail) > 50:
                fs_detail = fs_detail[:47] + "..."
            status = "[green]ok[/green]" if not it.error_class else f"[red]{it.error_class}[/red]"
            items_table.add_row(str(idx), "fs", fs_detail, status, "-")
        elif it.kind == "shell":
            shell_detail = f"shell steps ({len(it.steps)} dialog turns)"
            items_table.add_row(str(idx), "shell", shell_detail, "[green]dialog[/green]", "-")

    console.print(items_table)


def register_cassette_commands(app: Any, console: Any, renderer: CLIOutputRenderer) -> None:
    """Зарегистрировать команды record, replay и подгруппу cassette в Cyclopts-приложении."""

    @app.command
    def record(
        uri: Annotated[str, Parameter(help="Connection URI (ssh://user@host, telnet://..., local://)")],
        cassette: Annotated[str, Parameter(name=["--cassette", "-c"], help="Path to destination cassette file")],
        *command_args: Annotated[str, Parameter(help="Command and arguments to execute", allow_leading_hyphen=True)],
        command: Annotated[
            list[str] | None,
            Parameter(name=["--command", "-C"], help="Command to execute"),
        ] = None,
        mode: Annotated[
            str,
            Parameter(name=["--mode", "-m"], help="Record mode: once, all, new_episodes"),
        ] = "once",
        script: Annotated[
            str | None,
            Parameter(name=["--script"], help="Path to local script to execute on remote host"),
        ] = None,
        sudo: Annotated[
            bool,
            Parameter(name=["--sudo", "-s"], negative="", help="Execute command with sudo"),
        ] = False,
        mask_secrets: Annotated[
            bool,
            Parameter(name=["--mask-secrets"], help="Mask passwords and secret responses"),
        ] = True,
        sanitize_ip: Annotated[
            bool,
            Parameter(name=["--sanitize-ip"], negative="", help="Sanitize IPv4 addresses in recorded cassette"),
        ] = False,
        timeout: Annotated[
            float,
            Parameter(name=["--timeout", "-t"], help="Timeout in seconds"),
        ] = 30.0,
        output_format: Annotated[
            str,
            Parameter(name=["--format", "-f"], help="Output format: panel, json, plain"),
        ] = "panel",
        verbose: Annotated[
            bool,
            Parameter(name=["--verbose", "-v"], negative="", help="Verbose output"),
        ] = False,
    ) -> None:
        """Record command execution and interactions into a replay cassette."""
        cmd_str = _format_command(command, command_args)
        if not cmd_str and not script:
            console.print("[red]ERROR:[/red] command or --script argument is required for recording.")
            sys.exit(1)

        async def _execute() -> None:
            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            try:
                conn = Connection.from_uri(uri, logger=logger)
                async with conn:
                    async with conn.use_cassette(
                        cassette,
                        mode=RecordMode(mode),
                        mask_secrets=mask_secrets,
                    ) as active_cass:
                        if script:
                            result = await conn.run_script(script, sudo=sudo, timeout=timeout)
                        else:
                            result = await conn.run(cmd_str or "", sudo=sudo, timeout=timeout)

                        if sanitize_ip:
                            active_cass.sanitize(redact_ips=True)

                    renderer.render_single_result(result, output_format=output_format)
                    if output_format == "panel":
                        cassette_obj = Cassette.load(cassette)
                        console.print(
                            Panel(
                                f"[bold green]OK Cassette recorded:[/bold green] {cassette}\n"
                                f"[dim]Host:[/dim] {cassette_obj.host} | "
                                f"[dim]Transport:[/dim] {cassette_obj.transport} | "
                                f"[dim]Interactions:[/dim] {cassette_obj.total_interactions}",
                                title="Replay Cassette",
                                border_style="green",
                            )
                        )
            except Exception as e:
                renderer.print_error_and_exit(e, title="Record Error")

        asyncio.run(_execute())

    @app.command
    def replay(
        cassette: Annotated[str, Parameter(help="Path to cassette file to replay")],
        *command_args: Annotated[
            str,
            Parameter(help="Optional command to execute against cassette", allow_leading_hyphen=True),
        ],
        command: Annotated[
            list[str] | None,
            Parameter(name=["--command", "-C"], help="Command to execute"),
        ] = None,
        output_format: Annotated[
            str,
            Parameter(name=["--format", "-f"], help="Output format: panel, json, plain"),
        ] = "panel",
        verbose: Annotated[
            bool,
            Parameter(name=["--verbose", "-v"], negative="", help="Verbose output"),
        ] = False,
    ) -> None:
        """Replay recorded commands from a cassette without network connection."""
        cmd_str = _format_command(command, command_args)
        cassette_path = Path(cassette)
        if not cassette_path.is_file():
            console.print(f"[red]ERROR:[/red] Cassette file not found: {cassette_path}")
            sys.exit(1)

        cassette_obj = Cassette.load(cassette_path)

        if not cmd_str:
            _render_cassette_info(cassette_obj, cassette_path, console)
            return

        async def _execute() -> None:
            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            try:
                host = cassette_obj.host or "replayed-host"
                uri = f"replay://{host}?cassette={cassette_path}&mode=none"
                async with Connection.from_uri(uri, logger=logger) as conn:
                    result = await conn.run(cmd_str or "")
                    renderer.render_single_result(result, output_format=output_format)
            except Exception as e:
                renderer.print_error_and_exit(e, title="Replay Error")

        asyncio.run(_execute())

    cassette_app = cyclopts.App(
        name="cassette",
        help="Inspect, sanitize, and verify replay cassettes",
    )

    @cassette_app.command(name="info")
    def cassette_info(
        cassette: Annotated[str, Parameter(help="Path to cassette file")],
        output_format: Annotated[
            str,
            Parameter(name=["--format", "-f"], help="Output format: panel, json"),
        ] = "panel",
    ) -> None:
        """Display metadata and interaction summary of a cassette."""
        cass_path = Path(cassette)
        if not cass_path.is_file():
            console.print(f"[red]ERROR:[/red] Cassette file not found: {cass_path}")
            sys.exit(1)

        cass_obj = Cassette.load(cass_path)
        if output_format == "json":
            console.print(json.dumps(cass_obj.model_dump(mode="json"), indent=2, ensure_ascii=False))
        else:
            _render_cassette_info(cass_obj, cass_path, console)

    @cassette_app.command(name="sanitize")
    def cassette_sanitize(
        cassette: Annotated[str, Parameter(help="Path to cassette file to sanitize")],
        output: Annotated[
            str | None,
            Parameter(name=["--output", "-o"], help="Destination path (defaults to in-place overwrite)"),
        ] = None,
        redact_ip: Annotated[
            bool,
            Parameter(name=["--redact-ip"], negative="", help="Redact IPv4 addresses"),
        ] = True,
        redact_tokens: Annotated[
            bool,
            Parameter(name=["--redact-tokens"], negative="", help="Redact secret tokens and keys"),
        ] = True,
        pattern: Annotated[
            list[str] | None,
            Parameter(name=["--pattern", "-p"], help="Custom regex replacement (format: 'regex=replacement')"),
        ] = None,
    ) -> None:
        """Sanitize secrets, IP addresses, and sensitive tokens in a cassette."""
        cass_path = Path(cassette)
        if not cass_path.is_file():
            console.print(f"[red]ERROR:[/red] Cassette file not found: {cass_path}")
            sys.exit(1)

        custom_pats: dict[str | re.Pattern[str], str] = {}
        if pattern:
            for item in pattern:
                if "=" in item:
                    pat_str, repl_str = item.split("=", 1)
                    custom_pats[pat_str] = repl_str

        cass_obj = Cassette.load(cass_path)
        count = cass_obj.sanitize(
            redact_ips=redact_ip,
            redact_tokens=redact_tokens,
            custom_patterns=custom_pats or None,
        )

        dest_path = Path(output) if output else cass_path
        cass_obj.save(dest_path)
        console.print(
            Panel(
                f"[bold green]OK Cassette sanitized:[/bold green] {dest_path}\n"
                f"[dim]Replacements made:[/dim] {count} occurrences",
                title="Cassette Sanitize",
                border_style="green",
            )
        )

    @cassette_app.command(name="verify")
    def cassette_verify(
        cassette: Annotated[str, Parameter(help="Path to cassette file to verify")],
    ) -> None:
        """Verify structural integrity and schema conformity of a cassette."""
        cass_path = Path(cassette)
        if not cass_path.is_file():
            console.print(f"[red]ERROR:[/red] Cassette file not found: {cass_path}")
            sys.exit(1)

        try:
            cass_obj = Cassette.load(cass_path)
            errors = cass_obj.verify()
            if errors:
                console.print(
                    Panel(
                        f"[bold red]FAILED Cassette verification failed:[/bold red] {cass_path}\n"
                        + "\n".join(f" - {err}" for err in errors),
                        title="Cassette Verify",
                        border_style="red",
                    )
                )
                sys.exit(1)

            console.print(
                Panel(
                    f"[bold green]OK Cassette is valid:[/bold green] {cass_path}\n"
                    f"[dim]Version:[/dim] {cass_obj.version} | "
                    f"[dim]Interactions:[/dim] {cass_obj.total_interactions} | "
                    f"[dim]Transport:[/dim] {cass_obj.transport}",
                    title="Cassette Verify",
                    border_style="green",
                )
            )
        except Exception as exc:
            console.print(
                Panel(
                    f"[bold red]FAILED Cassette verification error:[/bold red] {exc}",
                    title="Cassette Verify",
                    border_style="red",
                )
            )
            sys.exit(1)

    app.command(cassette_app)
