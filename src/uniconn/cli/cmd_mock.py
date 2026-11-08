# src/uniconn/cli/cmd_mock.py
"""CLI-команда запуска автономного сокетного Mock SSH / Telnet сервера: mock-server."""

from __future__ import annotations

import asyncio
import contextlib
import json
import sys
from pathlib import Path
from typing import Annotated, Any, Literal

from ..mock import MockRequestEvent, MockServerConfig, MockSSHServer, MockTelnetServer
from ..transports.replay.models import Cassette
from .renderers import CLIOutputRenderer, Panel, Parameter


def register_mock_commands(app: Any, console: Any, renderer: CLIOutputRenderer) -> None:
    """Зарегистрировать команду ``mock-server`` в Cyclopts-приложении."""

    @app.command(name="mock-server")
    def mock_server(
        cassette: Annotated[str, Parameter(help="Path to cassette file (.yaml or .json)")],
        host: Annotated[
            str,
            Parameter(name=["--host", "-H"], help="Bind host address"),
        ] = "127.0.0.1",
        port: Annotated[
            int,
            Parameter(name=["--port", "-p"], help="Bind TCP port (0 for ephemeral port)"),
        ] = 0,
        server_type: Annotated[
            str,
            Parameter(name=["--type", "-t"], help="Server protocol: ssh or telnet"),
        ] = "ssh",
        strict: Annotated[
            bool,
            Parameter(name=["--strict"], negative="", help="Fail on unrecorded commands"),
        ] = False,
        username: Annotated[
            str | None,
            Parameter(name=["--user", "-u"], help="Required username for authentication"),
        ] = None,
        password: Annotated[
            str | None,
            Parameter(name=["--password"], help="Required password for authentication"),
        ] = None,
        duration: Annotated[
            float | None,
            Parameter(
                name=["--duration", "-d"],
                help="Optional run duration in seconds before automatic shutdown",
            ),
        ] = None,
        output_format: Annotated[
            str,
            Parameter(name=["--format", "-f"], help="Output format: panel, json"),
        ] = "panel",
    ) -> None:
        """Start a local socket Mock SSH or Telnet server replaying interactions from a cassette."""
        cass_path = Path(cassette)
        if not cass_path.is_file():
            console.print(f"[red]ERROR:[/red] Cassette file not found: {cass_path}")
            sys.exit(1)

        proto: Literal["ssh", "telnet"] = (
            "telnet" if server_type.strip().lower() == "telnet" else "ssh"
        )

        def _on_event(ev: MockRequestEvent) -> None:
            if output_format == "json":
                print(json.dumps(ev.to_dict(), ensure_ascii=False), flush=True)
                return
            tag = ev.channel.upper()
            status_str = (
                f"[green]matched[/green] (exit {ev.exit_code})"
                if ev.matched
                else "[red]miss[/red]"
            )
            console.print(f"[cyan][{tag}][/cyan] {ev.command} -> {status_str}")

        async def _serve() -> None:
            try:
                cass_obj = Cassette.load(cass_path)
                cfg = MockServerConfig(
                    cassette=cass_obj,
                    host=host,
                    port=port,
                    server_type=proto,
                    allow_any_auth=(username is None and password is None),
                    username=username,
                    password=password,
                    strict_mode=strict,
                    on_request=_on_event,
                )
                srv: MockSSHServer | MockTelnetServer = (
                    MockTelnetServer(cfg) if proto == "telnet" else MockSSHServer(cfg)
                )
                async with srv:
                    caps = ", ".join(cass_obj.capabilities)
                    if output_format == "json":
                        info = {
                            "status": "listening",
                            "server_type": proto,
                            "host": srv.host,
                            "port": srv.port,
                            "uri": srv.uri,
                            "cassette": str(cass_path),
                            "interactions": cass_obj.total_interactions,
                        }
                        print(json.dumps(info, ensure_ascii=False), flush=True)
                    else:
                        console.print(
                            Panel(
                                f"[bold green]Mock {proto.upper()} Server running on "
                                f"{srv.host}:{srv.port}[/bold green]\n"
                                f"[dim]URI:[/dim] {srv.uri}\n"
                                f"[dim]Cassette:[/dim] {cass_path} "
                                f"({cass_obj.total_interactions} interactions; "
                                f"capabilities: {caps})\n"
                                f"[dim]Strict Mode:[/dim] {strict}",
                                title=f"uniconn Mock {proto.upper()} Server",
                                border_style="green",
                            )
                        )
                    if duration is not None:
                        await asyncio.sleep(max(0.0, duration))
                    else:
                        stop_event = asyncio.Event()
                        await stop_event.wait()
            except KeyboardInterrupt:
                return
            except Exception as exc:
                renderer.print_error_and_exit(exc, title="Mock Server Error")

        with contextlib.suppress(KeyboardInterrupt):
            asyncio.run(_serve())
