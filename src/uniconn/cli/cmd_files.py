# src/uniconn/cli/cmd_files.py
"""Файловые CLI-команды: upload, download, sync, template."""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Annotated, Any

from .._logging import get_logger
from .renderers import CLIOutputRenderer, Parameter, Table, box, build_cli_pool


def register_file_commands(app: Any, console: Any, renderer: CLIOutputRenderer) -> None:
    """Зарегистрировать файловые команды (upload, download, sync, template)."""
    import uniconn.cli as cli_pkg

    @app.command
    def upload(
        local_path: Annotated[str, Parameter(help="Local file or directory path")],
        remote_path: Annotated[str, Parameter(help="Remote destination path")],
        *uris: Annotated[str, Parameter(help="Target connection URIs")],
        inventory: Annotated[
            str | None,
            Parameter(name=["--inventory", "-i"], help="Inventory file (.yaml/.json)"),
        ] = None,
        group: Annotated[
            str | None,
            Parameter(name=["--group", "-g"], help="Host group name in inventory"),
        ] = None,
        recurse: Annotated[
            bool,
            Parameter(
                name=["--recurse", "-r"],
                negative="",
                help="Upload directory recursively",
            ),
        ] = False,
        verify: Annotated[
            bool,
            Parameter(
                name="--verify",
                negative="",
                help="Verify SHA-256 checksum after upload",
            ),
        ] = False,
        max_concurrent: Annotated[
            int,
            Parameter(name=["--max-concurrent", "-j"], help="Max concurrent connections"),
        ] = 10,
        batch_size: Annotated[
            int | None,
            Parameter(name="--batch-size", help="Rollout wave/batch size"),
        ] = None,
        max_fail_ratio: Annotated[
            float,
            Parameter(
                name="--max-fail-ratio",
                help="Maximum allowed failure ratio per batch (0.0..1.0)",
            ),
        ] = 0.0,
        output_format: Annotated[
            str,
            Parameter(name=["--format", "-f"], help="Output format: table, json"),
        ] = "table",
        verbose: Annotated[
            bool, Parameter(name=["--verbose", "-v"], negative="", help="Verbose output")
        ] = False,
    ) -> None:
        """Upload file or directory to one or more remote hosts via SFTP."""
        host_uris = list(uris)
        if not host_uris and not inventory:
            console.print("[red]ERROR:[/red] specify at least one URI or --inventory/-i")
            sys.exit(1)

        async def _execute() -> None:
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
                target_labels = [pool._target_key(t) for t in pool._uris]
                await pool.upload(
                    local_path, remote_path, recurse=recurse, **({"verify": True} if verify else {})
                )

                if output_format == "json":
                    console.print(
                        json.dumps(
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
                renderer.print_error_and_exit(e, title="Upload Error")

        asyncio.run(_execute())

    @app.command
    def download(
        remote_path: Annotated[str, Parameter(help="Remote file or directory path")],
        local_path: Annotated[str, Parameter(help="Local destination path or pattern")],
        *uris: Annotated[str, Parameter(help="Target connection URIs")],
        inventory: Annotated[
            str | None,
            Parameter(name=["--inventory", "-i"], help="Inventory file (.yaml/.json)"),
        ] = None,
        group: Annotated[
            str | None,
            Parameter(name=["--group", "-g"], help="Host group name in inventory"),
        ] = None,
        recurse: Annotated[
            bool,
            Parameter(
                name=["--recurse", "-r"],
                negative="",
                help="Download directory recursively",
            ),
        ] = False,
        verify: Annotated[
            bool,
            Parameter(
                name="--verify",
                negative="",
                help="Verify SHA-256 checksum after download",
            ),
        ] = False,
        max_concurrent: Annotated[
            int,
            Parameter(name=["--max-concurrent", "-j"], help="Max concurrent connections"),
        ] = 10,
        batch_size: Annotated[
            int | None,
            Parameter(name="--batch-size", help="Rollout wave/batch size"),
        ] = None,
        max_fail_ratio: Annotated[
            float,
            Parameter(
                name="--max-fail-ratio",
                help="Maximum allowed failure ratio per batch (0.0..1.0)",
            ),
        ] = 0.0,
        output_format: Annotated[
            str,
            Parameter(name=["--format", "-f"], help="Output format: table, json"),
        ] = "table",
        verbose: Annotated[
            bool, Parameter(name=["--verbose", "-v"], negative="", help="Verbose output")
        ] = False,
    ) -> None:
        """Download file or directory from one or more remote hosts via SFTP."""
        host_uris = list(uris)
        if not host_uris and not inventory:
            console.print("[red]ERROR:[/red] specify at least one URI or --inventory/-i")
            sys.exit(1)

        async def _execute() -> None:
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
                saved = await pool.download(
                    remote_path, local_path, recurse=recurse, **({"verify": True} if verify else {})
                )

                if output_format == "json":
                    console.print(
                        json.dumps(
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
                renderer.print_error_and_exit(e, title="Download Error")

        asyncio.run(_execute())

    @app.command(name="sync")
    def sync(
        local_dir: Annotated[str, Parameter(help="Local source directory")],
        remote_dir: Annotated[str, Parameter(help="Remote destination directory")],
        *uris: Annotated[str, Parameter(help="Target connection URIs")],
        inventory: Annotated[
            str | None,
            Parameter(name=["--inventory", "-i"], help="Inventory file (.yaml/.json)"),
        ] = None,
        group: Annotated[
            str | None,
            Parameter(name=["--group", "-g"], help="Host group name in inventory"),
        ] = None,
        delete: Annotated[
            bool,
            Parameter(
                name="--delete",
                negative="",
                help="Delete remote files missing locally",
            ),
        ] = False,
        exclude: Annotated[
            list[str] | None,
            Parameter(
                name=["--exclude", "-x"], help="Exclude glob pattern (repeatable)"
            ),
        ] = None,
        dry_run: Annotated[
            bool,
            Parameter(
                name=["--dry-run", "-n"],
                negative="",
                help="Preview changes without modifying remote",
            ),
        ] = False,
        max_concurrent: Annotated[
            int,
            Parameter(name=["--max-concurrent", "-j"], help="Max concurrent connections"),
        ] = 10,
        batch_size: Annotated[
            int | None,
            Parameter(name="--batch-size", help="Rollout wave/batch size"),
        ] = None,
        max_fail_ratio: Annotated[
            float,
            Parameter(
                name="--max-fail-ratio",
                help="Maximum allowed failure ratio per batch (0.0..1.0)",
            ),
        ] = 0.0,
        output_format: Annotated[
            str,
            Parameter(name=["--format", "-f"], help="Output format: table, json"),
        ] = "table",
        verbose: Annotated[
            bool, Parameter(name=["--verbose", "-v"], negative="", help="Verbose output")
        ] = False,
    ) -> None:
        """Incrementally synchronize local directory to one or more hosts."""
        host_uris = list(uris)
        if not host_uris and not inventory:
            console.print("[red]ERROR:[/red] specify at least one URI or --inventory/-i")
            sys.exit(1)

        async def _execute() -> None:
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
                results = await pool.sync_dir(
                    local_dir=local_dir,
                    remote_dir=remote_dir,
                    delete=delete,
                    exclude=list(exclude or []),
                    dry_run=dry_run,
                )

                if output_format == "json":
                    console.print(
                        json.dumps(
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
                renderer.print_error_and_exit(e, title="Sync Error")

        asyncio.run(_execute())

    @app.command(name="template")
    def template(
        template_path: Annotated[
            str, Parameter(help="Template file path or inline string")
        ],
        remote_path: Annotated[str, Parameter(help="Remote destination file path")],
        *uris: Annotated[str, Parameter(help="Target connection URIs")],
        var: Annotated[
            list[str] | None,
            Parameter(
                name=["--var", "-D"],
                help="Template variable KEY=VALUE (repeatable)",
            ),
        ] = None,
        engine: Annotated[
            str,
            Parameter(
                name=["--engine", "-e"],
                help="Template engine: auto, string, jinja2",
            ),
        ] = "auto",
        mode: Annotated[
            str,
            Parameter(
                name=["--mode", "-m"],
                help="File permissions in octal (e.g., 0644)",
            ),
        ] = "0644",
        atomic: Annotated[
            bool,
            Parameter(
                name="--atomic",
                negative="",
                help="Stage template to temporary file and rename atomically",
            ),
        ] = False,
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
        batch_size: Annotated[
            int | None,
            Parameter(name="--batch-size", help="Rollout wave/batch size"),
        ] = None,
        max_fail_ratio: Annotated[
            float,
            Parameter(
                name="--max-fail-ratio",
                help="Maximum allowed failure ratio per batch (0.0..1.0)",
            ),
        ] = 0.0,
        output_format: Annotated[
            str,
            Parameter(name=["--format", "-f"], help="Output format: panel, json"),
        ] = "panel",
        verbose: Annotated[
            bool, Parameter(name=["--verbose", "-v"], negative="", help="Verbose output")
        ] = False,
    ) -> None:
        """Render configuration template and write to one or more remote hosts."""
        host_uris = list(uris)
        if not host_uris and not inventory:
            console.print("[red]ERROR:[/red] specify at least one URI or --inventory/-i")
            sys.exit(1)

        ctx: dict[str, Any] = {}
        for item in var or []:
            if "=" not in item:
                console.print(
                    f"[red]ERROR:[/red] invalid --var {item!r}, expected KEY=VALUE"
                )
                sys.exit(1)
            k, v = item.split("=", 1)
            ctx[k.strip()] = v

        mode_int = int(mode, 8)
        eng_val: Any = engine if engine in ("auto", "string", "jinja2") else "auto"

        async def _execute() -> None:
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
                rendered_map = await pool.write_template(
                    remote_path=remote_path,
                    template_str_or_path=template_path,
                    context=ctx,
                    mode=mode_int,
                    engine=eng_val,
                    **({"atomic": True} if atomic else {}),
                )

                if output_format == "json":
                    console.print(
                        json.dumps(
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
                renderer.print_error_and_exit(e, title="Template Error")

        asyncio.run(_execute())

    @app.command(name="checksum")
    def checksum_cmd(
        remote_path: Annotated[str, Parameter(help="Remote file path to hash")],
        *uris: Annotated[str, Parameter(help="Target connection URIs")],
        algorithm: Annotated[
            str,
            Parameter(
                name=["--algorithm", "-a"],
                help="Hash algorithm: sha256, sha1, md5",
            ),
        ] = "sha256",
        sudo: Annotated[
            bool,
            Parameter(name="--sudo", negative="", help="Run checksum with sudo"),
        ] = False,
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
        """Compute cryptographic checksum (sha256, sha1, md5) of a remote file across hosts."""
        host_uris = list(uris)
        if not host_uris and not inventory:
            host_uris = ["local://"]

        alg_val: Any = algorithm if algorithm in ("sha256", "sha1", "md5") else "sha256"

        async def _execute() -> None:
            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            try:
                pool = build_cli_pool(
                    cli_pkg, host_uris, inventory, group, max_concurrent, logger
                )
                digests = await pool.checksum(
                    remote_path, algorithm=alg_val, sudo=sudo
                )
                if output_format == "json":
                    console.print(
                        json.dumps(
                            {
                                "action": "checksum",
                                "remote_path": remote_path,
                                "algorithm": alg_val,
                                "checksums": digests,
                            },
                            indent=2,
                        )
                    )
                    return

                table = Table(
                    title=f"File Checksum ({alg_val}): {remote_path}",
                    box=box.ROUNDED,
                    show_header=True,
                    header_style="bold cyan",
                )
                table.add_column("Host", style="cyan")
                table.add_column("Algorithm", style="magenta")
                table.add_column("Digest", style="green")
                for host_key, digest in digests.items():
                    table.add_row(host_key, alg_val, digest)
                console.print(table)
            except Exception as e:
                renderer.print_error_and_exit(e, title="Checksum Error")

        asyncio.run(_execute())
