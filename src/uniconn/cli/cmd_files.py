# src/uniconn/cli/cmd_files.py
"""Файловые CLI-команды: upload, download, sync, template."""

from __future__ import annotations

import asyncio
import sys
from typing import Annotated, Any

from .._logging import get_logger
from .renderers import (
    CLIOutputRenderer,
    Parameter,
    Table,
    box,
    build_cli_pool,
    print_json,
)


def _build_transfer_kwargs(
    *,
    verify: bool,
    protocol: str,
    trigger: str | None,
    xmodem_mode: str,
    default_xmodem_mode: str,
) -> dict[str, Any]:
    extra_kw: dict[str, Any] = {"verify": True} if verify else {}
    if protocol != "auto":
        extra_kw["protocol"] = protocol
    if trigger is not None:
        extra_kw["trigger_command"] = trigger
    if xmodem_mode != default_xmodem_mode:
        extra_kw["xmodem_mode"] = xmodem_mode
    return extra_kw


async def _run_with_progress(
    console: Any,
    description: str,
    coro_factory: Any,
) -> Any:
    from rich.progress import (
        BarColumn,
        DownloadColumn,
        Progress,
        TextColumn,
        TimeRemainingColumn,
        TransferSpeedColumn,
    )

    with Progress(
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        DownloadColumn(),
        TransferSpeedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=True,
    ) as progress:
        task_id = progress.add_task(description, total=None)

        def _on_progress(copied: int, total: int) -> None:
            progress.update(task_id, completed=copied, total=total if total > 0 else None)

        return await coro_factory(_on_progress)


async def _exec_upload(
    cli_pkg: Any,
    console: Any,
    renderer: CLIOutputRenderer,
    *,
    local_path: str,
    effective_remote: str,
    host_uris: list[str],
    protocol: str,
    trigger: str | None,
    xmodem_mode: str,
    inventory: str | None,
    group: str | None,
    recurse: bool,
    verify: bool,
    max_concurrent: int,
    batch_size: int | None,
    max_fail_ratio: float,
    output_format: str,
    no_progress: bool,
    verbose: bool,
) -> None:
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
        extra_kw = _build_transfer_kwargs(
            verify=verify,
            protocol=protocol,
            trigger=trigger,
            xmodem_mode=xmodem_mode,
            default_xmodem_mode="1k",
        )
        if output_format == "table" and not no_progress:
            await _run_with_progress(
                console,
                f"Uploading {local_path}",
                lambda cb: pool.files.upload(
                    local_path, effective_remote, recurse=recurse, progress_callback=cb, **extra_kw
                ),
            )
        else:
            await pool.files.upload(local_path, effective_remote, recurse=recurse, **extra_kw)

        if output_format == "json":
            print_json(
                console,
                {
                    "action": "upload",
                    "local_path": local_path,
                    "remote_path": effective_remote,
                    "protocol": protocol,
                    "hosts": target_labels,
                    "ok": True,
                },
            )
        else:
            dest_label = effective_remote or ", ".join(target_labels)
            console.print(
                f"[green]OK[/green] Uploaded [cyan]{local_path}[/cyan] -> "
                f"[cyan]{dest_label}[/cyan] on {len(target_labels)} host(s)"
            )
    except Exception as e:
        renderer.print_error_and_exit(e, title="Upload Error")


async def _exec_download(
    cli_pkg: Any,
    console: Any,
    renderer: CLIOutputRenderer,
    *,
    remote_path: str,
    local_path: str,
    host_uris: list[str],
    protocol: str,
    trigger: str | None,
    xmodem_mode: str,
    inventory: str | None,
    group: str | None,
    recurse: bool,
    verify: bool,
    max_concurrent: int,
    batch_size: int | None,
    max_fail_ratio: float,
    output_format: str,
    no_progress: bool,
    verbose: bool,
) -> None:
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
        extra_kw = _build_transfer_kwargs(
            verify=verify,
            protocol=protocol,
            trigger=trigger,
            xmodem_mode=xmodem_mode,
            default_xmodem_mode="crc",
        )
        if output_format == "table" and not no_progress:
            saved = await _run_with_progress(
                console,
                f"Downloading {remote_path}",
                lambda cb: pool.files.download(
                    remote_path, local_path, recurse=recurse, progress_callback=cb, **extra_kw
                ),
            )
        else:
            saved = await pool.files.download(remote_path, local_path, recurse=recurse, **extra_kw)

        if output_format == "json":
            print_json(
                console,
                {
                    "action": "download",
                    "remote_path": remote_path,
                    "protocol": protocol,
                    "saved": saved,
                    "ok": True,
                },
            )
        else:
            for host_key, dest in saved.items():
                console.print(f"[green]OK[/green] {host_key}: [cyan]{remote_path}[/cyan] -> [cyan]{dest}[/cyan]")
    except Exception as e:
        renderer.print_error_and_exit(e, title="Download Error")


async def _exec_sync(
    cli_pkg: Any,
    console: Any,
    renderer: CLIOutputRenderer,
    *,
    local_dir: str,
    remote_dir: str,
    host_uris: list[str],
    inventory: str | None,
    group: str | None,
    delete: bool,
    exclude: list[str] | None,
    checksum_check: bool,
    preserve_permissions: bool,
    dry_run: bool,
    max_concurrent: int,
    batch_size: int | None,
    max_fail_ratio: float,
    output_format: str,
    verbose: bool,
) -> None:
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
        extra_sync_kw: dict[str, Any] = {}
        if checksum_check:
            extra_sync_kw["checksum_check"] = True
        if preserve_permissions:
            extra_sync_kw["preserve_permissions"] = True
        results = await pool.files.sync_dir(
            local_dir=local_dir,
            remote_dir=remote_dir,
            delete=delete,
            exclude=list(exclude or []),
            dry_run=dry_run,
            **extra_sync_kw,
        )
        if output_format == "json":
            print_json(console, {k: v.to_dict() for k, v in results.items()})
            return

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


async def _exec_template(
    cli_pkg: Any,
    console: Any,
    renderer: CLIOutputRenderer,
    *,
    template_path: str,
    remote_path: str,
    host_uris: list[str],
    ctx: dict[str, Any],
    eng_val: Any,
    mode_int: int,
    atomic: bool,
    inventory: str | None,
    group: str | None,
    max_concurrent: int,
    batch_size: int | None,
    max_fail_ratio: float,
    output_format: str,
    verbose: bool,
) -> None:
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
        rendered_map = await pool.files.write_template(
            remote_path=remote_path,
            template_str_or_path=template_path,
            context=ctx,
            mode=mode_int,
            engine=eng_val,
            **({"atomic": True} if atomic else {}),
        )
        if output_format == "json":
            print_json(
                console,
                {
                    "action": "template",
                    "remote_path": remote_path,
                    "hosts": list(rendered_map.keys()),
                    "rendered": next(iter(rendered_map.values()), ""),
                    "ok": True,
                },
            )
        else:
            console.print(
                f"[green]OK[/green] Rendered template to [cyan]{remote_path}[/cyan] "
                f"on {len(rendered_map)} host(s)"
            )
    except Exception as e:
        renderer.print_error_and_exit(e, title="Template Error")


async def _exec_checksum(
    cli_pkg: Any,
    console: Any,
    renderer: CLIOutputRenderer,
    *,
    remote_path: str,
    host_uris: list[str],
    alg_val: Any,
    sudo: bool,
    inventory: str | None,
    group: str | None,
    max_concurrent: int,
    output_format: str,
    verbose: bool,
) -> None:
    logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
    try:
        pool = build_cli_pool(cli_pkg, host_uris, inventory, group, max_concurrent, logger)
        digests = await pool.files.checksum(remote_path, algorithm=alg_val, sudo=sudo)
        if output_format == "json":
            print_json(
                console,
                {
                    "action": "checksum",
                    "remote_path": remote_path,
                    "algorithm": alg_val,
                    "checksums": digests,
                },
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


def register_file_commands(app: Any, console: Any, renderer: CLIOutputRenderer) -> None:
    """Зарегистрировать файловые команды (upload, download, sync, template, checksum)."""
    import uniconn.cli as cli_pkg

    @app.command
    def upload(
        local_path: Annotated[str, Parameter(help="Local file or directory path")],
        remote_path: Annotated[str, Parameter(help="Remote destination path")] = "",
        *uris: Annotated[str, Parameter(help="Target connection URIs")],
        protocol: Annotated[
            str,
            Parameter(
                name=["--protocol", "-p"],
                help="Transfer protocol (auto, sftp, ymodem, xmodem, zmodem)",
            ),
        ] = "auto",
        trigger: Annotated[
            str | None,
            Parameter(
                name=["--trigger", "-t"],
                help="Command to trigger receive mode in bootloader (e.g. 'loady 0x82000000')",
            ),
        ] = None,
        xmodem_mode: Annotated[
            str,
            Parameter(
                name="--xmodem-mode",
                help="XMODEM packet mode: 1k (default), crc, checksum",
            ),
        ] = "1k",
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
        no_progress: Annotated[
            bool,
            Parameter(name="--no-progress", negative="", help="Disable progress bar"),
        ] = False,
        verbose: Annotated[
            bool, Parameter(name=["--verbose", "-v"], negative="", help="Verbose output")
        ] = False,
    ) -> None:
        """Upload file or directory to one or more remote hosts via SFTP or Serial (XMODEM/YMODEM/ZMODEM)."""
        host_uris = list(uris)
        effective_remote = remote_path
        if not host_uris and "://" in remote_path:
            host_uris = [remote_path]
            effective_remote = ""
        if not host_uris and not inventory:
            console.print("[red]ERROR:[/red] specify at least one URI or --inventory/-i")
            sys.exit(1)

        asyncio.run(
            _exec_upload(
                cli_pkg,
                console,
                renderer,
                local_path=local_path,
                effective_remote=effective_remote,
                host_uris=host_uris,
                protocol=protocol,
                trigger=trigger,
                xmodem_mode=xmodem_mode,
                inventory=inventory,
                group=group,
                recurse=recurse,
                verify=verify,
                max_concurrent=max_concurrent,
                batch_size=batch_size,
                max_fail_ratio=max_fail_ratio,
                output_format=output_format,
                no_progress=no_progress,
                verbose=verbose,
            )
        )

    @app.command
    def download(
        remote_path: Annotated[str, Parameter(help="Remote file or directory path")],
        local_path: Annotated[str, Parameter(help="Local destination path or pattern")] = "",
        *uris: Annotated[str, Parameter(help="Target connection URIs")],
        protocol: Annotated[
            str,
            Parameter(
                name=["--protocol", "-p"],
                help="Transfer protocol (auto, sftp, ymodem, xmodem, zmodem)",
            ),
        ] = "auto",
        trigger: Annotated[
            str | None,
            Parameter(
                name=["--trigger", "-t"],
                help="Command to trigger send mode on target",
            ),
        ] = None,
        xmodem_mode: Annotated[
            str,
            Parameter(
                name="--xmodem-mode",
                help="XMODEM packet mode: crc (default), 1k, checksum",
            ),
        ] = "crc",
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
        no_progress: Annotated[
            bool,
            Parameter(name="--no-progress", negative="", help="Disable progress bar"),
        ] = False,
        verbose: Annotated[
            bool, Parameter(name=["--verbose", "-v"], negative="", help="Verbose output")
        ] = False,
    ) -> None:
        """Download file or directory from one or more remote hosts via SFTP or Serial."""
        host_uris = list(uris)
        if not host_uris and "://" in local_path:
            host_uris = [local_path]
            local_path = remote_path
            remote_path = ""
        if not host_uris and not inventory:
            console.print("[red]ERROR:[/red] specify at least one URI or --inventory/-i")
            sys.exit(1)

        asyncio.run(
            _exec_download(
                cli_pkg,
                console,
                renderer,
                remote_path=remote_path,
                local_path=local_path,
                host_uris=host_uris,
                protocol=protocol,
                trigger=trigger,
                xmodem_mode=xmodem_mode,
                inventory=inventory,
                group=group,
                recurse=recurse,
                verify=verify,
                max_concurrent=max_concurrent,
                batch_size=batch_size,
                max_fail_ratio=max_fail_ratio,
                output_format=output_format,
                no_progress=no_progress,
                verbose=verbose,
            )
        )

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
        checksum_check: Annotated[
            bool,
            Parameter(
                name=["--checksum", "-c"],
                negative="",
                help="Compare SHA-256 checksums when file sizes match",
            ),
        ] = False,
        preserve_permissions: Annotated[
            bool,
            Parameter(
                name=["--preserve-permissions", "-p"],
                negative="",
                help="Preserve local file permissions on remote host",
            ),
        ] = False,
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

        asyncio.run(
            _exec_sync(
                cli_pkg,
                console,
                renderer,
                local_dir=local_dir,
                remote_dir=remote_dir,
                host_uris=host_uris,
                inventory=inventory,
                group=group,
                delete=delete,
                exclude=exclude,
                checksum_check=checksum_check,
                preserve_permissions=preserve_permissions,
                dry_run=dry_run,
                max_concurrent=max_concurrent,
                batch_size=batch_size,
                max_fail_ratio=max_fail_ratio,
                output_format=output_format,
                verbose=verbose,
            )
        )

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
                console.print(f"[red]ERROR:[/red] invalid --var {item!r}, expected KEY=VALUE")
                sys.exit(1)
            k, v = item.split("=", 1)
            ctx[k.strip()] = v

        asyncio.run(
            _exec_template(
                cli_pkg,
                console,
                renderer,
                template_path=template_path,
                remote_path=remote_path,
                host_uris=host_uris,
                ctx=ctx,
                eng_val=engine if engine in ("auto", "string", "jinja2") else "auto",
                mode_int=int(mode, 8),
                atomic=atomic,
                inventory=inventory,
                group=group,
                max_concurrent=max_concurrent,
                batch_size=batch_size,
                max_fail_ratio=max_fail_ratio,
                output_format=output_format,
                verbose=verbose,
            )
        )

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

        asyncio.run(
            _exec_checksum(
                cli_pkg,
                console,
                renderer,
                remote_path=remote_path,
                host_uris=host_uris,
                alg_val=algorithm if algorithm in ("sha256", "sha1", "md5") else "sha256",
                sudo=sudo,
                inventory=inventory,
                group=group,
                max_concurrent=max_concurrent,
                output_format=output_format,
                verbose=verbose,
            )
        )
