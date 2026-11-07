# src/uniconn/cli/cmd_flow.py
"""CLI-команды оркестрации DAG-сценариев: flow run, flow inspect, flow list."""

from __future__ import annotations

import asyncio
import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Annotated, Any

from .. import cli as cli_pkg
from .._logging import get_logger
from ..exceptions import ConfigurationError
from ..orchestration.flow import Flow, SyncFlow
from ..orchestration.task import Task
from .renderers import (
    CLIOutputRenderer,
    Panel,
    Parameter,
    Table,
    box,
    build_cli_pool,
    cyclopts,
    print_json,
)


def _load_python_module(target_path_or_mod: str) -> Any:
    """Загрузить Python-модуль по пути к файлу ``.py`` или точечному имени модуля."""
    file_candidate = Path(target_path_or_mod)
    if file_candidate.is_file() or target_path_or_mod.endswith(".py"):
        if not file_candidate.is_file():
            raise ConfigurationError(f"Flow file not found: {target_path_or_mod}")
        mod_name = f"_uniconn_flow_{file_candidate.stem}"
        spec = importlib.util.spec_from_file_location(mod_name, file_candidate)
        if spec is None or spec.loader is None:
            raise ConfigurationError(f"Cannot load Python module from {file_candidate}")
        module = importlib.util.module_from_spec(spec)
        parent_dir = str(file_candidate.resolve().parent)
        added_to_path = parent_dir not in sys.path
        if added_to_path:
            sys.path.insert(0, parent_dir)
        sys.modules[mod_name] = module
        try:
            spec.loader.exec_module(module)
        finally:
            if added_to_path and parent_dir in sys.path:
                sys.path.remove(parent_dir)
        return module

    try:
        return importlib.import_module(target_path_or_mod)
    except Exception as exc:
        raise ConfigurationError(
            f"Cannot import module or file {target_path_or_mod!r}: {exc}"
        ) from exc


def resolve_flow_spec(spec_str: str) -> Flow:
    """Разрешить спецификацию ``path_or_module[:flow_or_task_name]`` в объект ``Flow``."""
    if ":" in spec_str and not (len(spec_str) >= 2 and spec_str[1] == ":" and ":" not in spec_str[2:]):
        mod_part, attr_name = spec_str.rsplit(":", 1)
    else:
        mod_part, attr_name = spec_str, ""

    module = _load_python_module(mod_part)

    if attr_name:
        if not hasattr(module, attr_name):
            # Также проверим поиск Task по полю .name
            for val in vars(module).values():
                if isinstance(val, Task) and val.name == attr_name:
                    return Flow(name=val.name, tasks=[val])
                if isinstance(val, Flow) and val.name == attr_name:
                    return val
            raise ConfigurationError(
                f"Object {attr_name!r} not found in {mod_part!r}"
            )
        obj = getattr(module, attr_name)
        if isinstance(obj, SyncFlow):
            return obj._async_flow
        if isinstance(obj, Flow):
            return obj
        if isinstance(obj, Task):
            return Flow(name=obj.name, tasks=[obj])
        if callable(obj):
            return Flow(name=attr_name, tasks=[obj])
        raise ConfigurationError(
            f"Attribute {attr_name!r} in {mod_part!r} is not a Flow or @task (got {type(obj).__name__})"
        )

    flows: list[Flow] = []
    tasks: list[Task[Any, Any]] = []
    for val in vars(module).values():
        if isinstance(val, SyncFlow):
            flows.append(val._async_flow)
        elif isinstance(val, Flow):
            flows.append(val)
        elif isinstance(val, Task):
            tasks.append(val)

    if len(flows) == 1:
        return flows[0]
    if len(flows) > 1:
        return flows[0]
    if tasks:
        mod_label = Path(mod_part).stem if mod_part.endswith(".py") else mod_part
        return Flow(name=mod_label, tasks=tasks)

    raise ConfigurationError(
        f"No Flow or @task definitions found in {mod_part!r}"
    )


def _parse_cli_vars(var_items: list[str] | None) -> dict[str, Any]:
    """Распарсить список ``KEY=VALUE`` аргументов в словарь переменных контекста."""
    parsed: dict[str, Any] = {}
    if not var_items:
        return parsed
    for item in var_items:
        if "=" not in item:
            parsed[item.strip()] = True
            continue
        k, v = item.split("=", 1)
        parsed[k.strip()] = v
    return parsed


def register_flow_commands(
    app: Any, console: Any, renderer: CLIOutputRenderer
) -> None:
    """Зарегистрировать подприложение ``uniconn flow`` и алиасы ``run-flow`` / ``flow-info``."""
    flow_app = cyclopts.App(
        name="flow",
        help="Execute, inspect, and list declarative Task DAG flows",
    )

    @flow_app.command(name="run")
    def flow_run(
        spec: Annotated[
            str,
            Parameter(help="Flow specification: path/to/file.py[:flow_or_task]"),
        ],
        *uris: Annotated[
            str,
            Parameter(help="Target host URIs (defaults to local:// if omitted and no --inventory)"),
        ],
        inventory: Annotated[
            str | None,
            Parameter(name=["--inventory", "-i"], help="Path to YAML/TOML/JSON inventory file"),
        ] = None,
        group: Annotated[
            str | None,
            Parameter(name=["--group", "-g"], help="Inventory host group name"),
        ] = None,
        mode: Annotated[
            str | None,
            Parameter(name=["--mode", "-m"], help="Fleet execution mode: barrier or independent"),
        ] = None,
        batch_size: Annotated[
            int | None,
            Parameter(name=["--batch-size"], help="Rollout wave/batch size"),
        ] = None,
        max_fail_ratio: Annotated[
            float | None,
            Parameter(name=["--max-fail-ratio"], help="Maximum allowed failure ratio (0.0..1.0)"),
        ] = None,
        max_concurrent: Annotated[
            int,
            Parameter(name=["--concurrency", "-c"], help="Max concurrent hosts"),
        ] = 10,
        tags: Annotated[
            str | None,
            Parameter(name=["--tags"], help="Comma-separated list of task tags to run"),
        ] = None,
        var: Annotated[
            list[str] | None,
            Parameter(name=["--var"], help="FlowContext variable in KEY=VALUE format"),
        ] = None,
        dry_run: Annotated[
            bool,
            Parameter(name=["--dry-run"], negative="", help="Execute flow in dry-run mode"),
        ] = False,
        output_format: Annotated[
            str,
            Parameter(name=["--format", "-f"], help="Output format: table, json"),
        ] = "table",
        verbose: Annotated[
            bool,
            Parameter(name=["--verbose", "-v"], negative="", help="Verbose logging"),
        ] = False,
    ) -> None:
        """Execute a declarative Task DAG flow across target hosts."""
        try:
            flow_obj = resolve_flow_spec(spec)
            if mode in ("barrier", "independent") and flow_obj.mode != mode:
                flow_obj = Flow(
                    name=flow_obj.name,
                    tasks=list(flow_obj.tasks.values()),
                    mode=mode,  # type: ignore[arg-type]
                    fail_fast=flow_obj.fail_fast,
                    max_fail_ratio=flow_obj.max_fail_ratio,
                    batch_size=flow_obj.batch_size,
                    batch_notifications=flow_obj.batch_notifications,
                )
        except Exception as exc:
            renderer.print_error_and_exit(exc, title="Flow Load Error")
            return

        tag_list = (
            [t.strip() for t in tags.split(",") if t.strip()]
            if tags
            else None
        )
        initial_vars = _parse_cli_vars(var)
        host_uris = list(uris) if uris else ([] if inventory else ["local://"])

        async def _execute() -> None:
            logger = get_logger("uniconn.cli", level="DEBUG" if verbose else "INFO")
            try:
                if len(host_uris) == 1 and not inventory:
                    async with cli_pkg.Connection.from_uri(
                        host_uris[0], logger=logger, dry_run=dry_run
                    ) as conn:
                        report = await flow_obj.run(
                            conn,
                            vars=initial_vars,
                            tags=tag_list,
                            dry_run=dry_run if dry_run else None,
                        )
                else:
                    pool = build_cli_pool(
                        cli_pkg,
                        host_uris,
                        inventory,
                        group,
                        max_concurrent,
                        logger,
                        batch_size=batch_size,
                        max_fail_ratio=max_fail_ratio or 0.0,
                    )
                    async with pool:
                        report = await flow_obj.run(
                            pool,
                            vars=initial_vars,
                            tags=tag_list,
                            dry_run=dry_run if dry_run else None,
                            batch_size=batch_size,
                            max_fail_ratio=max_fail_ratio,
                        )

                if output_format == "json":
                    print_json(console, report.to_dict())
                else:
                    console.print(report.to_rich_table())
                    status_color = "green" if report.ok else "red"
                    status_word = "SUCCESS" if report.ok else "FAILED"
                    console.print(
                        Panel(
                            f"[bold {status_color}]{status_word}[/bold {status_color}] "
                            f"{report.get_summary()}",
                            title=f"Flow Summary: {report.flow_name}",
                            border_style=status_color,
                        )
                    )

                if not report.ok:
                    sys.exit(1)
            except Exception as exc:
                renderer.print_error_and_exit(exc, title="Flow Execution Error")

        asyncio.run(_execute())

    @flow_app.command(name="inspect")
    def flow_inspect(
        spec: Annotated[
            str,
            Parameter(help="Flow specification: path/to/file.py[:flow_or_task]"),
        ],
        output_format: Annotated[
            str,
            Parameter(name=["--format", "-f"], help="Output format: tree, json"),
        ] = "tree",
    ) -> None:
        """Validate and inspect the topological layers and dependencies of a Flow."""
        try:
            flow_obj = resolve_flow_spec(spec)
            flow_obj.validate()
        except Exception as exc:
            renderer.print_error_and_exit(exc, title="Flow Inspect Error")
            return

        if output_format == "json":
            layers = [
                [t.name for t in layer] for layer in flow_obj.get_layers()
            ]
            data = {
                "flow_name": flow_obj.name,
                "mode": flow_obj.mode,
                "fail_fast": flow_obj.fail_fast,
                "batch_size": flow_obj.batch_size,
                "max_fail_ratio": flow_obj.max_fail_ratio,
                "batch_notifications": flow_obj.batch_notifications,
                "layers": layers,
                "tasks": {
                    name: {
                        "depends_on": sorted(flow_obj.dag.get(name, ())),
                        "post": [p.name for p in t.post],
                        "always_run": t.always_run,
                        "ignore_errors": t.options.ignore_errors,
                        "retries": t.options.retries,
                        "tags": list(t.tags),
                    }
                    for name, t in flow_obj.tasks.items()
                },
            }
            print_json(console, data)
        else:
            console.print(flow_obj.to_rich_tree())

    @flow_app.command(name="list")
    def flow_list(
        target: Annotated[
            str,
            Parameter(help="Python file path or module name containing @task and Flow definitions"),
        ],
        output_format: Annotated[
            str,
            Parameter(name=["--format", "-f"], help="Output format: table, json"),
        ] = "table",
    ) -> None:
        """List all @task and Flow objects defined in a Python file or module."""
        try:
            module = _load_python_module(target)
        except Exception as exc:
            renderer.print_error_and_exit(exc, title="Flow List Error")
            return

        flows: list[tuple[str, Flow]] = []
        tasks: list[tuple[str, Task[Any, Any]]] = []
        for attr_name, val in vars(module).items():
            if attr_name.startswith("_"):
                continue
            if isinstance(val, SyncFlow):
                flows.append((attr_name, val._async_flow))
            elif isinstance(val, Flow):
                flows.append((attr_name, val))
            elif isinstance(val, Task):
                tasks.append((attr_name, val))

        if output_format == "json":
            print_json(
                console,
                {
                    "flows": [
                        {
                            "attribute": attr,
                            "name": f.name,
                            "mode": f.mode,
                            "tasks": list(f.tasks.keys()),
                        }
                        for attr, f in flows
                    ],
                    "tasks": [
                        {
                            "attribute": attr,
                            "name": t.name,
                            "depends_on": [d.name for d in t.depends_on],
                            "post": [p.name for p in t.post],
                            "tags": list(t.tags),
                            "always_run": t.always_run,
                        }
                        for attr, t in tasks
                    ],
                },
            )
            return

        table = Table(
            title=f"Flows & Tasks in {target}",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Kind", style="magenta", no_wrap=True)
        table.add_column("Symbol", style="cyan", no_wrap=True)
        table.add_column("Name", style="green", no_wrap=True)
        table.add_column("Dependencies / Tasks", style="white")
        table.add_column("Tags / Mode", style="yellow")

        for attr, f in flows:
            table.add_row(
                "Flow",
                attr,
                f.name,
                ", ".join(f.tasks.keys()) or "-",
                f"mode={f.mode}",
            )
        for attr, t in tasks:
            deps = [d.name for d in t.depends_on]
            table.add_row(
                "@task",
                attr,
                t.name,
                ", ".join(deps) if deps else "-",
                ", ".join(t.tags) if t.tags else "-",
            )
        console.print(table)

    app.command(flow_app)
    app.command(flow_run, name="run-flow")
    app.command(flow_inspect, name="flow-info")


__all__ = [
    "register_flow_commands",
    "resolve_flow_spec",
]
