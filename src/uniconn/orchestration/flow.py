# src/uniconn/orchestration/flow.py
"""Декларативный оркестратор DAG-сценария Flow и синхронная обёртка SyncFlow."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from collections.abc import Set as AbstractSet
from graphlib import CycleError, TopologicalSorter
from typing import TYPE_CHECKING, Any, Literal, Self

from ..core.bridge import EventLoopPortal, SyncProxyMixin
from ..exceptions import ConfigurationError, CyclicDependencyError
from .context import FlowContext
from .models import FlowReport
from .scheduler import compute_active_tasks_by_tags, execute_flow
from .task import Task, task

if TYPE_CHECKING:
    from ..core.connection import Connection
    from ..pool.connection_pool import ConnectionPool
    from ..sync.connection import SyncConnection
    from ..sync.pool import SyncConnectionPool


class Flow:
    """Декларативный оркестратор сценария выполнения задач с графом зависимостей (DAG).

    Использует ``graphlib.TopologicalSorter`` для статической проверки на циклы,
    вычисления параллельных слоёв (волн) и исполнения задач на одиночном ``Connection``
    или пуле ``ConnectionPool`` (в режимах ``barrier`` или ``independent``).
    """

    def __init__(
        self,
        name: str = "uniconn_flow",
        tasks: Sequence[Task[Any, Any] | Callable[..., Any]] = (),
        *,
        mode: Literal["barrier", "independent"] = "barrier",
        fail_fast: bool = True,
        max_fail_ratio: float = 0.0,
        batch_size: int | None = None,
        batch_notifications: bool = True,
        description: str | None = None,
        params_model: Any | None = None,
        risk_tier: str | None = None,
        expose_as_tool: bool = True,
    ) -> None:
        """Инициализировать сценарий ``Flow`` и провалидировать граф задач."""
        if mode not in ("barrier", "independent"):
            raise ConfigurationError(
                f"Invalid flow mode {mode!r}: expected 'barrier' or 'independent'."
            )
        if not (0.0 <= max_fail_ratio <= 1.0):
            raise ConfigurationError(
                f"max_fail_ratio must be between 0.0 and 1.0, got {max_fail_ratio}"
            )
        if batch_size is not None and batch_size <= 0:
            raise ConfigurationError(f"batch_size must be > 0, got {batch_size}")

        self.name = name
        self.mode: Literal["barrier", "independent"] = mode
        self.fail_fast = fail_fast
        self.max_fail_ratio = max_fail_ratio
        self.batch_size = batch_size
        self.batch_notifications = batch_notifications
        self.description = description.strip() if isinstance(description, str) and description.strip() else None
        self.params_model = params_model
        self.risk_tier = risk_tier.strip().lower() if isinstance(risk_tier, str) and risk_tier.strip() else None
        self.expose_as_tool = bool(expose_as_tool)
        self._tasks: dict[str, Task[Any, Any]] = {}
        self._dag: dict[str, set[str]] = {}

        for item in tasks:
            self.register(item)
        if self._tasks:
            self.validate()

    @property
    def tasks(self) -> dict[str, Task[Any, Any]]:
        """Словарь зарегистрированных задач ``{task_name: Task}``."""
        return dict(self._tasks)

    @property
    def dag(self) -> dict[str, set[str]]:
        """Словарь зависимостей графа ``{task_name: set(predecessor_names)}``."""
        return {k: set(v) for k, v in self._dag.items()}

    def register(self, item: Task[Any, Any] | Callable[..., Any]) -> Self:
        """Рекурсивно зарегистрировать задачу, её ``depends_on``/``pre`` и ``post`` в графе."""
        t_obj: Task[Any, Any] = item if isinstance(item, Task) else task(item)
        existing = self._tasks.get(t_obj.name)
        if existing is not None:
            if existing.fn is not t_obj.fn:
                raise ConfigurationError(
                    f"Duplicate task name {t_obj.name!r} in flow {self.name!r} "
                    f"with different callables ({existing.fn!r} vs {t_obj.fn!r})."
                )
            return self

        self._tasks[t_obj.name] = t_obj
        self._dag.setdefault(t_obj.name, set())

        for dep in t_obj.depends_on:
            self.register(dep)
            self._dag[t_obj.name].add(dep.name)

        for post_task in t_obj.post:
            self.register(post_task)
            self._dag.setdefault(post_task.name, set()).add(t_obj.name)

        return self

    def validate(self) -> None:
        """Проверить граф зависимостей на отсутствие циклов и битых ссылок.

        Raises:
            CyclicDependencyError: Если в графе обнаружен цикл зависимостей.
            ConfigurationError: Если задача ссылается на незарегистрированный узел.

        """
        for node, deps in self._dag.items():
            for dep in deps:
                if dep not in self._tasks:
                    raise ConfigurationError(
                        f"Task {node!r} depends on unknown task {dep!r} in flow {self.name!r}."
                    )

        sorter: TopologicalSorter[str] = TopologicalSorter(self._dag)
        try:
            sorter.prepare()
        except CycleError as err:
            raw_cycle = (
                list(err.args[1])
                if len(err.args) > 1 and isinstance(err.args[1], (list, tuple))
                else []
            )
            cycle_names = [str(x) for x in reversed(raw_cycle)] if raw_cycle else []
            cycle_str = " -> ".join(cycle_names) if cycle_names else str(err)
            raise CyclicDependencyError(
                f"Cycle detected in flow {self.name!r}: {cycle_str}",
                cycle=cycle_names,
            ) from err

    def tasks_in_order(self) -> list[Task[Any, Any]]:
        """Вернуть плоский список задач в допустимом топологическом порядке."""
        self.validate()
        sorter: TopologicalSorter[str] = TopologicalSorter(self._dag)
        return [self._tasks[name] for name in sorter.static_order()]

    def get_layers(self) -> list[list[Task[Any, Any]]]:
        """Разбить DAG на последовательные волны (слои), внутри которых задачи независимы."""
        self.validate()
        if not self._tasks:
            return []

        sorter: TopologicalSorter[str] = TopologicalSorter(self._dag)
        sorter.prepare()
        layers: list[list[Task[Any, Any]]] = []
        while sorter.is_active():
            ready = sorter.get_ready()
            if not ready:
                break
            layers.append([self._tasks[name] for name in ready])
            sorter.done(*ready)
        return layers

    def describe_plan(
        self,
        *,
        targets: Sequence[str] = (),
        vars: Mapping[str, Any] | None = None,
        tags: Sequence[str] | None = None,
        mode: str | None = None,
        dry_run: bool | None = None,
    ) -> str:
        """Сформировать детерминированный ASCII-план выполнения DAG по волнам."""
        layers = self.get_layers()
        active_set = compute_active_tasks_by_tags(self._tasks, self._dag, tags)
        eff_mode = mode or self.mode
        lines: list[str] = [
            f"Flow: {self.name} (mode={eff_mode}, tasks={len(self._tasks)}, waves={len(layers)})"
        ]
        if self.description:
            lines.append(f"Description: {self.description}")
        if targets:
            lines.append(f"Targets ({len(targets)}): {', '.join(str(t) for t in targets)}")
        if tags:
            lines.append(f"Tag Filter: {', '.join(str(t) for t in tags)}")
        if dry_run is not None:
            lines.append(f"Dry Run: {dry_run}")
        if vars:
            kv = ", ".join(f"{k}={v!r}" for k, v in sorted(vars.items()))
            lines.append(f"Parameters: {kv}")
        lines.append("DAG Execution Plan:")
        for idx, layer in enumerate(layers, 1):
            lines.append(f"  Wave {idx} (parallel={len(layer)}):")
            for t_obj in layer:
                is_active = active_set is None or t_obj.name in active_set
                status_prefix = "+" if is_active else "~ (tag_filtered)"
                deps = sorted(self._dag.get(t_obj.name, ()))
                dep_str = f" <- [{', '.join(deps)}]" if deps else ""
                meta: list[str] = []
                if t_obj.tags:
                    meta.append(f"tags={list(t_obj.tags)}")
                if t_obj.always_run:
                    meta.append("always_run")
                if t_obj.options.ignore_errors:
                    meta.append("ignore_errors")
                if t_obj.options.retries > 0:
                    meta.append(f"retries={t_obj.options.retries}")
                meta_str = f" ({', '.join(meta)})" if meta else ""
                lines.append(f"    {status_prefix} {t_obj.name}{dep_str}{meta_str}")
        return "\n".join(lines)

    async def run(
        self,
        target: Connection | ConnectionPool,
        *,
        context: FlowContext | None = None,
        vars: Mapping[str, Any] | None = None,
        tags: Sequence[str] | None = None,
        dry_run: bool | None = None,
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
        completed_tasks_by_host: (
            Mapping[str, AbstractSet[str] | Sequence[str] | Mapping[str, Any]] | None
        ) = None,
        checkpoint_outputs_by_host: Mapping[str, Mapping[str, Any]] | None = None,
        run_id: str | None = None,
        resumed_from: str | None = None,
    ) -> FlowReport:
        """Асинхронно выполнить сценарий ``Flow`` на ``Connection`` или ``ConnectionPool``."""
        return await execute_flow(
            self,
            target,
            context=context,
            vars=dict(vars) if vars else None,
            tags=tags,
            dry_run=dry_run,
            batch_size=batch_size,
            max_fail_ratio=max_fail_ratio,
            completed_tasks_by_host=completed_tasks_by_host,
            checkpoint_outputs_by_host=checkpoint_outputs_by_host,
            run_id=run_id,
            resumed_from=resumed_from,
        )

    def to_sync(self) -> SyncFlow:
        """Создать синхронную обёртку ``SyncFlow`` поверх текущего сценария."""
        return SyncFlow(self)

    def to_rich_tree(self) -> Any:
        """Построить дерево ``rich.tree.Tree`` со слоями и фактическими DAG-зависимостями сценария."""
        from rich.tree import Tree

        layers = self.get_layers()
        root = Tree(
            f"[bold cyan]Flow:[/bold cyan] [bold white]{self.name}[/bold white] "
            f"[dim](mode={self.mode}, tasks={len(self._tasks)}, layers={len(layers)})[/dim]"
        )
        for idx, layer in enumerate(layers, 1):
            layer_branch = root.add(
                f"[bold yellow]Layer {idx}[/bold yellow] (parallel={len(layer)})"
            )
            for t_obj in layer:
                deps = sorted(self._dag.get(t_obj.name, ()))
                dep_info = f" [dim]<- {', '.join(deps)}[/dim]" if deps else ""
                flags: list[str] = []
                if t_obj.always_run:
                    flags.append("always_run")
                if t_obj.options.ignore_errors:
                    flags.append("ignore_errors")
                if t_obj.options.retries > 0:
                    flags.append(f"retries={t_obj.options.retries}")
                if t_obj.tags:
                    flags.append(f"tags={list(t_obj.tags)}")
                flag_str = f" [magenta][{', '.join(flags)}][/magenta]" if flags else ""
                layer_branch.add(f"[green]{t_obj.name}[/green]{dep_info}{flag_str}")
        return root

    def __repr__(self) -> str:
        return (
            f"Flow(name={self.name!r}, tasks={list(self._tasks.keys())}, "
            f"mode={self.mode!r})"
        )


class SyncFlow(SyncProxyMixin):
    """Синхронная обёртка над ``Flow`` на базе ``EventLoopPortal``."""

    def __init__(self, async_flow: Flow) -> None:
        """Инициализировать синхронную обёртку для ``Flow``."""
        self._async_flow = async_flow
        self._async_target = async_flow
        self._portal = EventLoopPortal(owner_name="SyncFlow")

    @property
    def name(self) -> str:
        """Имя сценария."""
        return self._async_flow.name

    @property
    def mode(self) -> Literal["barrier", "independent"]:
        """Режим раскатки сценария."""
        return self._async_flow.mode

    @property
    def description(self) -> str | None:
        """Описание сценария."""
        return self._async_flow.description

    @property
    def params_model(self) -> Any | None:
        """Модель параметров сценария."""
        return self._async_flow.params_model

    @property
    def risk_tier(self) -> str | None:
        """Явный уровень риска сценария."""
        return self._async_flow.risk_tier

    @property
    def expose_as_tool(self) -> bool:
        """Флаг экспорта в MCP."""
        return self._async_flow.expose_as_tool

    @property
    def tasks(self) -> dict[str, Task[Any, Any]]:
        """Словарь зарегистрированных задач."""
        return self._async_flow.tasks

    @property
    def dag(self) -> dict[str, set[str]]:
        """Словарь зависимостей графа."""
        return self._async_flow.dag

    def register(self, item: Task[Any, Any] | Callable[..., Any]) -> Self:
        """Зарегистрировать задачу в графе."""
        self._async_flow.register(item)
        return self

    def validate(self) -> None:
        """Провалидировать граф задач на циклы."""
        self._async_flow.validate()

    def tasks_in_order(self) -> list[Task[Any, Any]]:
        """Вернуть задачи в топологическом порядке."""
        return self._async_flow.tasks_in_order()

    def get_layers(self) -> list[list[Task[Any, Any]]]:
        """Вернуть слои параллельного выполнения задач."""
        return self._async_flow.get_layers()

    def describe_plan(
        self,
        *,
        targets: Sequence[str] = (),
        vars: Mapping[str, Any] | None = None,
        tags: Sequence[str] | None = None,
        mode: str | None = None,
        dry_run: bool | None = None,
    ) -> str:
        """Сформировать детерминированный ASCII-план выполнения DAG по волнам."""
        return self._async_flow.describe_plan(
            targets=targets,
            vars=vars,
            tags=tags,
            mode=mode,
            dry_run=dry_run,
        )

    def to_rich_tree(self) -> Any:
        """Построить ``rich.tree.Tree`` для визуализации графа."""
        return self._async_flow.to_rich_tree()

    def run(
        self,
        target: SyncConnection | SyncConnectionPool | Connection | ConnectionPool,
        *,
        context: FlowContext | None = None,
        vars: Mapping[str, Any] | None = None,
        tags: Sequence[str] | None = None,
        dry_run: bool | None = None,
        batch_size: int | None = None,
        max_fail_ratio: float | None = None,
        completed_tasks_by_host: (
            Mapping[str, AbstractSet[str] | Sequence[str] | Mapping[str, Any]] | None
        ) = None,
        checkpoint_outputs_by_host: Mapping[str, Mapping[str, Any]] | None = None,
        run_id: str | None = None,
        resumed_from: str | None = None,
    ) -> FlowReport:
        """Синхронно выполнить сценарий на ``SyncConnection``, ``SyncConnectionPool`` или async-цели."""
        async_target: Any = getattr(
            target, "_async_conn", getattr(target, "_async_pool", target)
        )
        portal = getattr(target, "_portal", self._portal)
        if getattr(portal, "closed", False):
            portal.reopen()
        return portal.call(
            self._async_flow.run(
                async_target,
                context=context,
                vars=vars,
                tags=tags,
                dry_run=dry_run,
                batch_size=batch_size,
                max_fail_ratio=max_fail_ratio,
                completed_tasks_by_host=completed_tasks_by_host,
                checkpoint_outputs_by_host=checkpoint_outputs_by_host,
                run_id=run_id,
                resumed_from=resumed_from,
            )
        )


__all__ = [
    "Flow",
    "SyncFlow",
]
