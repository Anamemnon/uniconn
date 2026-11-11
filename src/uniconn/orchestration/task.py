# src/uniconn/orchestration/task.py
"""Декоратор @task и модель узла графа выполнения Task."""

from __future__ import annotations

import asyncio
import functools
import inspect
import threading
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Generic, ParamSpec, TypeVar, overload

from ..core.bridge import _SHARED_LOOP_MANAGER
from ..exceptions import ConfigurationError
from .context import FlowContext, normalize_host_id

if TYPE_CHECKING:
    from ..core.connection import Connection

P = ParamSpec("P")
R = TypeVar("R")

_CONN_PARAM_NAMES: frozenset[str] = frozenset(
    {"conn", "connection", "c", "client", "host_conn", "sync_conn", "target"}
)
_CTX_PARAM_NAMES: frozenset[str] = frozenset(
    {"ctx", "context", "flow_ctx", "flow_context"}
)


def _is_ctx_param(param: inspect.Parameter) -> bool:
    """Проверить, ожидает ли параметр функции объект ``FlowContext``."""
    ann = str(param.annotation)
    return param.name in _CTX_PARAM_NAMES or "FlowContext" in ann


def _is_sync_conn_param(param: inspect.Parameter) -> bool:
    """Проверить, ожидает ли параметр синхронную обёртку ``SyncConnection``."""
    ann = str(param.annotation)
    return param.name == "sync_conn" or "SyncConnection" in ann


def _is_explicit_async_conn_param(param: inspect.Parameter) -> bool:
    """Проверить, аннотирован ли параметр явно как асинхронный ``Connection`` (не ``SyncConnection``)."""
    ann = str(param.annotation)
    return "Connection" in ann and "SyncConnection" not in ann


def _resolve_host_label(conn: Any) -> str:
    """Извлечь строковое имя хоста из объекта ``Connection`` или ``SyncConnection``."""
    cfg = getattr(conn, "config", None)
    if cfg is not None:
        host_val = getattr(cfg, "host", None)
        if isinstance(host_val, str) and host_val:
            return host_val
        uri_safe = getattr(cfg, "uri_safe", None)
        if isinstance(uri_safe, str) and uri_safe:
            return uri_safe
    return "localhost"


def _bind_callable_args(
    fn: Callable[..., Any],
    conn: Any,
    ctx: FlowContext,
    *,
    prefer_sync_conn: bool = False,
) -> tuple[tuple[Any, ...], dict[str, Any]]:
    """Подобрать позиционные и именованные аргументы для вызова задачи или предиката ``when``."""
    try:
        sig = inspect.signature(fn)
    except (ValueError, TypeError):
        return (conn,), {}

    params = list(sig.parameters.values())
    if not params:
        return (), {}

    def _resolve_conn_for_param(p: inspect.Parameter) -> Any:
        use_sync = _is_sync_conn_param(p) or (
            prefer_sync_conn and not _is_explicit_async_conn_param(p)
        )
        if use_sync and hasattr(conn, "to_sync"):
            from ..sync.connection import SyncConnection

            if not isinstance(conn, SyncConnection):
                return conn.to_sync()
        return conn

    pos_args: list[Any] = []
    kw_args: dict[str, Any] = {}
    conn_consumed = False
    ctx_consumed = False
    use_kw_for_pos_or_kw = False

    def _assign_arg(p: inspect.Parameter, val: Any) -> None:
        nonlocal use_kw_for_pos_or_kw
        if p.kind == inspect.Parameter.POSITIONAL_ONLY or (
            p.kind == inspect.Parameter.POSITIONAL_OR_KEYWORD
            and not use_kw_for_pos_or_kw
        ):
            pos_args.append(val)
        else:
            kw_args[p.name] = val

    for idx, param in enumerate(params):
        if param.kind == inspect.Parameter.VAR_POSITIONAL:
            if not conn_consumed:
                pos_args.append(_resolve_conn_for_param(param))
            break
        if param.kind == inspect.Parameter.VAR_KEYWORD:
            continue

        ann_str = str(param.annotation)
        is_conn_candidate = (
            not conn_consumed
            and not _is_ctx_param(param)
            and (
                param.name in _CONN_PARAM_NAMES
                or "Connection" in ann_str
                or (
                    idx == 0
                    and param.name != "host"
                    and param.name not in ctx.vars
                )
            )
        )

        if _is_ctx_param(param):
            _assign_arg(param, ctx)
            ctx_consumed = True
        elif is_conn_candidate:
            _assign_arg(param, _resolve_conn_for_param(param))
            conn_consumed = True
        elif param.name in ctx.vars:
            _assign_arg(param, ctx.vars[param.name])
        elif param.name == "host" and param.default is inspect.Parameter.empty:
            _assign_arg(param, _resolve_host_label(conn))
        elif (
            not ctx_consumed
            and idx == 1
            and getattr(fn, "__name__", "") == "<lambda>"
            and param.kind
            in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            )
            and param.default is inspect.Parameter.empty
            and param.annotation is inspect.Parameter.empty
        ):
            _assign_arg(param, ctx)
            ctx_consumed = True
        elif param.default is not inspect.Parameter.empty:
            use_kw_for_pos_or_kw = True
        else:
            fn_name = getattr(fn, "__name__", repr(fn))
            raise ValueError(
                f"Task {fn_name!r} missing required flow variable {param.name!r} in FlowContext.vars"
            )

    return tuple(pos_args), kw_args


def _detect_sync_conn_preference(
    fn: Callable[..., Any], in_portal_thread: bool
) -> bool:
    """Определить, следует ли передавать ``SyncConnection`` в синхронную функцию."""
    try:
        sig = inspect.signature(fn)
        params = list(sig.parameters.values())
    except (ValueError, TypeError):
        params = []

    if any(_is_sync_conn_param(p) for p in params):
        return True
    if any(_is_explicit_async_conn_param(p) for p in params):
        return False
    # Обычная синхронная def-функция (не lambda), вызванная из потока EventLoopPortal,
    # не может использовать await внутри тела, поэтому по умолчанию получает SyncConnection.
    is_lambda = getattr(fn, "__name__", None) == "<lambda>"
    return in_portal_thread and not is_lambda


async def invoke_flow_callable(
    fn: Callable[..., Any],
    conn: Any,
    ctx: FlowContext,
) -> Any:
    """Безопасно выполнить синхронную или асинхронную функцию задачи/предиката."""
    if inspect.iscoroutinefunction(fn):
        pos_args, kw_args = _bind_callable_args(fn, conn, ctx, prefer_sync_conn=False)
        return await fn(*pos_args, **kw_args)

    shared_thread = _SHARED_LOOP_MANAGER.thread
    in_portal_thread = (
        shared_thread is not None and threading.current_thread() is shared_thread
    )
    wants_sync_conn = _detect_sync_conn_preference(fn, in_portal_thread)
    pos_args, kw_args = _bind_callable_args(
        fn, conn, ctx, prefer_sync_conn=wants_sync_conn
    )

    if in_portal_thread or wants_sync_conn:
        outcome = await asyncio.to_thread(fn, *pos_args, **kw_args)
    else:
        outcome = fn(*pos_args, **kw_args)

    if inspect.isawaitable(outcome):
        return await outcome
    return outcome


def _coerce_task_list(
    items: Sequence[Task[Any, Any] | Callable[..., Any]] | None,
) -> tuple[Task[Any, Any], ...]:
    """Преобразовать последовательность функций или объектов ``Task`` в кортеж ``Task``."""
    if not items:
        return ()
    resolved: list[Task[Any, Any]] = []
    seen: set[str] = set()
    for item in items:
        t_obj: Task[Any, Any]
        if isinstance(item, Task):
            t_obj = item
        elif callable(item):
            t_obj = task(item)
        else:
            raise ConfigurationError(
                f"Invalid task dependency {item!r}: expected a @task object or callable."
            )
        if t_obj.name not in seen:
            seen.add(t_obj.name)
            resolved.append(t_obj)
    return tuple(resolved)


@dataclass(frozen=True, slots=True)
class TaskOptions:
    """Иммутабельная конфигурация выполнения отдельной задачи ``@task``."""

    name: str
    depends_on: tuple[Task[Any, Any], ...] = ()
    post: tuple[Task[Any, Any], ...] = ()
    when: Callable[..., bool | Awaitable[bool]] | None = None
    ignore_errors: bool = False
    always_run: bool = False
    retries: int = 0
    retry_delay: float = 1.0
    retry_backoff: float = 2.0
    timeout: float | None = None
    concurrency: int | None = None
    tags: tuple[str, ...] = ()
    hosts: Sequence[str] | Callable[[str], bool] | None = None


class Task(Generic[P, R]):
    """Обёртка функции-задачи, выступающая узлом графа зависимостей ``Flow``."""

    def __init__(
        self,
        fn: Callable[..., Awaitable[R] | R],
        options: TaskOptions,
    ) -> None:
        """Инициализировать задачу ``Task`` с функцией и параметрами ``TaskOptions``."""
        if not callable(fn):
            raise ConfigurationError(f"Task target {fn!r} must be callable.")
        if options.retries < 0:
            raise ConfigurationError("Task retries must be >= 0.")
        if options.concurrency is not None and options.concurrency <= 0:
            raise ConfigurationError("Task concurrency must be > 0.")

        self.fn = fn
        self.options = options
        self.name = options.name
        functools.update_wrapper(self, fn)

    @property
    def depends_on(self) -> tuple[Task[Any, Any], ...]:
        """Прямые зависимости задачи (предшественники в DAG)."""
        return self.options.depends_on

    @property
    def post(self) -> tuple[Task[Any, Any], ...]:
        """Задачи, которые должны быть выполнены после данной задачи."""
        return self.options.post

    @property
    def tags(self) -> tuple[str, ...]:
        """Теги задачи для селективной фильтрации."""
        return self.options.tags

    @property
    def always_run(self) -> bool:
        """Флаг гарантированного запуска задачи (даже при сбое предшественников)."""
        return self.options.always_run

    def matches_host(self, host_key: str, conn: Connection | Any = None) -> bool:
        """Проверить, разрешено ли выполнение задачи на указанном хосте."""
        hosts_spec = self.options.hosts
        if hosts_spec is None:
            return True

        primary, short = normalize_host_id(conn if conn is not None else host_key)
        key_short = host_key.split("://", 1)[-1].rsplit("@", 1)[-1].split(":", 1)[0]
        candidates = {host_key, primary, short, key_short}

        if callable(hosts_spec):
            return any(bool(hosts_spec(c)) for c in candidates if c)

        allowed = set(hosts_spec)
        return bool(candidates & allowed)

    async def execute(self, *args: Any, **kwargs: Any) -> R:
        """Выполнить функцию задачи напрямую (с поддержкой sync и async функций)."""
        if inspect.iscoroutinefunction(self.fn):
            return await self.fn(*args, **kwargs)

        shared_thread = _SHARED_LOOP_MANAGER.thread
        if shared_thread is not None and threading.current_thread() is shared_thread:
            res = await asyncio.to_thread(self.fn, *args, **kwargs)
        else:
            res = self.fn(*args, **kwargs)
        if inspect.isawaitable(res):
            return await res
        return res  # type: ignore[return-value]

    async def __call__(self, *args: P.args, **kwargs: P.kwargs) -> R:
        """Вызвать задачу как корутину ``await my_task(conn, ...)``."""
        return await self.execute(*args, **kwargs)

    def __hash__(self) -> int:
        return hash((self.name, self.fn))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Task):
            return NotImplemented
        return self.name == other.name and self.fn == other.fn

    def __repr__(self) -> str:
        deps = [t.name for t in self.options.depends_on]
        return f"Task(name={self.name!r}, depends_on={deps})"


@overload
def task(
    _func: Callable[P, Awaitable[R] | R],
    *,
    name: str | None = None,
    depends_on: Sequence[Task[Any, Any] | Callable[..., Any]] = (),
    pre: Sequence[Task[Any, Any] | Callable[..., Any]] = (),
    post: Sequence[Task[Any, Any] | Callable[..., Any]] = (),
    when: Callable[..., bool | Awaitable[bool]] | None = None,
    ignore_errors: bool = False,
    always_run: bool = False,
    retries: int = 0,
    retry_delay: float = 1.0,
    retry_backoff: float = 2.0,
    timeout: float | None = None,
    concurrency: int | None = None,
    tags: Sequence[str] = (),
    hosts: Sequence[str] | Callable[[str], bool] | None = None,
) -> Task[P, R]: ...


@overload
def task(
    _func: None = None,
    *,
    name: str | None = None,
    depends_on: Sequence[Task[Any, Any] | Callable[..., Any]] = (),
    pre: Sequence[Task[Any, Any] | Callable[..., Any]] = (),
    post: Sequence[Task[Any, Any] | Callable[..., Any]] = (),
    when: Callable[..., bool | Awaitable[bool]] | None = None,
    ignore_errors: bool = False,
    always_run: bool = False,
    retries: int = 0,
    retry_delay: float = 1.0,
    retry_backoff: float = 2.0,
    timeout: float | None = None,
    concurrency: int | None = None,
    tags: Sequence[str] = (),
    hosts: Sequence[str] | Callable[[str], bool] | None = None,
) -> Callable[[Callable[P, Awaitable[R] | R]], Task[P, R]]: ...


def task(
    _func: Callable[P, Awaitable[R] | R] | None = None,
    *,
    name: str | None = None,
    depends_on: Sequence[Task[Any, Any] | Callable[..., Any]] = (),
    pre: Sequence[Task[Any, Any] | Callable[..., Any]] = (),
    post: Sequence[Task[Any, Any] | Callable[..., Any]] = (),
    when: Callable[..., bool | Awaitable[bool]] | None = None,
    ignore_errors: bool = False,
    always_run: bool = False,
    retries: int = 0,
    retry_delay: float = 1.0,
    retry_backoff: float = 2.0,
    timeout: float | None = None,
    concurrency: int | None = None,
    tags: Sequence[str] = (),
    hosts: Sequence[str] | Callable[[str], bool] | None = None,
) -> Task[P, R] | Callable[[Callable[P, Awaitable[R] | R]], Task[P, R]]:
    """Декоратор объявления задачи ``Task`` с графом зависимостей ``depends_on``/``pre`` и ``post``."""
    combined_deps = [*depends_on, *pre]
    resolved_deps = _coerce_task_list(combined_deps)
    resolved_post = _coerce_task_list(post)

    def _decorator(fn: Callable[P, Awaitable[R] | R]) -> Task[P, R]:
        if isinstance(fn, Task):
            base_fn = fn.fn
            default_name = fn.name
        else:
            base_fn = fn
            default_name = getattr(fn, "__name__", "").strip() or "unnamed_task"

        task_name = (name.strip() if isinstance(name, str) else "") or default_name
        opts = TaskOptions(
            name=task_name,
            depends_on=resolved_deps,
            post=resolved_post,
            when=when,
            ignore_errors=ignore_errors,
            always_run=always_run,
            retries=retries,
            retry_delay=retry_delay,
            retry_backoff=retry_backoff,
            timeout=timeout,
            concurrency=concurrency,
            tags=tuple(tags),
            hosts=hosts,
        )
        return Task(base_fn, opts)

    if _func is not None:
        return _decorator(_func)
    return _decorator


__all__ = [
    "Task",
    "TaskOptions",
    "invoke_flow_callable",
    "task",
]
