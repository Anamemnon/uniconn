# src/uniconn/services/provisioning/_notify.py
"""Диспетчер реактивных уведомлений (Change Handlers / Notifiers) и контекст батчинга."""

from __future__ import annotations

import asyncio
import contextlib
import functools
import inspect
import threading
from collections.abc import Callable, Hashable, Sequence
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self, TypeAlias

from ...core.bridge import _SHARED_LOOP_MANAGER
from ...result import EnsureResult

if TYPE_CHECKING:
    from ...core.connection import Connection
    from .facade import StateManagementService

NotifyCallable: TypeAlias = Callable[..., Any]
NamedNotifyHandler: TypeAlias = tuple[str, NotifyCallable]
NotifyItem: TypeAlias = NotifyCallable | NamedNotifyHandler
NotifySpec: TypeAlias = NotifyItem | Sequence[NotifyItem] | None
NormalizedNotifyEntry: TypeAlias = tuple[Hashable, str, NotifyCallable]

_PRIMITIVE_TYPES = (str, int, float, bool, bytes, type(None), Path)
_RESULT_PARAM_NAMES: frozenset[str] = frozenset(
    {"res", "result", "ensure_result", "event"}
)
_CONN_PARAM_NAMES: frozenset[str] = frozenset(
    {"conn", "connection", "c", "client", "host_conn"}
)


def _value_token(val: Any) -> Hashable:
    """Представить значение переменной замыкания или глобальной области в виде хешируемого токена."""
    if isinstance(val, _PRIMITIVE_TYPES):
        return ("val", type(val), val)
    return ("id", id(val))


def _extract_lambda_context_tokens(fn: Any) -> tuple[Hashable, ...]:
    """Извлечь токены замыкания и задействованных глобальных переменных для лямбда-выражения."""
    tokens: list[Hashable] = []
    closure = getattr(fn, "__closure__", None) or ()
    for cell in closure:
        try:
            contents = cell.cell_contents
        except ValueError:
            tokens.append(("empty_cell",))
        else:
            tokens.append(_value_token(contents))

    code = getattr(fn, "__code__", None)
    fn_globals = getattr(fn, "__globals__", None)
    if code is not None and isinstance(fn_globals, dict):
        for name in code.co_names:
            if name in fn_globals:
                tokens.append(("global", name, _value_token(fn_globals[name])))
    return tuple(tokens)


def _callable_dedup_key(fn: NotifyCallable) -> Hashable:
    """Вычислить хешируемый ключ дедупликации для функции, метода или лямбда-выражения."""
    if isinstance(fn, functools.partial):
        kw_tuple = tuple(sorted((fn.keywords or {}).items()))
        candidate: Any = ("partial", _callable_dedup_key(fn.func), fn.args, kw_tuple)
        with contextlib.suppress(TypeError):
            hash(candidate)
            return candidate
        return id(fn)

    if inspect.ismethod(fn):
        return ("method", id(fn.__self__), fn.__func__)

    if getattr(fn, "__name__", None) == "<lambda>" and hasattr(fn, "__code__"):
        code = fn.__code__
        ctx_tokens = _extract_lambda_context_tokens(fn)
        lam_key: Any = (
            "lambda",
            code.co_code,
            code.co_consts,
            code.co_names,
            ctx_tokens,
        )
        with contextlib.suppress(TypeError):
            hash(lam_key)
            return lam_key
        return id(fn)

    with contextlib.suppress(TypeError):
        hash(fn)
        return fn
    return id(fn)


def _is_result_param(param: inspect.Parameter) -> bool:
    """Проверить, ожидает ли параметр объект ``EnsureResult``."""
    ann_str = str(param.annotation)
    return param.name in _RESULT_PARAM_NAMES or "EnsureResult" in ann_str


def _is_conn_param(param: inspect.Parameter) -> bool:
    """Проверить, ожидает ли параметр объект ``Connection``."""
    ann_str = str(param.annotation)
    return param.name in _CONN_PARAM_NAMES or "Connection" in ann_str


def _validate_callable_arity(fn: NotifyCallable) -> None:
    """Проверить на этапе входа, что обработчик не требует более 2 обязательных позиционных аргументов."""
    try:
        sig = inspect.signature(fn)
    except (ValueError, TypeError):
        return

    required_pos = [
        p
        for p in sig.parameters.values()
        if p.kind
        in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        and p.default is inspect.Parameter.empty
    ]
    if len(required_pos) > 2:
        raise TypeError(
            f"Notify handler {fn!r} requires {len(required_pos)} positional arguments; "
            "at most 2 (conn, result) are supported."
        )


def _extract_handler_entry(item: Any) -> NormalizedNotifyEntry:
    """Провалидировать одиночный элемент notify и вернуть ``(dedup_key, label, callable)``."""
    if isinstance(item, tuple):
        if len(item) == 2 and isinstance(item[0], str) and callable(item[1]):
            name = item[0].strip()
            if not name:
                raise ValueError("Notify handler name cannot be empty")
            _validate_callable_arity(item[1])
            return name, name, item[1]
        raise TypeError(
            "Named notify handler must be a 2-tuple of (name: str, handler: Callable)"
        )

    if callable(item):
        _validate_callable_arity(item)
        label = getattr(item, "__name__", None) or type(item).__name__
        return _callable_dedup_key(item), str(label), item

    raise TypeError(
        f"Invalid notify handler: {item!r}. Expected a callable or (name, callable) tuple."
    )


def normalize_notify_spec(notify: NotifySpec) -> list[NormalizedNotifyEntry]:
    """Нормализовать и провалидировать спецификацию ``notify`` до начала выполнения операции."""
    if notify is None:
        return []
    if isinstance(notify, tuple):
        if len(notify) == 2 and isinstance(notify[0], str) and callable(notify[1]):
            return [_extract_handler_entry(notify)]
        return [_extract_handler_entry(elem) for elem in notify]
    if callable(notify):
        return [_extract_handler_entry(notify)]
    if isinstance(notify, Sequence) and not isinstance(notify, (str, bytes)):
        return [_extract_handler_entry(elem) for elem in notify]
    raise TypeError(
        f"Unsupported notify specification: {notify!r}. "
        "Expected a callable, (name, callable) tuple, or sequence of handlers."
    )


def _bind_notify_args(
    fn: NotifyCallable,
    conn: Connection,
    result: EnsureResult,
) -> tuple[Any, ...]:
    """Определить позиционные аргументы вызова обработчика по его сигнатуре."""
    try:
        sig = inspect.signature(fn)
    except (ValueError, TypeError):
        return ()

    pos_params = [
        p
        for p in sig.parameters.values()
        if p.kind
        in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    if not pos_params:
        return ()

    required_pos = [
        p for p in pos_params if p.default is inspect.Parameter.empty
    ]
    if len(required_pos) >= 2:
        if _is_result_param(required_pos[0]) and not _is_result_param(required_pos[1]):
            return (result, conn)
        return (conn, result)

    if len(required_pos) == 1:
        return (result,) if _is_result_param(required_pos[0]) else (conn,)

    # Все позиционные параметры имеют значения по умолчанию: передаём conn/result
    # только если параметр явно назван или аннотирован под Connection / EnsureResult.
    if (
        len(pos_params) >= 2
        and (_is_conn_param(pos_params[0]) or _is_result_param(pos_params[0]))
        and (_is_conn_param(pos_params[1]) or _is_result_param(pos_params[1]))
    ):
        return (result, conn) if _is_result_param(pos_params[0]) else (conn, result)

    if _is_result_param(pos_params[0]):
        return (result,)
    if _is_conn_param(pos_params[0]):
        return (conn,)
    return ()


async def invoke_notify_handler(
    fn: NotifyCallable,
    conn: Connection,
    result: EnsureResult,
) -> Any:
    """Вызвать синхронный или асинхронный обработчик ``notify`` без риска deadlock в портале."""
    args = _bind_notify_args(fn, conn, result)
    if inspect.iscoroutinefunction(fn):
        return await fn(*args)

    shared_thread = _SHARED_LOOP_MANAGER.thread
    if shared_thread is not None and threading.current_thread() is shared_thread:
        outcome = await asyncio.to_thread(fn, *args)
    else:
        outcome = fn(*args)

    if inspect.isawaitable(outcome):
        return await outcome
    return outcome


class NotificationBatch:
    """Контекст отложенного выполнения и дедупликации уведомлений ``notify``."""

    def __init__(self, service: StateManagementService) -> None:
        """Инициализировать аккумулятор уведомлений для ``StateManagementService``."""
        self._service = service
        self._pending: dict[Hashable, tuple[str, NotifyCallable, Connection, EnsureResult]] = {}
        self._results: list[Any] = []
        self._notified_keys: list[str] = []
        self._triggered_count: int = 0
        self._executed_count: int = 0

    @property
    def pending_count(self) -> int:
        """Количество уникальных обработчиков, ожидающих вызова в очереди."""
        return len(self._pending)

    @property
    def triggered_count(self) -> int:
        """Общее число срабатываний триггеров ``notify`` (до дедупликации)."""
        return self._triggered_count

    @property
    def executed_count(self) -> int:
        """Количество фактически выполненных уникальных обработчиков."""
        return self._executed_count

    @property
    def results(self) -> list[Any]:
        """Список результатов выполнения вызванных обработчиков."""
        return list(self._results)

    @property
    def ok(self) -> bool:
        """Вернуть ``True``, если все выполненные обработчики завершились без ошибки (``ok != False``)."""
        return all(getattr(r, "ok", True) is not False for r in self._results)

    @property
    def notified_keys(self) -> list[str]:
        """Список имён/меток зарегистрированных уникальных обработчиков."""
        return list(self._notified_keys)

    def enqueue(
        self,
        dedup_key: Hashable,
        label: str,
        fn: NotifyCallable,
        conn: Connection,
        result: EnsureResult,
    ) -> None:
        """Поставить обработчик в очередь с дедупликацией по ``dedup_key``."""
        self._triggered_count += 1
        if dedup_key not in self._pending:
            self._pending[dedup_key] = (label, fn, conn, result)
            self._notified_keys.append(label)
        elif self._pending[dedup_key][3].dry_run and not result.dry_run:
            # Если первый триггер был в dry_run=True, а последующий — реальный (dry_run=False),
            # повышаем статус записи до реального выполнения.
            self._pending[dedup_key] = (label, fn, conn, result)

    async def flush(self) -> list[Any]:
        """Выполнить все накопленные обработчики в порядке первого срабатывания и очистить очередь."""
        if not self._pending:
            return []
        batch_outcomes: list[Any] = []
        seen_keys: set[Hashable] = set()
        while self._pending:
            wave = list(self._pending.items())
            self._pending.clear()
            for dedup_key, (_label, fn, conn, trigger_res) in wave:
                if dedup_key in seen_keys:
                    continue
                seen_keys.add(dedup_key)
                if trigger_res.dry_run:
                    continue
                outcome = await invoke_notify_handler(fn, conn, trigger_res)
                self._executed_count += 1
                self._results.append(outcome)
                batch_outcomes.append(outcome)
        return batch_outcomes

    async def __aenter__(self) -> Self:
        """Активировать режим аккумулирования уведомлений для сервиса состояния."""
        self._service._push_batch(self)
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Завершить батч и выполнить накопленные обработчики при отсутствии исключений."""
        try:
            if exc_type is None:
                await self.flush()
        finally:
            self._service._pop_batch(self)


async def finalize_ensure_with_notify(
    service: StateManagementService,
    result: EnsureResult,
    notify: NotifySpec | list[NormalizedNotifyEntry],
    *,
    _pre_normalized: bool = False,
) -> EnsureResult:
    """Обработать параметр ``notify`` после завершения базовой операции ``ensure_*``."""
    entries: list[NormalizedNotifyEntry] = (
        notify  # type: ignore[assignment]
        if _pre_normalized
        else normalize_notify_spec(notify)  # type: ignore[arg-type]
    )
    if not entries or not result.changed or not result.ok:
        return result

    active_batch = service._current_batch()
    if active_batch is not None:
        for dedup_key, label, fn in entries:
            active_batch.enqueue(dedup_key, label, fn, service._conn, result)
        return replace(result, notified=True)

    if result.dry_run:
        return replace(result, notified=True)

    outcomes: list[Any] = []
    overall_ok = result.ok
    failed_labels: list[str] = []
    for _dedup_key, label, fn in entries:
        outcome = await invoke_notify_handler(fn, service._conn, result)
        outcomes.append(outcome)
        if hasattr(outcome, "ok") and outcome.ok is False:
            overall_ok = False
            err_msg = (
                getattr(outcome, "details", "")
                or getattr(outcome, "stderr", "")
                or f"notify handler {label} failed"
            )
            failed_labels.append(str(err_msg).strip())

    details = (
        f"{result.details}; notify failed: {', '.join(failed_labels)}"
        if failed_labels
        else result.details
    )
    return replace(
        result,
        ok=overall_ok,
        details=details,
        notified=True,
        notify_results=tuple(outcomes),
    )


__all__ = [
    "NamedNotifyHandler",
    "NormalizedNotifyEntry",
    "NotificationBatch",
    "NotifyCallable",
    "NotifyItem",
    "NotifySpec",
    "finalize_ensure_with_notify",
    "invoke_notify_handler",
    "normalize_notify_spec",
]
