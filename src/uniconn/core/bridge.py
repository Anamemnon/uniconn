# src/uniconn/core/bridge.py
"""Универсальный портал исполнения асинхронных корутин и типизированные дескрипторы Sync-слоя.

Устраняет дублирование кода и сигнатур между ``Connection``, доменными сервисами,
``SyncConnection``, ``SyncConnectionPool`` и ``SyncShellSession``, переиспользуя единый
разделяемый фоновый цикл событий (Singleton Event Loop Portal) и ``ParamSpec``-дескрипторы.
"""

from __future__ import annotations

import asyncio
import builtins
import concurrent.futures
import contextlib
import contextvars
import functools
import inspect
import threading
from collections.abc import (
    AsyncIterator,
    Awaitable,
    Callable,
    Coroutine,
    Iterator,
    Mapping,
    Sequence,
)
from contextlib import AbstractAsyncContextManager
from typing import Any, ClassVar, Concatenate, Generic, ParamSpec, TypeVar, overload

from ..exceptions import TimeoutError

P = ParamSpec("P")
R = TypeVar("R")
T = TypeVar("T")
_STREAM_DONE = object()


def _extract_timeout(kwargs: Mapping[str, Any]) -> float | None:
    """Извлечь и преобразовать параметр timeout в float | None."""
    val = kwargs.get("timeout")
    return float(val) if isinstance(val, (int, float)) else None


def _extract_buffer_size(kwargs: dict[str, Any], default: int = 1000) -> int:
    """Извлечь и преобразовать параметр buffer_size в int."""
    val = kwargs.pop("buffer_size", default)
    if isinstance(val, int):
        return val
    if isinstance(val, (float, str)):
        with contextlib.suppress(ValueError, TypeError):
            return int(val)
    return default


class _SharedLoopManager:
    """Синглтон управления фоновым daemon-потоком с asyncio event loop."""

    def __init__(self) -> None:
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._ready_event: threading.Event | None = None

    @property
    def loop(self) -> asyncio.AbstractEventLoop | None:
        return self._loop

    @property
    def thread(self) -> threading.Thread | None:
        return self._thread

    def is_running(self) -> bool:
        return (
            self._loop is not None
            and not self._loop.is_closed()
            and self._thread is not None
            and self._thread.is_alive()
        )

    def get_or_create_loop(self) -> tuple[asyncio.AbstractEventLoop, threading.Thread]:
        with self._lock:
            if not self.is_running():
                loop = asyncio.new_event_loop()
                ready_event = threading.Event()
                self._ready_event = ready_event

                def _run_loop_worker() -> None:
                    asyncio.set_event_loop(loop)
                    loop.call_soon(ready_event.set)
                    try:
                        loop.run_forever()
                    finally:
                        asyncio.set_event_loop(None)

                thread = threading.Thread(
                    target=_run_loop_worker,
                    name="uniconn-event-loop-portal",
                    daemon=True,
                )
                thread.start()

                if not ready_event.wait(timeout=5.0):
                    raise RuntimeError(
                        "EventLoopPortal failed to start background event loop within 5.0s"
                    )

                self._loop = loop
                self._thread = thread

            assert self._loop is not None
            assert self._thread is not None
            return self._loop, self._thread

    def shutdown(self, timeout: float = 3.0) -> None:
        with self._lock:
            if self._loop is not None and not self._loop.is_closed():
                try:
                    for task in asyncio.all_tasks(self._loop):
                        task.cancel()
                except Exception:
                    pass
                self._loop.call_soon_threadsafe(self._loop.stop)

            if (
                self._thread is not None
                and self._thread.is_alive()
                and threading.current_thread() is not self._thread
            ):
                self._thread.join(timeout=timeout)

            if self._loop is not None and not self._loop.is_closed():
                with contextlib.suppress(Exception):
                    self._loop.close()

            self._loop = None
            self._thread = None
            self._ready_event = None


_SHARED_LOOP_MANAGER = _SharedLoopManager()


class EventLoopPortal:
    """Управляет разделяемым ``asyncio.AbstractEventLoop`` в фоновом daemon-потоке.

    Безопасно исполняет корутины, асинхронные контекстные менеджеры и
    асинхронные генераторы из синхронного кода через ``run_coroutine_threadsafe``.
    Все экземпляры ``EventLoopPortal`` разделяют один общий daemon-поток,
    предотвращая создание десятков потоков ОС при работе с множеством ``SyncConnection``.
    """

    _shared_loop: ClassVar[asyncio.AbstractEventLoop | None] = None
    _shared_thread: ClassVar[threading.Thread | None] = None
    _shared_lock: ClassVar[threading.Lock] = _SHARED_LOOP_MANAGER._lock

    def __init__(
        self,
        owner_name: str = "SyncPortal",
        default_timeout: float | None = None,
    ) -> None:
        """Инициализировать портал фонового цикла событий."""
        self._owner_name = owner_name
        self._default_timeout = (
            float(default_timeout) if isinstance(default_timeout, (int, float)) else None
        )
        self._loop: asyncio.AbstractEventLoop | None = None
        self._loop_thread: threading.Thread | None = None
        self._loop_lock = self._shared_lock
        self._closed = False

    @property
    def closed(self) -> bool:
        """Признак того, что портал закрыт."""
        return self._closed

    def reopen(self) -> None:
        """Повторно активировать портал (например, при повторном входе в ``with sync_conn:``)."""
        self._closed = False

    @staticmethod
    def _run_loop_forever(loop: asyncio.AbstractEventLoop) -> None:
        """Запустить event loop до вызова ``loop.stop()``."""
        asyncio.set_event_loop(loop)
        try:
            loop.run_forever()
        finally:
            asyncio.set_event_loop(None)

    @classmethod
    def _ensure_shared_loop(
        cls,
    ) -> tuple[asyncio.AbstractEventLoop, threading.Thread]:
        """Лениво создать и запустить единый фоновый event loop в daemon-потоке."""
        loop, thread = _SHARED_LOOP_MANAGER.get_or_create_loop()
        cls._shared_loop = loop
        cls._shared_thread = thread
        return loop, thread

    @classmethod
    def shutdown_all(cls, timeout: float = 3.0) -> None:
        """Остановить общий фоновый event loop и завершить поток (для тестов или shutdown)."""
        _SHARED_LOOP_MANAGER.shutdown(timeout=timeout)
        cls._shared_loop = None
        cls._shared_thread = None

    def get_loop(self) -> asyncio.AbstractEventLoop:
        """Вернуть активный фоновый event loop в daemon-потоке."""
        loop, thread = self._ensure_shared_loop()
        self._loop = loop
        self._loop_thread = thread
        return loop

    def call(self, coro: Any, timeout: float | None = None) -> Any:
        """Синхронно выполнить корутину в фоновом event loop и вернуть результат."""
        shared_thread = _SHARED_LOOP_MANAGER.thread
        current_thread = threading.current_thread()

        if self._loop_thread is None and shared_thread is not None:
            self._loop_thread = shared_thread

        if (
            (self._loop_thread is not None and current_thread is self._loop_thread)
            or (shared_thread is not None and current_thread is shared_thread)
        ):
            with contextlib.suppress(Exception):
                coro.close()
            raise RuntimeError(
                f"Deadlock detected: {self._owner_name}.call() cannot be called "
                "from within the portal event loop thread. Await the coroutine directly instead."
            )

        if self._closed:
            with contextlib.suppress(Exception):
                coro.close()
            raise RuntimeError(f"{self._owner_name} уже закрыт")

        raw_timeout = timeout if timeout is not None else self._default_timeout
        effective_timeout = (
            float(raw_timeout) if isinstance(raw_timeout, (int, float)) else None
        )
        loop = self.get_loop()
        caller_ctx = contextvars.copy_context()

        async def _run_in_caller_context() -> Any:
            for var, val in caller_ctx.items():
                var.set(val)
            return await coro

        future = asyncio.run_coroutine_threadsafe(_run_in_caller_context(), loop)
        try:
            return future.result(timeout=effective_timeout)
        except (concurrent.futures.TimeoutError, builtins.TimeoutError):
            future.cancel()
            raise TimeoutError(
                f"{self._owner_name}.call() timed out after {effective_timeout}s"
            ) from None

    def iter_async(
        self,
        async_gen: AsyncIterator[T],
        buffer_size: int = 1000,
        timeout: float | None = None,
    ) -> Iterator[T]:
        """Преобразовать асинхронный генератор в синхронный итератор через очередь."""
        shared_thread = _SHARED_LOOP_MANAGER.thread
        current_thread = threading.current_thread()

        if self._loop_thread is None and shared_thread is not None:
            self._loop_thread = shared_thread

        if (
            (self._loop_thread is not None and current_thread is self._loop_thread)
            or (shared_thread is not None and current_thread is shared_thread)
        ):
            raise RuntimeError(
                f"Deadlock detected: {self._owner_name}.iter_async() cannot be called "
                "from within the portal event loop thread. Iterate with 'async for' directly instead."
            )

        if self._closed:
            close_fn = getattr(async_gen, "aclose", None)
            if callable(close_fn):
                with contextlib.suppress(Exception):
                    coro: Any = close_fn()
                    coro_close = getattr(coro, "close", None)
                    if callable(coro_close):
                        coro_close()
            raise RuntimeError(f"{self._owner_name} уже закрыт")

        raw_timeout = timeout if timeout is not None else self._default_timeout
        effective_timeout = (
            float(raw_timeout) if isinstance(raw_timeout, (int, float)) else None
        )
        loop = self.get_loop()
        caller_ctx = contextvars.copy_context()
        q: asyncio.Queue[Any] = asyncio.Queue(maxsize=max(1, buffer_size))

        async def _pump() -> None:
            for var, val in caller_ctx.items():
                var.set(val)
            try:
                async for item in async_gen:
                    await q.put(item)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                await q.put(exc)
            else:
                await q.put(_STREAM_DONE)

        pump_future = asyncio.run_coroutine_threadsafe(_pump(), loop)

        try:
            while True:
                get_future = asyncio.run_coroutine_threadsafe(q.get(), loop)
                try:
                    item = get_future.result(timeout=effective_timeout)
                except (concurrent.futures.TimeoutError, builtins.TimeoutError):
                    get_future.cancel()
                    raise TimeoutError(
                        f"{self._owner_name}.iter_async() timed out waiting for next item after {effective_timeout}s"
                    ) from None
                if item is _STREAM_DONE:
                    break
                if isinstance(item, Exception):
                    raise item
                yield item
        finally:
            if not pump_future.done():
                pump_future.cancel()
                with contextlib.suppress(BaseException):
                    pump_future.result(timeout=2.0)
            close_fn = getattr(async_gen, "aclose", None)
            if callable(close_fn):
                async def _do_aclose() -> None:
                    res = close_fn()
                    if inspect.isawaitable(res):
                        await res

                with contextlib.suppress(Exception):
                    aclose_fut = asyncio.run_coroutine_threadsafe(_do_aclose(), loop)
                    with contextlib.suppress(BaseException):
                        aclose_fut.result(timeout=2.0)

    def close(self, cleanup_coro: Any = None) -> None:
        """Выполнить финальную корутину очистки и пометить портал закрытым."""
        if self._closed:
            if cleanup_coro is not None:
                with contextlib.suppress(Exception):
                    cleanup_coro.close()
            return

        if cleanup_coro is not None:
            with contextlib.suppress(Exception):
                self.call(cleanup_coro)

        self._closed = True
        self._loop = None
        self._loop_thread = None


class SyncContextBridge(Generic[T]):
    """Адаптер произвольного ``AsyncContextManager[T]`` в синхронный контекстный менеджер."""

    def __init__(
        self,
        portal_or_owner: EventLoopPortal | Any,
        async_cm: Any,
        cast_fn: Any = None,
    ) -> None:
        """Инициализировать синхронный мост для асинхронного контекстного менеджера."""
        self._portal: EventLoopPortal = (
            portal_or_owner
            if isinstance(portal_or_owner, EventLoopPortal)
            else portal_or_owner._portal
        )
        self._async_cm = async_cm
        self._cast_fn = cast_fn

    def __enter__(self) -> T:
        """Войти в контекстный менеджер синхронно."""
        val = self._portal.call(self._async_cm.__aenter__())
        return self._cast_fn(val) if self._cast_fn is not None else val

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Выйти из контекстного менеджера синхронно."""
        self._portal.call(self._async_cm.__aexit__(exc_type, exc_val, exc_tb))


# ─── Типизированные дескрипторы делегирования и Sync-моста ──────────────────


def _resolve_attr_path(obj: Any, attr_path: str) -> Any:
    """Разрешить вложенный путь атрибутов (например, ``_async_conn.files``)."""
    cur = obj
    for part in attr_path.split("."):
        cur = getattr(cur, part)
    return cur


class _AsyncDelegateDescriptor(Generic[P, R]):
    """Дескриптор делегирования async-метода доменному сервису (например, ``conn.files``)."""

    def __init__(
        self,
        service_attr: str,
        async_fn: Callable[Concatenate[Any, P], Coroutine[Any, Any, R]],
    ) -> None:
        self._service_attr = service_attr
        self._method_name = async_fn.__name__
        self._async_fn = async_fn
        functools.update_wrapper(self, async_fn)

    @overload
    def __get__(
        self, instance: None, owner: type | None = None
    ) -> _AsyncDelegateDescriptor[P, R]: ...

    @overload
    def __get__(
        self, instance: Any, owner: type | None = None
    ) -> Callable[P, Coroutine[Any, Any, R]]: ...

    def __get__(self, instance: Any, owner: type | None = None) -> Any:
        if instance is None:
            return self
        service = _resolve_attr_path(instance, self._service_attr)
        return getattr(service, self._method_name)

    def __call__(
        self, instance: Any, /, *args: P.args, **kwargs: P.kwargs
    ) -> Coroutine[Any, Any, R]:
        service = _resolve_attr_path(instance, self._service_attr)
        return getattr(service, self._method_name)(*args, **kwargs)


class _ContextDelegateDescriptor(Generic[P, R]):
    """Дескриптор делегирования фабрики контекстного менеджера доменному сервису."""

    def __init__(
        self,
        service_attr: str,
        cm_fn: Callable[Concatenate[Any, P], AbstractAsyncContextManager[R]],
    ) -> None:
        self._service_attr = service_attr
        self._method_name = cm_fn.__name__
        self._cm_fn = cm_fn
        functools.update_wrapper(self, cm_fn)

    @overload
    def __get__(
        self, instance: None, owner: type | None = None
    ) -> _ContextDelegateDescriptor[P, R]: ...

    @overload
    def __get__(
        self, instance: Any, owner: type | None = None
    ) -> Callable[P, AbstractAsyncContextManager[R]]: ...

    def __get__(self, instance: Any, owner: type | None = None) -> Any:
        if instance is None:
            return self
        service = _resolve_attr_path(instance, self._service_attr)
        return getattr(service, self._method_name)

    def __call__(
        self, instance: Any, /, *args: P.args, **kwargs: P.kwargs
    ) -> AbstractAsyncContextManager[R]:
        service = _resolve_attr_path(instance, self._service_attr)
        return getattr(service, self._method_name)(*args, **kwargs)


def async_delegate(
    service_attr: str,
    async_fn: Callable[Concatenate[Any, P], Coroutine[Any, Any, R]],
) -> _AsyncDelegateDescriptor[P, R]:
    """Создать типизированный дескриптор делегирования async-метода сервису."""
    return _AsyncDelegateDescriptor(service_attr, async_fn)


def context_delegate(
    service_attr: str,
    cm_fn: Callable[Concatenate[Any, P], AbstractAsyncContextManager[R]],
) -> _ContextDelegateDescriptor[P, R]:
    """Создать типизированный дескриптор делегирования async-контекстного менеджера."""
    return _ContextDelegateDescriptor(service_attr, cm_fn)


class _PoolFanOutDictDescriptor(Generic[P, R]):
    """Дескриптор параллельного fan-out вызова метода соединения по всем хостам пула."""

    def __init__(
        self,
        async_fn: Callable[Concatenate[Any, P], Coroutine[Any, Any, R]],
        *,
        conn_attr: str | None = None,
    ) -> None:
        self._async_fn = async_fn
        self._method_name = async_fn.__name__
        self._conn_attr = conn_attr
        functools.update_wrapper(self, async_fn)

    @overload
    def __get__(
        self, instance: None, owner: type | None = None
    ) -> _PoolFanOutDictDescriptor[P, R]: ...

    @overload
    def __get__(
        self, instance: Any, owner: type | None = None
    ) -> Callable[P, Coroutine[Any, Any, dict[str, R]]]: ...

    def __get__(self, instance: Any, owner: type | None = None) -> Any:
        if instance is None:
            return self
        pool = getattr(instance, "_pool", instance)
        conn_attr = self._conn_attr
        method_name = self._method_name

        @functools.wraps(self._async_fn)
        async def _fan_out_call(*args: P.args, **kwargs: P.kwargs) -> dict[str, R]:
            call_kwargs: dict[str, Any] = dict(kwargs)
            batch_size = call_kwargs.pop("batch_size", None)
            max_fail_ratio = call_kwargs.pop("max_fail_ratio", None)

            async def _worker(_key: str, conn: Any) -> R:
                target = (
                    _resolve_attr_path(conn, conn_attr)
                    if conn_attr is not None
                    else conn
                )
                return await getattr(target, method_name)(*args, **call_kwargs)

            return await pool._fan_out_dict(
                _worker,
                batch_size=batch_size,
                max_fail_ratio=max_fail_ratio,
            )

        return _fan_out_call

    def __call__(
        self, instance: Any, /, *args: P.args, **kwargs: P.kwargs
    ) -> Coroutine[Any, Any, dict[str, R]]:
        bound = self.__get__(instance, type(instance))
        return bound(*args, **kwargs)


def pool_fan_out_dict(
    async_fn: Callable[Concatenate[Any, P], Coroutine[Any, Any, R]],
    *,
    conn_attr: str | None = None,
) -> _PoolFanOutDictDescriptor[P, R]:
    """Создать типизированный дескриптор параллельного fan-out вызова по пулу хостов."""
    return _PoolFanOutDictDescriptor(async_fn, conn_attr=conn_attr)


class _SyncMethodDescriptor(Generic[P, R]):
    """Дескриптор, превращающий async-метод в синхронный вызов через ``EventLoopPortal``."""

    def __init__(
        self,
        async_fn: Any,
        *,
        target_attr: str = "_async_target",
        portal_attr: str = "_portal",
        delegate_attr: str | None = None,
    ) -> None:
        self._async_fn = async_fn
        self._method_name: str = getattr(async_fn, "__name__", "")
        self._target_attr = target_attr
        self._portal_attr = portal_attr
        self._delegate_attr = delegate_attr
        functools.update_wrapper(self, async_fn)

    @overload
    def __get__(
        self, instance: None, owner: type | None = None
    ) -> _SyncMethodDescriptor[P, R]: ...

    @overload
    def __get__(
        self, instance: Any, owner: type | None = None
    ) -> Callable[P, R]: ...

    def __get__(self, instance: Any, owner: type | None = None) -> Any:
        if instance is None:
            return self
        if self._delegate_attr is not None:
            delegate_obj = _resolve_attr_path(instance, self._delegate_attr)
            return getattr(delegate_obj, self._method_name)

        portal: EventLoopPortal = _resolve_attr_path(instance, self._portal_attr)
        target = _resolve_attr_path(instance, self._target_attr)
        bound_async = getattr(target, self._method_name)

        @functools.wraps(self._async_fn)
        def _sync_call(*args: P.args, **kwargs: P.kwargs) -> R:
            timeout = _extract_timeout(kwargs)
            return portal.call(bound_async(*args, **kwargs), timeout=timeout)

        return _sync_call

    def __call__(self, instance: Any, /, *args: P.args, **kwargs: P.kwargs) -> R:
        bound = self.__get__(instance, type(instance))
        return bound(*args, **kwargs)


class _SyncContextDescriptor(Generic[P, R]):
    """Дескриптор, оборачивающий async context manager в ``SyncContextBridge[R]``."""

    def __init__(
        self,
        async_cm_fn: Any,
        *,
        target_attr: str = "_async_target",
        portal_attr: str = "_portal",
        delegate_attr: str | None = None,
        cast_fn: Callable[[Any], R] | None = None,
        reopen_portal: bool = False,
    ) -> None:
        self._async_cm_fn = async_cm_fn
        self._method_name: str = getattr(async_cm_fn, "__name__", "")
        self._target_attr = target_attr
        self._portal_attr = portal_attr
        self._delegate_attr = delegate_attr
        self._cast_fn = cast_fn
        self._reopen_portal = reopen_portal
        functools.update_wrapper(self, async_cm_fn)

    @overload
    def __get__(
        self, instance: None, owner: type | None = None
    ) -> _SyncContextDescriptor[P, R]: ...

    @overload
    def __get__(
        self, instance: Any, owner: type | None = None
    ) -> Callable[P, SyncContextBridge[R]]: ...

    def __get__(self, instance: Any, owner: type | None = None) -> Any:
        if instance is None:
            return self
        if self._delegate_attr is not None:
            delegate_obj = _resolve_attr_path(instance, self._delegate_attr)
            return getattr(delegate_obj, self._method_name)

        portal: EventLoopPortal = _resolve_attr_path(instance, self._portal_attr)
        target = _resolve_attr_path(instance, self._target_attr)
        bound_cm_fn = getattr(target, self._method_name)

        @functools.wraps(self._async_cm_fn)
        def _sync_cm(*args: P.args, **kwargs: P.kwargs) -> SyncContextBridge[R]:
            if self._reopen_portal:
                portal.reopen()
            return SyncContextBridge(
                portal,
                bound_cm_fn(*args, **kwargs),
                cast_fn=self._cast_fn,
            )

        return _sync_cm

    def __call__(
        self, instance: Any, /, *args: P.args, **kwargs: P.kwargs
    ) -> SyncContextBridge[R]:
        bound = self.__get__(instance, type(instance))
        return bound(*args, **kwargs)


class _SyncIterDescriptor(Generic[P, R]):
    """Дескриптор, оборачивающий async-генератор в синхронный ``Iterator[R]``."""

    def __init__(
        self,
        async_gen_fn: Any,
        *,
        target_attr: str = "_async_target",
        portal_attr: str = "_portal",
        buffer_size: int = 1000,
    ) -> None:
        self._async_gen_fn = async_gen_fn
        self._method_name: str = getattr(async_gen_fn, "__name__", "")
        self._target_attr = target_attr
        self._portal_attr = portal_attr
        self._buffer_size = buffer_size
        functools.update_wrapper(self, async_gen_fn)

    @overload
    def __get__(
        self, instance: None, owner: type | None = None
    ) -> _SyncIterDescriptor[P, R]: ...

    @overload
    def __get__(
        self, instance: Any, owner: type | None = None
    ) -> Callable[P, Iterator[R]]: ...

    def __get__(self, instance: Any, owner: type | None = None) -> Any:
        if instance is None:
            return self
        portal: EventLoopPortal = _resolve_attr_path(instance, self._portal_attr)
        target = _resolve_attr_path(instance, self._target_attr)
        bound_gen_fn = getattr(target, self._method_name)

        @functools.wraps(self._async_gen_fn)
        def _sync_iter(*args: P.args, **kwargs: P.kwargs) -> Iterator[R]:
            kw = dict(kwargs)
            buf_size = _extract_buffer_size(kw, self._buffer_size)
            timeout = _extract_timeout(kw)
            return portal.iter_async(
                bound_gen_fn(*args, **kw),  # type: ignore[arg-type]
                buffer_size=buf_size,
                timeout=timeout,
            )

        return _sync_iter

    def __call__(
        self, instance: Any, /, *args: P.args, **kwargs: P.kwargs
    ) -> Iterator[R]:
        bound = self.__get__(instance, type(instance))
        return bound(*args, **kwargs)


@overload
def sync_method(
    async_fn: _PoolFanOutDictDescriptor[P, R],
    *,
    target_attr: str = "_async_target",
    portal_attr: str = "_portal",
    delegate_attr: str | None = None,
) -> _SyncMethodDescriptor[P, dict[str, R]]: ...


@overload
def sync_method(
    async_fn: _AsyncDelegateDescriptor[P, R],
    *,
    target_attr: str = "_async_target",
    portal_attr: str = "_portal",
    delegate_attr: str | None = None,
) -> _SyncMethodDescriptor[P, R]: ...


@overload
def sync_method(
    async_fn: Callable[Concatenate[Any, P], Awaitable[R]],
    *,
    target_attr: str = "_async_target",
    portal_attr: str = "_portal",
    delegate_attr: str | None = None,
) -> _SyncMethodDescriptor[P, R]: ...


def sync_method(
    async_fn: Any,
    *,
    target_attr: str = "_async_target",
    portal_attr: str = "_portal",
    delegate_attr: str | None = None,
) -> _SyncMethodDescriptor[Any, Any]:
    """Создать типизированный синхронный дескриптор для async-метода."""
    return _SyncMethodDescriptor(
        async_fn,
        target_attr=target_attr,
        portal_attr=portal_attr,
        delegate_attr=delegate_attr,
    )


@overload
def sync_context(
    async_cm_fn: _ContextDelegateDescriptor[P, R],
    *,
    target_attr: str = "_async_target",
    portal_attr: str = "_portal",
    delegate_attr: str | None = None,
    cast_fn: Callable[[Any], R] | None = None,
    reopen_portal: bool = False,
) -> _SyncContextDescriptor[P, R]: ...


@overload
def sync_context(
    async_cm_fn: Callable[Concatenate[Any, P], AbstractAsyncContextManager[R]],
    *,
    target_attr: str = "_async_target",
    portal_attr: str = "_portal",
    delegate_attr: str | None = None,
    cast_fn: Callable[[Any], R] | None = None,
    reopen_portal: bool = False,
) -> _SyncContextDescriptor[P, R]: ...


def sync_context(
    async_cm_fn: Any,
    *,
    target_attr: str = "_async_target",
    portal_attr: str = "_portal",
    delegate_attr: str | None = None,
    cast_fn: Callable[[Any], Any] | None = None,
    reopen_portal: bool = False,
) -> _SyncContextDescriptor[Any, Any]:
    """Создать типизированный синхронный дескриптор для async-контекстного менеджера."""
    return _SyncContextDescriptor(
        async_cm_fn,
        target_attr=target_attr,
        portal_attr=portal_attr,
        delegate_attr=delegate_attr,
        cast_fn=cast_fn,
        reopen_portal=reopen_portal,
    )


def sync_iter(
    async_gen_fn: Callable[Concatenate[Any, P], AsyncIterator[R]],
    *,
    target_attr: str = "_async_target",
    portal_attr: str = "_portal",
    buffer_size: int = 1000,
) -> _SyncIterDescriptor[P, R]:
    """Создать типизированный синхронный дескриптор для async-генератора."""
    return _SyncIterDescriptor(
        async_gen_fn,
        target_attr=target_attr,
        portal_attr=portal_attr,
        buffer_size=buffer_size,
    )


class _SyncFactoryDescriptor(Generic[P]):
    """Дескриптор классметода-фабрики ``SyncConnection``, оборачивающий результат ``Connection.from_*``."""

    def __init__(self, async_factory: Callable[P, Any]) -> None:
        self._async_factory = async_factory
        functools.update_wrapper(self, async_factory)

    def __get__(
        self, instance: Any, owner: type[T] | None = None
    ) -> Callable[P, T]:
        cls: type[Any] = owner if owner is not None else type(instance)
        factory = self._async_factory

        @functools.wraps(factory)
        def _bound_factory(*args: P.args, **kwargs: P.kwargs) -> T:
            return cls(factory(*args, **kwargs))

        return _bound_factory

    def __call__(self, *args: P.args, **kwargs: P.kwargs) -> Any:
        return self._async_factory(*args, **kwargs)


class _SyncListFactoryDescriptor(Generic[P]):
    """Дескриптор списочной фабрики ``SyncConnection.from_file``."""

    def __init__(self, async_list_factory: Callable[P, Sequence[Any]]) -> None:
        self._async_factory = async_list_factory
        functools.update_wrapper(self, async_list_factory)

    def __get__(
        self, instance: Any, owner: type[T] | None = None
    ) -> Callable[P, list[T]]:
        cls: type[Any] = owner if owner is not None else type(instance)
        factory = self._async_factory

        @functools.wraps(factory)
        def _bound_list_factory(*args: P.args, **kwargs: P.kwargs) -> list[T]:
            return [cls(item) for item in factory(*args, **kwargs)]

        return _bound_list_factory

    def __call__(self, *args: P.args, **kwargs: P.kwargs) -> Sequence[Any]:
        return self._async_factory(*args, **kwargs)


class _SyncCloneDescriptor(Generic[P]):
    """Дескриптор методов клонирования (``copy``, ``with_overrides``) для ``SyncConnection``."""

    def __init__(
        self,
        async_clone_fn: Callable[Concatenate[Any, P], Any],
        *,
        target_attr: str = "_async_target",
    ) -> None:
        self._async_clone_fn = async_clone_fn
        self._method_name: str = getattr(async_clone_fn, "__name__", "")
        self._target_attr = target_attr
        functools.update_wrapper(self, async_clone_fn)

    @overload
    def __get__(
        self, instance: None, owner: type | None = None
    ) -> _SyncCloneDescriptor[P]: ...

    @overload
    def __get__(
        self, instance: T, owner: type[T] | None = None
    ) -> Callable[P, T]: ...

    def __get__(self, instance: Any, owner: type | None = None) -> Any:
        if instance is None:
            return self
        target = _resolve_attr_path(instance, self._target_attr)
        bound_clone = getattr(target, self._method_name)
        cls = type(instance)

        @functools.wraps(self._async_clone_fn)
        def _sync_clone(*args: P.args, **kwargs: P.kwargs) -> Any:
            return cls(bound_clone(*args, **kwargs))

        return _sync_clone

    def __call__(self, instance: Any, /, *args: P.args, **kwargs: P.kwargs) -> Any:
        bound = self.__get__(instance, type(instance))
        return bound(*args, **kwargs)


def sync_factory(async_factory: Callable[P, Any]) -> _SyncFactoryDescriptor[P]:
    """Создать типизированный дескриптор классметода-фабрики ``SyncConnection``."""
    return _SyncFactoryDescriptor(async_factory)


def sync_list_factory(
    async_list_factory: Callable[P, Sequence[Any]],
) -> _SyncListFactoryDescriptor[P]:
    """Создать типизированный дескриптор списочной фабрики ``SyncConnection.from_file``."""
    return _SyncListFactoryDescriptor(async_list_factory)


def sync_clone_method(
    async_clone_fn: Callable[Concatenate[Any, P], Any],
    *,
    target_attr: str = "_async_target",
) -> _SyncCloneDescriptor[P]:
    """Создать типизированный дескриптор клонирующего метода ``SyncConnection``."""
    return _SyncCloneDescriptor(async_clone_fn, target_attr=target_attr)


class SyncProxyMixin:
    """Базовый миксин динамического делегирования к целевому async-объекту (``__getattr__``).

    Используется как fallback для любых свойств и методов, не переопределённых явно:
    - корутины автоматически исполняются через ``self._portal.call(...)``;
    - асинхронные генераторы оборачиваются через ``self._portal.iter_async(...)``;
    - обычные свойства и синхронные методы возвращаются напрямую.
    """

    _target_attr_name: ClassVar[str] = "_async_target"
    _portal_attr_name: ClassVar[str] = "_portal"

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        try:
            target = object.__getattribute__(self, self._target_attr_name)
        except AttributeError:
            target = getattr(self, self._target_attr_name, None)
            if target is None:
                raise AttributeError(
                    f"{type(self).__name__!r} object has no attribute {name!r}"
                ) from None

        attr = getattr(target, name)
        if inspect.iscoroutinefunction(attr):
            portal: EventLoopPortal = getattr(self, self._portal_attr_name)

            @functools.wraps(attr)
            def _sync_fallback(*args: Any, **kwargs: Any) -> Any:
                timeout = _extract_timeout(kwargs)
                return portal.call(attr(*args, **kwargs), timeout=timeout)

            return _sync_fallback

        if inspect.isasyncgenfunction(attr):
            portal = getattr(self, self._portal_attr_name)

            @functools.wraps(attr)
            def _sync_gen_fallback(*args: Any, **kwargs: Any) -> Iterator[Any]:
                kw = dict(kwargs)
                buf_size = _extract_buffer_size(kw, 1000)
                timeout = _extract_timeout(kw)
                return portal.iter_async(
                    attr(*args, **kw),
                    buffer_size=buf_size,
                    timeout=timeout,
                )

            return _sync_gen_fallback

        return attr
