# src/uniconn/core/bridge.py
"""Универсальный портал исполнения асинхронных корутин и генераторов в фоновом daemon-потоке.

Устраняет дублирование кода управления event loop между ``SyncConnection``,
``SyncConnectionPool`` и ``SyncShellSession`` и переиспользует единый
разделяемый фоновый цикл событий (Singleton Event Loop Portal).
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import threading
from collections.abc import AsyncIterator, Iterator
from typing import Any, ClassVar, Generic, TypeVar

T = TypeVar("T")
_STREAM_DONE = object()


class EventLoopPortal:
    """Управляет разделяемым ``asyncio.AbstractEventLoop`` в фоновом daemon-потоке.

    Безопасно исполняет корутины, асинхронные контекстные менеджеры и
    асинхронные генераторы из синхронного кода через ``run_coroutine_threadsafe``.
    Все экземпляры ``EventLoopPortal`` разделяют один общий daemon-поток,
    предотвращая создание десятков потоков ОС при работе с множеством ``SyncConnection``.
    """

    _shared_loop: ClassVar[asyncio.AbstractEventLoop | None] = None
    _shared_thread: ClassVar[threading.Thread | None] = None
    _shared_lock: ClassVar[threading.Lock] = threading.Lock()

    def __init__(self, owner_name: str = "SyncPortal") -> None:
        """Инициализировать портал фонового цикла событий."""
        self._owner_name = owner_name
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
        with cls._shared_lock:
            if (
                cls._shared_loop is None
                or cls._shared_loop.is_closed()
                or cls._shared_thread is None
                or not cls._shared_thread.is_alive()
            ):
                loop = asyncio.new_event_loop()
                thread = threading.Thread(
                    target=cls._run_loop_forever,
                    args=(loop,),
                    name="uniconn-event-loop-portal",
                    daemon=True,
                )
                thread.start()
                cls._shared_loop = loop
                cls._shared_thread = thread
            return cls._shared_loop, cls._shared_thread

    def get_loop(self) -> asyncio.AbstractEventLoop:
        """Вернуть активный фоновый event loop в daemon-потоке."""
        loop, thread = self._ensure_shared_loop()
        self._loop = loop
        self._loop_thread = thread
        return loop

    def call(self, coro: Any) -> Any:
        """Синхронно выполнить корутину в фоновом event loop и вернуть результат."""
        if self._loop_thread is None and self._shared_thread is not None:
            self._loop_thread = self._shared_thread
        if self._loop_thread is not None and threading.current_thread() is self._loop_thread:
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

        loop = self.get_loop()
        caller_ctx = contextvars.copy_context()

        async def _run_in_caller_context() -> Any:
            for var, val in caller_ctx.items():
                var.set(val)
            return await coro

        future = asyncio.run_coroutine_threadsafe(_run_in_caller_context(), loop)
        return future.result()

    def iter_async(self, async_gen: AsyncIterator[T]) -> Iterator[T]:
        """Преобразовать асинхронный генератор в синхронный итератор через очередь."""
        if self._loop_thread is None and self._shared_thread is not None:
            self._loop_thread = self._shared_thread
        if self._loop_thread is not None and threading.current_thread() is self._loop_thread:
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

        loop = self.get_loop()
        caller_ctx = contextvars.copy_context()
        q: asyncio.Queue[Any] = asyncio.Queue(maxsize=1000)

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
                item = asyncio.run_coroutine_threadsafe(q.get(), loop).result()
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
