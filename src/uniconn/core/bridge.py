# src/uniconn/core/bridge.py
"""Универсальный портал исполнения асинхронных корутин и генераторов в фоновом daemon-потоке.

Устраняет дублирование кода управления event loop между ``SyncConnection``,
``SyncConnectionPool`` и ``SyncShellSession``.
"""

from __future__ import annotations

import asyncio
import contextlib
import threading
from collections.abc import AsyncIterator, Iterator
from typing import Any, Generic, TypeVar

T = TypeVar("T")
_STREAM_DONE = object()


class EventLoopPortal:
    """Управляет выделенным ``asyncio.AbstractEventLoop`` в фоновом daemon-потоке.

    Безопасно исполняет корутины, асинхронные контекстные менеджеры и
    асинхронные генераторы из синхронного кода через ``run_coroutine_threadsafe``.
    """

    def __init__(self, owner_name: str = "SyncPortal") -> None:
        """Инициализировать портал фонового цикла событий."""
        self._owner_name = owner_name
        self._loop: asyncio.AbstractEventLoop | None = None
        self._loop_thread: threading.Thread | None = None
        self._loop_lock = threading.Lock()
        self._closed = False

    @property
    def closed(self) -> bool:
        """Признак того, что портал закрыт."""
        return self._closed

    @staticmethod
    def _run_loop_forever(loop: asyncio.AbstractEventLoop) -> None:
        """Запустить event loop до вызова ``loop.stop()``."""
        asyncio.set_event_loop(loop)
        try:
            loop.run_forever()
        finally:
            asyncio.set_event_loop(None)

    def get_loop(self) -> asyncio.AbstractEventLoop:
        """Лениво создать и запустить фоновый event loop в daemon-потоке."""
        with self._loop_lock:
            if self._loop is None or self._loop.is_closed():
                self._loop = asyncio.new_event_loop()
                self._loop_thread = threading.Thread(
                    target=self._run_loop_forever,
                    args=(self._loop,),
                    daemon=True,
                )
                self._loop_thread.start()
            return self._loop

    def call(self, coro: Any) -> Any:
        """Синхронно выполнить корутину в фоновом event loop и вернуть результат."""
        if self._closed:
            with contextlib.suppress(Exception):
                coro.close()
            raise RuntimeError(f"{self._owner_name} уже закрыт")

        loop = self.get_loop()
        future = asyncio.run_coroutine_threadsafe(coro, loop)
        return future.result()

    def iter_async(self, async_gen: AsyncIterator[T]) -> Iterator[T]:
        """Преобразовать асинхронный генератор в синхронный итератор через очередь."""
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
        q: asyncio.Queue[Any] = asyncio.Queue()

        async def _pump() -> None:
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
        """Выполнить финальную корутину очистки и остановить фоновый event loop."""
        if self._closed:
            if cleanup_coro is not None:
                with contextlib.suppress(Exception):
                    cleanup_coro.close()
            return

        if cleanup_coro is not None:
            with contextlib.suppress(Exception):
                self.call(cleanup_coro)

        self._closed = True

        with self._loop_lock:
            if self._loop and not self._loop.is_closed():
                self._loop.call_soon_threadsafe(self._loop.stop)
            thread = self._loop_thread

        if thread is not None:
            thread.join(timeout=5.0)

        with self._loop_lock:
            if self._loop and not self._loop.is_closed():
                self._loop.close()
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
