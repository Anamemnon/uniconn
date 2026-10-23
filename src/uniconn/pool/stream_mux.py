# src/uniconn/pool/stream_mux.py
"""Мультиплексор потокового вывода команд с группы хостов (ConnectionPool.stream)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Sequence
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .._pool import ConnectionPool, PoolTarget


class PoolStreamMultiplexer:
    """Объединяет потоки ``conn.stream()`` от всех хостов пула в единую ``asyncio.Queue``."""

    def __init__(self, pool: ConnectionPool) -> None:
        """Инициализировать мультиплексор потоков для пула подключений."""
        self._pool = pool

    async def stream(
        self,
        command: str | Sequence[str],
        timeout: float | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[tuple[str, str]]:
        """Запустить конкурентное чтение строк со всех хостов пула."""
        if not self._pool._uris:
            return

        done_sentinel = object()
        queue: asyncio.Queue[tuple[str, str] | BaseException | object] = asyncio.Queue()

        async def _pump_host(idx: int, target: PoolTarget) -> None:
            key = self._pool._target_key(target)
            try:
                async with (
                    self._pool._semaphore,
                    self._pool._use_conn(idx, target, with_defaults=True) as conn,
                ):
                    async for line in conn.stream(command, timeout=timeout, **kwargs):
                        await queue.put((key, line))
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                await queue.put(exc)
            finally:
                await queue.put(done_sentinel)

        tasks = [
            asyncio.create_task(_pump_host(idx, target))
            for idx, target in enumerate(self._pool._uris)
        ]
        finished_hosts = 0
        total_hosts = len(tasks)

        try:
            while finished_hosts < total_hosts:
                item = await queue.get()
                if item is done_sentinel:
                    finished_hosts += 1
                    continue
                if isinstance(item, BaseException):
                    raise item
                if isinstance(item, tuple):
                    yield item
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
