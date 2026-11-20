# src/uniconn/orchestration/_barrier_window.py
"""Ограниченное LRU-окно открытых соединений для барьерного исполнения DAG на больших флотах."""

from __future__ import annotations

import asyncio
import contextlib
from collections import OrderedDict
from collections.abc import Hashable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ..services.provisioning._notify import NotificationBatch, NotifyCallable

if TYPE_CHECKING:
    from ..core.connection import Connection
    from ..pool.connection_pool import ConnectionPool


@dataclass(slots=True)
class _WindowedHostConn:
    """Запись открытого соединения хоста внутри ограниченного LRU-окна барьерной раскатки."""

    idx: int
    key: str
    conn: Connection
    stack: contextlib.AsyncExitStack
    batch: NotificationBatch | None = None
    in_use: int = 0


class _BarrierConnectionWindow:
    """Ограниченное LRU-окно соединений для ``run_barrier_fleet`` с сохранением ``NotificationBatch``."""

    def __init__(
        self,
        pool: ConnectionPool,
        *,
        max_open: int,
        batch_notifications: bool,
    ) -> None:
        self._pool = pool
        self._max_open = max(1, max_open)
        self._batch_notifications = batch_notifications
        self._entries: OrderedDict[int, _WindowedHostConn] = OrderedDict()
        self._opening: set[int] = set()
        self._detached_notifications: dict[
            str, list[tuple[Hashable, str, NotifyCallable, Any]]
        ] = {}
        self._cond = asyncio.Condition()

    def _stash_entry_notifications(self, entry: _WindowedHostConn) -> None:
        if entry.batch is None:
            return
        specs = entry.batch.drain_pending_specs()
        if specs:
            self._detached_notifications.setdefault(entry.key, []).extend(specs)
        with contextlib.suppress(Exception):
            entry.conn.state.discard_batch(entry.batch)
        entry.batch = None

    async def _close_entry(self, entry: _WindowedHostConn) -> None:
        self._stash_entry_notifications(entry)
        with contextlib.suppress(Exception):
            await entry.stack.aclose()

    async def acquire(self, idx: int, target: Any, key: str) -> _WindowedHostConn:
        """Получить (или открыть с LRU-вытеснением) соединение хоста и увеличить счётчик ``in_use``."""
        evicted: _WindowedHostConn | None = None
        async with self._cond:
            while True:
                existing = self._entries.get(idx)
                if existing is not None:
                    self._entries.move_to_end(idx)
                    existing.in_use += 1
                    return existing

                if idx in self._opening:
                    await self._cond.wait()
                    continue

                total_slots = len(self._entries) + len(self._opening)
                if total_slots < self._max_open:
                    self._opening.add(idx)
                    break

                victim_idx: int | None = None
                for cand_idx, cand_entry in self._entries.items():
                    if cand_entry.in_use == 0:
                        victim_idx = cand_idx
                        break

                if victim_idx is not None:
                    evicted = self._entries.pop(victim_idx)
                    self._opening.add(idx)
                    break

                await self._cond.wait()

        host_stack = contextlib.AsyncExitStack()
        try:
            if evicted is not None:
                await self._close_entry(evicted)
            conn = await host_stack.enter_async_context(
                self._pool.use_target_connection(idx, target, with_defaults=True)
            )
            nb: NotificationBatch | None = None
            if self._batch_notifications:
                nb = conn.state.batch_notifications()
                await nb.__aenter__()
                prior_specs = self._detached_notifications.pop(key, ())
                if prior_specs:
                    nb.restore_pending_specs(prior_specs, conn)
        except BaseException:
            with contextlib.suppress(Exception):
                await host_stack.aclose()
            async with self._cond:
                self._opening.discard(idx)
                self._cond.notify_all()
            raise

        entry = _WindowedHostConn(
            idx=idx,
            key=key,
            conn=conn,
            stack=host_stack,
            batch=nb,
            in_use=1,
        )
        async with self._cond:
            self._opening.discard(idx)
            self._entries[idx] = entry
            self._cond.notify_all()
        return entry

    async def release(self, entry: _WindowedHostConn, *, close_now: bool = False) -> None:
        """Освободить аренду соединения (и при ``close_now=True`` закрыть его немедленно)."""
        to_close: _WindowedHostConn | None = None
        async with self._cond:
            entry.in_use = max(0, entry.in_use - 1)
            if close_now and entry.in_use == 0:
                popped = self._entries.pop(entry.idx, None)
                if popped is not None:
                    to_close = popped
            self._cond.notify_all()
        if to_close is not None:
            await self._close_entry(to_close)

    async def close_all(self) -> None:
        """Гарантированно очистить все батчи и закрыть все открытые соединения окна."""
        async with self._cond:
            entries = list(self._entries.values())
            self._entries.clear()
            self._detached_notifications.clear()
            self._cond.notify_all()
        for entry in entries:
            await self._close_entry(entry)


__all__ = ["_BarrierConnectionWindow", "_WindowedHostConn"]
