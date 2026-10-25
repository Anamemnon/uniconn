# src/uniconn/pool/session_pool.py
"""Пул SSH-сессий для одного хоста с адаптивным управлением лимитами.

Позволяет выполнять множество команд через ограниченное число
SSH-соединений, каждое из которых мультиплексирует каналы.
Поддерживает автоматическое снижение ``max_sessions_per_conn`` (при упоре в
``MaxSessions`` на сервере) и ``max_connections`` (при упоре в ``MaxStartups``),
а также динамическое изменение лимитов ``resize()`` с мягким дренажем.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Self

from ..core.connection import Connection, _resolve_rate_limiter
from ..core.resilience import CircuitBreaker, RateLimiter
from ..exceptions import (
    CircuitOpenError,
    ConfigurationError,
    ConnectionError,
    TimeoutError,
)
from ..result import Result

_CHANNEL_LIMIT_HINTS: tuple[str, ...] = (
    "channel",
    "administratively prohibited",
    "maxsessions",
    "open failed",
    "no more sessions",
    "session request failed",
)


@dataclass(slots=True)
class _PooledConnectionSlot:
    """Слот одного TCP/SSH-соединения в ``SSHSessionPool``."""

    conn: Connection
    in_flight: int = 0
    opening_or_running: int = 0
    draining: bool = False
    closed: bool = False
    ever_succeeded: bool = False


class SSHSessionPool:
    """Пул SSH-соединений с динамическим и адаптивным ограничением числа каналов и соединений."""

    def __init__(
        self,
        uri: str,
        max_sessions_per_conn: int = 6,
        max_connections: int = 6,
        retry_attempts: int = 3,
        logger: logging.Logger | None = None,
        health_check: bool = False,
        rate_limit: float | RateLimiter | None = None,
        circuit_breaker: CircuitBreaker | bool = False,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        adaptive: bool = True,
        min_sessions_per_conn: int = 1,
    ) -> None:
        """Инициализировать SSHSessionPool."""
        if max_sessions_per_conn < 1:
            raise ConfigurationError("max_sessions_per_conn must be >= 1")
        if max_connections < 1:
            raise ConfigurationError("max_connections must be >= 1")
        if min_sessions_per_conn < 1:
            raise ConfigurationError("min_sessions_per_conn must be >= 1")

        self._uri = uri
        self._max_sessions = max_sessions_per_conn
        self._max_connections = max_connections
        self._min_sessions = min(min_sessions_per_conn, max_sessions_per_conn)
        self._adaptive = adaptive
        self._retry_attempts = retry_attempts
        self._logger = logger or logging.getLogger(__name__)
        self._health_check = health_check
        self._rate_limiter = _resolve_rate_limiter(rate_limit, {})
        if isinstance(circuit_breaker, CircuitBreaker):
            self._circuit_breaker: CircuitBreaker | None = circuit_breaker
        elif circuit_breaker is True:
            self._circuit_breaker = CircuitBreaker(
                failure_threshold=failure_threshold,
                recovery_timeout=recovery_timeout,
            )
        else:
            self._circuit_breaker = None

        self._slots: list[_PooledConnectionSlot] = []
        self._semaphores: list[asyncio.Semaphore] = []
        self._condition = asyncio.Condition()
        self._scale_down_events = 0

    @property
    def _connections(self) -> list[Connection]:
        """Список открытых соединений пула (для обратной совместимости)."""
        return [s.conn for s in self._slots if not s.closed]

    @_connections.setter
    def _connections(self, value: Sequence[Connection]) -> None:
        """Установить список соединений пула (для обратной совместимости в тестах)."""
        self._slots = [_PooledConnectionSlot(conn=c) for c in value]

    @property
    def max_sessions_per_conn(self) -> int:
        """Текущий эффективный лимит одновременных каналов на одно соединение."""
        return self._max_sessions

    @property
    def max_connections(self) -> int:
        """Текущий эффективный лимит количества SSH-соединений в пуле."""
        return self._max_connections

    @property
    def min_sessions_per_conn(self) -> int:
        """Минимальный порог автоматического снижения каналов на соединение."""
        return self._min_sessions

    @property
    def adaptive(self) -> bool:
        """Включено ли автоматическое снижение лимитов при отказах сервера."""
        return self._adaptive

    @property
    def scale_down_events(self) -> int:
        """Количество срабатываний автоматического понижения лимитов."""
        return self._scale_down_events

    @property
    def active_connections(self) -> int:
        """Количество активных (не находящихся в дренаже) открытых соединений."""
        return sum(1 for s in self._slots if not s.draining and not s.closed)

    @property
    def draining_connections(self) -> int:
        """Количество соединений, ожидающих завершения текущих команд перед закрытием."""
        return sum(1 for s in self._slots if s.draining and not s.closed)

    @property
    def in_flight_sessions(self) -> int:
        """Суммарное количество выполняющихся в данный момент команд во всех слотах."""
        return sum(s.in_flight for s in self._slots if not s.closed)

    @property
    def rate_limiter(self) -> RateLimiter | None:
        """Ограничитель скорости команд пула SSH-сессий (если настроен)."""
        return self._rate_limiter

    @property
    def circuit_breaker(self) -> CircuitBreaker | None:
        """Автоматический предохранитель пула SSH-сессий (если настроен)."""
        return self._circuit_breaker

    def stats(self) -> dict[str, Any]:
        """Вернуть сводку текущих лимитов и телеметрии пула."""
        return {
            "uri": self._uri,
            "max_sessions_per_conn": self._max_sessions,
            "max_connections": self._max_connections,
            "min_sessions_per_conn": self._min_sessions,
            "adaptive": self._adaptive,
            "active_connections": self.active_connections,
            "draining_connections": self.draining_connections,
            "in_flight_sessions": self.in_flight_sessions,
            "scale_down_events": self._scale_down_events,
        }

    async def resize(
        self,
        *,
        max_sessions_per_conn: int | None = None,
        max_connections: int | None = None,
    ) -> dict[str, Any]:
        """Динамически изменить лимиты каналов и соединений на лету."""
        if max_sessions_per_conn is not None and max_sessions_per_conn < 1:
            raise ConfigurationError("max_sessions_per_conn must be >= 1")
        if max_connections is not None and max_connections < 1:
            raise ConfigurationError("max_connections must be >= 1")

        idle_to_close: list[Connection] = []
        async with self._condition:
            if max_sessions_per_conn is not None:
                self._max_sessions = max_sessions_per_conn
                if self._min_sessions > self._max_sessions:
                    self._min_sessions = self._max_sessions

            if max_connections is not None:
                self._max_connections = max_connections
                active_slots = [
                    s for s in self._slots if not s.draining and not s.closed
                ]
                excess = len(active_slots) - self._max_connections
                if excess > 0:
                    candidates = sorted(
                        active_slots,
                        key=lambda s: s.in_flight,
                    )
                    for slot in candidates[:excess]:
                        slot.draining = True
                        if slot.in_flight == 0 and not slot.closed:
                            slot.closed = True
                            if slot in self._slots:
                                self._slots.remove(slot)
                            idle_to_close.append(slot.conn)

            self._condition.notify_all()

        for conn in idle_to_close:
            await conn.close()

        return self.stats()

    async def _acquire_slot(self) -> tuple[_PooledConnectionSlot, bool]:
        """Получить доступный слот соединения или создать новое соединение при наличии квоты."""
        async with self._condition:
            while True:
                for slot in self._slots:
                    if (
                        not slot.draining
                        and not slot.closed
                        and slot.in_flight < self._max_sessions
                    ):
                        slot.in_flight += 1
                        return slot, False

                active_count = sum(
                    1 for s in self._slots if not s.draining and not s.closed
                )
                if active_count < self._max_connections:
                    self._logger.debug(
                        f"Creating SSH connection #{active_count + 1} for {self._uri}"
                    )
                    conn = Connection.from_uri(
                        self._uri,
                        retry_attempts=self._retry_attempts,
                        logger=self._logger,
                    )
                    new_slot = _PooledConnectionSlot(conn=conn, in_flight=1)
                    self._slots.append(new_slot)
                    return new_slot, True

                await self._condition.wait()

    async def _release_slot(self, slot: _PooledConnectionSlot) -> None:
        """Освободить слот и закрыть соединение, если оно в режиме дренажа и не имеет задач."""
        conn_to_close: Connection | None = None
        async with self._condition:
            slot.in_flight = max(0, slot.in_flight - 1)
            if slot.draining and slot.in_flight == 0 and not slot.closed:
                slot.closed = True
                if slot in self._slots:
                    self._slots.remove(slot)
                conn_to_close = slot.conn
            self._condition.notify_all()

        if conn_to_close is not None:
            await conn_to_close.close()

    @staticmethod
    async def _is_conn_alive_safe(conn: Connection) -> bool:
        """Безопасно проверить живость соединения без выброса исключений."""
        is_alive_fn = getattr(conn, "is_alive", None)
        if not callable(is_alive_fn):
            return True
        try:
            res = is_alive_fn()
            if asyncio.iscoroutine(res):
                return bool(await res)
            return bool(res)
        except Exception:
            return False

    @staticmethod
    def _has_channel_limit_hint(exc: BaseException) -> bool:
        """Проверить, содержит ли ошибка признаки отказа открытия SSH-канала (MaxSessions)."""
        msg = str(exc).lower()
        return any(hint in msg for hint in _CHANNEL_LIMIT_HINTS)

    async def _try_adaptive_recovery(
        self,
        slot: _PooledConnectionSlot,
        exc: Exception,
        channel_idx: int,
    ) -> bool:
        """Попытаться адаптировать лимиты пула при отказе канала или нового соединения."""
        if not self._adaptive or isinstance(exc, CircuitOpenError):
            return False

        if not slot.ever_succeeded and channel_idx == 1:
            async with self._condition:
                other_active = [
                    s
                    for s in self._slots
                    if s is not slot and not s.draining and not s.closed
                ]
                if len(other_active) >= 1:
                    slot.draining = True
                    new_max_conns = max(1, len(other_active))
                    if new_max_conns < self._max_connections:
                        old_max = self._max_connections
                        self._max_connections = new_max_conns
                        self._scale_down_events += 1
                        self._logger.warning(
                            f"Adaptive SSHSessionPool ({self._uri}): new connection rejected; "
                            f"scaling down max_connections {old_max} -> {new_max_conns}"
                        )
                    self._condition.notify_all()
                    return True

        has_hint = self._has_channel_limit_hint(exc)
        if channel_idx > 1 or (
            slot.ever_succeeded
            and has_hint
            and self._max_sessions > self._min_sessions
        ):
            conn_alive = (
                True if has_hint else await self._is_conn_alive_safe(slot.conn)
            )
            if conn_alive:
                async with self._condition:
                    if channel_idx > 1:
                        target_sessions = max(self._min_sessions, channel_idx - 1)
                    else:
                        target_sessions = max(
                            self._min_sessions, self._max_sessions // 2
                        )

                    if target_sessions < self._max_sessions:
                        old_sessions = self._max_sessions
                        self._max_sessions = target_sessions
                        self._scale_down_events += 1
                        self._logger.warning(
                            f"Adaptive SSHSessionPool ({self._uri}): channel limit reached at "
                            f"concurrency={channel_idx}; scaling down max_sessions_per_conn "
                            f"{old_sessions} -> {target_sessions}"
                        )
                        self._condition.notify_all()
                        return True
                    if channel_idx > self._max_sessions:
                        return True

        return False

    async def _run_on_slot(
        self,
        slot: _PooledConnectionSlot,
        command: str,
        **kwargs: Any,
    ) -> tuple[Result | None, bool]:
        """Выполнить команду в выделенном слоте."""
        if self._circuit_breaker is not None:
            self._circuit_breaker.check_or_raise(host=self._uri, command=command)
        if self._rate_limiter is not None:
            await self._rate_limiter.acquire()

        slot.opening_or_running += 1
        channel_idx = slot.opening_or_running
        try:
            transport = getattr(slot.conn, "transport", None) or getattr(
                slot.conn, "_transport", None
            )
            is_connected = getattr(transport, "is_connected", True)
            if (
                self._health_check
                and is_connected
                and not await slot.conn.is_alive()
            ):
                self._logger.debug(
                    f"Unhealthy connection detected in SSHSessionPool for {self._uri}; reconnecting"
                )
                await slot.conn.close()
            res = await slot.conn.run(command, **kwargs)
        except (ConnectionError, TimeoutError, OSError) as exc:
            recovered = await self._try_adaptive_recovery(slot, exc, channel_idx)
            if recovered:
                return None, True
            if self._circuit_breaker is not None:
                self._circuit_breaker.record_failure()
            raise
        else:
            slot.ever_succeeded = True
            if self._circuit_breaker is not None:
                self._circuit_breaker.record_success()
            return res, False
        finally:
            slot.opening_or_running = max(0, slot.opening_or_running - 1)

    async def check_health(self, timeout: float | None = None) -> int:
        """Проверить живость всех соединений пула и удалить оборванные."""
        dead_conns: list[Connection] = []
        async with self._condition:
            for slot in list(self._slots):
                if slot.closed:
                    continue
                if await slot.conn.is_alive(timeout=timeout):
                    continue
                slot.draining = True
                if slot.in_flight == 0:
                    slot.closed = True
                    self._slots.remove(slot)
                    dead_conns.append(slot.conn)
            self._condition.notify_all()

        for conn in dead_conns:
            await conn.close()
        return self.active_connections

    async def _execute(self, command: str, **kwargs: Any) -> Result:
        """Выполнить команду через доступный слот с поддержкой адаптивного повтора."""
        max_adaptive_attempts = 8
        for _ in range(max_adaptive_attempts):
            slot, _ = await self._acquire_slot()
            try:
                res, retry_adaptively = await self._run_on_slot(
                    slot, command, **kwargs
                )
                if not retry_adaptively and res is not None:
                    return res
            finally:
                await self._release_slot(slot)

        slot, _ = await self._acquire_slot()
        try:
            res, _ = await self._run_on_slot(slot, command, **kwargs)
            assert res is not None
            return res
        finally:
            await self._release_slot(slot)

    async def run(self, command: str, **kwargs: Any) -> Result:
        """Выполнить одну команду через пул."""
        return await self._execute(command, **kwargs)

    async def map(
        self,
        commands: Sequence[str],
        timeout: float | None = None,
        raise_on_error: bool = False,
    ) -> list[Result]:
        """Выполнить несколько команд параллельно."""
        async with asyncio.TaskGroup() as tg:
            tasks = [
                tg.create_task(
                    self._execute(
                        cmd,
                        timeout=timeout,
                        raise_on_error=raise_on_error,
                    )
                )
                for cmd in commands
            ]
        return [t.result() for t in tasks]

    async def close(self) -> None:
        """Закрыть все соединения в пуле."""
        async with self._condition:
            slots_to_close = [s for s in self._slots if not s.closed]
            for s in slots_to_close:
                s.draining = True
                s.closed = True
            self._slots.clear()
            self._condition.notify_all()

        for s in slots_to_close:
            await s.conn.close()

    async def __aenter__(self) -> Self:
        """Войти в контекстный менеджер пула."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Закрыть все соединения при выходе из контекста."""
        await self.close()
