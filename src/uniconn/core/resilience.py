# src/uniconn/core/resilience.py
"""Примитивы отказоустойчивости: CircuitBreaker и RateLimiter (Token Bucket)."""

from __future__ import annotations

import asyncio
import threading
import time
from enum import StrEnum
from typing import Any

from ..exceptions import CircuitOpenError


class CircuitState(StrEnum):
    """Состояния автоматического выключателя (Circuit Breaker)."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """Автоматический выключатель (Circuit Breaker) для защиты от каскадных сбоев.

    Переходит из состояния ``CLOSED`` в ``OPEN`` после ``failure_threshold``
    последовательных сетевых сбоев или таймаутов. По истечении ``recovery_timeout``
    переходит в ``HALF_OPEN`` и пропускает до ``half_open_max_calls`` пробных
    запросов: при успехе возвращается в ``CLOSED``, при сбое — снова размыкается в ``OPEN``.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        half_open_max_calls: int = 1,
    ) -> None:
        """Инициализировать CircuitBreaker."""
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        if recovery_timeout <= 0:
            raise ValueError("recovery_timeout must be > 0")
        if half_open_max_calls < 1:
            raise ValueError("half_open_max_calls must be >= 1")

        self._failure_threshold = failure_threshold
        self._recovery_timeout = float(recovery_timeout)
        self._half_open_max_calls = half_open_max_calls

        self._state: CircuitState = CircuitState.CLOSED
        self._failure_count: int = 0
        self._opened_at: float | None = None
        self._half_open_calls: int = 0
        self._lock = threading.RLock()

    @property
    def failure_threshold(self) -> int:
        """Порог последовательных ошибок для размыкания цепи."""
        return self._failure_threshold

    @property
    def recovery_timeout(self) -> float:
        """Время ожидания в секундах перед переходом из OPEN в HALF_OPEN."""
        return self._recovery_timeout

    @property
    def failure_count(self) -> int:
        """Текущее число последовательных ошибок."""
        with self._lock:
            return self._failure_count

    @property
    def state(self) -> CircuitState:
        """Текущее состояние цепи (с учётом автоматического истечения recovery_timeout)."""
        with self._lock:
            if self._state == CircuitState.OPEN and self._opened_at is not None:
                elapsed = time.monotonic() - self._opened_at
                if elapsed >= self._recovery_timeout:
                    self._state = CircuitState.HALF_OPEN
                    self._half_open_calls = 0
            return self._state

    @property
    def remaining_seconds(self) -> float:
        """Оставшееся время в секундах до перехода из OPEN в HALF_OPEN (0.0 если не OPEN)."""
        with self._lock:
            if self._state != CircuitState.OPEN or self._opened_at is None:
                return 0.0
            rem = self._recovery_timeout - (time.monotonic() - self._opened_at)
            return max(0.0, round(rem, 3))

    def allow_request(self) -> bool:
        """Проверить, разрешён ли очередной запрос в текущем состоянии цепи."""
        with self._lock:
            current = self.state
            if current == CircuitState.CLOSED:
                return True
            if current == CircuitState.HALF_OPEN:
                if self._half_open_calls < self._half_open_max_calls:
                    self._half_open_calls += 1
                    return True
                return False
            return False

    def check_or_raise(
        self,
        *,
        host: str | None = None,
        command: str | None = None,
    ) -> None:
        """Проверить разрешение на вызов или выбросить ``CircuitOpenError``."""
        with self._lock:
            if not self.allow_request():
                rem = self.remaining_seconds
                target = host or "target"
                raise CircuitOpenError(
                    f"Circuit breaker is {self._state.value.upper()} for {target} "
                    f"(failures={self._failure_count}/{self._failure_threshold}, "
                    f"retry in {rem:.2f}s)",
                    host=host,
                    remaining_seconds=rem,
                    command=command,
                )

    def record_success(self) -> None:
        """Зафиксировать успешное выполнение и замкнуть цепь (CLOSED)."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._opened_at = None
            self._half_open_calls = 0

    def record_failure(self) -> None:
        """Зафиксировать сбой и при достижении порога разомкнуть цепь (OPEN)."""
        with self._lock:
            self._failure_count += 1
            if (
                self._state == CircuitState.HALF_OPEN
                or self._failure_count >= self._failure_threshold
            ):
                self._state = CircuitState.OPEN
                self._opened_at = time.monotonic()
                self._half_open_calls = 0

    def reset(self) -> None:
        """Принудительно сбросить CircuitBreaker в начальное состояние CLOSED."""
        self.record_success()

    def to_dict(self) -> dict[str, Any]:
        """Сериализовать состояние CircuitBreaker в словарь."""
        with self._lock:
            return {
                "state": self.state.value,
                "failure_count": self._failure_count,
                "failure_threshold": self._failure_threshold,
                "recovery_timeout": self._recovery_timeout,
                "remaining_seconds": self.remaining_seconds,
            }


class RateLimiter:
    """Асинхронный ограничитель частоты запросов (Token Bucket).

    Позволяет ограничить скорость запуска команд до ``rate`` операций в секунду
    с пиковой ёмкостью корзины ``burst`` токенов.
    """

    def __init__(self, rate: float, burst: int = 1) -> None:
        """Инициализировать RateLimiter."""
        if rate <= 0:
            raise ValueError("rate must be > 0")
        if burst < 1:
            raise ValueError("burst must be >= 1")

        self._rate = float(rate)
        self._burst = int(burst)
        self._tokens = float(burst)
        self._updated_at = time.monotonic()
        self._lock = asyncio.Lock()
        self._total_acquired = 0
        self._total_wait_seconds = 0.0

    @property
    def rate(self) -> float:
        """Разрешённое число операций в секунду."""
        return self._rate

    @property
    def burst(self) -> int:
        """Максимальная ёмкость корзины токенов."""
        return self._burst

    @property
    def total_acquired(self) -> int:
        """Общее число выданных разрешений."""
        return self._total_acquired

    @property
    def total_wait_seconds(self) -> float:
        """Суммарное время ожидания троттлинга в секундах."""
        return round(self._total_wait_seconds, 6)

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = max(0.0, now - self._updated_at)
        self._updated_at = now
        self._tokens = min(float(self._burst), self._tokens + elapsed * self._rate)

    async def acquire(self) -> float:
        """Получить токен на выполнение операции, при необходимости дождавшись пополнения.

        Returns:
            Время ожидания в секундах (0.0, если токен был доступен сразу).

        """
        async with self._lock:
            self._refill()
            wait_time = 0.0
            if self._tokens < 1.0:
                deficit = 1.0 - self._tokens
                wait_time = deficit / self._rate
                await asyncio.sleep(wait_time)
                self._refill()
            self._tokens = max(0.0, self._tokens - 1.0)
            self._total_acquired += 1
            self._total_wait_seconds += wait_time
            return round(wait_time, 6)

    def reset(self) -> None:
        """Сбросить корзину токенов и статистику ожидания."""
        self._tokens = float(self._burst)
        self._updated_at = time.monotonic()
        self._total_acquired = 0
        self._total_wait_seconds = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Сериализовать параметры и метрики RateLimiter в словарь."""
        return {
            "rate": self._rate,
            "burst": self._burst,
            "total_acquired": self._total_acquired,
            "total_wait_seconds": self.total_wait_seconds,
        }


__all__ = [
    "CircuitBreaker",
    "CircuitState",
    "RateLimiter",
]
