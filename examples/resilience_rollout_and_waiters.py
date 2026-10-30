"""Отказоустойчивость (CircuitBreaker, RateLimiter), батч-роллаут, ожидание и SSH-туннели.

Демонстрирует:
- RateLimiter (Token Bucket) и CircuitBreaker (CLOSED -> OPEN -> HALF_OPEN)
- Каскадную раскатку пула (batch_size, max_fail_ratio, BatchAbortedError) и pool.select()
- Адаптивный SSHSessionPool (adaptive=True, resize(), stats())
- Проброс локальных и удалённых TCP-портов через conn.tunnels (forward_local_port / forward_remote_port)
"""

from __future__ import annotations

import asyncio

from uniconn import (
    BatchAbortedError,
    CircuitBreaker,
    CircuitOpenError,
    Connection,
    ConnectionPool,
    ExecutionError,
    RateLimiter,
    SSHSessionPool,
)

# ─── Справочные примеры для SSH-туннелей и SSHSessionPool ───────────


async def ssh_port_forwarding_and_session_pool_example() -> None:
    """Проброс портов через conn.tunnels и адаптивный мультиплексинг SSHSessionPool."""
    async with (
        Connection.from_uri("ssh://admin@bastion.internal") as conn,
        conn.tunnels.forward_local_port(
            remote_host="db.internal",
            remote_port=5432,
            local_port=0,
        ) as local_bound_port,
    ):
        print(f"Туннель открыт: 127.0.0.1:{local_bound_port} -> db.internal:5432")

    # Адаптивный пул каналов поверх SSH-подключения (авто-понижение при MaxSessions)
    async with SSHSessionPool(
        "ssh://admin@compute-node",
        max_sessions_per_conn=6,
        max_connections=4,
        adaptive=True,
    ) as ssh_pool:
        await ssh_pool.map(["uptime", "df -h", "free -m"])
        await ssh_pool.resize(max_sessions_per_conn=2, max_connections=2)


# ─── Самодостаточная локальная демонстрация ─────────────────────────


async def main() -> None:
    """Локальная демонстрация RateLimiter, CircuitBreaker и волнового роллаута."""
    print("=== 1. Ограничение частоты запросов (RateLimiter) ===")
    limiter = RateLimiter(rate=50.0, burst=5)
    async with Connection.local(rate_limit=limiter) as conn:
        res = await conn.run(["echo", "rate-limited-ok"])
        print(f"Выполнено с RateLimiter: {res.text}")

    print("\n=== 2. Автоматический предохранитель (CircuitBreaker -> CircuitOpenError) ===")
    breaker = CircuitBreaker(failure_threshold=2, recovery_timeout=10.0)
    async with Connection.local(circuit_breaker=breaker, retry_attempts=1) as conn:
        for attempt in range(1, 3):
            try:
                await conn.run(["python3", "-c", "import sys; sys.exit(1)"], raise_on_error=True)
            except ExecutionError:
                print(f"  Сбой #{attempt}: state={breaker.state.value}")

        try:
            await conn.run(["echo", "should-be-blocked"])
        except CircuitOpenError as err:
            print(f"  CircuitBreaker разомкнут ({breaker.state.value}): вызов мгновенно отклонён ({err})")

    print("\n=== 3. Волновой роллаут ConnectionPool (batch_size + max_fail_ratio) ===")
    nodes = [
        Connection.local().with_overrides(host=f"app-{i}")
        for i in range(1, 5)
    ]
    async with ConnectionPool(nodes, max_concurrent=2, batch_size=2, max_fail_ratio=0.5) as pool:
        # Выборка канареечной группы через select()
        canary = pool.select(["app-1", "app-2"])
        pings = await canary.ping()
        print("Canary batch ping:", {k: p.alive for k, p in pings.items()})

        # Демонстрация автоматической остановки раскатки при превышении порога ошибок
        try:
            await pool.map(
                ["python3", "-c", "import sys; sys.exit(1)"],
                raise_on_error=True,
                batch_size=2,
                max_fail_ratio=0.0,
            )
        except BatchAbortedError as err:
            print(
                f"BatchAbortedError: раскатка остановлена после батча #{err.batch_index} "
                f"(fail_ratio={err.fail_ratio:.0%}, упавших хостов: {len(err.failed_hosts)})"
            )


if __name__ == "__main__":
    asyncio.run(main())
