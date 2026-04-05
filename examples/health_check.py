"""
Проверка доступности хостов (health check).

Демонстрирует:
- is_alive() для одного хоста
- ping() для транспорта
- Массовая проверка пула хостов
"""

import asyncio
from uniconn import Connection, ConnectionPool


# ─── Single host ────────────────────────────────────────────────────

async def check_single_host():
    """Проверка одного хоста."""
    async with Connection.from_uri("ssh://user@host") as conn:
        if await conn.is_alive():
            print("Host is alive!")
        else:
            print("Host is unreachable")


async def check_single_host_timeout():
    """Проверка с таймаутом."""
    async with Connection.from_uri("ssh://user@host") as conn:
        alive = await conn.is_alive(timeout=5.0)
        print(f"Alive: {alive}")


# ─── Pool health check ──────────────────────────────────────────────

async def check_pool():
    """Массовая проверка хостов через ConnectionPool."""
    hosts = [
        "ssh://user:pass@node1",
        "ssh://user:pass@node2",
        "ssh://user:pass@node3",
        "ssh://user:pass@down-node",  # этот будет недоступен
    ]

    results = {}
    for host in hosts:
        try:
            async with Connection.from_uri(host) as conn:
                alive = await conn.is_alive(timeout=5.0)
                results[host] = "✅ alive" if alive else "❌ dead"
        except Exception as e:
            results[host] = f"❌ error: {e}"

    for host, status in results.items():
        print(f"  {host}: {status}")


# ─── Pool with map_safe ─────────────────────────────────────────────

async def check_pool_map_safe():
    """Проверка через map_safe — ошибки как значения."""
    hosts = [
        "ssh://user:pass@node1",
        "ssh://user:pass@down-node",
        "ssh://user:pass@node3",
    ]

    pool = ConnectionPool(hosts, max_concurrent=5)
    results = await pool.map_safe("echo alive")

    for uri, result in results.items():
        if isinstance(result, Exception):
            print(f"  {uri}: ❌ {type(result).__name__}")
        elif result.ok:
            print(f"  {uri}: ✅ alive")
        else:
            print(f"  {uri}: ❌ dead")


# ─── Before command ─────────────────────────────────────────────────

async def check_before_command():
    """Проверка перед выполнением команды."""
    async with Connection.from_uri("ssh://user@host") as conn:
        if not await conn.is_alive():
            print("Skipping — host is down")
            return

        result = await conn.run("uptime")
        print(result.stdout)


# ─── Main ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== Single Host Check ===")
    asyncio.run(check_single_host())

    print("\n=== Pool Check ===")
    asyncio.run(check_pool())
