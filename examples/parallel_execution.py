"""
Параллельное выполнение команд на множестве хостов.

Демонстрирует:
- ConnectionPool.map()
- ConnectionPool.map_safe()
- ConnectionPool.map_with_callback()
- Ограничение параллелизма
"""

import asyncio
from uniconn import ConnectionPool, Connection


# ─── Basic parallel execution ──────────────────────────────────────

async def basic_parallel():
    """Параллельное выполнение на нескольких хостах."""
    hosts = [
        "ssh://user:pass@node1",
        "ssh://user:pass@node2",
        "ssh://user:pass@node3",
    ]

    pool = ConnectionPool(hosts, max_concurrent=5)
    results = await pool.map("uptime")

    for host, result in zip(hosts, results):
        print(f"{host}: {result.stdout.strip()}")


# ─── map_safe — ошибки как значения ────────────────────────────────

async def map_safe():
    """Безопасное выполнение — ошибки не выбрасываются."""
    hosts = [
        "ssh://user:pass@node1",
        "ssh://user:pass@nonexistent-host",  # этот упадёт
        "ssh://user:pass@node3",
    ]

    pool = ConnectionPool(hosts, max_concurrent=3)
    results = await pool.map_safe("hostname")

    for uri, result in results.items():
        if isinstance(result, Exception):
            print(f"  {uri}: ERROR — {result}")
        else:
            print(f"  {uri}: {result.stdout.strip()}")


# ─── Callback по мере готовности ────────────────────────────────────

async def with_callback():
    """Выполнение с callback."""
    hosts = [
        "ssh://user:pass@node1",
        "ssh://user:pass@node2",
        "ssh://user:pass@node3",
    ]

    def on_complete(uri, result):
        status = "OK" if result.ok else "FAIL"
        print(f"[{status}] {uri}: {result.stdout.strip()}")

    pool = ConnectionPool(hosts, max_concurrent=5)
    await pool.map_with_callback("hostname", on_complete)


# ─── Limited concurrency ───────────────────────────────────────────

async def limited_concurrency():
    """Ограничение параллелизма."""
    hosts = [f"ssh://user:pass@node{i}" for i in range(1, 51)]

    # Не более 10 одновременных подключений
    pool = ConnectionPool(hosts, max_concurrent=10)
    results = await pool.map("uptime")

    successful = sum(1 for r in results if r.ok)
    print(f"Successful: {successful}/{len(hosts)}")


# ─── Retry per pool ─────────────────────────────────────────────────

async def with_retry():
    """Пул с retry при ошибках подключения."""
    hosts = [
        "ssh://user:pass@unstable-host",
        "ssh://user:pass@stable-host",
    ]

    pool = ConnectionPool(
        hosts,
        max_concurrent=5,
        retry_attempts=3,  # 3 попытки на каждый хост
    )
    results = await pool.map("uptime")

    for host, result in zip(hosts, results):
        print(f"  {host}: exit_code={result.exit_code}")


# ─── From file ──────────────────────────────────────────────────────

async def from_file():
    """Загрузка хостов из файла и параллельное выполнение.

    Файл hosts.json:
    [
        {"transport": "ssh", "host": "node1", "username": "admin"},
        {"transport": "ssh", "host": "node2", "username": "admin"}
    ]
    """
    conns = Connection.from_file("hosts.json")

    # Извлекаем URI из подключений для пула
    uris = [f"ssh://{c.config.host}" for c in conns]
    pool = ConnectionPool(uris, max_concurrent=5)
    results = await pool.map("hostname")

    for uri, result in zip(uris, results):
        print(f"  {uri}: {result.stdout.strip()}")


# ─── Main ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== Basic Parallel ===")
    asyncio.run(basic_parallel())
