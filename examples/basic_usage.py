"""
Базовое использование uniconn.

Демонстрирует:
- Подключение через URI и Config
- Async и Sync API
- Выполнение команд
- Потоковый вывод
- Клонирование подключений
"""

import asyncio
from uniconn import Connection, ConnectionConfig


# ─── Async API ──────────────────────────────────────────────────────

async def async_basic():
    """Базовое async подключение."""
    async with Connection.from_uri("ssh://user:pass@host") as conn:
        result = await conn.run("uptime")
        print(f"Exit code: {result.exit_code}")
        print(f"Duration: {result.duration:.2f}s")
        print(f"Output: {result.stdout}")


async def async_with_timeout():
    """Выполнение с таймаутом."""
    async with Connection.from_uri("ssh://user@host") as conn:
        try:
            result = await conn.run("sleep 100", timeout=5.0)
        except TimeoutError:
            print("Command timed out!")


async def async_raise_on_error():
    """Исключение при ошибке."""
    async with Connection.from_uri("ssh://user@host") as conn:
        try:
            result = await conn.run("false", raise_on_error=True)
        except Exception as e:
            print(f"Command failed: {e}")


# ─── Sync API ───────────────────────────────────────────────────────

def sync_basic():
    """Базовое синхронное подключение."""
    with Connection.from_uri("ssh://user@host").to_sync() as conn:
        result = conn.run("whoami")
        print(result.stdout)


def sync_with_config():
    """Синхронное подключение из Config."""
    config = ConnectionConfig(
        transport="local",
        host="localhost",
        timeout=30.0,
    )
    with Connection.from_config(config).to_sync() as conn:
        result = conn.run("echo hello from local")
        print(result.stdout)


# ─── Streaming ──────────────────────────────────────────────────────

async def streaming():
    """Потоковый вывод команды."""
    async with Connection.from_uri("ssh://user@host") as conn:
        async for line in conn.stream("tail -f /var/log/syslog"):
            print(line)


# ─── Config ─────────────────────────────────────────────────────────

async def from_config():
    """Подключение из ConnectionConfig."""
    config = ConnectionConfig(
        transport="ssh",
        host="example.com",
        port=22,
        username="admin",
        timeout=60.0,
        options={"compress": True},
    )

    async with Connection.from_config(config) as conn:
        result = await conn.run("uname -a")
        print(result.stdout)


async def from_dict():
    """Подключение из словаря."""
    async with Connection.from_dict({
        "transport": "ssh",
        "host": "example.com",
        "username": "admin",
        "timeout": 60,
    }) as conn:
        result = await conn.run("date")
        print(result.stdout)


async def from_file():
    """Подключение из JSON файла.

    Файл hosts.json:
    [
        {"transport": "ssh", "host": "node1"},
        {"transport": "ssh", "host": "node2", "username": "admin"}
    ]
    """
    conns = Connection.from_file("hosts.json")
    for conn in conns:
        async with conn:
            result = await conn.run("hostname")
            print(result.stdout)


# ─── Clone / Override ───────────────────────────────────────────────

async def copy_connection():
    """Клонирование подключения."""
    prod = Connection.from_uri("ssh://admin@prod-server")

    # Клон с другим хостом
    dev = prod.copy(host="dev-server", timeout=120)

    async with dev:
        result = await dev.run("hostname")
        print(result.stdout)


async def with_overrides():
    """Override через словарь."""
    prod = Connection.from_uri("ssh://admin@prod:22")

    staging = prod.with_overrides(
        host="staging",
        timeout=60,
        options={"compress": True},
    )

    async with staging:
        result = await staging.run("hostname")
        print(result.stdout)


# ─── Main ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Синхронный пример
    print("=== Sync API ===")
    sync_basic()

    # Асинхронный пример
    print("\n=== Async API ===")
    asyncio.run(async_basic())
