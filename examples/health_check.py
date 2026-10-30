"""Проверка доступности хостов (ping, is_alive) и примитивы ожидания (wait_for_*).

Демонстрирует:
- conn.ping() и pool.ping() -> PingResult (alive, latency_ms, transport, error)
- conn.is_alive() — быстрая булева проверка живости транспорта
- conn.wait_for_connection() — ожидание готовности соединения
- conn.wait_for_port() — ожидание открытия или закрытия TCP-порта
- conn.wait_for_path() — ожидание появления файла и паттерна (content_regex)
"""

from __future__ import annotations

import asyncio
import socket
import tempfile
from pathlib import Path

from uniconn import Connection, ConnectionPool

# ─── Справочный пример для удалённых SSH-хостов ─────────────────────


async def ssh_wait_after_reboot_example() -> None:
    """Ожидание возвращения сервера после перезагрузки и старта PostgreSQL."""
    async with Connection.from_uri("ssh://admin@db-node-01") as conn:
        # 1. Дождаться доступности SSH-транспорта
        ping_res = await conn.wait_for_connection(timeout=120.0, interval=2.0)
        print(f"Host is back online ({ping_res.latency_ms:.1f} ms)")

        # 2. Дождаться открытия порта PostgreSQL (5432) на самом сервере
        elapsed = await conn.wait_for_port(5432, state="open", check_from="remote", timeout=60.0)
        print(f"PostgreSQL port 5432 opened in {elapsed:.2f}s")


# ─── Самодостаточная локальная демонстрация ─────────────────────────


async def main() -> None:
    """Локальная демонстрация ping(), is_alive() и примитивов wait_for_*."""
    async with Connection.local() as conn:
        print("=== 1. Проверка доступности и задержки через ping() и is_alive() ===")
        alive = await conn.is_alive(timeout=5.0)
        ping_res = await conn.ping(timeout=5.0)
        print(f"is_alive={alive}, ping: alive={ping_res.alive}, rtt={ping_res.latency_ms:.2f}ms")

        print("\n=== 2. Ожидание соединения и появления файла с regex (wait_for_path) ===")
        await conn.wait_for_connection(timeout=5.0, interval=0.1)

        with tempfile.TemporaryDirectory(prefix="uniconn_wait_") as tmpdir:
            status_file = Path(tmpdir) / "service.status"

            async def _delayed_writer() -> None:
                await asyncio.sleep(0.05)
                status_file.write_text("BOOTING...\nSTATUS=READY\n", encoding="utf-8")

            writer_task = asyncio.create_task(_delayed_writer())
            elapsed_path = await conn.wait_for_path(
                status_file,
                state="present",
                content_regex=r"STATUS=READY",
                timeout=5.0,
                interval=0.02,
            )
            await writer_task
            print(f"Файл готовности обнаружен за {elapsed_path:.3f}s")

        print("\n=== 3. Ожидание открытия TCP-порта (wait_for_port) ===")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            bound_port = srv.getsockname()[1]

            elapsed_port = await conn.wait_for_port(
                bound_port,
                host="127.0.0.1",
                state="open",
                check_from="local",
                timeout=5.0,
                interval=0.05,
            )
            print(f"TCP-порт 127.0.0.1:{bound_port} открыт (проверено за {elapsed_port:.3f}s)")

    print("\n=== 4. Пакетный ping() по пулу хостов (ConnectionPool.ping) ===")
    pool = ConnectionPool(["local://", "local://?timeout=10"], max_concurrent=2)
    ping_map = await pool.ping(timeout=5.0)
    for host_key, pr in ping_map.items():
        print(f"  [{host_key}] alive={pr.alive} ({pr.latency_ms:.2f} ms)")


if __name__ == "__main__":
    asyncio.run(main())
