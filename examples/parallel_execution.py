"""Параллельное выполнение, групповые сервисы и волновой роллаут в ConnectionPool.

Демонстрирует:
- ConnectionPool.map(), map_safe(), map_with_callback() и apply()
- Каскадный/волновой роллаут (batch_size, max_fail_ratio, BatchAbortedError)
- Выборку подмножества хостов через pool.select() без закрытия родительского пула
- Групповые доменные сервисы pool.files и pool.state
- Мультиплексированный стриминг вывода со всех хостов через pool.stream()
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from uniconn import BatchAbortedError, Connection, ConnectionPool, Result

# ─── Справочный пример для продакшн SSH-кластера ────────────────────


async def ssh_fleet_rollout_example() -> None:
    """Пример волнового деплоя на группу SSH-хостов из YAML-инвентаря."""
    # Загрузка группы хостов из инвентаря с раскаткой волнами по 2 узла
    async with ConnectionPool.from_file(
        "inventory.yaml",
        group="web",
        max_concurrent=10,
        batch_size=2,
        max_fail_ratio=0.0,
    ) as pool:
        # 1. Канареечная проверка на первом узле
        canary = pool.select(["web-1"])
        await canary.ping()

        # 2. Синхронизация статики и перезапуск сервиса на всём пуле
        await pool.files.sync_dir("./dist", "/var/www/html", delete=True)
        await pool.state.ensure_service("nginx", state="restarted", sudo=True)


# ─── Самодостаточная локальная демонстрация ConnectionPool ──────────


async def main() -> None:
    """Локальный запуск параллельных операций, пула сервисов и батч-роллаута."""
    hosts = [
        Connection.from_uri("local://", logger=None).with_overrides(host="node-1"),
        Connection.from_uri("local://", logger=None).with_overrides(host="node-2"),
        Connection.from_uri("local://", logger=None).with_overrides(host="node-3"),
    ]

    async with ConnectionPool(hosts, max_concurrent=3, batch_size=2, max_fail_ratio=0.0) as pool:
        print("=== 1. Параллельный запуск map() и выборка подмножества select() ===")
        results = await pool.map(["echo", "cluster-ready"])
        for res in results:
            print(f"  [{res.host}] exit={res.exit_code} text={res.text!r}")

        canary_pool = pool.select(predicate=lambda key, _conn: "node-1" in key)
        canary_ping = await canary_pool.ping()
        print("Canary ping:", {k: p.alive for k, p in canary_ping.items()})

        print("\n=== 2. Callback по мере готовности и мультиплексированный stream() ===")
        completed: list[str] = []

        def on_done(uri: str, result: Result) -> None:
            completed.append(f"{uri}:{result.text}")

        await pool.map_with_callback(["echo", "done"], on_done)
        print("Callback results:", completed)

        stream_events: list[str] = []
        async for host_key, line in pool.stream(["echo", "log-line"]):
            stream_events.append(f"{host_key}->{line.strip()}")
        print("Multiplexed stream:", stream_events)

        print("\n=== 3. Групповые операции pool.files и pool.state ===")
        with tempfile.TemporaryDirectory(prefix="uniconn_pool_") as tmpdir:
            target_file = str(Path(tmpdir) / "cluster_hosts.txt")
            ens_map = await pool.state.ensure_line(target_file, "10.0.0.10 internal.service")
            hashes = await pool.files.checksum(target_file)
            print("ensure_line across pool:", {k: v.ok for k, v in ens_map.items()})
            print("SHA-256 across pool:", {k: h[:12] for k, h in hashes.items()})

        print("\n=== 4. Защита релиза при сбое батча (BatchAbortedError) ===")
        try:
            await pool.map(
                ["python3", "-c", "import sys; sys.exit(1)"],
                raise_on_error=True,
                batch_size=1,
                max_fail_ratio=0.0,
            )
        except BatchAbortedError as err:
            print(f"Роллаут остановлен на батче #{err.batch_index}: fail_ratio={err.fail_ratio:.0%}")


if __name__ == "__main__":
    asyncio.run(main())
