"""
Управление серверами через BMC (IPMI).

Демонстрирует:
- IPMI управление питанием
- Получение данных сенсоров
- Массовые BMC операции на нескольких серверах
"""

import asyncio
from uniconn import Connection


# ─── IPMI ───────────────────────────────────────────────────────────

async def ipmi_power_cycle():
    """Перезагрузка сервера через IPMI."""
    async with Connection.from_uri(
        "ipmi://admin:password@bmc.local"
    ) as conn:
        # Статус
        result = await conn.run("power status")
        print(f"Before: {result.stdout}")

        # Перезагрузка
        result = await conn.run("power cycle")
        print(f"Cycle: {result.stdout}")


async def ipmi_sensors():
    """Получение данных сенсоров через IPMI."""
    async with Connection.from_uri(
        "ipmi://admin:password@bmc.local"
    ) as conn:
        result = await conn.run("sensors")
        print(result.stdout)


async def ipmi_boot_device():
    """Просмотр boot устройства через IPMI."""
    async with Connection.from_uri(
        "ipmi://admin:password@bmc.local"
    ) as conn:
        result = await conn.run("boot device")
        print(f"Boot device: {result.stdout}")


# ─── Batch BMC operations ───────────────────────────────────────────

async def batch_bmc():
    """Массовые BMC операции на нескольких серверах."""
    from uniconn import ConnectionPool

    bmc_hosts = [
        "ipmi://admin:pass@bmc1.local",
        "ipmi://admin:pass@bmc2.local",
        "ipmi://admin:pass@bmc3.local",
    ]

    pool = ConnectionPool(bmc_hosts, max_concurrent=5)
    results = await pool.map("power status")

    for host, result in zip(bmc_hosts, results):
        print(f"  {host}: {result.stdout.strip()}")


# ─── Main ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== IPMI Power Status ===")
    asyncio.run(ipmi_power_cycle())

    print("\n=== IPMI Sensors ===")
    asyncio.run(ipmi_sensors())
