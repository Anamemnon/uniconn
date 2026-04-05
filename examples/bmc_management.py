"""
Управление серверами через BMC (IPMI / Redfish).

Демонстрирует:
- IPMI управление питанием
- Redfish REST API
- Получение информации о системе и сенсорах
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


# ─── Redfish ────────────────────────────────────────────────────────

async def redfish_power_management():
    """Управление питанием через Redfish."""
    async with Connection.from_uri(
        "redfish://admin:password@idrac.local"
    ) as conn:
        # Статус
        result = await conn.run("power status")
        print(f"Power: {result.stdout}")

        # Graceful shutdown
        result = await conn.run("power off")
        print(f"Shutdown: {result.stdout}")


async def redfish_system_info():
    """Получение информации о системе."""
    async with Connection.from_uri(
        "redfish://admin:password@idrac.local"
    ) as conn:
        # Общая информация
        result = await conn.run("info")
        print(result.stdout)


async def redfish_boot_device():
    """Просмотр и изменение boot устройства."""
    async with Connection.from_uri(
        "redfish://admin:password@idrac.local"
    ) as conn:
        result = await conn.run("boot device")
        print(f"Boot device: {result.stdout}")


async def redfish_custom_request():
    """Произвольный REST запрос через Redfish."""
    async with Connection.from_uri(
        "redfish://admin:password@idrac.local"
    ) as conn:
        # GET запрос к произвольному эндпоинту
        result = await conn.run("get /redfish/v1/Systems")
        print(f"Status: {result.exit_code}")
        print(f"Body: {result.stdout}")


# ─── Batch BMC operations ───────────────────────────────────────────

async def batch_bmc():
    """Массовые BMC операции на нескольких серверах."""
    from uniconn import ConnectionPool

    bmc_hosts = [
        "redfish://admin:pass@idrac1.local",
        "redfish://admin:pass@idrac2.local",
        "redfish://admin:pass@idrac3.local",
    ]

    pool = ConnectionPool(bmc_hosts, max_concurrent=5)
    results = await pool.map("power status")

    for host, result in zip(bmc_hosts, results):
        print(f"  {host}: {result.stdout.strip()}")


# ─── Main ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== IPMI Sensors ===")
    asyncio.run(ipmi_sensors())

    print("\n=== Redfish System Info ===")
    asyncio.run(redfish_system_info())
