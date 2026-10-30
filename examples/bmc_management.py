"""Управление серверным оборудованием через BMC: Redfish (HTTP/2) и IPMI.

Демонстрирует:
- RedfishTransport (redfish://) — статус питания, сенсоры, инвентаризация системы и менеджер задач
- IPMITransport (ipmi://) — управление питанием, чтение сенсоров и выбор загрузочного устройства
- Пакетный опрос парка BMC-контроллеров через ConnectionPool
- Детерминированное локальное воспроизведение BMC-ответов через кассету (без реального железа)
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from uniconn import Cassette, Connection, ConnectionPool, RecordedExecInteraction

# ─── Боевые примеры для Redfish и IPMI контроллеров ─────────────────


async def redfish_bmc_operations() -> None:
    """Управление современным BMC по протоколу DMTF Redfish (niquests)."""
    uri = "redfish://admin:env://BMC_PASS@bmc-node01.local:443?verify_ssl=false&system_id=1"
    async with Connection.from_uri(uri) as bmc:
        power = await bmc.run("power status")
        system_info = await bmc.run("system info")
        sensors = await bmc.run("sensors")
        print("Redfish power:", power.text)
        print("System info:", system_info.text)
        print("Thermal/power sensors:", sensors.text)


async def ipmi_bmc_operations() -> None:
    """Управление сервером по протоколу IPMI 2.0 (pyghmi)."""
    async with Connection.from_uri("ipmi://admin:env://BMC_PASS@bmc-legacy.local:623") as bmc:
        status = await bmc.run("power status")
        boot_dev = await bmc.run("boot device")
        print(f"IPMI power={status.text}, boot={boot_dev.text}")


async def batch_bmc_fleet_status() -> None:
    """Массовый опрос питания смешанного парка Redfish и IPMI серверов."""
    bmc_hosts = [
        "redfish://admin:env://BMC_PASS@bmc-gen11-01.local?verify_ssl=false",
        "redfish://admin:env://BMC_PASS@bmc-gen11-02.local?verify_ssl=false",
        "ipmi://admin:env://BMC_PASS@bmc-gen10-03.local",
    ]
    async with ConnectionPool(bmc_hosts, max_concurrent=5) as pool:
        results = await pool.map_safe("power status")
        for host, res in results.items():
            print(f"  {host}: {res if isinstance(res, Exception) else res.text}")


# ─── Самодостаточная локальная демонстрация (через Replay-кассету) ──


async def main() -> None:
    """Локальный прогон сценария инспекции BMC с использованием предзаписанной кассеты."""
    with tempfile.TemporaryDirectory(prefix="uniconn_bmc_") as tmpdir:
        cassette_path = Path(tmpdir) / "redfish_bmc.yaml"
        cassette = Cassette(
            transport="redfish",
            host="bmc-node01.local",
            interactions=[
                RecordedExecInteraction(
                    command="power status",
                    exit_code=0,
                    stdout='{"power_state": "On", "health": "OK"}\n',
                ),
                RecordedExecInteraction(
                    command="sensors",
                    exit_code=0,
                    stdout='{"CPU1_Temp": "48 C", "Inlet_Temp": "23 C", "Fan1_RPM": 6400}\n',
                ),
                RecordedExecInteraction(
                    command="system info",
                    exit_code=0,
                    stdout='{"manufacturer": "Dell Inc.", "model": "PowerEdge R760", "bios": "1.6.4"}\n',
                ),
            ],
        )
        cassette.save(cassette_path)

        replay_uri = f"replay://bmc-node01.local?cassette={cassette_path}&mode=none"
        async with Connection.from_uri(replay_uri) as bmc:
            print("=== 1. Статус питания BMC (JSON) ===")
            pwr = await bmc.run("power status")
            print("Power status:", pwr.json())

            print("\n=== 2. Показания датчиков температуры и вентиляторов ===")
            sens = await bmc.run("sensors")
            print("Sensors:", sens.json())

            print("\n=== 3. Инвентарная информация о сервере ===")
            info = await bmc.run("system info")
            print("System info:", info.json())


if __name__ == "__main__":
    asyncio.run(main())
