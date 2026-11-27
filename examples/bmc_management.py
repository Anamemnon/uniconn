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
        system_info = await bmc.run("inventory")
        sensors = await bmc.run("sensors")
        print("Redfish power:", power.text)
        print("System info:", system_info.text)
        print("Thermal/power sensors:", sensors.text)


async def ipmi_bmc_operations() -> None:
    """Управление сервером и платой базовой станции по протоколу IPMI 2.0 (pyghmi)."""
    async with Connection.from_uri("ipmi://admin:env://BMC_PASS@bmc-legacy.local:623") as bmc:
        status = await bmc.run("power status")
        sensors = await bmc.run("sensors")
        sel_log = await bmc.run("sel list")
        await bmc.run("boot pxe once uefi")
        # Отправка сырой команды IPMI (например, установка ручного ШИМ вентиляторов 80% = 0x50)
        pwm_res = await bmc.run("raw 0x30 0x30 0x02 0xff 0x50")
        print(
            f"IPMI power={status.json()}, sensors={len(sensors.json()['sensors'])}, "
            f"sel_count={sel_log.json()['count']}, raw_hex={pwm_res.json()['hex']}"
        )


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
    """Локальный прогон сценариев инспекции Redfish и IPMI с использованием предзаписанных кассет."""
    with tempfile.TemporaryDirectory(prefix="uniconn_bmc_") as tmpdir:
        redfish_cassette_path = Path(tmpdir) / "redfish_bmc.yaml"
        redfish_cassette = Cassette(
            transport="redfish",
            host="bmc-node01.local",
            interactions=[
                RecordedExecInteraction(
                    command="power status",
                    exit_code=0,
                    stdout='{"PowerState": "On", "Health": "OK"}\n',
                ),
                RecordedExecInteraction(
                    command="sensors",
                    exit_code=0,
                    stdout='{"CPU1_Temp": "48 C", "Inlet_Temp": "23 C", "Fan1_RPM": 6400}\n',
                ),
                RecordedExecInteraction(
                    command="inventory",
                    exit_code=0,
                    stdout='{"Manufacturer": "Dell Inc.", "Model": "PowerEdge R760", "BiosVersion": "1.6.4"}\n',
                ),
                RecordedExecInteraction(
                    command="virtual_media status",
                    exit_code=0,
                    stdout='{"inserted": false, "media_types": ["CD", "DVD"]}\n',
                ),
                RecordedExecInteraction(
                    command="boot secureboot status",
                    exit_code=0,
                    stdout='{"SecureBootEnable": true, "SecureBootMode": "UserMode"}\n',
                ),
            ],
        )
        redfish_cassette.save(redfish_cassette_path)

        redfish_replay_uri = f"replay://bmc-node01.local?cassette={redfish_cassette_path}&mode=none"
        async with Connection.from_uri(redfish_replay_uri) as bmc:
            print("=== 1. Redfish BMC: питание, сенсоры, инвентарь, VirtualMedia и SecureBoot ===")
            print("Power:", (await bmc.run("power status")).json())
            print("Sensors:", (await bmc.run("sensors")).json())
            print("Inventory:", (await bmc.run("inventory")).json())
            print("VirtualMedia:", (await bmc.run("virtual_media status")).json())
            print("SecureBoot:", (await bmc.run("boot secureboot status")).json())

        ipmi_cassette_path = Path(tmpdir) / "ipmi_bmc.yaml"
        ipmi_cassette = Cassette(
            transport="ipmi",
            host="bmc-legacy.local",
            interactions=[
                RecordedExecInteraction(
                    command="power status",
                    exit_code=0,
                    stdout='{"power_state": "on"}\n',
                ),
                RecordedExecInteraction(
                    command="sensors",
                    exit_code=0,
                    stdout='{"sensors": [{"name": "Inlet Temp", "value": 24.0, "unit": "C"}]}\n',
                ),
                RecordedExecInteraction(
                    command="sel list",
                    exit_code=0,
                    stdout='{"count": 1, "entries": [{"severity": "OK", "message": "System Boot"}]}\n',
                ),
                RecordedExecInteraction(
                    command="boot pxe once uefi",
                    exit_code=0,
                    stdout='{"bootdev": "network", "persistent": false, "uefiboot": true}\n',
                ),
                RecordedExecInteraction(
                    command="raw 0x30 0x30 0x02 0xff 0x50",
                    exit_code=0,
                    stdout='{"netfn": "0x30", "command": "0x30", "hex": "00"}\n',
                ),
            ],
        )
        ipmi_cassette.save(ipmi_cassette_path)

        ipmi_replay_uri = f"replay://bmc-legacy.local?cassette={ipmi_cassette_path}&mode=none"
        async with Connection.from_uri(ipmi_replay_uri) as ipmi:
            print("\n=== 2. IPMI 2.0: питание, SDR-сенсоры, SEL, PXE UEFI и raw-команды ===")
            print("IPMI power:", (await ipmi.run("power status")).json())
            print("IPMI sensors:", (await ipmi.run("sensors")).json())
            print("IPMI SEL:", (await ipmi.run("sel list")).json())
            print("IPMI boot:", (await ipmi.run("boot pxe once uefi")).json())
            print("IPMI raw:", (await ipmi.run("raw 0x30 0x30 0x02 0xff 0x50")).json())


if __name__ == "__main__":
    asyncio.run(main())
