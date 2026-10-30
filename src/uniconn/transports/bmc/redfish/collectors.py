# src/uniconn/transports/bmc/redfish/collectors.py
"""Сбор телеметрии (Sensors/Thermal/Power), дисковой подсистемы (Storage/RAID) и паспорта сервера."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from .client import normalize_redfish_path
from .models import (
    FanSensorDict,
    PowerSupplyDict,
    StorageDriveDict,
    StorageVolumeDict,
    TemperatureSensorDict,
)

RequestJsonFn = Callable[..., Awaitable[tuple[int, dict[str, Any]]]]


async def collect_sensors(
    chassis_path: str,
    request_json: RequestJsonFn,
    timeout: float | None = None,
) -> tuple[int, dict[str, Any]]:
    """Собрать показатели датчиков температуры, вентиляторов и питания.

    Поддерживает как классические эндпоинты ``/Thermal`` и ``/Power``, так и
    современную коллекцию ``/Sensors`` стандарта DMTF Redfish DSP0268 (2020.4+).
    """
    (th_status, thermal), (pw_status, power) = await asyncio.gather(
        request_json("GET", f"{chassis_path}/Thermal", timeout=timeout),
        request_json("GET", f"{chassis_path}/Power", timeout=timeout),
    )

    temperatures: list[TemperatureSensorDict] = []
    for temp in thermal.get("Temperatures", []) or []:
        if not isinstance(temp, dict):
            continue
        reading = temp.get("ReadingCelsius")
        if reading is None:
            reading = temp.get("Reading")
        temperatures.append(
            {
                "name": str(temp.get("Name") or temp.get("MemberId") or "Temp"),
                "reading_celsius": reading,
                "status": str((temp.get("Status") or {}).get("Health", "OK")),
                "upper_threshold_critical": temp.get("UpperThresholdCritical"),
            }
        )

    fans: list[FanSensorDict] = []
    for fan in thermal.get("Fans", []) or []:
        if not isinstance(fan, dict):
            continue
        fans.append(
            {
                "name": str(fan.get("Name") or fan.get("FanName") or "Fan"),
                "reading": fan.get("Reading"),
                "units": str(fan.get("ReadingUnits", "RPM")),
                "status": str((fan.get("Status") or {}).get("Health", "OK")),
            }
        )

    power_watts: float | int | None = None
    power_capacity_watts: float | int | None = None
    for pctrl in power.get("PowerControl", []) or []:
        if isinstance(pctrl, dict):
            if pctrl.get("PowerConsumedWatts") is not None:
                power_watts = pctrl.get("PowerConsumedWatts")
            if pctrl.get("PowerCapacityWatts") is not None:
                power_capacity_watts = pctrl.get("PowerCapacityWatts")
            break

    power_supplies: list[PowerSupplyDict] = []
    for psu in power.get("PowerSupplies", []) or []:
        if not isinstance(psu, dict):
            continue
        power_supplies.append(
            {
                "name": str(psu.get("Name") or psu.get("MemberId") or "PSU"),
                "model": psu.get("Model"),
                "power_output_watts": psu.get("PowerOutputWatts")
                or psu.get("LastPowerOutputWatts"),
                "status": str((psu.get("Status") or {}).get("Health", "OK")),
            }
        )

    legacy_ok = 200 <= th_status < 300 or 200 <= pw_status < 300
    has_any_readings = bool(
        temperatures or fans or power_watts is not None or power_supplies
    )

    # Fallback на современную коллекцию /Sensors (DMTF DSP0268) при 404 или пустых данных
    if not legacy_ok or not has_any_readings:
        sens_status, sens_col = await request_json(
            "GET", f"{chassis_path}/Sensors", timeout=timeout
        )
        if 200 <= sens_status < 300:
            members = sens_col.get("Members") or []
            sensor_objs: list[dict[str, Any]] = []
            to_fetch: list[str] = []
            for m in members:
                if not isinstance(m, dict):
                    continue
                if "Reading" in m or "ReadingType" in m:
                    sensor_objs.append(m)
                elif "@odata.id" in m:
                    to_fetch.append(normalize_redfish_path(str(m["@odata.id"])))

            if to_fetch:
                fetched = await asyncio.gather(
                    *(request_json("GET", uri, timeout=timeout) for uri in to_fetch)
                )
                for fst, fdata in fetched:
                    if 200 <= fst < 300 and isinstance(fdata, dict):
                        sensor_objs.append(fdata)

            for sdata in sensor_objs:
                rtype = str(sdata.get("ReadingType") or "").lower()
                runits = str(sdata.get("ReadingUnits") or "")
                sname = str(sdata.get("Name") or sdata.get("Id") or "Sensor")
                shealth = str((sdata.get("Status") or {}).get("Health") or "OK")
                sreading = sdata.get("Reading")

                if rtype == "temperature" or runits.lower() in ("cel", "c", "degc"):
                    thresholds = sdata.get("Thresholds") or {}
                    upper_crit = (thresholds.get("UpperCritical") or {}).get(
                        "Reading"
                    ) or sdata.get("UpperThresholdCritical")
                    temperatures.append(
                        {
                            "name": sname,
                            "reading_celsius": sreading,
                            "status": shealth,
                            "upper_threshold_critical": upper_crit,
                        }
                    )
                elif (
                    rtype in ("rotational", "fan", "airflow")
                    or runits.upper() == "RPM"
                    or ("fan" in sname.lower() and rtype == "percent")
                ):
                    fans.append(
                        {
                            "name": sname,
                            "reading": sreading,
                            "units": runits or "RPM",
                            "status": shealth,
                        }
                    )
                elif rtype == "power" or runits == "W":
                    if power_watts is None and isinstance(sreading, (int, float)):
                        power_watts = sreading

            if not legacy_ok:
                th_status = sens_status
                legacy_ok = True

    status_code = 200 if legacy_ok else th_status
    return status_code, {
        "chassis_uri": chassis_path,
        "temperatures": temperatures,
        "fans": fans,
        "power_consumed_watts": power_watts,
        "power_capacity_watts": power_capacity_watts,
        "power_supplies": power_supplies,
    }


def _parse_drive(ddata: dict[str, Any], index: int) -> StorageDriveDict:
    """Нормализовать JSON физического диска Redfish Drive в StorageDriveDict."""
    did = str(ddata.get("Id") or ddata.get("Name") or f"Drive.{index}")
    dname = str(ddata.get("Name") or did)
    model = str(ddata.get("Model") or ddata.get("Manufacturer") or "").strip()
    serial = str(ddata.get("SerialNumber") or "").strip()
    try:
        cap_bytes = int(ddata.get("CapacityBytes") or 0)
    except (ValueError, TypeError):
        cap_bytes = 0
    media_type = str(ddata.get("MediaType") or "Unknown")
    protocol = str(ddata.get("Protocol") or "")
    health = str((ddata.get("Status") or {}).get("Health") or "OK")
    life_left = ddata.get("PredictedMediaLifeLeftPercent")
    return {
        "id": did,
        "name": dname,
        "model": model,
        "serial_number": serial,
        "capacity_bytes": cap_bytes,
        "media_type": media_type,
        "protocol": protocol,
        "health": health,
        "predicted_media_life_left_percent": life_left,
    }


async def collect_storage(
    sys_path: str,
    request_json: RequestJsonFn,
    timeout: float | None = None,
) -> tuple[int, dict[str, Any]]:
    """Собрать инвентаризацию дисковой подсистемы и RAID-томов (``/Storage`` и ``/SimpleStorage``)."""
    st, storage_col = await request_json(
        "GET", f"{sys_path}/Storage", timeout=timeout
    )
    controllers: list[dict[str, Any]] = []
    drives: list[StorageDriveDict] = []
    volumes: list[StorageVolumeDict] = []
    seen_drive_uris: set[str] = set()

    if 200 <= st < 300:
        members = storage_col.get("Members") or []
        ctrl_uris = [
            normalize_redfish_path(str(m["@odata.id"]))
            for m in members
            if isinstance(m, dict) and "@odata.id" in m
        ]
        ctrl_responses = await asyncio.gather(
            *(request_json("GET", uri, timeout=timeout) for uri in ctrl_uris)
        )

        for ctrl_uri, (cst, cdata) in zip(ctrl_uris, ctrl_responses, strict=False):
            if not (200 <= cst < 300) or not isinstance(cdata, dict):
                continue

            ctrl_list = cdata.get("StorageControllers") or []
            first_ctrl = (
                ctrl_list[0]
                if (isinstance(ctrl_list, list) and ctrl_list and isinstance(ctrl_list[0], dict))
                else {}
            )
            controllers.append(
                {
                    "id": str(cdata.get("Id") or ctrl_uri.rsplit("/", 1)[-1]),
                    "name": str(cdata.get("Name") or first_ctrl.get("Name") or "Storage Controller"),
                    "model": str(first_ctrl.get("Model") or cdata.get("Description") or ""),
                    "health": str((cdata.get("Status") or {}).get("Health") or "OK"),
                }
            )

            # Физические накопители (Drives)
            raw_drives = cdata.get("Drives") or []
            drive_uris_to_fetch: list[str] = []
            for dref in raw_drives:
                if not isinstance(dref, dict):
                    continue
                if "CapacityBytes" in dref or "MediaType" in dref:
                    drives.append(_parse_drive(dref, len(drives)))
                elif "@odata.id" in dref:
                    d_uri = normalize_redfish_path(str(dref["@odata.id"]))
                    if d_uri not in seen_drive_uris:
                        seen_drive_uris.add(d_uri)
                        drive_uris_to_fetch.append(d_uri)

            if drive_uris_to_fetch:
                d_resps = await asyncio.gather(
                    *(request_json("GET", u, timeout=timeout) for u in drive_uris_to_fetch)
                )
                for dst, ddata in d_resps:
                    if 200 <= dst < 300 and isinstance(ddata, dict):
                        drives.append(_parse_drive(ddata, len(drives)))

            # Логические RAID-тома (Volumes)
            vols_ref = cdata.get("Volumes")
            if isinstance(vols_ref, dict) and "@odata.id" in vols_ref:
                vols_col_uri = normalize_redfish_path(str(vols_ref["@odata.id"]))
                vst, vcol = await request_json("GET", vols_col_uri, timeout=timeout)
                if 200 <= vst < 300:
                    v_members = vcol.get("Members") or []
                    v_uris = [
                        normalize_redfish_path(str(vm["@odata.id"]))
                        for vm in v_members
                        if isinstance(vm, dict) and "@odata.id" in vm
                    ]
                    if v_uris:
                        v_resps = await asyncio.gather(
                            *(request_json("GET", u, timeout=timeout) for u in v_uris)
                        )
                        for _, (ivst, vdata) in zip(v_uris, v_resps, strict=False):
                            if 200 <= ivst < 300 and isinstance(vdata, dict):
                                try:
                                    vcap = int(vdata.get("CapacityBytes") or 0)
                                except (ValueError, TypeError):
                                    vcap = 0
                                volumes.append(
                                    {
                                        "id": str(vdata.get("Id") or f"Volume.{len(volumes)}"),
                                        "name": str(vdata.get("Name") or vdata.get("Id") or "Volume"),
                                        "raid_type": str(
                                            vdata.get("RAIDType")
                                            or vdata.get("VolumeType")
                                            or "Unknown"
                                        ),
                                        "capacity_bytes": vcap,
                                        "health": str((vdata.get("Status") or {}).get("Health") or "OK"),
                                    }
                                )

    # Fallback на SimpleStorage, если коллекция /Storage недоступна (404)
    if not (200 <= st < 300):
        sst, simple_col = await request_json(
            "GET", f"{sys_path}/SimpleStorage", timeout=timeout
        )
        if 200 <= sst < 300:
            st = sst
            for sm in simple_col.get("Members") or []:
                if not isinstance(sm, dict) or "@odata.id" not in sm:
                    continue
                s_uri = normalize_redfish_path(str(sm["@odata.id"]))
                sc_st, sc_data = await request_json("GET", s_uri, timeout=timeout)
                if 200 <= sc_st < 300 and isinstance(sc_data, dict):
                    for dev in sc_data.get("Devices") or []:
                        if isinstance(dev, dict) and (dev.get("CapacityBytes") or dev.get("Model")):
                            drives.append(_parse_drive(dev, len(drives)))

    return st, {
        "system_uri": sys_path,
        "controllers": controllers,
        "drives": drives,
        "volumes": volumes,
    }


async def collect_ethernet_interfaces(
    sys_path: str,
    mgr_path: str,
    request_json: RequestJsonFn,
    timeout: float | None = None,
) -> list[dict[str, Any]]:
    """Собрать сетевые интерфейсы системы или контроллера BMC."""
    interfaces: list[dict[str, Any]] = []
    for base_path in (sys_path, mgr_path):
        st, col = await request_json(
            "GET", f"{base_path}/EthernetInterfaces", timeout=timeout
        )
        if not (200 <= st < 300):
            continue
        members = col.get("Members") or []
        for member in members:
            if not isinstance(member, dict) or "@odata.id" not in member:
                continue
            ist, idata = await request_json(
                "GET", str(member["@odata.id"]), timeout=timeout
            )
            if not (200 <= ist < 300):
                continue
            ipv4_list = [
                str(addr["Address"])
                for addr in (idata.get("IPv4Addresses") or [])
                if isinstance(addr, dict) and addr.get("Address")
            ]
            ipv6_list = [
                str(addr["Address"])
                for addr in (idata.get("IPv6Addresses") or [])
                if isinstance(addr, dict) and addr.get("Address")
            ]
            interfaces.append(
                {
                    "name": str(
                        idata.get("Id") or idata.get("Name") or f"eth{len(interfaces)}"
                    ),
                    "mac": str(idata.get("MACAddress") or ""),
                    "ipv4": ipv4_list,
                    "ipv6": ipv6_list,
                    "state": "UP"
                    if idata.get("LinkStatus") in ("LinkUp", None)
                    and idata.get("InterfaceEnabled", True)
                    else "DOWN",
                    "mtu": int(idata.get("MTUSize") or 1500),
                }
            )
        if interfaces:
            break
    return interfaces


async def collect_inventory(
    *,
    sys_path: str,
    mgr_path: str,
    chassis_path: str,
    default_host: str | None,
    request_json: RequestJsonFn,
    timeout: float | None = None,
) -> tuple[int, dict[str, Any]]:
    """Собрать полный аппаратный паспорт сервера (System, Manager, Sensors, NICs, Storage)."""
    (sys_status, sys_data), (_, mgr_data), (_, sensors_data) = await asyncio.gather(
        request_json("GET", sys_path, timeout=timeout),
        request_json("GET", mgr_path, timeout=timeout),
        collect_sensors(chassis_path, request_json, timeout=timeout),
    )

    proc_summary = sys_data.get("ProcessorSummary") or {}
    mem_summary = sys_data.get("MemorySummary") or {}
    sys_status_obj = sys_data.get("Status") or {}

    interfaces, (_, storage_data) = await asyncio.gather(
        collect_ethernet_interfaces(sys_path, mgr_path, request_json, timeout=timeout),
        collect_storage(sys_path, request_json, timeout=timeout),
    )

    inventory: dict[str, Any] = {
        "manufacturer": sys_data.get("Manufacturer")
        or mgr_data.get("Manufacturer")
        or "Unknown",
        "model": sys_data.get("Model") or mgr_data.get("Model") or "Redfish Server",
        "serial_number": sys_data.get("SerialNumber") or "",
        "sku": sys_data.get("SKU") or "",
        "uuid": sys_data.get("UUID") or "",
        "hostname": sys_data.get("HostName") or default_host or "localhost",
        "power_state": sys_data.get("PowerState") or "Unknown",
        "health": sys_status_obj.get("Health") or "OK",
        "bios_version": sys_data.get("BiosVersion") or "",
        "bmc_firmware_version": mgr_data.get("FirmwareVersion") or "",
        "processor_summary": {
            "count": int(proc_summary.get("Count") or 1),
            "model": proc_summary.get("Model") or "",
            "arch": proc_summary.get("InstructionSet") or "x86_64",
        },
        "memory_summary": {
            "total_system_memory_gib": float(
                mem_summary.get("TotalSystemMemoryGiB") or 0.0
            ),
            "health": (mem_summary.get("Status") or {}).get("Health", "OK"),
        },
        "power_consumed_watts": sensors_data.get("power_consumed_watts"),
        "power_capacity_watts": sensors_data.get("power_capacity_watts"),
        "temperatures": sensors_data.get("temperatures", []),
        "fans": sensors_data.get("fans", []),
        "power_supplies": sensors_data.get("power_supplies", []),
        "interfaces": interfaces,
        "disks": storage_data.get("drives", []),
        "storage": {
            "controllers": storage_data.get("controllers", []),
            "drives": storage_data.get("drives", []),
            "volumes": storage_data.get("volumes", []),
        },
        "system_uri": sys_path,
        "manager_uri": mgr_path,
    }
    return sys_status, inventory


__all__ = [
    "collect_ethernet_interfaces",
    "collect_inventory",
    "collect_sensors",
    "collect_storage",
]
