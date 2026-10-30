# src/uniconn/transports/bmc/redfish/models.py
"""Константы, таблицы маппинга и типизированные структуры данных для транспорта DMTF Redfish."""

from __future__ import annotations

from typing import TypedDict

POWER_RESET_MAP: dict[str, str] = {
    "power on": "On",
    "power off": "ForceOff",
    "power graceful_off": "GracefulShutdown",
    "power shutdown": "GracefulShutdown",
    "power cycle": "ForceRestart",
    "power reset": "ForceRestart",
    "power graceful_restart": "GracefulRestart",
    "power reboot": "GracefulRestart",
    "power nmi": "Nmi",
}

MANAGER_RESET_MAP: dict[str, str] = {
    "graceful": "GracefulRestart",
    "graceful_restart": "GracefulRestart",
    "restart": "GracefulRestart",
    "reboot": "GracefulRestart",
    "force": "ForceRestart",
    "force_restart": "ForceRestart",
    "hard": "ForceRestart",
}

BOOT_TARGET_MAP: dict[str, str] = {
    "pxe": "Pxe",
    "hdd": "Hdd",
    "disk": "Hdd",
    "cd": "Cd",
    "iso": "Cd",
    "bios": "BiosSetup",
    "setup": "BiosSetup",
    "biossetup": "BiosSetup",
    "usb": "Usb",
    "floppy": "Floppy",
    "none": "None",
}

BOOT_ENABLED_MAP: dict[str, str] = {
    "once": "Once",
    "continuous": "Continuous",
    "always": "Continuous",
    "disabled": "Disabled",
    "off": "Disabled",
}

BOOT_MODE_MAP: dict[str, str] = {
    "uefi": "UEFI",
    "legacy": "Legacy",
    "bios": "Legacy",
}

SUPPORTED_COMMANDS: tuple[str, ...] = (
    "power status",
    "status",
    "power on",
    "power off",
    "power graceful_off",
    "power shutdown",
    "power cycle",
    "power reset",
    "power graceful_restart",
    "power reboot",
    "power nmi",
    "manager status",
    "bmc status",
    "manager reset [graceful|force]",
    "bmc reset [graceful|force]",
    "sensors",
    "health",
    "storage",
    "disks",
    "inventory",
    "system",
    "info",
    "sel",
    "logs",
    "sel clear",
    "logs clear",
    "boot status",
    "boot device",
    "boot <target> [once|continuous|disabled] [uefi|legacy]",
    "boot secureboot [status|on|off]",
    "secureboot [status|on|off]",
    "virtual_media status",
    "vmedia status",
    "virtual_media mount <image_url>",
    "virtual_media unmount",
    "vmedia eject",
    "tasks",
    "task status <task_id_or_uri>",
    "task wait <task_id_or_uri> [timeout]",
    "GET /redfish/v1/...",
    "POST /redfish/v1/... {json}",
    "PATCH /redfish/v1/... {json}",
    "DELETE /redfish/v1/...",
)


class TemperatureSensorDict(TypedDict):
    """Показание датчика температуры BMC."""

    name: str
    reading_celsius: float | int | None
    status: str
    upper_threshold_critical: float | int | None


class FanSensorDict(TypedDict):
    """Показание датчика вентилятора охлаждения."""

    name: str
    reading: float | int | None
    units: str
    status: str


class PowerSupplyDict(TypedDict):
    """Информация о блоке питания (PSU)."""

    name: str
    model: str | None
    power_output_watts: float | int | None
    status: str


class StorageDriveDict(TypedDict):
    """Информация о физическом накопителе (HDD/SSD/NVMe)."""

    id: str
    name: str
    model: str
    serial_number: str
    capacity_bytes: int
    media_type: str
    protocol: str
    health: str
    predicted_media_life_left_percent: float | int | None


class StorageVolumeDict(TypedDict):
    """Информация о логическом томе (RAID Volume)."""

    id: str
    name: str
    raid_type: str
    capacity_bytes: int
    health: str


class LogEntryDict(TypedDict):
    """Запись системного журнала событий (SEL / EventLog)."""

    id: str | None
    created: str
    severity: str
    message: str
    sensor_type: str | None


class TaskSummaryDict(TypedDict):
    """Сводка состояния асинхронной задачи Redfish TaskService."""

    task_uri: str
    id: str
    name: str
    task_state: str
    task_status: str
    percent_complete: int | None
    messages: list[str]


__all__ = [
    "BOOT_ENABLED_MAP",
    "BOOT_MODE_MAP",
    "BOOT_TARGET_MAP",
    "MANAGER_RESET_MAP",
    "POWER_RESET_MAP",
    "SUPPORTED_COMMANDS",
    "FanSensorDict",
    "LogEntryDict",
    "PowerSupplyDict",
    "StorageDriveDict",
    "StorageVolumeDict",
    "TaskSummaryDict",
    "TemperatureSensorDict",
]
