# src/uniconn/transports/bmc/redfish/__init__.py
"""Модульный пакет транспорта DMTF Redfish BMC (redfish://) на базе niquests.AsyncSession."""

from __future__ import annotations

from .client import (
    RedfishHttpClient,
    builtins_timeout_errors,
    niquests,
    normalize_redfish_path,
    resolve_lazy_response,
)
from .collectors import (
    collect_ethernet_interfaces,
    collect_inventory,
    collect_sensors,
    collect_storage,
)
from .discovery import (
    RedfishDiscovery,
    resolve_action_target,
    score_log_service_member,
    score_vmedia_member,
)
from .models import (
    BOOT_ENABLED_MAP,
    BOOT_MODE_MAP,
    BOOT_TARGET_MAP,
    MANAGER_RESET_MAP,
    POWER_RESET_MAP,
    SUPPORTED_COMMANDS,
    FanSensorDict,
    LogEntryDict,
    PowerSupplyDict,
    StorageDriveDict,
    StorageVolumeDict,
    TaskSummaryDict,
    TemperatureSensorDict,
)
from .tasks import (
    RedfishTaskMonitor,
    extract_task_uri_from_response,
    parse_task_summary,
    resolve_task_uri,
)
from .transport import RedfishTransport

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
    "RedfishDiscovery",
    "RedfishHttpClient",
    "RedfishTaskMonitor",
    "RedfishTransport",
    "StorageDriveDict",
    "StorageVolumeDict",
    "TaskSummaryDict",
    "TemperatureSensorDict",
    "builtins_timeout_errors",
    "collect_ethernet_interfaces",
    "collect_inventory",
    "collect_sensors",
    "collect_storage",
    "extract_task_uri_from_response",
    "niquests",
    "normalize_redfish_path",
    "parse_task_summary",
    "resolve_action_target",
    "resolve_lazy_response",
    "resolve_task_uri",
    "score_log_service_member",
    "score_vmedia_member",
]
