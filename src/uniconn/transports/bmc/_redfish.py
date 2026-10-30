# src/uniconn/transports/bmc/_redfish.py
"""Реэкспорт транспорта DMTF Redfish BMC (redfish://) для обратной совместимости."""

from __future__ import annotations

from .redfish import (
    BOOT_ENABLED_MAP as _BOOT_ENABLED_MAP,
)
from .redfish import (
    BOOT_MODE_MAP as _BOOT_MODE_MAP,
)
from .redfish import (
    BOOT_TARGET_MAP as _BOOT_TARGET_MAP,
)
from .redfish import (
    POWER_RESET_MAP as _POWER_RESET_MAP,
)
from .redfish import (
    RedfishDiscovery,
    RedfishHttpClient,
    RedfishTaskMonitor,
    RedfishTransport,
    builtins_timeout_errors,
    niquests,
)

__all__ = [
    "_BOOT_ENABLED_MAP",
    "_BOOT_MODE_MAP",
    "_BOOT_TARGET_MAP",
    "_POWER_RESET_MAP",
    "RedfishDiscovery",
    "RedfishHttpClient",
    "RedfishTaskMonitor",
    "RedfishTransport",
    "builtins_timeout_errors",
    "niquests",
]
