# src/uniconn/transports/bmc/__init__.py
"""
BMC (Baseboard Management Controller) транспорты.

Этот пакет содержит транспорты для управления серверным оборудованием
через out-of-band интерфейсы.

Доступные транспорты:
    - IPMITransport: IPMI через pyghmi
    - RedfishTransport: Redfish REST API через aiohttp
"""

from ._ipmi import IPMITransport
from ._redfish import RedfishTransport

__all__ = [
    "IPMITransport",
    "RedfishTransport",
]
