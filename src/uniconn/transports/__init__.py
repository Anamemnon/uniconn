# src/uniconn/transports/__init__.py
"""Транспорты для uniconn.

Этот пакет содержит реализации различных транспортов для подключения
и выполнения команд на удалённых хостах.

Доступные транспорты:
    - LocalTransport: Локальное выполнение через subprocess
    - SSHTransport: SSH подключение через asyncssh
    - TelnetTransport: Telnet через telnetlib3
    - SerialTransport: Serial/UART через pyserial-asyncio
    - IPMITransport: IPMI BMC через pyghmi
    - RedfishTransport: Redfish API через aiohttp
"""

from ._base import BaseTransport
from ._local import LocalTransport

__all__ = [
    "BaseTransport",
    "LocalTransport",
]
