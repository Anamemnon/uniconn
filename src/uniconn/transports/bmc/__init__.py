# src/uniconn/transports/bmc/__init__.py
"""BMC (Baseboard Management Controller) транспорты.

Этот пакет содержит транспорты для управления серверным оборудованием
через out-of-band интерфейсы.

Доступные транспорты:
    - IPMITransport: IPMI через pyghmi
"""

from ._ipmi import IPMITransport

__all__ = [
    "IPMITransport",
]
