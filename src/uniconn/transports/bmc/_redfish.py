# src/uniconn/transports/bmc/_redfish.py
"""Redfish транспорт для управления BMC через REST API.

Redfish - открытый стандарт DMTF для управления серверным оборудованием.
Поддерживает операции: power on/off/cycle, boot device, sensors, etc.

Поддерживает:
    - Базовая аутентификация (Basic Auth)
    - HTTPS с валидацией/без валидации сертификатов
    - Проксирование запросов
    - Таймауты

Пример URI:
    redfish://admin:password@bmc.local
    redfish://admin:password@bmc.local:443?verify_ssl=false

Зависимости:
    aiohttp >= 3.8
"""

import asyncio
import time
from collections.abc import AsyncIterator
from typing import Any

from ...exceptions import AuthenticationError, BMCCapabilityError, ConnectionError
from ...result import Result
from .._base import BaseTransport

# Импорт опциональный (extra dependency)
try:
    import aiohttp
except ImportError:
    aiohttp = None  # type: ignore


class RedfishTransport(BaseTransport):
    """Redfish транспорт для управления серверным оборудованием.

    Реализует стандарт DMTF Redfish API для out-of-band management.
    """

    # Стандартные пути Redfish API
    REDFISH_ROOT = "/redfish/v1"
    SYSTEMS_PATH = "/redfish/v1/Systems"

    # Маппинг команд на Redfish операции
    _COMMAND_MAP = {
        # Power operations
        "power on": {"action": "PowerOn", "method": "POST"},
        "power off": {"action": "GracefulShutdown", "method": "POST"},
        "power forceoff": {"action": "ForceOff", "method": "POST"},
        "power cycle": {"action": "ForceRestart", "method": "POST"},
        "power restart": {"action": "GracefulRestart", "method": "POST"},
        "power status": {"action": "status", "method": "GET"},
        "status": {"action": "status", "method": "GET"},
        # Boot device
        "boot device": {"action": "boot", "method": "GET"},
        "sensors": {"action": "sensors", "method": "GET"},
        "info": {"action": "info", "method": "GET"},
    }

    def __init__(self, config):
        if aiohttp is None:
            raise ImportError(
                "aiohttp not installed. "
                "Run: pip install uniconn[bmc]"
            )
        super().__init__(config)
        self._session: aiohttp.ClientSession | None = None
        self._base_url: str = ""
        self._system_id: str | None = None

    @property
    def name(self) -> str:
        """Название транспорта."""
        return "redfish"

    def _get_base_url(self) -> str:
        """Построить базовый URL из конфигурации."""
        scheme = "https"
        host = self.config.host
        port = self.config.port or 443

        # Проверяем кастомный base_path из опций
        base_path = self.config.options.get('base_path', '')

        if port == 443:
            return f"{scheme}://{host}{base_path}"
        return f"{scheme}://{host}:{port}{base_path}"

    async def connect(self) -> None:
        """Инициализировать HTTP сессию и получить токен системы.

        Raises:
            ConnectionError: При ошибке подключения
            AuthenticationError: При ошибке аутентификации

        """
        try:
            self._base_url = self._get_base_url()

            # Настраиваем SSL
            verify_ssl = self.config.options.get('verify_ssl', True)
            if isinstance(verify_ssl, str):
                verify_ssl = verify_ssl.lower() in ('true', '1', 'yes')

            ssl_context = None
            if not verify_ssl:
                import ssl
                ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

            # Создаём сессию с базовой аутентификацией
            auth = None
            if self.config.username and self.config.password:
                auth = aiohttp.BasicAuth(
                    self.config.username,
                    self.config.password.get_secret_value()
                )

            timeout = aiohttp.ClientTimeout(
                total=self.config.timeout,
                connect=min(10, self.config.timeout)
            )

            self._session = aiohttp.ClientSession(
                auth=auth,
                timeout=timeout,
                raise_for_status=False
            )

            # Проверяем доступность и получаем system ID
            await self._discover_system()

            self._connected = True

        except aiohttp.ClientResponseError as e:
            if e.status in (401, 403):
                raise AuthenticationError(
                    f"Redfish authentication failed: {e.message}",
                    host=self.config.host
                ) from e
            raise ConnectionError(
                f"Redfish connection error: {e.message}",
                host=self.config.host
            ) from e
        except Exception as e:
            raise ConnectionError(
                f"Redfish connection failed: {e}",
                host=self.config.host
            ) from e

    async def _discover_system(self) -> None:
        """Обнаружить доступные системы в Redfish API."""
        if not self._session:
            return

        # Проверяем корневой ресурс
        async with self._session.get(f"{self._base_url}{self.REDFISH_ROOT}") as resp:
            if resp.status != 200:
                raise ConnectionError(
                    f"Redfish API not available: {resp.status}",
                    host=self.config.host
                )

        # Получаем список систем
        async with self._session.get(f"{self._base_url}{self.SYSTEMS_PATH}") as resp:
            if resp.status == 200:
                data = await resp.json()
                members = data.get('Members', [])
                if members:
                    # Берём первую доступную систему
                    system_url = members[0].get('@odata.id', '')
                    self._system_id = system_url.split('/')[-1]
                else:
                    # Fallback на стандартный ID
                    self._system_id = "1"
            else:
                self._system_id = "1"

    async def disconnect(self) -> None:
        """Закрыть HTTP сессию."""
        if self._session:
            await self._session.close()
            self._session = None
        self._connected = False

    async def ping(self, timeout: float | None = None) -> bool:
        """Проверить доступность Redfish API через запрос корневого ресурса.

        Args:
            timeout: Таймаут в секундах

        Returns:
            True если Redfish API доступен
        """
        if not self._connected or not self._session:
            return False
        try:
            timeout_val = timeout or self.config.timeout
            async with asyncio.timeout(timeout_val):
                async with self._session.get(
                    f"{self._base_url}{self.REDFISH_ROOT}"
                ) as resp:
                    return resp.status == 200
        except Exception:
            return False

    async def run(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs
    ) -> Result:
        """Выполнить Redfish команду.

        Args:
            command: Команда для выполнения (power on/off/cycle/status, etc.)
            timeout: Таймаут операции
            **kwargs: Дополнительные аргументы
                - data: Данные для POST запроса
                - custom_path: Кастомный путь API

        Returns:
            Result объект с результатом

        Raises:
            BMCCapabilityError: Если команда не поддерживается
            ExecutionError: При ошибке выполнения

        """
        if not self._session:
            raise ConnectionError("Not connected", host=self.config.host)

        start_time = time.monotonic()

        # Нормализуем команду
        cmd_lower = command.lower().strip()

        # Проверяем кастомные запросы
        if cmd_lower.startswith("get "):
            path = command[4:].strip()
            return await self._do_request("GET", path, start_time)

        if cmd_lower.startswith("post "):
            parts = command[5:].strip().split(" ", 1)
            path = parts[0]
            data = parts[1] if len(parts) > 1 else None
            return await self._do_request("POST", path, start_time, data=data)

        # Проверяем в маппинге команд
        if cmd_lower not in self._COMMAND_MAP:
            available = ", ".join(self._COMMAND_MAP.keys())
            raise BMCCapabilityError(
                f"Unknown Redfish command: {command}. "
                f"Available: {available}"
            )

        cmd_info = self._COMMAND_MAP[cmd_lower]

        try:
            if cmd_info["action"] == "status":
                result = await self._get_power_status()
            elif cmd_info["action"] == "boot":
                result = await self._get_boot_device()
            elif cmd_info["action"] == "sensors":
                result = await self._get_sensors()
            elif cmd_info["action"] == "info":
                result = await self._get_system_info()
            else:
                # Power action
                result = await self._do_power_action(cmd_info["action"])

            duration = time.monotonic() - start_time

            return Result(
                exit_code=0,
                stdout=str(result),
                stderr="",
                duration=duration,
                command=command,
                host=self.config.host
            )

        except Exception as e:
            raise BMCCapabilityError(
                f"Redfish command failed: {e}",
                command=command,
                host=self.config.host
            ) from e

    async def _do_request(
        self,
        method: str,
        path: str,
        start_time: float,
        data: Any = None
    ) -> Result:
        """Выполнить произвольный HTTP запрос."""
        if not self._session:
            raise ConnectionError("Not connected", host=self.config.host)

        # Формируем полный URL
        url = f"{self._base_url}{path}" if path.startswith("/") else f"{self._base_url}/{path}"

        # Подготавливаем данные
        json_data = None
        if data and isinstance(data, str):
            import json
            try:
                json_data = json.loads(data)
            except json.JSONDecodeError:
                json_data = {"data": data}
        elif data:
            json_data = data

        # Выполняем запрос
        if method.upper() == "GET":
            async with self._session.get(url) as resp:
                body = await resp.text()
                status = resp.status
        elif method.upper() == "POST":
            async with self._session.post(url, json=json_data) as resp:
                body = await resp.text()
                status = resp.status
        elif method.upper() == "PATCH":
            async with self._session.patch(url, json=json_data) as resp:
                body = await resp.text()
                status = resp.status
        else:
            raise BMCCapabilityError(f"Unsupported HTTP method: {method}")

        duration = time.monotonic() - start_time

        return Result(
            exit_code=0 if status < 400 else status,
            stdout=body,
            stderr="" if status < 400 else f"HTTP {status}",
            duration=duration,
            command=f"{method} {path}",
            host=self.config.host
        )

    async def _get_power_status(self) -> str:
        """Получить статус питания."""
        system_url = f"{self.SYSTEMS_PATH}/{self._system_id}"

        async with self._session.get(f"{self._base_url}{system_url}") as resp:
            if resp.status != 200:
                raise BMCCapabilityError(f"Failed to get power status: {resp.status}")

            data = await resp.json()
            power_state = data.get('PowerState', 'Unknown')
            return f"Power State: {power_state}"

    async def _do_power_action(self, action: str) -> str:
        """Выполнить power action (On, Off, Restart, etc.)."""
        system_url = f"{self.SYSTEMS_PATH}/{self._system_id}"
        action_url = f"{system_url}/Actions/ComputerSystem.Reset"

        payload = {"ResetType": action}

        async with self._session.post(
            f"{self._base_url}{action_url}",
            json=payload
        ) as resp:
            if resp.status in (200, 202, 204):
                return f"Power action '{action}' initiated successfully"

            body = await resp.text()
            raise BMCCapabilityError(f"Power action failed: {resp.status} - {body}")

    async def _get_boot_device(self) -> str:
        """Получить текущее boot устройство."""
        system_url = f"{self.SYSTEMS_PATH}/{self._system_id}"

        async with self._session.get(f"{self._base_url}{system_url}") as resp:
            if resp.status != 200:
                raise BMCCapabilityError(f"Failed to get boot device: {resp.status}")

            data = await resp.json()
            boot = data.get('Boot', {})
            boot_source = boot.get('BootSourceOverrideTarget', 'Unknown')
            return f"Boot Device: {boot_source}"

    async def _get_sensors(self) -> str:
        """Получить информацию с сенсоров (simplified)."""
        # Пытаемся получить Chassis информацию для сенсоров
        chassis_path = "/redfish/v1/Chassis"

        try:
            async with self._session.get(f"{self._base_url}{chassis_path}") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    members = data.get('Members', [])
                    if members:
                        # Берём первый chassis
                        chassis_url = members[0].get('@odata.id', '')
                        return await self._get_chassis_sensors(chassis_url)
        except Exception:
            pass

        return "Sensors: Not available"

    async def _get_chassis_sensors(self, chassis_url: str) -> str:
        """Получить сенсоры из chassis."""
        async with self._session.get(f"{self._base_url}{chassis_url}") as resp:
            if resp.status != 200:
                return "Sensors: Failed to read"

            data = await resp.json()

            # Собираем информацию о сенсорах
            parts = ["Sensors:"]

            # Thermal
            thermal = data.get('Thermal', {})
            if thermal:
                parts.append("  Thermal: Available")

            # Power
            power = data.get('Power', {})
            if power:
                parts.append("  Power: Available")

            # Health
            health = data.get('Status', {}).get('Health', 'Unknown')
            parts.append(f"  Health: {health}")

            return "\n".join(parts)

    async def _get_system_info(self) -> str:
        """Получить общую информацию о системе."""
        system_url = f"{self.SYSTEMS_PATH}/{self._system_id}"

        async with self._session.get(f"{self._base_url}{system_url}") as resp:
            if resp.status != 200:
                raise BMCCapabilityError(f"Failed to get system info: {resp.status}")

            data = await resp.json()

            parts = ["System Information:"]
            parts.append(f"  Model: {data.get('Model', 'Unknown')}")
            parts.append(f"  Manufacturer: {data.get('Manufacturer', 'Unknown')}")
            parts.append(f"  Serial: {data.get('SerialNumber', 'Unknown')}")
            parts.append(f"  Power State: {data.get('PowerState', 'Unknown')}")
            parts.append(f"  Health: {data.get('Status', {}).get('Health', 'Unknown')}")
            parts.append(f"  State: {data.get('Status', {}).get('State', 'Unknown')}")

            return "\n".join(parts)

    async def stream(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs
    ) -> AsyncIterator[str]:
        """Redfish не поддерживает стриминг в классическом смысле.
        Возвращаем результат построчно.
        """
        result = await self.run(command, timeout=timeout, **kwargs)
        for line in result.stdout.splitlines():
            yield line
