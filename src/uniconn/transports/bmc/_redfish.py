# src/uniconn/transports/bmc/_redfish.py
"""Транспорт DMTF Redfish BMC (redfish://) на базе асинхронного HTTP-клиента niquests."""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from ...exceptions import (
    AuthenticationError,
    BMCCapabilityError,
    ConfigurationError,
    ConnectionError,
    TimeoutError,
)
from ...result import Result
from ..base import BaseTransport

if TYPE_CHECKING:
    from ...config.models import ConnectionConfig

try:
    import niquests
except ImportError:
    niquests = None  # type: ignore[assignment]


_POWER_RESET_MAP: dict[str, str] = {
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

_BOOT_TARGET_MAP: dict[str, str] = {
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

_BOOT_ENABLED_MAP: dict[str, str] = {
    "once": "Once",
    "continuous": "Continuous",
    "always": "Continuous",
    "disabled": "Disabled",
    "off": "Disabled",
}

_BOOT_MODE_MAP: dict[str, str] = {
    "uefi": "UEFI",
    "legacy": "Legacy",
    "bios": "Legacy",
}


class RedfishTransport(BaseTransport):
    """Асинхронный транспорт DMTF Redfish BMC (HTTPS REST API) на базе ``niquests.AsyncSession``.

    Использует постоянный пул TLS-соединений и HTTP/2 мультиплексирование ``niquests``
    с поддержкой сессионной аутентификации (``X-Auth-Token``) и автоматическим откатом
    на HTTP Basic Auth.
    """

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
        "sensors",
        "health",
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
        "virtual_media status",
        "vmedia status",
        "virtual_media mount <image_url>",
        "virtual_media unmount",
        "vmedia eject",
        "GET /redfish/v1/...",
        "POST /redfish/v1/... {json}",
        "PATCH /redfish/v1/... {json}",
        "DELETE /redfish/v1/...",
    )

    def __init__(self, config: ConnectionConfig) -> None:
        if niquests is None:
            raise ImportError("niquests not installed. Run: pip install uniconn[bmc]")
        super().__init__(config)
        opts = config.options
        self._scheme: str = str(opts.get("scheme", "https")).lower()
        default_port = 443 if self._scheme == "https" else 80
        self._port: int = config.port or default_port
        host = config.host or "localhost"
        self._base_url: str = f"{self._scheme}://{host}:{self._port}"

        ca_file = opts.get("ca_file")
        if ca_file:
            self._verify: bool | str = str(ca_file)
        else:
            self._verify = bool(opts.get("verify_ssl", False))

        self._multiplexed: bool = bool(opts.get("multiplexed", True))
        self._auth_pref: str = str(opts.get("auth", "auto")).lower()

        self._session: Any = None
        self._auth_mode: str = "none"
        self._session_token: str | None = None
        self._session_location: str | None = None

        self._system_path: str | None = None
        self._chassis_path: str | None = None
        self._manager_path: str | None = None

    @property
    def name(self) -> str:
        return "redfish"

    @property
    def base_url(self) -> str:
        """Базовый URL подключения к BMC."""
        return self._base_url

    @property
    def auth_mode(self) -> str:
        """Активный режим аутентификации ('session', 'basic' или 'none')."""
        return self._auth_mode

    def _password_str(self) -> str:
        if self.config.password is None:
            return ""
        return self.config.password.get_secret_value()

    def _create_async_session(self) -> Any:
        assert niquests is not None
        session = niquests.AsyncSession(
            base_url=self._base_url,
            multiplexed=self._multiplexed,
        )
        session.verify = self._verify
        session.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "OData-Version": "4.0",
            }
        )
        return session

    async def connect(self) -> None:
        """Установить сессию с Redfish BMC (Session Token с откатом на Basic Auth)."""
        if self._connected and self._session is not None:
            return

        if not self.config.host:
            raise ConfigurationError("RedfishTransport requires a target BMC host")

        session = self._create_async_session()
        username = self.config.username
        password = self._password_str()
        timeout = self.config.timeout or 30.0

        try:
            if username and self._auth_pref in ("auto", "session"):
                created = await self._try_create_redfish_session(
                    session, username, password, timeout
                )
                if created:
                    self._session = session
                    self._auth_mode = "session"
                    self._connected = True
                    return

            # Fallback или явный режим Basic Auth
            if username:
                session.auth = (username, password)
                self._auth_mode = "basic"
            else:
                self._auth_mode = "none"

            resp = await session.get("/redfish/v1", timeout=timeout)
            await self._resolve_lazy_response(session, resp)
            status = int(getattr(resp, "status_code", 0) or 0)
            if status in (401, 403):
                raise AuthenticationError(
                    f"Redfish authentication failed on {self._base_url} (HTTP {status})"
                )
            if status >= 400 or status == 0:
                raise ConnectionError(
                    f"Redfish service root check failed on {self._base_url} (HTTP {status})"
                )

            self._session = session
            self._connected = True
        except (AuthenticationError, ConnectionError, ConfigurationError, TimeoutError):
            with contextlib.suppress(Exception):
                await session.close()
            raise
        except builtins_timeout_errors() as exc:
            with contextlib.suppress(Exception):
                await session.close()
            raise TimeoutError(
                f"Redfish connection to {self._base_url} timed out after {timeout}s"
            ) from exc
        except Exception as exc:
            with contextlib.suppress(Exception):
                await session.close()
            raise ConnectionError(
                f"Failed to connect to Redfish BMC {self._base_url}: {exc}"
            ) from exc

    @staticmethod
    async def _resolve_lazy_response(session: Any, resp: Any) -> Any:
        """Разрешить отложенный (lazy) ответ ``niquests`` при ``multiplexed=True``."""
        if getattr(resp, "lazy", False) is True and hasattr(session, "gather"):
            await session.gather(resp)
        return resp

    @staticmethod
    def _normalize_path(path: str) -> str:
        """Нормализовать путь или полный URL Redfish к относительному пути ``/redfish/...``."""
        stripped = path.strip()
        if stripped.startswith(("http://", "https://")):
            parsed = urlsplit(stripped)
            rel = parsed.path or "/"
            if parsed.query:
                rel = f"{rel}?{parsed.query}"
            return rel if rel.startswith("/") else f"/{rel}"
        return stripped if stripped.startswith("/") else f"/{stripped}"

    async def _try_create_redfish_session(
        self,
        session: Any,
        username: str,
        password: str,
        timeout: float,
    ) -> bool:
        """Попытаться создать сессию через POST /redfish/v1/SessionService/Sessions."""
        resp = await session.post(
            "/redfish/v1/SessionService/Sessions",
            json={"UserName": username, "Password": password},
            timeout=timeout,
        )
        await self._resolve_lazy_response(session, resp)
        status = int(getattr(resp, "status_code", 0) or 0)
        headers = getattr(resp, "headers", {}) or {}
        token = headers.get("X-Auth-Token") or headers.get("x-auth-token")

        if status in (200, 201, 202, 204) and token:
            session.headers["X-Auth-Token"] = str(token)
            self._session_token = str(token)
            location = headers.get("Location") or headers.get("location")
            if not location:
                with contextlib.suppress(Exception):
                    body = resp.json()
                    if isinstance(body, dict) and "@odata.id" in body:
                        location = str(body["@odata.id"])
            self._session_location = (
                self._normalize_path(str(location)) if location else None
            )
            return True

        if status in (401, 403):
            if self._auth_pref == "session":
                raise AuthenticationError(
                    f"Redfish session login rejected on {self._base_url} (HTTP {status})"
                )
            return False

        if self._auth_pref == "session":
            raise ConnectionError(
                f"Redfish SessionService unavailable on {self._base_url} (HTTP {status})"
            )
        return False

    async def disconnect(self) -> None:
        """Закрыть Redfish-сессию (DELETE сессии + закрытие пула niquests.AsyncSession)."""
        session = self._session
        location = self._session_location
        self._session = None
        self._session_token = None
        self._session_location = None
        self._auth_mode = "none"
        self._system_path = None
        self._chassis_path = None
        self._manager_path = None
        self._connected = False

        if session is not None:
            if location:
                with contextlib.suppress(Exception):
                    del_resp = await session.delete(
                        self._normalize_path(location), timeout=5.0
                    )
                    await self._resolve_lazy_response(session, del_resp)
            with contextlib.suppress(Exception):
                await session.close()

    async def ping(self, timeout: float | None = None) -> bool:
        """Проверить доступность BMC через лёгкий запрос к ``/redfish/v1``."""
        if not self._connected or self._session is None:
            return False
        eff_timeout = timeout if timeout is not None else (self.config.timeout or 10.0)
        try:
            resp = await self._session.get("/redfish/v1", timeout=eff_timeout)
            await self._resolve_lazy_response(self._session, resp)
            status = int(getattr(resp, "status_code", 0) or 0)
            return 200 <= status < 300
        except Exception:
            return False

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> tuple[int, dict[str, Any]]:
        """Выполнить HTTP-запрос через ``niquests.AsyncSession`` и вернуть (status, json_dict)."""
        if not self._connected or self._session is None:
            await self.connect()
        assert self._session is not None

        eff_timeout = timeout if timeout is not None else (self.config.timeout or 30.0)
        norm_path = self._normalize_path(path)

        try:
            req_fn = getattr(self._session, method.lower())
            if payload is not None:
                resp = await req_fn(norm_path, json=payload, timeout=eff_timeout)
            else:
                resp = await req_fn(norm_path, timeout=eff_timeout)
            await self._resolve_lazy_response(self._session, resp)
        except builtins_timeout_errors() as exc:
            raise TimeoutError(
                f"Redfish {method.upper()} {norm_path} timed out after {eff_timeout}s"
            ) from exc
        except Exception as exc:
            raise ConnectionError(
                f"Redfish {method.upper()} {norm_path} failed: {exc}"
            ) from exc

        status = int(getattr(resp, "status_code", 0) or 0)
        if status in (401, 403):
            raise AuthenticationError(
                f"Redfish {method.upper()} {norm_path} unauthorized (HTTP {status})"
            )

        data: dict[str, Any] = {}
        raw_text = getattr(resp, "text", "")
        if raw_text:
            try:
                parsed = resp.json()
                data = parsed if isinstance(parsed, dict) else {"data": parsed}
            except Exception:
                data = {"raw": str(raw_text)}
        return status, data

    async def _discover_first_member(
        self,
        collection_path: str,
        fallback_path: str,
        timeout: float | None = None,
    ) -> str:
        status, data = await self._request_json("GET", collection_path, timeout=timeout)
        if 200 <= status < 300:
            members = data.get("Members")
            if isinstance(members, list) and members:
                first = members[0]
                if isinstance(first, dict) and "@odata.id" in first:
                    return self._normalize_path(str(first["@odata.id"])).rstrip("/")
        return fallback_path

    async def _get_system_path(self, timeout: float | None = None) -> str:
        if self._system_path:
            return self._system_path
        explicit = self.config.options.get("system_id")
        if explicit:
            path = str(explicit)
            self._system_path = (
                path if path.startswith("/redfish/") else f"/redfish/v1/Systems/{path}"
            )
            return self._system_path
        self._system_path = await self._discover_first_member(
            "/redfish/v1/Systems", "/redfish/v1/Systems/1", timeout=timeout
        )
        return self._system_path

    async def _get_chassis_path(self, timeout: float | None = None) -> str:
        if self._chassis_path:
            return self._chassis_path
        explicit = self.config.options.get("chassis_id")
        if explicit:
            path = str(explicit)
            self._chassis_path = (
                path if path.startswith("/redfish/") else f"/redfish/v1/Chassis/{path}"
            )
            return self._chassis_path
        self._chassis_path = await self._discover_first_member(
            "/redfish/v1/Chassis", "/redfish/v1/Chassis/1", timeout=timeout
        )
        return self._chassis_path

    async def _get_manager_path(self, timeout: float | None = None) -> str:
        if self._manager_path:
            return self._manager_path
        explicit = self.config.options.get("manager_id")
        if explicit:
            path = str(explicit)
            self._manager_path = (
                path if path.startswith("/redfish/") else f"/redfish/v1/Managers/{path}"
            )
            return self._manager_path
        self._manager_path = await self._discover_first_member(
            "/redfish/v1/Managers", "/redfish/v1/Managers/1", timeout=timeout
        )
        return self._manager_path

    async def run(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> Result:
        """Выполнить BMC-команду или прямой REST-запрос к Redfish API."""
        _ = kwargs
        start_time = time.monotonic()
        cmd_stripped = command.strip()
        cmd_lower = " ".join(cmd_stripped.lower().split())

        status_code = 200
        output_payload: dict[str, Any]
        stderr_str = ""

        # 1. Power status
        if cmd_lower in ("power status", "status"):
            sys_path = await self._get_system_path(timeout=timeout)
            status_code, sys_data = await self._request_json(
                "GET", sys_path, timeout=timeout
            )
            output_payload = {
                "PowerState": sys_data.get("PowerState", "Unknown"),
                "Status": sys_data.get("Status", {}),
                "IndicatorLED": sys_data.get("IndicatorLED"),
                "HostName": sys_data.get("HostName"),
                "SystemUri": sys_path,
            }

        # 2. Power reset actions
        elif cmd_lower in _POWER_RESET_MAP:
            reset_type = _POWER_RESET_MAP[cmd_lower]
            sys_path = await self._get_system_path(timeout=timeout)
            action_path = f"{sys_path}/Actions/ComputerSystem.Reset"
            status_code, resp_data = await self._request_json(
                "POST",
                action_path,
                payload={"ResetType": reset_type},
                timeout=timeout,
            )
            output_payload = {
                "ok": 200 <= status_code < 300,
                "action": "ComputerSystem.Reset",
                "ResetType": reset_type,
                "status_code": status_code,
                "response": resp_data,
            }

        # 3. Sensors & Thermal / Power telemetry (multiplexed via asyncio.gather)
        elif cmd_lower in ("sensors", "health"):
            status_code, output_payload = await self._collect_sensors(timeout=timeout)

        # 4. Full hardware inventory / system passport
        elif cmd_lower in ("inventory", "system", "info"):
            status_code, output_payload = await self._collect_inventory(timeout=timeout)

        # 5. System Event Logs (SEL / Lifecycle Logs)
        elif cmd_lower in ("sel", "logs") or cmd_lower.startswith(("sel ", "logs ")):
            status_code, output_payload = await self._handle_logs_command(
                cmd_lower, timeout=timeout
            )

        # 6. Boot configuration & override
        elif cmd_lower.startswith("boot"):
            status_code, output_payload = await self._handle_boot_command(
                cmd_stripped, cmd_lower, timeout=timeout
            )

        # 7. Virtual Media (ISO mount / unmount / status)
        elif cmd_lower.startswith(("virtual_media", "vmedia")):
            status_code, output_payload = await self._handle_vmedia_command(
                cmd_stripped, cmd_lower, timeout=timeout
            )

        # 8. Raw REST call: GET/POST/PATCH/DELETE /redfish/v1/...
        elif self._is_raw_rest_command(cmd_stripped):
            status_code, output_payload = await self._handle_raw_rest(
                cmd_stripped, timeout=timeout
            )

        else:
            raise BMCCapabilityError(
                f"Unknown Redfish command: {command!r}. "
                f"Available commands: {list(self.SUPPORTED_COMMANDS)}"
            )

        duration = time.monotonic() - start_time
        exit_code = 0 if 200 <= status_code < 300 else 1
        if exit_code != 0:
            stderr_str = json.dumps(output_payload, ensure_ascii=False)

        return Result(
            exit_code=exit_code,
            stdout=json.dumps(output_payload, indent=2, ensure_ascii=False),
            stderr=stderr_str,
            duration=duration,
            command=command,
            host=self.config.host,
        )

    async def _collect_sensors(
        self, timeout: float | None = None
    ) -> tuple[int, dict[str, Any]]:
        chassis_path = await self._get_chassis_path(timeout=timeout)
        (th_status, thermal), (pw_status, power) = await asyncio.gather(
            self._request_json("GET", f"{chassis_path}/Thermal", timeout=timeout),
            self._request_json("GET", f"{chassis_path}/Power", timeout=timeout),
        )

        temperatures: list[dict[str, Any]] = []
        for temp in thermal.get("Temperatures", []) or []:
            if not isinstance(temp, dict):
                continue
            reading = temp.get("ReadingCelsius")
            temperatures.append(
                {
                    "name": temp.get("Name") or temp.get("MemberId") or "Temp",
                    "reading_celsius": reading,
                    "status": (temp.get("Status") or {}).get("Health", "OK"),
                    "upper_threshold_critical": temp.get("UpperThresholdCritical"),
                }
            )

        fans: list[dict[str, Any]] = []
        for fan in thermal.get("Fans", []) or []:
            if not isinstance(fan, dict):
                continue
            fans.append(
                {
                    "name": fan.get("Name") or fan.get("FanName") or "Fan",
                    "reading": fan.get("Reading"),
                    "units": fan.get("ReadingUnits", "RPM"),
                    "status": (fan.get("Status") or {}).get("Health", "OK"),
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

        power_supplies: list[dict[str, Any]] = []
        for psu in power.get("PowerSupplies", []) or []:
            if not isinstance(psu, dict):
                continue
            power_supplies.append(
                {
                    "name": psu.get("Name") or psu.get("MemberId") or "PSU",
                    "model": psu.get("Model"),
                    "power_output_watts": psu.get("PowerOutputWatts")
                    or psu.get("LastPowerOutputWatts"),
                    "status": (psu.get("Status") or {}).get("Health", "OK"),
                }
            )

        status_code = (
            200 if (200 <= th_status < 300 or 200 <= pw_status < 300) else th_status
        )
        return status_code, {
            "chassis_uri": chassis_path,
            "temperatures": temperatures,
            "fans": fans,
            "power_consumed_watts": power_watts,
            "power_capacity_watts": power_capacity_watts,
            "power_supplies": power_supplies,
        }

    async def _collect_inventory(
        self, timeout: float | None = None
    ) -> tuple[int, dict[str, Any]]:
        sys_path, mgr_path = await asyncio.gather(
            self._get_system_path(timeout=timeout),
            self._get_manager_path(timeout=timeout),
        )
        (sys_status, sys_data), (_, mgr_data), (_, sensors_data) = await asyncio.gather(
            self._request_json("GET", sys_path, timeout=timeout),
            self._request_json("GET", mgr_path, timeout=timeout),
            self._collect_sensors(timeout=timeout),
        )

        proc_summary = sys_data.get("ProcessorSummary") or {}
        mem_summary = sys_data.get("MemorySummary") or {}
        sys_status_obj = sys_data.get("Status") or {}

        interfaces = await self._collect_ethernet_interfaces(
            sys_path, mgr_path, timeout=timeout
        )

        inventory = {
            "manufacturer": sys_data.get("Manufacturer")
            or mgr_data.get("Manufacturer")
            or "Unknown",
            "model": sys_data.get("Model") or mgr_data.get("Model") or "Redfish Server",
            "serial_number": sys_data.get("SerialNumber") or "",
            "sku": sys_data.get("SKU") or "",
            "uuid": sys_data.get("UUID") or "",
            "hostname": sys_data.get("HostName") or self.config.host or "localhost",
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
            "system_uri": sys_path,
            "manager_uri": mgr_path,
        }
        return sys_status, inventory

    async def _collect_ethernet_interfaces(
        self,
        sys_path: str,
        mgr_path: str,
        timeout: float | None = None,
    ) -> list[dict[str, Any]]:
        interfaces: list[dict[str, Any]] = []
        for base_path in (sys_path, mgr_path):
            st, col = await self._request_json(
                "GET", f"{base_path}/EthernetInterfaces", timeout=timeout
            )
            if not (200 <= st < 300):
                continue
            members = col.get("Members") or []
            for member in members:
                if not isinstance(member, dict) or "@odata.id" not in member:
                    continue
                ist, idata = await self._request_json(
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

    async def _discover_log_service_path(self, timeout: float | None = None) -> str:
        for getter in (self._get_system_path, self._get_manager_path):
            parent = await getter(timeout=timeout)
            st, col = await self._request_json(
                "GET", f"{parent}/LogServices", timeout=timeout
            )
            if 200 <= st < 300:
                members = col.get("Members") or []
                if isinstance(members, list) and members:
                    first = members[0]
                    if isinstance(first, dict) and "@odata.id" in first:
                        return self._normalize_path(str(first["@odata.id"])).rstrip("/")
        sys_path = await self._get_system_path(timeout=timeout)
        return f"{sys_path}/LogServices/Log1"

    async def _handle_logs_command(
        self,
        cmd_lower: str,
        timeout: float | None = None,
    ) -> tuple[int, dict[str, Any]]:
        log_path = await self._discover_log_service_path(timeout=timeout)
        parts = cmd_lower.split()
        if len(parts) >= 2 and parts[1] == "clear":
            action_path = f"{log_path}/Actions/LogService.ClearLog"
            st, resp = await self._request_json(
                "POST", action_path, payload={}, timeout=timeout
            )
            return st, {
                "ok": 200 <= st < 300,
                "action": "LogService.ClearLog",
                "log_service_uri": log_path,
                "response": resp,
            }

        limit = 50
        if len(parts) >= 2 and parts[1].isdigit():
            limit = max(1, int(parts[1]))

        st, entries_data = await self._request_json(
            "GET", f"{log_path}/Entries", timeout=timeout
        )
        raw_members = entries_data.get("Members") or []
        entries: list[dict[str, Any]] = []
        for item in raw_members[-limit:]:
            if not isinstance(item, dict):
                continue
            entries.append(
                {
                    "id": item.get("Id"),
                    "created": item.get("Created") or item.get("EventTimestamp") or "",
                    "severity": item.get("Severity") or "OK",
                    "message": item.get("Message") or item.get("Name") or "",
                    "sensor_type": item.get("SensorType"),
                }
            )
        return st, {
            "log_service_uri": log_path,
            "count": len(entries),
            "entries": entries,
        }

    async def _handle_boot_command(
        self,
        cmd_stripped: str,
        cmd_lower: str,
        timeout: float | None = None,
    ) -> tuple[int, dict[str, Any]]:
        sys_path = await self._get_system_path(timeout=timeout)
        if cmd_lower in ("boot", "boot status", "boot device"):
            st, sys_data = await self._request_json("GET", sys_path, timeout=timeout)
            boot_info = sys_data.get("Boot") or {}
            return st, {
                "BootSourceOverrideTarget": boot_info.get("BootSourceOverrideTarget"),
                "BootSourceOverrideEnabled": boot_info.get("BootSourceOverrideEnabled"),
                "BootSourceOverrideMode": boot_info.get("BootSourceOverrideMode"),
                "UefiTargetBootSourceOverride": boot_info.get(
                    "UefiTargetBootSourceOverride"
                ),
            }

        tokens = cmd_lower.split()[1:]
        if not tokens or tokens[0] not in _BOOT_TARGET_MAP:
            raise BMCCapabilityError(
                f"Unsupported boot command: {cmd_stripped!r}. "
                f"Supported targets: {list(_BOOT_TARGET_MAP.keys())}"
            )

        target = _BOOT_TARGET_MAP[tokens[0]]
        enabled = "disabled" if target == "None" else "once"
        mode: str | None = None

        for tok in tokens[1:]:
            if tok in _BOOT_ENABLED_MAP:
                enabled = tok
            elif tok in _BOOT_MODE_MAP:
                mode = _BOOT_MODE_MAP[tok]
            else:
                raise BMCCapabilityError(f"Unknown boot modifier: {tok!r}")

        boot_patch: dict[str, Any] = {
            "BootSourceOverrideTarget": target,
            "BootSourceOverrideEnabled": _BOOT_ENABLED_MAP[enabled],
        }
        if mode is not None:
            boot_patch["BootSourceOverrideMode"] = mode

        st, resp = await self._request_json(
            "PATCH",
            sys_path,
            payload={"Boot": boot_patch},
            timeout=timeout,
        )
        return st, {
            "ok": 200 <= st < 300,
            "Boot": boot_patch,
            "response": resp,
        }

    async def _discover_vmedia_path(self, timeout: float | None = None) -> str:
        mgr_path = await self._get_manager_path(timeout=timeout)
        return await self._discover_first_member(
            f"{mgr_path}/VirtualMedia",
            f"{mgr_path}/VirtualMedia/CD1",
            timeout=timeout,
        )

    async def _handle_vmedia_command(
        self,
        cmd_stripped: str,
        cmd_lower: str,
        timeout: float | None = None,
    ) -> tuple[int, dict[str, Any]]:
        vmedia_path = await self._discover_vmedia_path(timeout=timeout)
        parts = cmd_stripped.split(maxsplit=2)
        action = parts[1].lower() if len(parts) >= 2 else "status"

        if action == "status":
            st, vm_data = await self._request_json("GET", vmedia_path, timeout=timeout)
            return st, {
                "virtual_media_uri": vmedia_path,
                "image": vm_data.get("Image"),
                "inserted": bool(vm_data.get("Inserted", False)),
                "media_types": vm_data.get("MediaTypes", []),
                "connected_via": vm_data.get("ConnectedVia"),
            }

        if action in ("mount", "insert"):
            if len(parts) < 3 or not parts[2].strip():
                raise BMCCapabilityError(
                    "virtual_media mount requires an <image_url> argument"
                )
            image_url = parts[2].strip()
            insert_uri = f"{vmedia_path}/Actions/VirtualMedia.InsertMedia"
            st, resp = await self._request_json(
                "POST",
                insert_uri,
                payload={"Image": image_url, "Inserted": True},
                timeout=timeout,
            )
            return st, {
                "ok": 200 <= st < 300,
                "action": "VirtualMedia.InsertMedia",
                "Image": image_url,
                "virtual_media_uri": vmedia_path,
                "response": resp,
            }

        if action in ("unmount", "eject"):
            eject_uri = f"{vmedia_path}/Actions/VirtualMedia.EjectMedia"
            st, resp = await self._request_json(
                "POST", eject_uri, payload={}, timeout=timeout
            )
            return st, {
                "ok": 200 <= st < 300,
                "action": "VirtualMedia.EjectMedia",
                "virtual_media_uri": vmedia_path,
                "response": resp,
            }

        raise BMCCapabilityError(
            f"Unsupported virtual_media command: {cmd_stripped!r}. "
            "Use 'virtual_media status', 'virtual_media mount <url>', or 'virtual_media unmount'"
        )

    @staticmethod
    def _is_raw_rest_command(cmd_stripped: str) -> bool:
        parts = cmd_stripped.split(maxsplit=2)
        if len(parts) < 2:
            return False
        method = parts[0].upper()
        norm_path = RedfishTransport._normalize_path(parts[1])
        return method in ("GET", "POST", "PATCH", "PUT", "DELETE") and norm_path.startswith(
            "/redfish"
        )

    async def _handle_raw_rest(
        self,
        cmd_stripped: str,
        timeout: float | None = None,
    ) -> tuple[int, dict[str, Any]]:
        parts = cmd_stripped.split(maxsplit=2)
        method = parts[0].upper()
        path = parts[1]
        payload: dict[str, Any] | None = None
        if len(parts) == 3 and parts[2].strip():
            try:
                parsed = json.loads(parts[2].strip())
                if not isinstance(parsed, dict):
                    raise BMCCapabilityError("REST JSON payload must be a JSON object")
                payload = parsed
            except json.JSONDecodeError as exc:
                raise BMCCapabilityError(
                    f"Invalid JSON payload in raw REST command: {exc}"
                ) from exc

        return await self._request_json(method, path, payload=payload, timeout=timeout)

    async def stream(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Потоковое чтение вывода команды (для ``sel`` / ``logs`` отдаёт события построчно)."""
        result = await self.run(command, timeout=timeout, **kwargs)
        cmd_lower = " ".join(command.strip().lower().split())
        if cmd_lower in ("sel", "logs") or cmd_lower.startswith(("sel ", "logs ")):
            with contextlib.suppress(Exception):
                payload = json.loads(result.stdout)
                entries = payload.get("entries")
                if isinstance(entries, list):
                    for entry in entries:
                        if isinstance(entry, dict):
                            ts = entry.get("created") or "-"
                            sev = entry.get("severity") or "OK"
                            msg = entry.get("message") or ""
                            yield f"[{ts}] [{sev}] {msg}"
                    return

        for line in result.stdout.splitlines():
            yield line


def builtins_timeout_errors() -> tuple[type[BaseException], ...]:
    """Собрать кортеж классов исключений таймаута (включая builtins.TimeoutError и niquests)."""
    import builtins

    errs: list[type[BaseException]] = [builtins.TimeoutError]
    if niquests is not None:
        niq_timeout = getattr(getattr(niquests, "exceptions", None), "Timeout", None)
        if isinstance(niq_timeout, type) and issubclass(niq_timeout, BaseException):
            errs.append(niq_timeout)
    return tuple(errs)


__all__ = ["RedfishTransport"]
