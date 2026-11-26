# src/uniconn/transports/bmc/redfish/transport.py
"""Фасад транспорта DMTF Redfish BMC (redfish://) на базе niquests.AsyncSession."""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from ...._logging import get_logger
from ....core._shell_quoting import parse_bool, parse_verify_ssl
from ....exceptions import (
    AuthenticationError,
    BMCCapabilityError,
    ConfigurationError,
    ConnectionError,
    TimeoutError,
)
from ....result import Result
from ..._http_base import (
    SSE_MIME,
    close_response_quietly,
    extract_response_headers,
    iter_sse_response,
)
from ...base import BaseTransport, _maybe_aclosing
from .client import (
    RedfishHttpClient,
    builtins_timeout_errors,
    get_niquests_module,
    normalize_redfish_path,
    resolve_lazy_response,
)
from .collectors import (
    collect_inventory,
    collect_sensors,
    collect_storage,
)
from .discovery import (
    RedfishDiscovery,
    resolve_action_target,
)
from .models import (
    BOOT_ENABLED_MAP,
    BOOT_MODE_MAP,
    BOOT_TARGET_MAP,
    MANAGER_RESET_MAP,
    POWER_RESET_MAP,
    SUPPORTED_COMMANDS,
)
from .tasks import (
    RedfishTaskMonitor,
    extract_task_uri_from_response,
)

if TYPE_CHECKING:
    from ....config.models import ConnectionConfig

_logger = get_logger("uniconn.transports.bmc.redfish")


class _RedfishSseUnsupportedError(Exception):
    """Внутренняя ошибка отсутствия поддержки EventService SSE для переключения на polling."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class RedfishTransport(BaseTransport):
    """Асинхронный транспорт DMTF Redfish BMC (HTTPS REST API) на базе ``niquests.AsyncSession``.

    Использует постоянный пул TLS-соединений и HTTP/2 мультиплексирование ``niquests``
    с поддержкой сессионной аутентификации (``X-Auth-Token``), откатом на HTTP Basic Auth,
    кэшированием ``ETag`` (``If-Match``), динамическим резолвингом ``Actions``,
    инвентаризацией дисков/RAID и отслеживанием фоновых задач ``TaskService``.
    """

    SUPPORTED_COMMANDS: tuple[str, ...] = SUPPORTED_COMMANDS

    def __init__(self, config: ConnectionConfig) -> None:
        if get_niquests_module() is None:
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
        elif "verify_ssl" in opts:
            self._verify = parse_verify_ssl(opts["verify_ssl"], default=True)
        elif "verify_tls" in opts:
            self._verify = parse_bool(opts["verify_tls"], default=True)
        elif "insecure" in opts:
            self._verify = not parse_bool(opts["insecure"], default=False)
        else:
            self._verify = True

        self._multiplexed: bool = parse_bool(opts.get("multiplexed"), default=True)
        self._auth_pref: str = str(opts.get("auth", "auto")).lower()
        self._wait_for_tasks: bool = parse_bool(opts.get("wait_for_tasks"), default=True)
        poll_interval = float(opts.get("task_poll_interval", 0.05))

        self._http = RedfishHttpClient(
            base_url=self._base_url,
            verify=self._verify,
            multiplexed=self._multiplexed,
            auth_pref=self._auth_pref,
            username=self.config.username,
            password=self._password_str(),
            default_timeout=self.config.timeout or 30.0,
        )
        self._discovery = RedfishDiscovery(
            options=opts,
            request_json=self._request_json,
        )
        self._tasks = RedfishTaskMonitor(
            request_json=self._request_json,
            default_timeout=self.config.timeout or 30.0,
            poll_interval=poll_interval,
        )

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
        return self._http.auth_mode

    @property
    def _session(self) -> Any:
        return self._http.session

    @_session.setter
    def _session(self, value: Any) -> None:
        self._http.session = value

    @property
    def _auth_mode(self) -> str:
        return self._http.auth_mode

    @_auth_mode.setter
    def _auth_mode(self, value: str) -> None:
        self._http.auth_mode = value

    @property
    def _session_token(self) -> str | None:
        return self._http.session_token

    @_session_token.setter
    def _session_token(self, value: str | None) -> None:
        self._http.session_token = value

    @property
    def _session_location(self) -> str | None:
        return self._http.session_location

    @_session_location.setter
    def _session_location(self, value: str | None) -> None:
        self._http.session_location = value

    @property
    def _system_path(self) -> str | None:
        return self._discovery.system_path

    @_system_path.setter
    def _system_path(self, value: str | None) -> None:
        self._discovery.system_path = value

    @property
    def _chassis_path(self) -> str | None:
        return self._discovery.chassis_path

    @_chassis_path.setter
    def _chassis_path(self, value: str | None) -> None:
        self._discovery.chassis_path = value

    @property
    def _manager_path(self) -> str | None:
        return self._discovery.manager_path

    @_manager_path.setter
    def _manager_path(self, value: str | None) -> None:
        self._discovery.manager_path = value

    def _password_str(self) -> str:
        if self.config.password is None:
            return ""
        return self.config.password.get_secret_value()

    def _create_async_session(self) -> Any:
        return self._http.create_async_session()

    @staticmethod
    async def _resolve_lazy_response(session: Any, resp: Any) -> Any:
        return await resolve_lazy_response(session, resp)

    @staticmethod
    def _normalize_path(path: str) -> str:
        return normalize_redfish_path(path)

    async def _try_create_redfish_session(
        self,
        session: Any,
        username: str,
        password: str,
        timeout: float,
    ) -> bool:
        return await self._http.try_create_redfish_session(
            session, username, password, timeout
        )

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

            # Поскольку /redfish/v1 по стандарту DSP0266 публичен, при Basic Auth
            # дополнительно проверяем доступ к защищённой коллекции /redfish/v1/Systems.
            if self._auth_mode == "basic" and username:
                auth_probe = await session.get("/redfish/v1/Systems", timeout=timeout)
                await self._resolve_lazy_response(session, auth_probe)
                probe_status = int(getattr(auth_probe, "status_code", 0) or 0)
                if probe_status in (401, 403):
                    raise AuthenticationError(
                        f"Redfish Basic authentication rejected on {self._base_url} (HTTP {probe_status})"
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

    async def disconnect(self) -> None:
        """Закрыть Redfish-сессию (DELETE сессии + закрытие пула niquests.AsyncSession)."""
        session = self._session
        location = self._session_location
        self._session = None
        self._session_token = None
        self._session_location = None
        self._auth_mode = "none"
        self._http.etags.clear()
        self._discovery.reset()
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
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        _retry_on_401: bool = True,
    ) -> tuple[int, dict[str, Any]]:
        """Выполнить HTTP-запрос через ``RedfishHttpClient`` и вернуть ``(status, json_dict)``."""
        if not self._connected or self._session is None:
            await self.connect()
        if self._session is None:
            raise ConnectionError("Redfish HTTP session is not initialized", host=self.config.host)

        status, data, _ = await self._http.request_json(
            self._session,
            method,
            path,
            payload=payload,
            headers=headers,
            timeout=timeout,
            _retry_on_401=_retry_on_401,
        )
        if method.upper() == "GET" and 200 <= status < 300:
            norm = self._normalize_path(path).rstrip("/") or "/"
            self._discovery.cached_resources[norm] = data
        return status, data

    async def _request_json_with_headers(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        _retry_on_401: bool = True,
    ) -> tuple[int, dict[str, Any], dict[str, str]]:
        """Выполнить HTTP-запрос и вернуть ``(status, json_dict, response_headers)``."""
        if "_request_json" in self.__dict__:
            st, data = await self._request_json(
                method,
                path,
                payload=payload,
                headers=headers,
                timeout=timeout,
                _retry_on_401=_retry_on_401,
            )
            return st, data, dict(self._http.last_response_headers)

        if not self._connected or self._session is None:
            await self.connect()
        if self._session is None:
            raise ConnectionError("Redfish HTTP session is not initialized", host=self.config.host)

        status, data, resp_headers = await self._http.request_json(
            self._session,
            method,
            path,
            payload=payload,
            headers=headers,
            timeout=timeout,
            _retry_on_401=_retry_on_401,
        )
        if method.upper() == "GET" and 200 <= status < 300:
            norm = self._normalize_path(path).rstrip("/") or "/"
            self._discovery.cached_resources[norm] = data
        return status, data, resp_headers

    async def _invoke_action(
        self,
        *,
        parent_path: str,
        action_name: str,
        default_action_path: str,
        payload: dict[str, Any],
        timeout: float | None = None,
    ) -> tuple[int, dict[str, Any], str]:
        """Выполнить POST-действие Redfish с динамическим резолвингом target URI и ожиданием Task."""
        norm_parent = self._normalize_path(parent_path).rstrip("/")
        cached_parent = self._discovery.cached_resources.get(norm_parent)
        action_path, allowable = resolve_action_target(
            cached_parent, action_name, default_action_path
        )

        effective_payload = dict(payload)
        if allowable and "ResetType" in effective_payload:
            req_rt = str(effective_payload["ResetType"])
            if req_rt not in allowable:
                # Автоматический подбор совместимого типа перезагрузки при различиях вендора
                fallback_pairs = {
                    "GracefulRestart": "ForceRestart",
                    "ForceRestart": "GracefulRestart",
                    "GracefulShutdown": "ForceOff",
                }
                alt = fallback_pairs.get(req_rt)
                if alt and alt in allowable:
                    effective_payload["ResetType"] = alt

        st, resp_data, resp_headers = await self._request_json_with_headers(
            "POST", action_path, payload=effective_payload, timeout=timeout
        )

        # Если стандартный путь вернул 404 и родительский ресурс ещё не запрашивался —
        # получаем родительский ресурс и извлекаем OEM/кастомный target из блока Actions.
        if st == 404 and cached_parent is None:
            pst, pdata = await self._request_json("GET", norm_parent, timeout=timeout)
            if 200 <= pst < 300:
                resolved_target, allowable = resolve_action_target(
                    pdata, action_name, default_action_path
                )
                if resolved_target != action_path:
                    action_path = resolved_target
                    st, resp_data, resp_headers = await self._request_json_with_headers(
                        "POST", action_path, payload=effective_payload, timeout=timeout
                    )

        # Обработка HTTP 202 Accepted (фоновая задача TaskService)
        if st == 202 and self._wait_for_tasks:
            task_uri = extract_task_uri_from_response(
                st, resp_data, resp_headers
            )
            if task_uri:
                task_st, task_summary = await self._tasks.wait_for_task(
                    task_uri, timeout=timeout, initial_data=resp_data
                )
                resp_data = {
                    **resp_data,
                    "task": dict(task_summary),
                }
                st = task_st

        return st, resp_data, action_path

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
            sys_path = await self._discovery.get_system_path(timeout=timeout)
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
        elif cmd_lower in POWER_RESET_MAP:
            reset_type = POWER_RESET_MAP[cmd_lower]
            sys_path = await self._discovery.get_system_path(timeout=timeout)
            default_action = f"{sys_path}/Actions/ComputerSystem.Reset"
            status_code, resp_data, used_target = await self._invoke_action(
                parent_path=sys_path,
                action_name="ComputerSystem.Reset",
                default_action_path=default_action,
                payload={"ResetType": reset_type},
                timeout=timeout,
            )
            output_payload = {
                "ok": 200 <= status_code < 300,
                "action": "ComputerSystem.Reset",
                "target": used_target,
                "ResetType": reset_type,
                "status_code": status_code,
                "response": resp_data,
            }

        # 3. Manager / BMC controller status & reset
        elif cmd_lower in ("manager", "bmc", "manager status", "bmc status") or cmd_lower.startswith(
            ("manager ", "bmc ")
        ):
            status_code, output_payload = await self._handle_manager_command(
                cmd_stripped, cmd_lower, timeout=timeout
            )

        # 4. Sensors & Thermal / Power / DSP0268 Sensors telemetry
        elif cmd_lower in ("sensors", "health"):
            chassis_path = await self._discovery.get_chassis_path(timeout=timeout)
            status_code, output_payload = await collect_sensors(
                chassis_path, self._request_json, timeout=timeout
            )

        # 5. Storage / RAID & Physical Drives
        elif cmd_lower in ("storage", "disks"):
            sys_path = await self._discovery.get_system_path(timeout=timeout)
            status_code, output_payload = await collect_storage(
                sys_path, self._request_json, timeout=timeout
            )

        # 6. Full hardware inventory / system passport
        elif cmd_lower in ("inventory", "system", "info"):
            sys_path, mgr_path, chassis_path = await asyncio.gather(
                self._discovery.get_system_path(timeout=timeout),
                self._discovery.get_manager_path(timeout=timeout),
                self._discovery.get_chassis_path(timeout=timeout),
            )
            status_code, output_payload = await collect_inventory(
                sys_path=sys_path,
                mgr_path=mgr_path,
                chassis_path=chassis_path,
                default_host=self.config.host,
                request_json=self._request_json,
                timeout=timeout,
            )

        # 7. System Event Logs (SEL / Lifecycle Logs)
        elif cmd_lower in ("sel", "logs") or cmd_lower.startswith(("sel ", "logs ")):
            status_code, output_payload = await self._handle_logs_command(
                cmd_lower, timeout=timeout
            )

        # 8. Boot configuration, override & UEFI SecureBoot
        elif cmd_lower.startswith(("boot", "secureboot")):
            status_code, output_payload = await self._handle_boot_command(
                cmd_stripped, cmd_lower, timeout=timeout
            )

        # 9. Virtual Media (ISO mount / unmount / status)
        elif cmd_lower.startswith(("virtual_media", "vmedia")):
            status_code, output_payload = await self._handle_vmedia_command(
                cmd_stripped, cmd_lower, timeout=timeout
            )

        # 10. TaskService monitoring (tasks / task status / task wait)
        elif cmd_lower == "tasks" or cmd_lower.startswith("task "):
            status_code, output_payload = await self._tasks.handle_task_command(
                cmd_stripped, timeout=timeout
            )

        # 10b. EventService metadata & capabilities (events / sse)
        elif cmd_lower in ("events", "sse", "events status", "sse status"):
            status_code, es_data = await self._request_json(
                "GET", "/redfish/v1/EventService", timeout=timeout
            )
            output_payload = {
                "service_uri": "/redfish/v1/EventService",
                "ServiceEnabled": es_data.get("ServiceEnabled"),
                "ServerSentEventUri": es_data.get("ServerSentEventUri"),
                "SSEFilterPropertiesSupported": es_data.get(
                    "SSEFilterPropertiesSupported"
                ),
                "DeliveryRetryAttempts": es_data.get("DeliveryRetryAttempts"),
                "Status": es_data.get("Status", {}),
                "raw": es_data,
            }

        # 11. Raw REST call: GET/POST/PATCH/PUT/DELETE /redfish/v1/...
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

    async def _handle_manager_command(
        self,
        cmd_stripped: str,
        cmd_lower: str,
        timeout: float | None = None,
    ) -> tuple[int, dict[str, Any]]:
        """Обработать команды статуса и перезагрузки контроллера BMC (``manager`` / ``bmc``)."""
        mgr_path = await self._discovery.get_manager_path(timeout=timeout)
        tokens = cmd_lower.split()
        if len(tokens) == 1 or tokens[1] == "status":
            st, mgr_data = await self._request_json("GET", mgr_path, timeout=timeout)
            return st, {
                "Id": mgr_data.get("Id"),
                "Name": mgr_data.get("Name"),
                "Model": mgr_data.get("Model"),
                "Manufacturer": mgr_data.get("Manufacturer"),
                "FirmwareVersion": mgr_data.get("FirmwareVersion"),
                "PowerState": mgr_data.get("PowerState", "On"),
                "Status": mgr_data.get("Status", {}),
                "DateTime": mgr_data.get("DateTime"),
                "ManagerUri": mgr_path,
            }

        if tokens[1] in ("reset", "reboot", "restart"):
            modifier = tokens[2] if len(tokens) >= 3 else "graceful"
            if modifier not in MANAGER_RESET_MAP:
                raise BMCCapabilityError(
                    f"Unknown manager reset modifier: {modifier!r}. "
                    "Use 'graceful' or 'force'"
                )
            reset_type = MANAGER_RESET_MAP[modifier]
            default_action = f"{mgr_path}/Actions/Manager.Reset"
            st, resp, used_target = await self._invoke_action(
                parent_path=mgr_path,
                action_name="Manager.Reset",
                default_action_path=default_action,
                payload={"ResetType": reset_type},
                timeout=timeout,
            )
            return st, {
                "ok": 200 <= st < 300,
                "action": "Manager.Reset",
                "target": used_target,
                "ResetType": reset_type,
                "manager_uri": mgr_path,
                "status_code": st,
                "response": resp,
            }

        raise BMCCapabilityError(
            f"Unsupported manager command: {cmd_stripped!r}. "
            "Use 'manager status' or 'manager reset [graceful|force]'"
        )

    async def _handle_logs_command(
        self,
        cmd_lower: str,
        timeout: float | None = None,
    ) -> tuple[int, dict[str, Any]]:
        log_path = await self._discovery.discover_log_service_path(timeout=timeout)
        parts = cmd_lower.split()
        if len(parts) >= 2 and parts[1] == "clear":
            default_action = f"{log_path}/Actions/LogService.ClearLog"
            st, resp, used_target = await self._invoke_action(
                parent_path=log_path,
                action_name="LogService.ClearLog",
                default_action_path=default_action,
                payload={},
                timeout=timeout,
            )
            return st, {
                "ok": 200 <= st < 300,
                "action": "LogService.ClearLog",
                "target": used_target,
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

    async def _handle_secureboot_command(
        self,
        sys_path: str,
        tokens: list[str],
        cmd_stripped: str,
        timeout: float | None = None,
    ) -> tuple[int, dict[str, Any]]:
        """Обработать команды просмотра и управления UEFI SecureBoot."""
        sb_path = f"{sys_path}/SecureBoot"
        action = tokens[0] if tokens else "status"

        if action == "status":
            st, sb_data = await self._request_json("GET", sb_path, timeout=timeout)
            return st, {
                "secure_boot_uri": sb_path,
                "SecureBootEnable": sb_data.get("SecureBootEnable"),
                "SecureBootCurrentBoot": sb_data.get("SecureBootCurrentBoot"),
                "SecureBootMode": sb_data.get("SecureBootMode"),
            }

        if action in ("on", "enable", "enabled", "true"):
            enable_val = True
        elif action in ("off", "disable", "disabled", "false"):
            enable_val = False
        else:
            raise BMCCapabilityError(
                f"Unsupported SecureBoot action: {cmd_stripped!r}. "
                "Use 'boot secureboot status', 'boot secureboot on', or 'boot secureboot off'"
            )

        st, resp = await self._request_json(
            "PATCH",
            sb_path,
            payload={"SecureBootEnable": enable_val},
            timeout=timeout,
        )
        return st, {
            "ok": 200 <= st < 300,
            "secure_boot_uri": sb_path,
            "SecureBootEnable": enable_val,
            "response": resp,
        }

    async def _handle_boot_command(
        self,
        cmd_stripped: str,
        cmd_lower: str,
        timeout: float | None = None,
    ) -> tuple[int, dict[str, Any]]:
        sys_path = await self._discovery.get_system_path(timeout=timeout)
        all_tokens = cmd_lower.split()

        if all_tokens[0] == "secureboot":
            return await self._handle_secureboot_command(
                sys_path, all_tokens[1:], cmd_stripped, timeout=timeout
            )
        if len(all_tokens) >= 2 and all_tokens[1] == "secureboot":
            return await self._handle_secureboot_command(
                sys_path, all_tokens[2:], cmd_stripped, timeout=timeout
            )

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

        tokens = all_tokens[1:]
        if not tokens or tokens[0] not in BOOT_TARGET_MAP:
            raise BMCCapabilityError(
                f"Unsupported boot command: {cmd_stripped!r}. "
                f"Supported targets: {list(BOOT_TARGET_MAP.keys())}"
            )

        target = BOOT_TARGET_MAP[tokens[0]]
        enabled = "disabled" if target == "None" else "once"
        mode: str | None = None

        for tok in tokens[1:]:
            if tok in BOOT_ENABLED_MAP:
                enabled = tok
            elif tok in BOOT_MODE_MAP:
                mode = BOOT_MODE_MAP[tok]
            else:
                raise BMCCapabilityError(f"Unknown boot modifier: {tok!r}")

        boot_patch: dict[str, Any] = {
            "BootSourceOverrideTarget": target,
            "BootSourceOverrideEnabled": BOOT_ENABLED_MAP[enabled],
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

    async def _handle_vmedia_command(
        self,
        cmd_stripped: str,
        cmd_lower: str,
        timeout: float | None = None,
    ) -> tuple[int, dict[str, Any]]:
        _ = cmd_lower
        vmedia_path = await self._discovery.discover_vmedia_path(timeout=timeout)
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
            default_insert_uri = f"{vmedia_path}/Actions/VirtualMedia.InsertMedia"
            st, resp, used_target = await self._invoke_action(
                parent_path=vmedia_path,
                action_name="VirtualMedia.InsertMedia",
                default_action_path=default_insert_uri,
                payload={"Image": image_url, "Inserted": True},
                timeout=timeout,
            )
            return st, {
                "ok": 200 <= st < 300,
                "action": "VirtualMedia.InsertMedia",
                "target": used_target,
                "Image": image_url,
                "virtual_media_uri": vmedia_path,
                "response": resp,
            }

        if action in ("unmount", "eject"):
            default_eject_uri = f"{vmedia_path}/Actions/VirtualMedia.EjectMedia"
            st, resp, used_target = await self._invoke_action(
                parent_path=vmedia_path,
                action_name="VirtualMedia.EjectMedia",
                default_action_path=default_eject_uri,
                payload={},
                timeout=timeout,
            )
            return st, {
                "ok": 200 <= st < 300,
                "action": "VirtualMedia.EjectMedia",
                "target": used_target,
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
        norm_path = normalize_redfish_path(parts[1])
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

    @staticmethod
    def _format_sse_event_lines(sse_ev: dict[str, str]) -> list[str]:
        """Преобразовать распарсенное SSE-событие Redfish в JSON-строки (разворачивая ``Events``)."""
        raw_data = sse_ev.get("data", "")
        event_name = sse_ev.get("event") or "message"
        sse_id = sse_ev.get("id") or None
        parsed: Any = None
        with contextlib.suppress(json.JSONDecodeError, ValueError, TypeError):
            if raw_data.strip():
                parsed = json.loads(raw_data)

        if isinstance(parsed, dict) and isinstance(parsed.get("Events"), list):
            lines: list[str] = []
            for item in parsed["Events"]:
                if isinstance(item, dict):
                    payload = {
                        "transport_mode": "sse",
                        "event_name": event_name,
                        "event_id": item.get("EventId") or sse_id,
                        "event_type": item.get("EventType") or parsed.get("@odata.type"),
                        "message_id": item.get("MessageId"),
                        "message": item.get("Message"),
                        "severity": item.get("Severity"),
                        "timestamp": item.get("EventTimestamp")
                        or parsed.get("EventTimestamp"),
                        "origin": item.get("OriginOfCondition"),
                        "raw": item,
                    }
                    lines.append(json.dumps(payload, ensure_ascii=False))
            return lines

        if isinstance(parsed, dict):
            payload = dict(parsed)
            payload["transport_mode"] = "sse"
            payload.setdefault("event_name", event_name)
            payload.setdefault(
                "event_id", sse_id or parsed.get("EventId") or parsed.get("Id")
            )
            if "Message" in parsed and "message" not in payload:
                payload["message"] = parsed["Message"]
            if "Severity" in parsed and "severity" not in payload:
                payload["severity"] = parsed["Severity"]
            if "EventTimestamp" in parsed and "timestamp" not in payload:
                payload["timestamp"] = parsed["EventTimestamp"]
            return [json.dumps(payload, ensure_ascii=False)]

        return [
            json.dumps(
                {
                    "transport_mode": "sse",
                    "event_name": event_name,
                    "event_id": sse_id,
                    "message": raw_data,
                },
                ensure_ascii=False,
            )
        ]

    async def _stream_redfish_events(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Потоковая подписка на DMTF Redfish EventService SSE с откатом на polling LogServices."""
        tokens = command.strip().split()[1:]
        strict = parse_bool(kwargs.get("strict"), default=False)
        once = parse_bool(kwargs.get("once"), default=False)
        raw_max = kwargs.get("max_events")
        max_events = int(raw_max) if raw_max is not None else None
        poll_interval = max(0.01, float(kwargs.get("poll_interval", 0.5)))
        filter_expr = kwargs.get("filter")

        if max_events is not None and max_events <= 0:
            return

        for tok in tokens:
            tok_low = tok.lower()
            if tok_low == "strict":
                strict = True
            elif tok_low == "once":
                once = True
            elif tok_low.startswith("filter=") and filter_expr is None:
                filter_expr = tok.split("=", 1)[1]

        if not self._connected or self._session is None:
            await self.connect()
        if self._session is None:
            raise ConnectionError(
                "Redfish HTTP session is not initialized", host=self.config.host
            )

        emitted = 0
        fallback_reason: str | None = None

        try:
            sse_uri = await self._discovery.discover_event_stream_path(timeout=timeout)
            if not sse_uri:
                raise _RedfishSseUnsupportedError(
                    "ServerSentEventUri not advertised by /redfish/v1/EventService"
                )

            target_uri = sse_uri
            if filter_expr:
                sep = "&" if "?" in target_uri else "?"
                target_uri = f"{target_uri}{sep}$filter={quote(str(filter_expr), safe='')}"

            resp = await self._http.open_stream(
                self._session, target_uri, timeout=timeout
            )
            try:
                status = int(getattr(resp, "status_code", 0) or 0)
                resp_hdrs = {
                    k.lower(): v for k, v in extract_response_headers(resp).items()
                }
                ctype = resp_hdrs.get("content-type", "").lower()

                if status in (404, 405, 406, 501) or status >= 400 or status == 0:
                    raise _RedfishSseUnsupportedError(f"HTTP {status}", status=status)
                if SSE_MIME not in ctype:
                    raise _RedfishSseUnsupportedError(
                        f"Unexpected Content-Type {ctype!r}"
                    )
            except BaseException:
                await close_response_quietly(resp)
                raise

            sse_stream = iter_sse_response(
                resp,
                timeout=timeout,
                timeout_errors=builtins_timeout_errors(),
                error_prefix="Redfish EventService SSE",
            )
            async with _maybe_aclosing(sse_stream):
                async for sse_ev in sse_stream:
                    for line in self._format_sse_event_lines(sse_ev):
                        yield line
                        emitted += 1
                        if max_events is not None and emitted >= max_events:
                            return
            return
        except _RedfishSseUnsupportedError as exc:
            fallback_reason = str(exc)

        if strict:
            raise BMCCapabilityError(
                f"Redfish EventService SSE is not supported on {self._base_url}: "
                f"{fallback_reason}",
                host=self.config.host,
            )

        _logger.warning(
            "Redfish EventService SSE unavailable (%s); falling back to LogServices polling",
            fallback_reason,
        )

        log_path = await self._discovery.discover_log_service_path(timeout=timeout)
        seen_keys: set[tuple[str, str, str]] = set()
        deadline = (time.monotonic() + timeout) if timeout is not None else None

        while True:
            _, entries_data = await self._request_json(
                "GET", f"{log_path}/Entries", timeout=timeout
            )
            raw_members = entries_data.get("Members") or []
            if isinstance(raw_members, list):
                for item in raw_members:
                    if not isinstance(item, dict):
                        continue
                    entry_id = str(item.get("Id") or "")
                    created = str(
                        item.get("Created") or item.get("EventTimestamp") or ""
                    )
                    message = str(item.get("Message") or item.get("Name") or "")
                    key = (entry_id, created, message)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    payload = {
                        "transport_mode": "polling",
                        "log_service_uri": log_path,
                        "id": item.get("Id"),
                        "created": created,
                        "severity": item.get("Severity") or "OK",
                        "message": message,
                        "sensor_type": item.get("SensorType"),
                        "raw": item,
                    }
                    yield json.dumps(payload, ensure_ascii=False)
                    emitted += 1
                    if max_events is not None and emitted >= max_events:
                        return

            if once:
                return
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return
                await asyncio.sleep(min(poll_interval, remaining))
            else:
                await asyncio.sleep(poll_interval)

    async def stream(
        self,
        command: str | None = None,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Потоковое чтение вывода (SSE для ``events``/``sse`` и построчный вывод для ``sel``/``logs``)."""
        eff_cmd = command if command is not None else "sel"
        cmd_lower = " ".join(eff_cmd.strip().lower().split())

        if cmd_lower in ("events", "sse") or cmd_lower.startswith(("events ", "sse ")):
            async for line in self._stream_redfish_events(
                eff_cmd, timeout=timeout, **kwargs
            ):
                yield line
            return

        result = await self.run(eff_cmd, timeout=timeout, **kwargs)
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


__all__ = ["RedfishTransport"]
