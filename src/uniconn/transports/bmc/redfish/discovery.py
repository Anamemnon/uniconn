# src/uniconn/transports/bmc/redfish/discovery.py
"""Автообнаружение ресурсов DMTF Redfish (Systems, Chassis, Managers, LogServices, VirtualMedia, Actions)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from .client import normalize_redfish_path

RequestJsonFn = Callable[..., Awaitable[tuple[int, dict[str, Any]]]]

_PREFERRED_LOG_KEYWORDS: tuple[str, ...] = (
    "sel",
    "systemevent",
    "eventlog",
    "lclog",
    "lifecycle",
    "iel",
    "log1",
)
_DEPRIORITIZED_LOG_KEYWORDS: tuple[str, ...] = (
    "faultlist",
    "crashdump",
    "postcode",
    "diagnostic",
)

_PREFERRED_VMEDIA_KEYWORDS: tuple[str, ...] = (
    "cd",
    "dvd",
    "optical",
    "iso",
)
_DEPRIORITIZED_VMEDIA_KEYWORDS: tuple[str, ...] = (
    "floppy",
    "fd",
    "usbstick",
)


def score_log_service_member(member: dict[str, Any]) -> int:
    """Оценить приоритет элемента коллекции LogServices (предпочитая SEL/EventLog вместо FaultList)."""
    odata_id = str(member.get("@odata.id") or "").rstrip("/")
    tail = odata_id.rsplit("/", 1)[-1].lower()
    ident = str(member.get("Id") or "").lower()
    name = str(member.get("Name") or "").lower()
    combined = f"{tail} {ident} {name}"

    if any(bad in combined for bad in _DEPRIORITIZED_LOG_KEYWORDS):
        return -1
    if any(good in combined for good in _PREFERRED_LOG_KEYWORDS):
        return 2
    return 0


def score_vmedia_member(member: dict[str, Any]) -> int:
    """Оценить приоритет слота VirtualMedia (предпочитая CD/DVD слоты вместо Floppy)."""
    media_types = [str(m).upper() for m in (member.get("MediaTypes") or [])]
    if "CD" in media_types or "DVD" in media_types:
        return 3

    odata_id = str(member.get("@odata.id") or "").rstrip("/")
    tail = odata_id.rsplit("/", 1)[-1].lower()
    ident = str(member.get("Id") or "").lower()
    name = str(member.get("Name") or "").lower()
    combined = f"{tail} {ident} {name}"

    if any(bad in combined for bad in _DEPRIORITIZED_VMEDIA_KEYWORDS):
        return -1
    if any(good in combined for good in _PREFERRED_VMEDIA_KEYWORDS):
        return 2
    return 0


def resolve_action_target(
    resource_data: dict[str, Any] | None,
    action_name: str,
    default_target: str,
) -> tuple[str, list[str] | None]:
    """Извлечь целевой URI действия и список AllowableValues из блока ``Actions`` ресурса Redfish.

    Позволяет корректно работать с BMC, использующими нестандартные или OEM-пути
    для ``#ComputerSystem.Reset``, ``#Manager.Reset``, ``#LogService.ClearLog`` и ``#VirtualMedia.*``.
    """
    if not isinstance(resource_data, dict):
        return default_target, None

    actions = resource_data.get("Actions")
    if not isinstance(actions, dict):
        return default_target, None

    candidates: list[dict[str, Any]] = [actions]
    oem_block = actions.get("Oem")
    if isinstance(oem_block, dict):
        candidates.append(oem_block)

    keys_to_check = (f"#{action_name}", action_name)
    short_suffix = action_name.rsplit(".", 1)[-1]

    for container in candidates:
        action_obj: dict[str, Any] | None = None
        for key in keys_to_check:
            if isinstance(container.get(key), dict):
                action_obj = container[key]
                break
        if action_obj is None:
            for k, v in container.items():
                if isinstance(v, dict) and k.endswith(
                    (f".{action_name}", f".{short_suffix}")
                ):
                    action_obj = v
                    break

        if isinstance(action_obj, dict):
            raw_target = action_obj.get("target")
            target = (
                normalize_redfish_path(str(raw_target))
                if raw_target
                else default_target
            )
            allowable: list[str] | None = None
            for ak, av in action_obj.items():
                if ak.endswith("@Redfish.AllowableValues") and isinstance(av, list):
                    allowable = [str(x) for x in av]
                    break
            return target, allowable

    return default_target, None


class RedfishDiscovery:
    """Сервис обнаружения и кэширования путей к ресурсам DMTF Redfish."""

    def __init__(
        self,
        options: dict[str, Any],
        request_json: RequestJsonFn,
    ) -> None:
        self._options = options
        self._request_json = request_json

        self.system_path: str | None = None
        self.chassis_path: str | None = None
        self.manager_path: str | None = None
        self.cached_resources: dict[str, dict[str, Any]] = {}

    def reset(self) -> None:
        """Сбросить закэшированные пути ресурсов при отключении."""
        self.system_path = None
        self.chassis_path = None
        self.manager_path = None
        self.cached_resources.clear()

    async def discover_first_member(
        self,
        collection_path: str,
        fallback_path: str,
        *,
        timeout: float | None = None,
        scorer: Callable[[dict[str, Any]], int] | None = None,
    ) -> str:
        """Найти оптимальный элемент коллекции Redfish ``Members``."""
        status, data = await self._request_json("GET", collection_path, timeout=timeout)
        if 200 <= status < 300:
            members = data.get("Members")
            if isinstance(members, list) and members:
                valid = [
                    m for m in members if isinstance(m, dict) and "@odata.id" in m
                ]
                if valid:
                    best = (
                        max(valid, key=scorer)
                        if scorer is not None and len(valid) > 1
                        else valid[0]
                    )
                    return normalize_redfish_path(str(best["@odata.id"])).rstrip("/")
        return fallback_path

    async def get_system_path(self, timeout: float | None = None) -> str:
        """Получить путь к целевому ресурсу ``ComputerSystem``."""
        if self.system_path:
            return self.system_path
        explicit = self._options.get("system_id")
        if explicit:
            path = str(explicit)
            self.system_path = (
                path if path.startswith("/redfish/") else f"/redfish/v1/Systems/{path}"
            )
            return self.system_path
        self.system_path = await self.discover_first_member(
            "/redfish/v1/Systems", "/redfish/v1/Systems/1", timeout=timeout
        )
        return self.system_path

    async def get_chassis_path(self, timeout: float | None = None) -> str:
        """Получить путь к целевому ресурсу ``Chassis``."""
        if self.chassis_path:
            return self.chassis_path
        explicit = self._options.get("chassis_id")
        if explicit:
            path = str(explicit)
            self.chassis_path = (
                path if path.startswith("/redfish/") else f"/redfish/v1/Chassis/{path}"
            )
            return self.chassis_path
        self.chassis_path = await self.discover_first_member(
            "/redfish/v1/Chassis", "/redfish/v1/Chassis/1", timeout=timeout
        )
        return self.chassis_path

    async def get_manager_path(self, timeout: float | None = None) -> str:
        """Получить путь к целевому ресурсу ``Manager`` (BMC)."""
        if self.manager_path:
            return self.manager_path
        explicit = self._options.get("manager_id")
        if explicit:
            path = str(explicit)
            self.manager_path = (
                path if path.startswith("/redfish/") else f"/redfish/v1/Managers/{path}"
            )
            return self.manager_path
        self.manager_path = await self.discover_first_member(
            "/redfish/v1/Managers", "/redfish/v1/Managers/1", timeout=timeout
        )
        return self.manager_path

    async def discover_log_service_path(self, timeout: float | None = None) -> str:
        """Обнаружить путь к сервису системного журнала (предпочитая SEL/EventLog вместо FaultList)."""
        for getter in (self.get_system_path, self.get_manager_path):
            parent = await getter(timeout=timeout)
            st, col = await self._request_json(
                "GET", f"{parent}/LogServices", timeout=timeout
            )
            if 200 <= st < 300:
                members = col.get("Members") or []
                if isinstance(members, list) and members:
                    valid = [
                        m for m in members if isinstance(m, dict) and "@odata.id" in m
                    ]
                    if valid:
                        best = (
                            max(valid, key=score_log_service_member)
                            if len(valid) > 1
                            else valid[0]
                        )
                        return normalize_redfish_path(str(best["@odata.id"])).rstrip("/")
        sys_path = await self.get_system_path(timeout=timeout)
        return f"{sys_path}/LogServices/Log1"

    async def discover_vmedia_path(self, timeout: float | None = None) -> str:
        """Обнаружить путь к слоту VirtualMedia (предпочитая CD/DVD вместо Floppy)."""
        mgr_path = await self.get_manager_path(timeout=timeout)
        st, col = await self._request_json(
            "GET", f"{mgr_path}/VirtualMedia", timeout=timeout
        )
        if 200 <= st < 300:
            members = col.get("Members") or []
            if isinstance(members, list) and members:
                valid = [
                    m for m in members if isinstance(m, dict) and "@odata.id" in m
                ]
                if len(valid) == 1:
                    return normalize_redfish_path(str(valid[0]["@odata.id"])).rstrip("/")
                if len(valid) > 1:
                    best = max(valid, key=score_vmedia_member)
                    if score_vmedia_member(best) > 0:
                        return normalize_redfish_path(str(best["@odata.id"])).rstrip("/")
                    # Если по URI нельзя определить тип носителя, проверим MediaTypes элементов
                    for cand in valid:
                        cand_path = normalize_redfish_path(
                            str(cand["@odata.id"])
                        ).rstrip("/")
                        cst, cdata = await self._request_json(
                            "GET", cand_path, timeout=timeout
                        )
                        if 200 <= cst < 300:
                            self.cached_resources[cand_path] = cdata
                            if score_vmedia_member(cdata) >= 2:
                                return cand_path
                    return normalize_redfish_path(str(best["@odata.id"])).rstrip("/")
        return f"{mgr_path}/VirtualMedia/CD1"


__all__ = [
    "RedfishDiscovery",
    "resolve_action_target",
    "score_log_service_member",
    "score_vmedia_member",
]
