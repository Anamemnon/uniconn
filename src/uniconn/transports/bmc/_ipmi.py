# src/uniconn/transports/bmc/_ipmi.py
"""Транспорт IPMI 2.0 RMCP+ для управления BMC на базе ``pyghmi``."""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
from collections.abc import AsyncIterator, Callable, Iterable, Mapping
from typing import TYPE_CHECKING, Any

from ...exceptions import BMCCapabilityError
from ...exceptions import TimeoutError as UniconnTimeoutError
from ...result import Result
from ..base import BaseTransport

if TYPE_CHECKING:
    from ...config.models import ConnectionConfig

# Импорт опциональный (extra dependency: uniconn[bmc])
try:
    from pyghmi.ipmi import command as ipmi_cmd  # type: ignore[import-untyped]
except ImportError:
    ipmi_cmd = None

_BOOT_DEVICE_MAP: dict[str, tuple[str, str]] = {
    "pxe": ("pxe", "network"),
    "network": ("pxe", "network"),
    "net": ("pxe", "network"),
    "disk": ("disk", "hd"),
    "hdd": ("disk", "hd"),
    "hd": ("disk", "hd"),
    "default": ("disk", "hd"),
    "bios": ("bios", "setup"),
    "setup": ("bios", "setup"),
    "biossetup": ("bios", "setup"),
    "cdrom": ("cdrom", "optical"),
    "cd": ("cdrom", "optical"),
    "iso": ("cdrom", "optical"),
    "optical": ("cdrom", "optical"),
}

_HEALTH_CODE_MAP: dict[int, str] = {
    0: "OK",
    1: "Warning",
    2: "Critical",
    4: "Failed",
}

_TEMP_UNIT_ALIASES: frozenset[str] = frozenset(
    {"c", "°c", "degc", "deg c", "celsius", "degrees c"}
)

_THRESHOLD_KEYS: tuple[str, ...] = (
    "upper_non_critical",
    "upper_critical",
    "upper_non_recoverable",
    "lower_non_critical",
    "lower_critical",
    "lower_non_recoverable",
)

SUPPORTED_IPMI_COMMANDS: tuple[str, ...] = (
    "power on",
    "power off",
    "power cycle",
    "power reset",
    "power shutdown",
    "power status",
    "status",
    "boot device",
    "boot status",
    "boot <pxe|disk|bios|cdrom> [once|continuous] [uefi|legacy]",
    "sensors",
    "health",
    "sel",
    "sel list",
    "sel clear",
    "logs",
    "logs clear",
    "raw <netfn> <cmd> [data...]",
)


def _json_default(obj: Any) -> Any:
    """Сериализовать нестандартные типы pyghmi (bytearray, bytes, множества, объекты) в JSON."""
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return list(bytes(obj))
    if isinstance(obj, set):
        return list(obj)
    if hasattr(obj, "__dict__"):
        return {
            k: v for k, v in vars(obj).items() if not str(k).startswith("_")
        }
    return str(obj)


def _raise_if_bmc_error(result: Any, operation: str) -> Any:
    """Проверить ответ pyghmi на словарь ``{"error": ...}`` и выбросить ``BMCCapabilityError``."""
    if isinstance(result, Mapping) and result.get("error"):
        raise BMCCapabilityError(f"IPMI {operation} failed: {result['error']}")
    return result


def _parse_ipmi_byte(token: str, label: str = "byte") -> int:
    """Распарсить одиночный байт IPMI (в форматах ``0x30``, ``30h`` или ``48``) с проверкой 0..255."""
    cleaned = token.strip().lower()
    if not cleaned:
        raise BMCCapabilityError(f"Empty IPMI {label} value")
    try:
        if cleaned.startswith("0x"):
            val = int(cleaned, 16)
        elif cleaned.endswith("h") and len(cleaned) > 1:
            val = int(cleaned[:-1], 16)
        else:
            val = int(cleaned, 0)
    except ValueError as exc:
        raise BMCCapabilityError(
            f"Invalid IPMI {label} {token!r}: expected hex (0x00..0xff) or int (0..255)"
        ) from exc

    if not (0 <= val <= 0xFF):
        raise BMCCapabilityError(
            f"IPMI {label} {token!r} out of range: must be between 0x00 (0) and 0xFF (255)"
        )
    return val


def _normalize_health_status(raw_health: Any, states: list[str] | None = None) -> str:
    """Привести числовой или строковый код здоровья pyghmi к ``OK | Warning | Critical | Failed``."""
    if isinstance(raw_health, int) and not isinstance(raw_health, bool):
        return _HEALTH_CODE_MAP.get(raw_health, "Warning" if raw_health > 0 else "OK")
    if isinstance(raw_health, str) and raw_health.strip():
        low = raw_health.strip().lower()
        if low in ("ok", "normal", "good"):
            return "OK"
        if "Warn" in raw_health or "warn" in low or "non-critical" in low:
            return "Warning"
        if "Crit" in raw_health or "crit" in low:
            return "Critical"
        if "Fail" in raw_health or "fail" in low or "non-recoverable" in low:
            return "Failed"
        return raw_health.strip()
    if states:
        joined = " ".join(states).lower()
        if "non-recoverable" in joined or "failed" in joined:
            return "Failed"
        if "critical" in joined and "non-critical" not in joined:
            return "Critical"
        if "non-critical" in joined or "warning" in joined:
            return "Warning"
    return "OK"


def _extract_thresholds(
    item: Any, extra_desc: Mapping[str, Any] | None = None
) -> dict[str, float | int | None]:
    """Извлечь пороговые значения SDR-датчика из объекта/словаря pyghmi и описания."""
    thresholds: dict[str, float | int | None] = dict.fromkeys(_THRESHOLD_KEYS)
    sources: list[Mapping[str, Any]] = []

    if isinstance(item, Mapping):
        if isinstance(item.get("thresholds"), Mapping):
            sources.append(item["thresholds"])
        sources.append(item)
    else:
        raw_thr = getattr(item, "thresholds", None)
        if isinstance(raw_thr, Mapping):
            sources.append(raw_thr)
        elif raw_thr is not None and hasattr(raw_thr, "__dict__"):
            sources.append(vars(raw_thr))
        if hasattr(item, "__dict__"):
            sources.append(vars(item))

    if extra_desc is not None:
        if isinstance(extra_desc.get("thresholds"), Mapping):
            sources.append(extra_desc["thresholds"])
        sources.append(extra_desc)

    alias_map: dict[str, tuple[str, ...]] = {
        "upper_non_critical": (
            "upper_non_critical",
            "upper_noncritical",
            "unc",
            "UpperThresholdNonCritical",
            "high_warn",
        ),
        "upper_critical": (
            "upper_critical",
            "uc",
            "UpperThresholdCritical",
            "high_crit",
            "crit",
        ),
        "upper_non_recoverable": (
            "upper_non_recoverable",
            "upper_nonrecoverable",
            "unr",
            "UpperThresholdFatal",
            "high_fatal",
        ),
        "lower_non_critical": (
            "lower_non_critical",
            "lower_noncritical",
            "lnc",
            "LowerThresholdNonCritical",
            "low_warn",
        ),
        "lower_critical": (
            "lower_critical",
            "lc",
            "LowerThresholdCritical",
            "low_crit",
        ),
        "lower_non_recoverable": (
            "lower_non_recoverable",
            "lower_nonrecoverable",
            "lnr",
            "LowerThresholdFatal",
            "low_fatal",
        ),
    }

    for canonical_key, aliases in alias_map.items():
        for src in sources:
            found = False
            for alias in aliases:
                val = src.get(alias)
                if isinstance(val, (int, float)) and not isinstance(val, bool):
                    thresholds[canonical_key] = val
                    found = True
                    break
            if found:
                break

    return thresholds


def _normalize_sensor_entry(
    item: Any, desc_by_name: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    """Преобразовать показание датчика pyghmi (`SensorReading` или `dict`) в детальный словарь."""
    if isinstance(item, Mapping):
        name = str(item.get("name") or item.get("id") or "Sensor")
        stype = str(item.get("type") or item.get("sensor_type") or "")
        value = item.get("value")
        if value is None:
            value = item.get("reading_celsius", item.get("reading"))
        units = str(item.get("units") or ("°C" if "reading_celsius" in item else ""))
        raw_states = item.get("states") or []
        states = (
            [str(s) for s in raw_states]
            if isinstance(raw_states, Iterable)
            and not isinstance(raw_states, (str, bytes))
            else []
        )
        raw_health = item.get("status", item.get("health"))
        imprecision = item.get("imprecision")
    else:
        name = str(getattr(item, "name", None) or "Sensor")
        stype = str(getattr(item, "type", None) or "")
        value = getattr(item, "value", None)
        units = str(getattr(item, "units", None) or "")
        raw_states = getattr(item, "states", None) or ()
        states = [str(s) for s in raw_states]
        raw_health = getattr(item, "health", getattr(item, "status", None))
        imprecision = getattr(item, "imprecision", None)

    desc = desc_by_name.get(name)
    if not stype and desc is not None:
        stype = str(desc.get("type") or "")

    thresholds = _extract_thresholds(item, desc)
    status = _normalize_health_status(raw_health, states)

    # Если статус OK, но значение вышло за критические или некритические пороги SDR — уточняем статус
    if status == "OK" and isinstance(value, (int, float)) and not isinstance(value, bool):
        unr = thresholds["upper_non_recoverable"]
        uc = thresholds["upper_critical"]
        unc = thresholds["upper_non_critical"]
        lnr = thresholds["lower_non_recoverable"]
        lc = thresholds["lower_critical"]
        lnc = thresholds["lower_non_critical"]
        if (unr is not None and value >= unr) or (lnr is not None and value <= lnr):
            status = "Failed"
        elif (uc is not None and value >= uc) or (lc is not None and value <= lc):
            status = "Critical"
        elif (unc is not None and value >= unc) or (lnc is not None and value <= lnc):
            status = "Warning"

    return {
        "name": name,
        "type": stype or "Unknown",
        "value": value,
        "units": units,
        "status": status,
        "states": states,
        "imprecision": imprecision,
        "thresholds": thresholds,
        "upper_threshold_critical": thresholds["upper_critical"],
        "lower_threshold_critical": thresholds["lower_critical"],
    }


def _collect_detailed_sensors(cmd: Any) -> dict[str, Any]:
    """Собрать детальную телеметрию датчиков SDR (`get_sensor_data`) с откатом на `get_health`."""
    desc_by_name: dict[str, Mapping[str, Any]] = {}
    get_desc = getattr(cmd, "get_sensor_descriptions", None)
    if callable(get_desc):
        try:
            raw_descs = get_desc()
            if isinstance(raw_descs, Iterable):
                for d in raw_descs:
                    if isinstance(d, Mapping):
                        if d.get("name"):
                            desc_by_name[str(d["name"])] = d
                    elif hasattr(d, "name") and hasattr(d, "__dict__"):
                        desc_by_name[str(d.name)] = vars(d)
        except Exception:
            pass

    raw_readings: list[Any] = []
    get_sdata = getattr(cmd, "get_sensor_data", None)
    if callable(get_sdata):
        try:
            sdata_iter = get_sdata()
            if isinstance(sdata_iter, Iterable) and not isinstance(
                sdata_iter, (Mapping, str, bytes)
            ):
                raw_readings = list(sdata_iter)
        except Exception:
            raw_readings = []

    if raw_readings:
        sensors: list[dict[str, Any]] = [
            _normalize_sensor_entry(r, desc_by_name) for r in raw_readings
        ]
        temperatures: list[dict[str, Any]] = []
        fans: list[dict[str, Any]] = []
        voltages: list[dict[str, Any]] = []
        power: list[dict[str, Any]] = []

        for s in sensors:
            stype_low = s["type"].lower()
            units_low = s["units"].strip().lower()
            name_low = s["name"].lower()
            if (
                "temp" in stype_low
                or units_low in _TEMP_UNIT_ALIASES
                or "temp" in name_low
            ):
                norm_temp_unit = (
                    "°C" if (not s["units"] or units_low in _TEMP_UNIT_ALIASES) else s["units"]
                )
                temperatures.append(
                    {
                        "name": s["name"],
                        "reading_celsius": s["value"],
                        "units": norm_temp_unit,
                        "status": s["status"],
                        "upper_threshold_critical": s["upper_threshold_critical"],
                        "lower_threshold_critical": s["lower_threshold_critical"],
                        "thresholds": s["thresholds"],
                    }
                )
            elif (
                "fan" in stype_low
                or units_low in ("rpm", "%")
                or "fan" in name_low
            ):
                fans.append(
                    {
                        "name": s["name"],
                        "reading": s["value"],
                        "units": s["units"] or "RPM",
                        "status": s["status"],
                        "lower_threshold_critical": s["lower_threshold_critical"],
                        "thresholds": s["thresholds"],
                    }
                )
            elif "volt" in stype_low or units_low in ("v", "volts", "mv"):
                voltages.append(s)
            elif (
                "power" in stype_low
                or "current" in stype_low
                or units_low in ("w", "watts", "a", "amps")
            ):
                power.append(s)

        return {
            "sensors": sensors,
            "temperatures": temperatures,
            "fans": fans,
            "voltages": voltages,
            "power": power,
        }

    # Откат на get_health() (для базовых моков и BMC без SDR)
    health_data = _raise_if_bmc_error(cmd.get_health(), "get_health")
    if isinstance(health_data, Mapping):
        result_dict = dict(health_data)
        result_dict.setdefault("temperatures", [])
        result_dict.setdefault("fans", [])
        result_dict.setdefault("voltages", [])
        result_dict.setdefault("power", [])
        if "sensors" not in result_dict:
            derived_sensors: list[dict[str, Any]] = []
            for t in result_dict.get("temperatures") or []:
                derived_sensors.append(_normalize_sensor_entry(t, desc_by_name))
            for f in result_dict.get("fans") or []:
                derived_sensors.append(_normalize_sensor_entry(f, desc_by_name))
            result_dict["sensors"] = derived_sensors
        return result_dict
    return {
        "health": health_data,
        "sensors": [],
        "temperatures": [],
        "fans": [],
        "voltages": [],
        "power": [],
    }


def _normalize_sel_entry(entry: Any, idx: int) -> dict[str, Any]:
    """Привести запись журнала событий IPMI SEL к единому словарю."""
    if isinstance(entry, Mapping):
        rec = dict(entry)
        rec.setdefault("id", rec.get("record_id", idx + 1))
        rec.setdefault("timestamp", rec.get("time") or rec.get("created") or "")
        rec["severity"] = _normalize_health_status(
            rec.get("severity", rec.get("health", "OK"))
        )
        rec.setdefault(
            "sensor",
            rec.get("component")
            or rec.get("sensor_type")
            or rec.get("sensor_name")
            or "",
        )
        rec.setdefault("event", rec.get("message") or rec.get("event_data") or "")
        return rec

    return {
        "id": getattr(entry, "record_id", idx + 1),
        "timestamp": str(getattr(entry, "timestamp", getattr(entry, "time", ""))),
        "severity": _normalize_health_status(getattr(entry, "severity", "OK")),
        "sensor": str(getattr(entry, "component", getattr(entry, "sensor", ""))),
        "event": str(getattr(entry, "event", entry)),
    }


def _execute_sel(cmd: Any, *, clear: bool) -> dict[str, Any]:
    """Выполнить чтение (`sel` / `sel list`) или очистку (`sel clear`) журнала IPMI SEL."""
    get_log = getattr(cmd, "get_event_log", None)
    if not callable(get_log):
        raise BMCCapabilityError("IPMI SEL is not supported by the underlying command client")

    try:
        raw_log = get_log(clear=clear)
    except TypeError:
        raw_log = get_log()
        if clear and callable(getattr(cmd, "clear_event_log", None)):
            cmd.clear_event_log()

    _raise_if_bmc_error(raw_log, "get_event_log")
    raw_items = (
        list(raw_log)
        if isinstance(raw_log, Iterable) and not isinstance(raw_log, (Mapping, str, bytes))
        else ([raw_log] if raw_log is not None else [])
    )
    entries = [_normalize_sel_entry(item, i) for i, item in enumerate(raw_items)]
    return {
        "entries": entries,
        "count": len(entries),
        "cleared": clear,
    }


def _execute_boot(cmd: Any, args: list[str]) -> Any:
    """Выполнить чтение (`boot device`/`boot status`) или установку (`boot <target> ...`) загрузки."""
    if not args or args[0].lower() in ("device", "status", "get"):
        return _raise_if_bmc_error(cmd.get_bootdev(), "get_bootdev")

    target_key = args[0].lower()
    if target_key not in _BOOT_DEVICE_MAP:
        allowed = "pxe, disk, bios, cdrom"
        raise BMCCapabilityError(
            f"Unsupported IPMI boot target: {args[0]!r}. Available targets: {allowed}"
        )

    canonical_target, pyghmi_target = _BOOT_DEVICE_MAP[target_key]
    persist: bool | None = None
    uefiboot: bool | None = None

    for modifier in args[1:]:
        mod_low = modifier.lower()
        if mod_low == "once":
            persist = False
        elif mod_low in ("continuous", "always", "persist", "persistent"):
            persist = True
        elif mod_low == "uefi":
            uefiboot = True
        elif mod_low in ("legacy", "bios"):
            uefiboot = False
        else:
            raise BMCCapabilityError(
                f"Unsupported boot modifier {modifier!r}. "
                "Allowed modifiers: once, continuous, uefi, legacy"
            )

    kwargs: dict[str, Any] = {}
    if persist is not None:
        kwargs["persist"] = persist
    if uefiboot is not None:
        kwargs["uefiboot"] = uefiboot

    raw_res = (
        cmd.set_bootdev(pyghmi_target, **kwargs)
        if kwargs
        else cmd.set_bootdev(pyghmi_target)
    )
    _raise_if_bmc_error(raw_res, "set_bootdev")

    return {
        "bootdev": canonical_target,
        "pyghmi_bootdev": pyghmi_target,
        "persist": bool(persist) if persist is not None else False,
        "uefiboot": uefiboot,
        "response": raw_res,
    }


def _execute_raw(cmd: Any, args: list[str]) -> dict[str, Any]:
    """Отправить сырую байтовую команду IPMI: ``raw <netfn> <cmd> [data...]``."""
    if len(args) < 2:
        raise BMCCapabilityError(
            "IPMI raw command requires at least <netfn> and <cmd>: "
            "raw <netfn> <cmd> [data...]"
        )

    netfn = _parse_ipmi_byte(args[0], label="netfn")
    cmd_byte = _parse_ipmi_byte(args[1], label="cmd")
    data_bytes = [_parse_ipmi_byte(tok, label="data byte") for tok in args[2:]]

    raw_resp = cmd.raw_command(netfn=netfn, command=cmd_byte, data=data_bytes)
    if isinstance(raw_resp, Mapping):
        if raw_resp.get("error"):
            raise BMCCapabilityError(
                f"IPMI raw command failed: {raw_resp['error']} "
                f"(code={raw_resp.get('code', -1)})"
            )
        code = int(raw_resp.get("code", 0) or 0)
        if code != 0:
            raise BMCCapabilityError(
                f"IPMI raw command failed with non-zero completion code "
                f"0x{code:02x} ({code})"
            )
        raw_data = raw_resp.get("data", ())
        resp_bytes = (
            [int(b) & 0xFF for b in raw_data]
            if isinstance(raw_data, Iterable)
            and not isinstance(raw_data, (str, Mapping))
            else []
        )
    elif isinstance(raw_resp, (bytes, bytearray, memoryview, list, tuple)):
        code = 0
        resp_bytes = [int(b) & 0xFF for b in raw_resp]
    else:
        code = 0
        resp_bytes = []

    hex_str = " ".join(f"{b:02x}" for b in resp_bytes)
    return {
        "netfn": netfn,
        "command": cmd_byte,
        "request_data": data_bytes,
        "code": code,
        "data": resp_bytes,
        "hex": hex_str,
    }


class IPMITransport(BaseTransport):
    """IPMI 2.0 RMCP+ транспорт для управления BMC, чтения датчиков SDR, SEL и отправки raw-команд."""

    SUPPORTED_COMMANDS: tuple[str, ...] = SUPPORTED_IPMI_COMMANDS

    # Базовая таблица статических команд (сохранена для обратной совместимости)
    _COMMAND_MAP: dict[str, Callable[[Any], Any]] = {
        "power on": lambda c: c.set_power("on"),
        "power off": lambda c: c.set_power("off"),
        "power shutdown": lambda c: c.set_power("shutdown"),
        "power graceful_off": lambda c: c.set_power("shutdown"),
        "power cycle": lambda c: c.set_power("cycle"),
        "power reset": lambda c: c.set_power("reset"),
        "power status": lambda c: c.get_power(),
        "status": lambda c: c.get_power(),
        "boot device": lambda c: c.get_bootdev(),
        "boot status": lambda c: c.get_bootdev(),
        "sensors": _collect_detailed_sensors,
        "health": _collect_detailed_sensors,
        "sel": lambda c: _execute_sel(c, clear=False),
        "sel list": lambda c: _execute_sel(c, clear=False),
        "logs": lambda c: _execute_sel(c, clear=False),
        "sel clear": lambda c: _execute_sel(c, clear=True),
        "logs clear": lambda c: _execute_sel(c, clear=True),
    }

    def __init__(self, config: ConnectionConfig) -> None:
        if ipmi_cmd is None:
            raise ImportError("pyghmi not installed. Run: pip install uniconn[bmc]")
        super().__init__(config)
        self._bmc = None

    @property
    def name(self) -> str:
        return "ipmi"

    async def connect(self) -> None:
        """IPMI не требует постоянного TCP-соединения (stateless RMCP+)."""
        self._connected = True

    async def disconnect(self) -> None:
        """Отметить транспорт как отключённый."""
        self._connected = False

    async def ping(self, timeout: float | None = None) -> bool:
        """Проверить доступность BMC через лёгкую IPMI команду ``power status``."""
        if not self._connected:
            return False
        try:
            result = await self.run("power status", timeout=timeout)
            return result.ok
        except Exception:
            return False

    def _dispatch_command(self, cmd: Any, command: str) -> Any:
        """Разрешить и выполнить IPMI-команду на экземпляре ``pyghmi.ipmi.command.Command``."""
        normalized = " ".join(command.strip().split())
        low = normalized.lower()

        if low in self._COMMAND_MAP:
            return _raise_if_bmc_error(self._COMMAND_MAP[low](cmd), low)

        parts = normalized.split()
        if not parts:
            raise BMCCapabilityError(
                f"Empty IPMI command. Available: {list(self.SUPPORTED_COMMANDS)}"
            )

        verb = parts[0].lower()
        if verb == "boot":
            return _execute_boot(cmd, parts[1:])

        if verb == "raw":
            return _execute_raw(cmd, parts[1:])

        if verb in ("sel", "logs"):
            raise BMCCapabilityError(
                f"Unsupported IPMI SEL subcommand: {command!r}. "
                "Allowed: 'sel', 'sel list', 'sel clear'"
            )

        raise BMCCapabilityError(
            f"Unknown IPMI command: {command}. "
            f"Available: {list(self.SUPPORTED_COMMANDS)}"
        )

    async def run(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> Result:
        """Выполнить IPMI-команду в пуле потоков и вернуть JSON-сериализованный ``Result``."""
        start_time = time.monotonic()
        loop = asyncio.get_running_loop()

        def _execute() -> Any:
            assert ipmi_cmd is not None
            cmd = ipmi_cmd.Command(
                bmc=self.config.host,
                userid=self.config.username,
                password=(
                    self.config.password.get_secret_value()
                    if self.config.password
                    else None
                ),
                port=self.config.port or 623,
            )
            try:
                return self._dispatch_command(cmd, command)
            finally:
                if type(cmd).__module__.startswith("pyghmi"):
                    session = getattr(cmd, "ipmi_session", None)
                    logout = getattr(session, "logout", None)
                    if callable(logout):
                        with contextlib.suppress(Exception):
                            logout()

        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, _execute),
                timeout=timeout or self.config.timeout,
            )
        except TimeoutError as exc:
            raise UniconnTimeoutError(
                f"IPMI command timed out: {command}",
                command=command,
                host=self.config.host,
            ) from exc

        duration = time.monotonic() - start_time
        stdout_str = (
            result
            if isinstance(result, str)
            else json.dumps(result, ensure_ascii=False, default=_json_default)
        )

        return Result(
            exit_code=0,
            stdout=stdout_str,
            stderr="",
            duration=duration,
            command=command,
            host=self.config.host,
        )

    async def stream(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Построчный вывод результата выполнения IPMI-команды."""
        result = await self.run(command, timeout=timeout, **kwargs)
        for line in result.stdout.splitlines():
            yield line

