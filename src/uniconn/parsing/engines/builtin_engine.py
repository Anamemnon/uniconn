# src/uniconn/parsing/engines/builtin_engine.py
"""Встроенные zero-dependency микро-парсеры для системных и сетевых CLI-утилит."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from ...exceptions import ParserNotFoundError, ParsingError

_INT_RE = re.compile(r"^-?\d+$")
_FLOAT_RE = re.compile(r"^-?\d+\.\d+$")
_UPTIME_LOAD_RE = re.compile(
    r"load averages?:\s*([0-9]+(?:[.,][0-9]+)?)[,\s]+([0-9]+(?:[.,][0-9]+)?)[,\s]+([0-9]+(?:[.,][0-9]+)?)",
    re.IGNORECASE,
)
_UPTIME_USERS_RE = re.compile(r"(\d+)\s+users?", re.IGNORECASE)
_UPTIME_TIME_RE = re.compile(r"^\s*(\d{1,2}:\d{2}(?::\d{2})?)\s+up\s+(.+?),\s+\d+\s+user", re.IGNORECASE)
_MOUNT_LINE_RE = re.compile(r"^(.+?)\s+on\s+(.+?)\s+type\s+(\S+)\s*(?:\(([^)]*)\))?$")
_IP_ADDR_HEADER_RE = re.compile(r"^(\d+):\s+([^:@]+)(?:@[^:]+)?:\s+<([^>]*)>\s*(.*)$")


def _coerce_scalar(val: str) -> int | float | bool | str:
    """Преобразовать строковый токен в число или булево значение, если возможно."""
    s = val.strip()
    if _INT_RE.match(s):
        return int(s)
    if _FLOAT_RE.match(s):
        return float(s)
    low = s.lower()
    if low in ("true", "false"):
        return low == "true"
    return s


def _normalize_header(col: str) -> str:
    """Нормализовать имя колонки таблицы в snake_case."""
    cleaned = col.strip().lower().replace("%", "percent_").replace("/", "_").replace("-", "_")
    cleaned = re.sub(r"[^a-z0-9_]+", "_", cleaned)
    return re.sub(r"_+", "_", cleaned).strip("_") or "col"


def parse_df(text: str) -> list[dict[str, Any]]:
    """Распарсить вывод команды ``df`` (``df -h``, ``df -k``, ``df -P``, ``df -T``)."""
    lines = [line.rstrip() for line in text.strip().splitlines() if line.strip()]
    if len(lines) < 2:
        return []

    raw_rows: list[str] = []
    idx = 1
    while idx < len(lines):
        line = lines[idx].strip()
        if not line:
            idx += 1
            continue
        parts = line.split()
        # Обработка переноса длинного имени файловой системы на следующую строку
        if len(parts) == 1 and idx + 1 < len(lines):
            raw_rows.append(f"{line} {lines[idx + 1].strip()}")
            idx += 2
        else:
            raw_rows.append(line)
            idx += 1

    results: list[dict[str, Any]] = []
    for row in raw_rows:
        # Ищем колонку процента вида '42%' или '-' перед точкой монтирования
        match = re.search(r"\s+(\d+%|-)\s+(.+)$", row)
        if not match:
            continue
        pct_raw = match.group(1)
        mount_pt = match.group(2).strip()
        pct_num = int(pct_raw.rstrip("%")) if pct_raw.endswith("%") else 0

        left_part = row[: match.start()].strip()
        left_tokens = left_part.split()
        if len(left_tokens) < 4:
            continue

        fs = left_tokens[0]
        avail_val = left_tokens[-1]
        used_val = left_tokens[-2]
        size_val = left_tokens[-3]
        fstype = left_tokens[1] if len(left_tokens) >= 5 else None

        entry: dict[str, Any] = {
            "filesystem": fs,
            "size": _coerce_scalar(size_val),
            "used": _coerce_scalar(used_val),
            "available": _coerce_scalar(avail_val),
            "percent_used": pct_num,
            "use_percent": pct_num,
            "mounted_on": mount_pt,
        }
        if fstype is not None:
            entry["type"] = fstype
        results.append(entry)
    return results


def parse_uptime(text: str) -> dict[str, Any]:
    """Распарсить вывод команды ``uptime`` (включая ``uptime -p``)."""
    stripped = text.strip()
    if not stripped:
        raise ParsingError("Empty uptime output.")

    load_match = _UPTIME_LOAD_RE.search(stripped)
    if not load_match:
        # Поддержка 'uptime -p' вида "up 2 weeks, 3 days, 1 hour"
        if stripped.lower().startswith("up "):
            up_str = stripped[3:].strip()
            return {
                "time": None,
                "uptime": up_str,
                "users": 0,
                "load_1m": 0.0,
                "load_5m": 0.0,
                "load_15m": 0.0,
                "load_average_1m": 0.0,
                "load_average_5m": 0.0,
                "load_average_15m": 0.0,
            }
        raise ParsingError(f"Could not parse load averages from uptime output: {stripped!r}")

    l1, l5, l15 = (float(val.replace(",", ".")) for val in load_match.groups())
    users_match = _UPTIME_USERS_RE.search(stripped)
    users = int(users_match.group(1)) if users_match else 0

    time_match = _UPTIME_TIME_RE.search(stripped)
    curr_time = time_match.group(1) if time_match else None
    up_str = time_match.group(2).strip() if time_match else None

    return {
        "time": curr_time,
        "uptime": up_str,
        "users": users,
        "load_1m": l1,
        "load_5m": l5,
        "load_15m": l15,
        "load_average_1m": l1,
        "load_average_5m": l5,
        "load_average_15m": l15,
    }


def parse_free(text: str) -> dict[str, Any]:
    """Распарсить вывод команды ``free`` (``free -m``, ``free -h``, ``free -b``)."""
    lines = [line.strip() for line in text.strip().splitlines() if line.strip()]
    mem_info: dict[str, Any] = {}
    swap_info: dict[str, Any] = {}

    for line in lines:
        low = line.lower()
        if low.startswith("mem:"):
            parts = [_coerce_scalar(p) for p in line.split()[1:]]
            keys = ("total", "used", "free", "shared", "buff_cache", "available")
            mem_info = dict(zip(keys, parts, strict=False))
        elif low.startswith("swap:"):
            parts = [_coerce_scalar(p) for p in line.split()[1:]]
            keys = ("total", "used", "free")
            swap_info = dict(zip(keys, parts, strict=False))

    return {
        "mem": mem_info,
        "swap": swap_info,
        "total": mem_info.get("total", 0),
        "used": mem_info.get("used", 0),
        "free": mem_info.get("free", 0),
        "shared": mem_info.get("shared", 0),
        "buff_cache": mem_info.get("buff_cache", 0),
        "available": mem_info.get("available", mem_info.get("free", 0)),
        "swap_total": swap_info.get("total", 0),
        "swap_used": swap_info.get("used", 0),
        "swap_free": swap_info.get("free", 0),
    }


def parse_ps(text: str) -> list[dict[str, Any]]:
    """Распарсить вывод ``ps aux`` или ``ps -ef``."""
    lines = [line.rstrip() for line in text.strip().splitlines() if line.strip()]
    if len(lines) < 2:
        return []

    header_tokens = [_normalize_header(h) for h in lines[0].split()]
    alias_map = {
        "percent_cpu": "cpu_percent",
        "percent_mem": "mem_percent",
        "cmd": "command",
        "uid": "user",
    }
    headers = [alias_map.get(h, h) for h in header_tokens]
    num_cols = len(headers)
    if num_cols == 0:
        return []

    results: list[dict[str, Any]] = []
    for line in lines[1:]:
        parts = line.split(None, num_cols - 1)
        if len(parts) < num_cols:
            continue
        item: dict[str, Any] = {}
        for key, raw_val in zip(headers, parts, strict=False):
            item[key] = raw_val if key == "command" else _coerce_scalar(raw_val)
        results.append(item)
    return results


def parse_ip_route(text: str) -> list[dict[str, Any]]:
    """Распарсить вывод команды ``ip route``."""
    routes: list[dict[str, Any]] = []
    for raw_line in text.strip().splitlines():
        tokens = raw_line.strip().split()
        if not tokens:
            continue
        entry: dict[str, Any] = {"destination": tokens[0], "ip": tokens[0], "flags": []}
        idx = 1
        while idx < len(tokens):
            tok = tokens[idx]
            if tok in ("via", "dev", "proto", "scope", "src", "metric", "table", "pref") and (
                idx + 1 < len(tokens)
            ):
                val = _coerce_scalar(tokens[idx + 1])
                entry[tok] = val
                if tok == "via":
                    entry["gateway"] = val
                idx += 2
            else:
                entry["flags"].append(tok)
                idx += 1
        routes.append(entry)
    return routes


def parse_ip_addr(text: str) -> list[dict[str, Any]]:
    """Распарсить вывод команды ``ip addr``."""
    interfaces: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None

    for raw_line in text.splitlines():
        if not raw_line.strip():
            continue
        hdr_match = _IP_ADDR_HEADER_RE.match(raw_line)
        if hdr_match:
            idx_str, ifname, flags_str, tail = hdr_match.groups()
            tail_tokens = tail.split()
            mtu = None
            state = "UNKNOWN"
            for i, tok in enumerate(tail_tokens):
                if tok == "mtu" and i + 1 < len(tail_tokens) and tail_tokens[i + 1].isdigit():
                    mtu = int(tail_tokens[i + 1])
                elif tok == "state" and i + 1 < len(tail_tokens):
                    state = tail_tokens[i + 1]
            current = {
                "index": int(idx_str),
                "interface": ifname.strip(),
                "flags": [f for f in flags_str.split(",") if f],
                "mtu": mtu,
                "state": state,
                "mac_address": None,
                "ipv4": [],
                "ipv6": [],
            }
            interfaces.append(current)
            continue

        if current is None:
            continue

        stripped = raw_line.strip()
        parts = stripped.split()
        if not parts:
            continue
        if parts[0].startswith("link/") and len(parts) >= 2:
            current["mac_address"] = parts[1]
        elif parts[0] == "inet" and len(parts) >= 2:
            ip_cidr = parts[1]
            ip_part, _, prefix = ip_cidr.partition("/")
            current["ipv4"].append(
                {
                    "address": ip_part,
                    "prefixlen": int(prefix) if prefix.isdigit() else None,
                    "cidr": ip_cidr,
                }
            )
            if "ip" not in current or current["ip"] is None:
                current["ip"] = ip_part
                current["ip_address"] = ip_part
        elif parts[0] == "inet6" and len(parts) >= 2:
            ip_cidr = parts[1]
            ip_part, _, prefix = ip_cidr.partition("/")
            current["ipv6"].append(
                {
                    "address": ip_part,
                    "prefixlen": int(prefix) if prefix.isdigit() else None,
                    "cidr": ip_cidr,
                }
            )

    return interfaces


def parse_mount(text: str) -> list[dict[str, Any]]:
    """Распарсить вывод команды ``mount``."""
    entries: list[dict[str, Any]] = []
    for raw_line in text.strip().splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = _MOUNT_LINE_RE.match(line)
        if not match:
            continue
        fs, mount_pt, fstype, opts_raw = match.groups()
        opts = [o.strip() for o in (opts_raw or "").split(",") if o.strip()]
        entries.append(
            {
                "filesystem": fs.strip(),
                "mounted_on": mount_pt.strip(),
                "type": fstype.strip(),
                "options": opts,
            }
        )
    return entries


def parse_ss(text: str) -> list[dict[str, Any]]:
    """Распарсить вывод ``ss`` или ``netstat`` в список сокетов."""
    lines = [line.strip() for line in text.strip().splitlines() if line.strip()]
    if not lines:
        return []

    sockets: list[dict[str, Any]] = []
    start_idx = 1 if lines[0].lower().startswith(("netid", "proto", "state", "active")) else 0
    if start_idx == 1 and len(lines) > 1 and lines[1].lower().startswith("proto"):
        start_idx = 2

    for line in lines[start_idx:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        # Формат ss: Netid State Recv-Q Send-Q Local_Address:Port Peer_Address:Port [Process]
        if _INT_RE.match(parts[2]) and _INT_RE.match(parts[3]):
            netid, state, recv_q, send_q, local_ep, peer_ep = (
                parts[0],
                parts[1],
                int(parts[2]),
                int(parts[3]),
                parts[4],
                parts[5] if len(parts) > 5 else "*:*",
            )
            proc = " ".join(parts[6:]) if len(parts) > 6 else None
        elif _INT_RE.match(parts[1]) and _INT_RE.match(parts[2]):
            # Формат netstat или ss без колонки Netid: Proto Recv-Q Send-Q Local Foreign [State]
            netid = parts[0]
            recv_q, send_q = int(parts[1]), int(parts[2])
            local_ep, peer_ep = parts[3], parts[4]
            state = parts[5] if len(parts) > 5 else "UNKNOWN"
            proc = " ".join(parts[6:]) if len(parts) > 6 else None
        else:
            continue

        loc_host, _, loc_port = local_ep.rpartition(":")
        peer_host, _, peer_port = peer_ep.rpartition(":")
        sockets.append(
            {
                "netid": netid,
                "proto": netid,
                "state": state,
                "recv_q": recv_q,
                "send_q": send_q,
                "local_address": loc_host or local_ep,
                "local_port": _coerce_scalar(loc_port) if loc_port else "*",
                "peer_address": peer_host or peer_ep,
                "peer_port": _coerce_scalar(peer_port) if peer_port else "*",
                "process": proc,
            }
        )
    return sockets


def parse_systemctl_status(text: str) -> dict[str, Any]:
    """Распарсить вывод ``systemctl status <unit>``."""
    lines = [line.strip() for line in text.strip().splitlines() if line.strip()]
    if not lines:
        return {}

    result: dict[str, Any] = {
        "unit": None,
        "description": None,
        "loaded": None,
        "active": None,
        "sub_state": None,
        "main_pid": None,
    }
    first = lines[0].lstrip("●*○× ").strip()
    if " - " in first:
        unit_name, desc = first.split(" - ", 1)
        result["unit"] = unit_name.strip()
        result["description"] = desc.strip()
    else:
        result["unit"] = first.split()[0] if first else None

    for line in lines[1:]:
        if line.startswith("Loaded:"):
            val = line[len("Loaded:") :].strip()
            result["loaded"] = val.split()[0] if val else None
        elif line.startswith("Active:"):
            val = line[len("Active:") :].strip()
            parts = val.split()
            if parts:
                result["active"] = parts[0]
            sub_match = re.search(r"\(([^)]+)\)", val)
            if sub_match:
                result["sub_state"] = sub_match.group(1)
        elif line.startswith("Main PID:"):
            val = line[len("Main PID:") :].strip()
            pid_part = val.split()[0] if val else ""
            if pid_part.isdigit():
                result["main_pid"] = int(pid_part)
        elif line.startswith("Memory:"):
            result["memory"] = line[len("Memory:") :].strip()
        elif line.startswith("CPU:"):
            result["cpu"] = line[len("CPU:") :].strip()

    active_val = result.get("active")
    result["is_active"] = active_val == "active"
    return result


def parse_kv(text: str) -> dict[str, Any]:
    """Распарсить строки вида ``KEY=VALUE`` или ``key = value`` (``env``, ``sysctl``)."""
    data: dict[str, Any] = {}
    for raw_line in text.strip().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        sep = "=" if "=" in line else (":" if ":" in line else None)
        if sep is None:
            continue
        k, v = line.split(sep, 1)
        key = k.strip()
        val_str = v.strip().strip("'\"")
        if key:
            data[key] = _coerce_scalar(val_str)
    return data


def parse_table(text: str) -> list[dict[str, Any]]:
    """Универсальный парсер табличного вывода с заголовком в первой строке."""
    lines = [line.rstrip() for line in text.strip().splitlines() if line.strip()]
    if len(lines) < 2:
        return []

    # Пропускаем разделительную строку из дефисов (например, '--- --- ---')
    header_line = lines[0]
    data_lines = lines[1:]
    if data_lines and all(c in "-=+ \t" for c in data_lines[0]):
        data_lines = data_lines[1:]

    # Если колонки разделены двумя и более пробелами, используем выравнивание по колонкам
    multi_space_cols = [c.strip() for c in re.split(r"\s{2,}", header_line.strip()) if c.strip()]
    if len(multi_space_cols) >= 2:
        headers = [_normalize_header(h) for h in multi_space_cols]
    else:
        headers = [_normalize_header(h) for h in header_line.split()]

    num_cols = len(headers)
    if num_cols == 0:
        return []

    rows: list[dict[str, Any]] = []
    for line in data_lines:
        stripped = line.strip()
        if not stripped or all(c in "-=+ \t" for c in stripped):
            continue
        parts = stripped.split(None, num_cols - 1)
        if len(parts) < num_cols:
            multi_parts = [p.strip() for p in re.split(r"\s{2,}", stripped) if p.strip()]
            if len(multi_parts) == num_cols:
                parts = multi_parts
        row_dict: dict[str, Any] = {}
        for idx, hdr in enumerate(headers):
            val = parts[idx] if idx < len(parts) else ""
            row_dict[hdr] = _coerce_scalar(val)
        rows.append(row_dict)
    return rows


def parse_cisco_show_ip_int_brief(text: str) -> list[dict[str, Any]]:
    """Распарсить вывод ``show ip interface brief`` (Cisco IOS / IOS-XE / Arista)."""
    lines = [line.strip() for line in text.strip().splitlines() if line.strip()]
    results: list[dict[str, Any]] = []
    int_re = re.compile(
        r"^(\S+)\s+(\S+)\s+(YES|NO)\s+(\S+)\s+"
        r"(administratively\s+down|up|down|deleted)\s+(up|down)\s*$",
        re.IGNORECASE,
    )
    for line in lines:
        if line.lower().startswith("interface"):
            continue
        match = int_re.match(line)
        if not match:
            continue
        intf, ipaddr, ok_val, method, status, proto = match.groups()
        status_norm = " ".join(status.lower().split())
        proto_norm = proto.lower()
        results.append(
            {
                "intf": intf,
                "interface": intf,
                "ipaddr": ipaddr,
                "ip_address": ipaddr,
                "ok": ok_val.upper(),
                "method": method,
                "status": status_norm,
                "proto": proto_norm,
                "protocol": proto_norm,
            }
        )
    return results


def parse_cisco_show_interfaces_status(text: str) -> list[dict[str, Any]]:
    """Распарсить вывод ``show interfaces status``."""
    lines = [line.rstrip() for line in text.strip().splitlines() if line.strip()]
    results: list[dict[str, Any]] = []
    row_re = re.compile(
        r"^(\S+)\s+(.*?)\s+(connected|notconnect|disabled|err-disabled|monitoring|inactive)\s+"
        r"(\S+)\s+(\S+)\s+(\S+)\s*(.*)$",
        re.IGNORECASE,
    )
    for line in lines:
        if line.strip().lower().startswith("port"):
            continue
        match = row_re.match(line.strip())
        if not match:
            continue
        port, name, status, vlan, duplex, speed, media_type = match.groups()
        results.append(
            {
                "port": port,
                "name": name.strip(),
                "status": status.lower(),
                "vlan": vlan,
                "duplex": duplex,
                "speed": speed,
                "type": media_type.strip(),
            }
        )
    return results


def parse_cisco_show_version(text: str) -> dict[str, Any]:
    """Распарсить ключевые поля из вывода ``show version``."""
    ver_match = re.search(r"Version\s+([^,\s]+)", text, re.IGNORECASE)
    up_match = re.search(r"^(\S+)\s+uptime is\s+(.+)$", text, re.IGNORECASE | re.MULTILINE)
    img_match = re.search(r'System image file is\s+"([^"]+)"', text, re.IGNORECASE)
    serial_match = re.search(r"Processor board ID\s+(\S+)", text, re.IGNORECASE)
    return {
        "version": ver_match.group(1) if ver_match else None,
        "hostname": up_match.group(1) if up_match else None,
        "uptime": up_match.group(2).strip() if up_match else None,
        "image": img_match.group(1) if img_match else None,
        "serial": serial_match.group(1) if serial_match else None,
    }


def parse_cisco_show_ip_route(text: str) -> list[dict[str, Any]]:
    """Распарсить маршруты из вывода ``show ip route``."""
    routes: list[dict[str, Any]] = []
    route_re = re.compile(
        r"^([A-Z*]{1,4})\s+(\d+\.\d+\.\d+\.\d+)(?:/(\d+))?\s+"
        r"(?:\[(\d+)/(\d+)\]\s+via\s+(\d+\.\d+\.\d+\.\d+)(?:,\s*([^,\s]+))?(?:,\s*(\S+))?|"
        r"is directly connected,\s*(\S+))"
    )
    for raw_line in text.strip().splitlines():
        line = raw_line.strip()
        match = route_re.match(line)
        if not match:
            continue
        (
            code,
            network,
            prefix,
            distance,
            metric,
            nexthop_ip,
            uptime,
            nexthop_if,
            direct_if,
        ) = match.groups()
        routes.append(
            {
                "protocol": code.strip(),
                "network": network,
                "prefix_length": int(prefix) if prefix and prefix.isdigit() else None,
                "distance": int(distance) if distance and distance.isdigit() else 0,
                "metric": int(metric) if metric and metric.isdigit() else 0,
                "nexthop_ip": nexthop_ip,
                "nexthop_if": nexthop_if or direct_if,
                "uptime": uptime,
            }
        )
    return routes


_BUILTIN_PARSERS: dict[str, Callable[[str], Any]] = {
    "df": parse_df,
    "uptime": parse_uptime,
    "free": parse_free,
    "ps": parse_ps,
    "ip_route": parse_ip_route,
    "ip-route": parse_ip_route,
    "ip_addr": parse_ip_addr,
    "ip-address": parse_ip_addr,
    "ip": parse_ip_addr,
    "mount": parse_mount,
    "ss": parse_ss,
    "netstat": parse_ss,
    "systemctl_status": parse_systemctl_status,
    "systemctl-status": parse_systemctl_status,
    "lsof": parse_table,
    "sysctl": parse_kv,
    "kv": parse_kv,
    "env": parse_kv,
    "table": parse_table,
    "cisco_ios_show_ip_int_brief": parse_cisco_show_ip_int_brief,
    "cisco_ios_show_ip_interface_brief": parse_cisco_show_ip_int_brief,
    "show_ip_interface_brief": parse_cisco_show_ip_int_brief,
    "cisco_ios_show_interfaces_status": parse_cisco_show_interfaces_status,
    "cisco_ios_show_version": parse_cisco_show_version,
    "cisco_ios_show_ip_route": parse_cisco_show_ip_route,
}


class BuiltinEngine:
    """Встроенный zero-dependency движок микро-парсеров для системных и сетевых команд."""

    name: str = "builtin"

    def can_parse(self, spec: str) -> bool:
        """Проверить наличие встроенного микро-парсера для указанной спецификации."""
        return spec.lower() in _BUILTIN_PARSERS

    def parse(self, text: str, spec: str, **kwargs: Any) -> Any:
        """Выполнить разбор вывода с помощью встроенного микро-парсера."""
        key = spec.lower()
        parser_fn = _BUILTIN_PARSERS.get(key)
        if parser_fn is None:
            raise ParserNotFoundError(f"Built-in parser {spec!r} is not registered.")
        return parser_fn(text)


__all__ = ["BuiltinEngine"]
