"""Сбор системных фактов (HostFacts) о целевом хосте за один батч-запрос."""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel, Field


class DiskInfo(BaseModel):
    """Информация о примонтированном дисковом разделе."""

    device: str
    mountpoint: str
    fstype: str = ""
    total_bytes: int = 0
    used_bytes: int = 0
    available_bytes: int = 0
    use_percent: float = 0.0


class NetworkInterface(BaseModel):
    """Информация о сетевом интерфейсе хоста."""

    name: str
    mac: str = ""
    ipv4: list[str] = Field(default_factory=list)
    ipv6: list[str] = Field(default_factory=list)
    state: str = "UNKNOWN"
    mtu: int = 0


class HostFacts(BaseModel):
    """Типизированная модель системных фактов хоста."""

    os_family: str = "Unknown"
    distro: str = "Unknown"
    kernel: str = "Unknown"
    arch: str = "Unknown"
    hostname: str = "localhost"
    uptime_seconds: float = 0.0
    cpu_count: int = 1
    memory_total_bytes: int = 0
    memory_available_bytes: int = 0
    disks: list[DiskInfo] = Field(default_factory=list)
    interfaces: list[NetworkInterface] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Сериализует системные факты в словарь JSON-совместимых типов."""
        return self.model_dump()


FACT_COLLECTION_SCRIPT = (
    'echo "===UNICONN_SECTION:UNAME==="; '
    'uname -srmn 2>/dev/null || uname -a 2>/dev/null || true; '
    'echo "===UNICONN_SECTION:HOSTNAME==="; '
    'hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null || true; '
    'echo "===UNICONN_SECTION:OS_RELEASE==="; '
    'cat /etc/os-release 2>/dev/null || true; '
    'echo "===UNICONN_SECTION:UPTIME==="; '
    'cat /proc/uptime 2>/dev/null || true; '
    'echo "===UNICONN_SECTION:CPU==="; '
    'nproc 2>/dev/null || grep -c "^processor" /proc/cpuinfo 2>/dev/null || echo 1; '
    'echo "===UNICONN_SECTION:MEMINFO==="; '
    'cat /proc/meminfo 2>/dev/null || free -b 2>/dev/null || true; '
    'echo "===UNICONN_SECTION:DISKS==="; '
    'df -PTk 2>/dev/null || df -Pk 2>/dev/null || true; '
    'echo "===UNICONN_SECTION:NET_JSON==="; '
    'ip -j addr 2>/dev/null || true; '
    'echo "===UNICONN_SECTION:NET_TEXT==="; '
    'ip -o addr 2>/dev/null || ifconfig -a 2>/dev/null || true; '
    'echo "===UNICONN_SECTION:END==="'
)

_SECTION_RE = re.compile(r"^===UNICONN_SECTION:([A-Z_]+)===$", re.MULTILINE)

_DEBIAN_DISTROS = {"debian", "ubuntu", "linuxmint", "pop", "kali", "raspbian"}
_REDHAT_DISTROS = {"rhel", "centos", "fedora", "rocky", "almalinux", "ol", "amzn"}
_ALPINE_DISTROS = {"alpine"}
_ARCH_DISTROS = {"arch", "manjaro", "endeavouros"}
_SUSE_DISTROS = {"sles", "opensuse", "opensuse-leap", "opensuse-tumbleweed"}
_PSEUDO_FS = {"tmpfs", "devtmpfs", "squashfs", "overlay", "proc", "sysfs", "cgroup", "cgroup2", "mqueue", "shm"}


def _split_sections(raw_stdout: str) -> dict[str, str]:
    """Разбивает вывод батч-скрипта по маркерам секций."""
    sections: dict[str, str] = {}
    matches = list(_SECTION_RE.finditer(raw_stdout))
    for idx, match in enumerate(matches):
        name = match.group(1)
        if name == "END":
            break
        start = match.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(raw_stdout)
        sections[name] = raw_stdout[start:end].strip()
    return sections


def _parse_os_release(text: str) -> dict[str, str]:
    """Парсит содержимое /etc/os-release."""
    result: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        val = val.strip().strip('"').strip("'")
        result[key.strip()] = val
    return result


def _detect_os_family(os_rel: dict[str, str], kernel_sys: str) -> str:
    """Определяет семейство ОС по /etc/os-release и имени ядра."""
    id_val = os_rel.get("ID", "").lower()
    like_tokens = set(os_rel.get("ID_LIKE", "").lower().split())
    all_ids = {id_val} | like_tokens

    if all_ids & _DEBIAN_DISTROS:
        return "Debian"
    if all_ids & _REDHAT_DISTROS:
        return "RedHat"
    if all_ids & _ALPINE_DISTROS:
        return "Alpine"
    if all_ids & _ARCH_DISTROS:
        return "Arch"
    if all_ids & _SUSE_DISTROS:
        return "Suse"
    if "darwin" in kernel_sys.lower():
        return "Darwin"
    if "freebsd" in kernel_sys.lower() or "openbsd" in kernel_sys.lower():
        return "BSD"
    if "linux" in kernel_sys.lower():
        return "Linux"
    return kernel_sys or "Unknown"


def _parse_meminfo(text: str) -> tuple[int, int]:
    """Извлекает (memory_total_bytes, memory_available_bytes) из /proc/meminfo или free -b."""
    mem_kb: dict[str, int] = {}
    for line in text.splitlines():
        if ":" in line:
            key, rest = line.split(":", 1)
            parts = rest.strip().split()
            if parts and parts[0].isdigit():
                mem_kb[key.strip()] = int(parts[0])
    if "MemTotal" in mem_kb:
        total = mem_kb["MemTotal"] * 1024
        if "MemAvailable" in mem_kb:
            avail = mem_kb["MemAvailable"] * 1024
        else:
            free_kb = mem_kb.get("MemFree", 0) + mem_kb.get("Buffers", 0) + mem_kb.get("Cached", 0)
            avail = free_kb * 1024
        return total, avail

    # Fallback для вывода `free -b`
    for line in text.splitlines():
        if line.lower().startswith("mem:"):
            parts = line.split()
            if len(parts) >= 4 and parts[1].isdigit():
                total = int(parts[1])
                avail = int(parts[6]) if len(parts) >= 7 and parts[6].isdigit() else int(parts[3])
                return total, avail
    return 0, 0


def _parse_disks(text: str) -> list[DiskInfo]:
    """Парсит вывод df -PTk или df -Pk в список DiskInfo."""
    disks: list[DiskInfo] = []
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if len(lines) <= 1:
        return disks

    header = lines[0].lower()
    has_type_col = "type" in header

    for line in lines[1:]:
        parts = line.split()
        if has_type_col and len(parts) >= 7:
            device, fstype = parts[0], parts[1]
            blocks_str, used_str, avail_str, pct_str, mountpoint = (
                parts[2],
                parts[3],
                parts[4],
                parts[5],
                parts[6],
            )
        elif len(parts) >= 6:
            device, fstype = parts[0], ""
            blocks_str, used_str, avail_str, pct_str, mountpoint = (
                parts[1],
                parts[2],
                parts[3],
                parts[4],
                parts[5],
            )
        else:
            continue

        if fstype.lower() in _PSEUDO_FS or device in _PSEUDO_FS:
            continue
        if not blocks_str.isdigit():
            continue

        total_bytes = int(blocks_str) * 1024
        used_bytes = int(used_str) * 1024 if used_str.isdigit() else 0
        avail_bytes = int(avail_str) * 1024 if avail_str.isdigit() else 0
        pct_clean = pct_str.rstrip("%")
        try:
            use_percent = float(pct_clean)
        except ValueError:
            use_percent = round((used_bytes / total_bytes) * 100.0, 1) if total_bytes > 0 else 0.0

        disks.append(
            DiskInfo(
                device=device,
                mountpoint=mountpoint,
                fstype=fstype,
                total_bytes=total_bytes,
                used_bytes=used_bytes,
                available_bytes=avail_bytes,
                use_percent=use_percent,
            )
        )
    return disks


def _parse_interfaces(net_json: str, net_text: str) -> list[NetworkInterface]:
    """Парсит информацию о сетевых интерфейсах из `ip -j addr` или текстового `ip -o addr`."""
    if net_json:
        try:
            raw_list = json.loads(net_json)
            if isinstance(raw_list, list):
                interfaces: list[NetworkInterface] = []
                for item in raw_list:
                    if not isinstance(item, dict):
                        continue
                    name = str(item.get("ifname", ""))
                    if not name:
                        continue
                    mac = str(item.get("address", "")) if item.get("link_type") != "loopback" else "00:00:00:00:00:00"
                    state = str(item.get("operstate", "UNKNOWN"))
                    mtu = int(item.get("mtu", 0)) if str(item.get("mtu", "")).isdigit() else 0
                    ipv4: list[str] = []
                    ipv6: list[str] = []
                    for addr_info in item.get("addr_info", []):
                        if not isinstance(addr_info, dict):
                            continue
                        family = addr_info.get("family")
                        local_ip = addr_info.get("local")
                        if not local_ip:
                            continue
                        if family == "inet":
                            ipv4.append(str(local_ip))
                        elif family == "inet6":
                            ipv6.append(str(local_ip))
                    interfaces.append(
                        NetworkInterface(
                            name=name,
                            mac=mac,
                            ipv4=ipv4,
                            ipv6=ipv6,
                            state=state,
                            mtu=mtu,
                        )
                    )
                if interfaces:
                    return interfaces
        except (ValueError, TypeError):
            pass

    # Fallback: парсинг `ip -o addr`
    by_name: dict[str, NetworkInterface] = {}
    for line in net_text.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0].rstrip(":").isdigit():
            ifname = parts[1].rstrip(":")
            family = parts[2]
            addr_cidr = parts[3]
            ip_only = addr_cidr.split("/")[0]
            iface = by_name.setdefault(ifname, NetworkInterface(name=ifname))
            if family == "inet" and ip_only not in iface.ipv4:
                iface.ipv4.append(ip_only)
            elif family == "inet6" and ip_only not in iface.ipv6:
                iface.ipv6.append(ip_only)
    return list(by_name.values())


def parse_facts_output(raw_stdout: str, default_host: str | None = None) -> HostFacts:
    """Преобразует сырой stdout батч-скрипта `FACT_COLLECTION_SCRIPT` в `HostFacts`."""
    sections = _split_sections(raw_stdout)

    uname_line = sections.get("UNAME", "").splitlines()[0].strip() if sections.get("UNAME") else ""
    uname_parts = uname_line.split()
    kernel_sys = uname_parts[0] if len(uname_parts) >= 1 else "Linux"
    kernel_rel = uname_parts[1] if len(uname_parts) >= 2 else "Unknown"
    arch = uname_parts[2] if len(uname_parts) >= 3 else "Unknown"
    uname_host = uname_parts[3] if len(uname_parts) >= 4 else ""

    hostname_sec = sections.get("HOSTNAME", "").splitlines()[0].strip() if sections.get("HOSTNAME") else ""
    hostname = hostname_sec or uname_host or default_host or "localhost"

    os_rel = _parse_os_release(sections.get("OS_RELEASE", ""))
    distro = os_rel.get("PRETTY_NAME") or os_rel.get("NAME") or kernel_sys or "Unknown"
    os_family = _detect_os_family(os_rel, kernel_sys)

    uptime_seconds = 0.0
    uptime_raw = sections.get("UPTIME", "").split()
    if uptime_raw:
        try:
            uptime_seconds = float(uptime_raw[0])
        except ValueError:
            uptime_seconds = 0.0

    cpu_count = 1
    cpu_lines = [ln.strip() for ln in sections.get("CPU", "").splitlines() if ln.strip()]
    if cpu_lines:
        try:
            cpu_count = max(1, int(cpu_lines[0]))
        except ValueError:
            cpu_count = 1

    mem_total, mem_avail = _parse_meminfo(sections.get("MEMINFO", ""))
    disks = _parse_disks(sections.get("DISKS", ""))
    interfaces = _parse_interfaces(sections.get("NET_JSON", ""), sections.get("NET_TEXT", ""))

    return HostFacts(
        os_family=os_family,
        distro=distro,
        kernel=kernel_rel,
        arch=arch,
        hostname=hostname,
        uptime_seconds=uptime_seconds,
        cpu_count=cpu_count,
        memory_total_bytes=mem_total,
        memory_available_bytes=mem_avail,
        disks=disks,
        interfaces=interfaces,
    )


__all__ = [
    "FACT_COLLECTION_SCRIPT",
    "DiskInfo",
    "HostFacts",
    "NetworkInterface",
    "parse_facts_output",
]
