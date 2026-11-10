# src/uniconn/services/facts.py
"""Доменный сервис сбора системных фактов (HostFacts) о целевом хосте."""

from __future__ import annotations

import contextlib
import json
import re
import shlex
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .facts_models import (
    DEFAULT_DIFF_FIELDS,
    FACT_COLLECTION_SCRIPT,
    WINDOWS_FACT_POWERSHELL_SCRIPT,
    CustomCommandSpec,
    DiskInfo,
    ExternalToolSpec,
    FactsDiffReport,
    FactSpec,
    FileSourceSpec,
    HostFacts,
    NetworkInterface,
    diff_facts,
    parse_facts_output,
    parse_redfish_facts,
    parse_windows_facts_output,
)

if TYPE_CHECKING:
    from ..core.connection import Connection

_ARTIFACT_PATH_RE = re.compile(
    r"(/[A-Za-z0-9._/-]+\.(?:tar\.xz|tar\.gz|tgz|tar\.bz2|zip|log|json|txt))"
)


def _collect_windows_local_facts(default_host: str) -> HostFacts:
    """Собрать базовые системные факты для локального хоста на платформе Windows через единый Python-сборщик."""
    from ..core.python_worker import collect_local_python_facts

    return collect_local_python_facts(default_host, force_windows=True)


def _is_windows_remote_connection(conn: Connection) -> bool:
    """Проверить, является ли подключение удалённым Windows-хостом (winrm/wsman/qga/pve, включая Cassette)."""
    cfg = getattr(conn, "config", None)
    if getattr(cfg, "transport", "") in ("winrm", "wsman"):
        return True
    tr = getattr(conn, "transport", None)
    if getattr(tr, "name", "") in ("winrm", "wsman") or bool(getattr(tr, "_is_windows", False)):
        return True
    wrapped = getattr(tr, "_wrapped", None) or getattr(tr, "_inner", None)
    if getattr(wrapped, "name", "") in ("winrm", "wsman") or bool(getattr(wrapped, "_is_windows", False)):
        return True
    cassette = getattr(tr, "cassette", None)
    return getattr(cassette, "transport", "") in ("winrm", "wsman")


class ExternalToolRunner:
    """Адаптер делегирования сбора информации внешним диагностическим утилитам."""

    def __init__(self, conn: Connection) -> None:
        """Инициализировать адаптер внешних утилит для подключения."""
        self._conn = conn

    async def run_tool(
        self,
        tool: ExternalToolSpec,
        default_timeout: float | None = None,
        artifact_dir: str | Path | None = None,
    ) -> Any:
        """Выполнить внешнюю утилиту и вернуть структурированный результат или путь к артефакту."""
        if (
            tool.output_mode == "artifact"
            and tool.artifact_glob
            and re.search(r"[;|&`$><\n\r]", tool.artifact_glob)
        ):
            return {
                "ok": False,
                "exit_code": 1,
                "error": f"Unsafe characters in artifact_glob: {tool.artifact_glob!r}",
            }

        binary = tool.resolved_binary()
        if binary:
            if _is_windows_remote_connection(self._conn):
                ps_bin = "'" + binary.replace("'", "''") + "'"
                probe = f"if (Get-Command {ps_bin} -ErrorAction SilentlyContinue) {{ exit 0 }} else {{ exit 1 }}"
                chk = await self._conn.run(
                    probe,
                    raise_on_error=False,
                )
                found = chk.ok
            elif (
                self._conn.config.transport == "local"
                and sys.platform == "win32"
                and not FactCollector(self._conn)._is_run_mocked()
            ):
                import shutil

                win_builtins = {"echo", "dir", "type", "set", "ver", "cd", "copy", "del"}
                found = binary.lower() in win_builtins or shutil.which(binary) is not None
            else:
                probe = f"command -v {shlex.quote(binary)} >/dev/null 2>&1"
                chk = await self._conn.run(
                    probe,
                    raise_on_error=False,
                )
                found = chk.ok
            if not found:
                return {
                    "ok": False,
                    "error": f"Tool {binary!r} not found on host",
                    "binary": binary,
                }

        eff_timeout = tool.timeout if tool.timeout is not None else default_timeout
        res = await self._conn.run(
            tool.command,
            timeout=eff_timeout,
            raise_on_error=False,
        )

        if tool.output_mode == "json":
            raw = res.stdout.strip()
            if raw:
                try:
                    return json.loads(raw)
                except ValueError:
                    pass
            return {
                "ok": res.ok,
                "exit_code": res.exit_code,
                "raw": raw,
                "stderr": res.stderr.strip(),
            }

        if tool.output_mode == "artifact":
            remote_artifact = ""
            if tool.artifact_glob:
                if _is_windows_remote_connection(self._conn):
                    ps_glob = "'" + tool.artifact_glob.replace("'", "''") + "'"
                    glob_cmd = (
                        f"Get-ChildItem -Path {ps_glob} -ErrorAction SilentlyContinue | "
                        "Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName"
                    )
                else:
                    glob_cmd = f"ls -1td {tool.artifact_glob} 2>/dev/null | head -n 1"
                glob_res = await self._conn.run(
                    glob_cmd,
                    raise_on_error=False,
                )
                if glob_res.ok and glob_res.stdout.strip():
                    remote_artifact = glob_res.stdout.strip().splitlines()[0].strip()

            if not remote_artifact:
                combined = f"{res.stdout}\n{res.stderr}"
                match = _ARTIFACT_PATH_RE.search(combined)
                if match:
                    remote_artifact = match.group(1)

            if not remote_artifact:
                return {
                    "ok": False,
                    "exit_code": res.exit_code,
                    "error": "Artifact file not found after running tool",
                    "stdout": res.stdout.strip(),
                }

            artifact_name = Path(remote_artifact.replace("\\", "/")).name
            if not artifact_name or artifact_name in {".", ".."}:
                return {
                    "ok": False,
                    "exit_code": res.exit_code,
                    "error": f"Invalid artifact filename resolved from {remote_artifact!r}",
                }

            target_dir = Path(tool.local_dir or artifact_dir or "./artifacts")
            target_dir.mkdir(parents=True, exist_ok=True)
            local_dest = target_dir / artifact_name
            await self._conn.files.download(remote_artifact, str(local_dest))
            if tool.cleanup_remote:
                with contextlib.suppress(Exception):
                    await self._conn.files.remove_file(remote_artifact)
            return {
                "ok": True,
                "artifact_path": str(local_dest),
                "remote_path": remote_artifact,
            }

        if res.ok:
            return res.stdout.strip()
        return {
            "ok": False,
            "exit_code": res.exit_code,
            "error": res.stderr.strip() or res.stdout.strip(),
        }


class FactCollector:
    """Сервис инспекции хоста и кэширования ``HostFacts``."""

    def __init__(self, conn: Connection) -> None:
        """Инициализировать сборщик фактов для подключения."""
        self._conn = conn
        self.cached: HostFacts | None = None
        self._cached_at: float | None = None
        self._tool_runner = ExternalToolRunner(conn)

    def _is_run_mocked(self) -> bool:
        """Проверить, переопределен ли метод run у подключения или транспорта (для тестов/моков)."""
        conn_run = getattr(self._conn, "run", None)
        conn_type_run = getattr(type(self._conn), "run", None)
        if getattr(conn_run, "__func__", None) is not conn_type_run:
            return True
        tr = getattr(self._conn, "transport", None)
        if tr is not None:
            tr_run = getattr(tr, "run", None)
            tr_type_run = getattr(type(tr), "run", None)
            if getattr(tr_run, "__func__", None) is not tr_type_run:
                return True
        return False

    def _is_redfish_connection(self) -> bool:
        """Проверить, является ли целевое соединение Redfish BMC (включая Cassette/Replay)."""
        if self._conn.config.transport == "redfish":
            return True
        tr = self._conn.transport
        if getattr(tr, "name", "") == "redfish":
            return True
        wrapped = getattr(tr, "_wrapped", None) or getattr(tr, "_inner", None)
        if getattr(wrapped, "name", "") == "redfish":
            return True
        cassette = getattr(tr, "cassette", None)
        return getattr(cassette, "transport", "") == "redfish"

    def _is_network_structured_connection(self) -> bool:
        """Проверить, является ли целевое соединение структурированным сетевым транспортом (netconf/restconf/gnmi)."""
        net_names = {"netconf", "restconf", "gnmi"}
        if self._conn.config.transport in net_names:
            return True
        tr = self._conn.transport
        if getattr(tr, "name", "") in net_names or hasattr(tr, "gather_network_native_facts"):
            return True
        wrapped = getattr(tr, "_wrapped", None) or getattr(tr, "_inner", None)
        if getattr(wrapped, "name", "") in net_names or hasattr(wrapped, "gather_network_native_facts"):
            return True
        cassette = getattr(tr, "cassette", None)
        return getattr(cassette, "transport", "") in net_names

    async def _gather_network_structured_facts(
        self,
        *,
        default_host: str,
        timeout: float | None = None,
    ) -> HostFacts:
        """Собрать ``HostFacts`` из YANG-моделей ``ietf-interfaces`` / ``openconfig-interfaces``."""
        from ..transports.network.base import extract_yang_interfaces_and_system

        tr: Any = getattr(self._conn, "transport", None)
        wrapped: Any = getattr(tr, "_wrapped", None) or getattr(tr, "_inner", None)
        can_replay = hasattr(tr, "_can_replay") and tr._can_replay()

        net_data: dict[str, Any] = {}
        if not can_replay and hasattr(tr, "gather_network_native_facts"):
            net_data = await tr.gather_network_native_facts(timeout=timeout)
        elif not can_replay and hasattr(wrapped, "gather_network_native_facts"):
            if not wrapped.is_connected:
                await wrapped.connect()
            net_data = await wrapped.gather_network_native_facts(timeout=timeout)
        else:
            res = await self._conn.net.get("", timeout=timeout)
            extracted = extract_yang_interfaces_and_system(res.data)
            net_data = {
                "protocol": self._conn.transport_name,
                "hostname": extracted.get("hostname"),
                "os_version": extracted.get("os_version"),
                "interfaces": extracted.get("interfaces", []),
                "raw_data": res.data,
            }

        hostname = str(net_data.get("hostname") or default_host)
        vendor = str(net_data.get("vendor") or "NetworkOS")
        os_ver = str(net_data.get("os_version") or vendor)
        ifaces: list[NetworkInterface] = []
        for item in net_data.get("interfaces") or []:
            if not isinstance(item, Mapping) or not item.get("name"):
                continue
            ifaces.append(
                NetworkInterface(
                    name=str(item["name"]),
                    mac=str(item.get("mac") or ""),
                    ipv4=[str(x) for x in (item.get("ipv4") or [])],
                    ipv6=[str(x) for x in (item.get("ipv6") or [])],
                    state=str(item.get("state") or "UP"),
                    mtu=int(item.get("mtu") or 1500),
                )
            )
        return HostFacts(
            hostname=hostname,
            os_family="NetworkOS",
            distro=os_ver,
            interfaces=ifaces,
            custom={"net": net_data},
        )

    def _is_windows_connection(self) -> bool:
        """Проверить, является ли целевое соединение WinRM/WSMan (включая Cassette/Replay)."""
        return _is_windows_remote_connection(self._conn)

    async def gather(
        self,
        refresh: bool = False,
        timeout: float | None = None,
        spec: FactSpec | Mapping[str, Any] | str | Path | None = None,
        artifact_dir: str | Path | None = None,
        ttl: float | None = None,
    ) -> HostFacts:
        """Собрать системные факты (базовые + декларативные источники ``FactSpec``)."""
        resolved_spec = FactSpec.coerce(spec)
        if (
            not refresh
            and resolved_spec is None
            and self.cached is not None
            and (
                ttl is None
                or (
                    self._cached_at is not None
                    and (time.monotonic() - self._cached_at) <= ttl
                )
            )
        ):
            return self.cached

        default_host = self._conn.config.host or "localhost"
        if self._conn.dry_run:
            os_fam = (
                "Windows"
                if self._is_windows_connection()
                else ("NetworkOS" if self._is_network_structured_connection() else "Unknown")
            )
            facts = HostFacts(os_family=os_fam, hostname=default_host)
            self.cached = facts
            self._cached_at = time.monotonic()
            return facts

        include_builtin = (
            True if resolved_spec is None else resolved_spec.include_builtin
        )
        if include_builtin:
            if self._is_redfish_connection():
                res = await self._conn.run(
                    "inventory",
                    timeout=timeout,
                    raise_on_error=False,
                )
                facts = parse_redfish_facts(res.stdout, default_host=default_host)
            elif self._is_network_structured_connection():
                facts = await self._gather_network_structured_facts(
                    default_host=default_host,
                    timeout=timeout,
                )
            elif self._is_windows_connection():
                win_res = await self._conn.run(
                    WINDOWS_FACT_POWERSHELL_SCRIPT,
                    timeout=timeout,
                    raise_on_error=False,
                )
                facts = parse_windows_facts_output(
                    win_res.stdout, default_host=default_host
                )
                await self._enrich_with_qga_native_facts(
                    facts,
                    default_host=default_host,
                    timeout=timeout,
                )
            else:
                worker = getattr(self._conn, "_python_worker", None)
                worker_facts: HostFacts | None = None
                if worker is not None and worker.can_auto_accelerate():
                    with contextlib.suppress(Exception):
                        worker_facts = await worker.gather_facts(
                            default_host=default_host,
                            timeout=timeout,
                        )
                if worker_facts is not None:
                    facts = worker_facts
                elif (
                    sys.platform == "win32"
                    and self._conn.transport_name == "local"
                    and not self._is_run_mocked()
                ):
                    facts = _collect_windows_local_facts(default_host)
                else:
                    res = await self._conn.run(
                        FACT_COLLECTION_SCRIPT,
                        timeout=timeout,
                        raise_on_error=False,
                    )
                    facts = parse_facts_output(res.stdout, default_host=default_host)
                    if facts.os_family == "Unknown":
                        win_res = await self._conn.run(
                            WINDOWS_FACT_POWERSHELL_SCRIPT,
                            timeout=timeout,
                            raise_on_error=False,
                        )
                        if win_res.ok and win_res.stdout.strip():
                            win_facts = parse_windows_facts_output(
                                win_res.stdout, default_host=default_host
                            )
                            if win_facts.os_family == "Windows":
                                facts = win_facts
                    await self._enrich_with_qga_native_facts(
                        facts,
                        default_host=default_host,
                        timeout=timeout,
                    )
        else:
            facts = HostFacts(hostname=default_host)

        if resolved_spec is not None:
            await self._collect_spec_sources(
                facts,
                resolved_spec,
                default_timeout=timeout,
                artifact_dir=artifact_dir,
            )

        if include_builtin:
            self.cached = facts
            self._cached_at = time.monotonic()
        return facts

    async def _enrich_with_qga_native_facts(
        self,
        facts: HostFacts,
        *,
        default_host: str,
        timeout: float | None = None,
    ) -> None:
        """Обогатить ``HostFacts`` нативными RPC-данными QEMU Guest Agent (для ``qga://`` и ``pve://``)."""
        tr: Any = getattr(self._conn, "transport", None)
        wrapped: Any = getattr(tr, "_wrapped", None) or getattr(tr, "_inner", None)
        target_tr: Any = wrapped if hasattr(wrapped, "gather_qga_native_facts") else tr
        if not hasattr(target_tr, "gather_qga_native_facts"):
            return

        with contextlib.suppress(Exception):
            qga_data = await target_tr.gather_qga_native_facts(timeout=timeout or 5.0)
            if not isinstance(qga_data, dict) or not qga_data:
                return

            tr_name = getattr(target_tr, "name", "qga")
            custom_key = "pve" if tr_name == "pve" else "qga"
            facts.custom[custom_key] = qga_data

            qga_hn = str(qga_data.get("hostname") or "").strip()
            if qga_hn and facts.hostname in ("localhost", default_host, "Unknown", ""):
                facts.hostname = qga_hn

            osinfo = qga_data.get("osinfo")
            if isinstance(osinfo, dict) and osinfo:
                if facts.distro == "Unknown":
                    facts.distro = str(
                        osinfo.get("pretty-name") or osinfo.get("name") or "Unknown"
                    )
                if facts.kernel == "Unknown" and osinfo.get("kernel-release"):
                    facts.kernel = str(osinfo["kernel-release"])
                if facts.arch == "Unknown" and osinfo.get("machine"):
                    facts.arch = str(osinfo["machine"])
                if facts.os_family == "Unknown":
                    os_id = str(osinfo.get("id") or "").lower()
                    if "mswindows" in os_id:
                        facts.os_family = "Windows"
                    elif os_id:
                        from .facts_models import _detect_os_family

                        facts.os_family = _detect_os_family({"ID": os_id}, "Linux")

            vcpus = qga_data.get("vcpus")
            if isinstance(vcpus, list) and vcpus and facts.cpu_count <= 1:
                facts.cpu_count = len(vcpus)

            native_ifaces = qga_data.get("interfaces")
            if isinstance(native_ifaces, list) and native_ifaces:
                by_name = {iface.name: iface for iface in facts.interfaces}
                for item in native_ifaces:
                    if not isinstance(item, dict) or not item.get("name"):
                        continue
                    if_name = str(item["name"])
                    if if_name in by_name:
                        existing = by_name[if_name]
                        if not existing.mac or existing.mac == "00:00:00:00:00:00":
                            existing.mac = str(item.get("mac") or existing.mac)
                        for ip4 in item.get("ipv4") or []:
                            if ip4 not in existing.ipv4:
                                existing.ipv4.append(str(ip4))
                        for ip6 in item.get("ipv6") or []:
                            if ip6 not in existing.ipv6:
                                existing.ipv6.append(str(ip6))
                    else:
                        new_iface = NetworkInterface(
                            name=if_name,
                            mac=str(item.get("mac") or ""),
                            ipv4=[str(x) for x in (item.get("ipv4") or [])],
                            ipv6=[str(x) for x in (item.get("ipv6") or [])],
                            state=str(item.get("state") or "UP"),
                            mtu=int(item.get("mtu") or 1500),
                        )
                        facts.interfaces.append(new_iface)
                        by_name[if_name] = new_iface

            fsinfo = qga_data.get("fsinfo")
            if isinstance(fsinfo, list) and fsinfo and not facts.disks:
                for fs in fsinfo:
                    if not isinstance(fs, dict):
                        continue
                    mount = str(fs.get("mountpoint") or "")
                    if not mount:
                        continue
                    total_b = int(fs.get("total-bytes") or 0)
                    used_b = int(fs.get("used-bytes") or 0)
                    avail_b = max(0, total_b - used_b)
                    pct = round((used_b / total_b) * 100.0, 1) if total_b > 0 else 0.0
                    facts.disks.append(
                        DiskInfo(
                            device=str(fs.get("name") or mount),
                            mountpoint=mount,
                            fstype=str(fs.get("type") or ""),
                            total_bytes=total_b,
                            used_bytes=used_b,
                            available_bytes=avail_b,
                            use_percent=pct,
                        )
                    )

    @staticmethod
    def _parse_custom_value(raw: str, parse_json: bool) -> Any:
        """Безопасно преобразовать JSON-строку или вернуть сырое текстовое значение."""
        if parse_json and raw:
            with contextlib.suppress(ValueError):
                return json.loads(raw)
        return raw

    async def _read_file_source(
        self,
        file_spec: FileSourceSpec,
        default_timeout: float | None = None,
    ) -> str:
        """Прочитать содержимое файла с ограничением по байтам и безопасным fallback."""
        max_bytes = int(file_spec.max_bytes)
        try:
            content = await self._conn.files.read_file(file_spec.path, encoding="utf-8")
            if isinstance(content, str):
                return content[:max_bytes].strip()
            if isinstance(content, bytes):
                return content[:max_bytes].decode("utf-8", errors="replace").strip()
        except Exception:
            pass

        # Fallback через shell-команду head -c (для совместимости с моками или хостами без SFTP)
        try:
            q_path = shlex.quote(file_spec.path)
            cmd = f"head -c {max_bytes} {q_path} 2>/dev/null || true"
            res = await self._conn.run(cmd, timeout=default_timeout, raise_on_error=False)
            return res.stdout.strip()
        except Exception:
            return ""

    async def _collect_spec_sources(
        self,
        facts: HostFacts,
        spec: FactSpec,
        default_timeout: float | None = None,
        artifact_dir: str | Path | None = None,
    ) -> None:
        """Собрать пользовательские команды, файлы и внешние утилиты по ``FactSpec``."""
        for cmd_spec in spec.commands:
            eff_timeout = cmd_spec.timeout if cmd_spec.timeout is not None else default_timeout
            res = await self._conn.run(
                cmd_spec.command,
                timeout=eff_timeout,
                raise_on_error=False,
            )
            facts.custom[cmd_spec.name] = self._parse_custom_value(res.stdout.strip(), cmd_spec.parse_json)

        for file_spec in spec.files:
            raw_file = await self._read_file_source(file_spec, default_timeout=default_timeout)
            facts.custom[file_spec.name] = self._parse_custom_value(raw_file, file_spec.parse_json)

        for tool_spec in spec.tools:
            facts.tools[tool_spec.name] = await self._tool_runner.run_tool(
                tool_spec,
                default_timeout=default_timeout,
                artifact_dir=artifact_dir,
            )


__all__ = [
    "DEFAULT_DIFF_FIELDS",
    "FACT_COLLECTION_SCRIPT",
    "WINDOWS_FACT_POWERSHELL_SCRIPT",
    "CustomCommandSpec",
    "DiskInfo",
    "ExternalToolRunner",
    "ExternalToolSpec",
    "FactCollector",
    "FactSpec",
    "FactsDiffReport",
    "FileSourceSpec",
    "HostFacts",
    "NetworkInterface",
    "diff_facts",
    "parse_facts_output",
    "parse_redfish_facts",
    "parse_windows_facts_output",
]

