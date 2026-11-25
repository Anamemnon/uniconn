# src/uniconn/core/_diag_strategies.py
"""Платформенные стратегии автоматической диагностики сбоев (Passive, Linux, Windows)."""

from __future__ import annotations

import contextlib
import json
import re
import shlex
import time
from typing import Protocol

from ..result import DiagnosticSummary, ErrorCategory, PortConflictInfo, SystemVitals
from ._diag_classifier import (
    ClassificationMatch,
    ErrorClassifier,
    ProbeRunner,
    _build_hint_and_actions,
    _sanitize_lines,
)


class DiagnosticStrategy(Protocol):
    """Протокол платформо-специфичной стратегии диагностического зондирования."""

    async def collect(
        self,
        command: str,
        stdout: str,
        stderr: str,
        exit_code: int,
        probe: ProbeRunner,
        *,
        max_log_lines: int = 25,
    ) -> DiagnosticSummary:
        """Выполнить классификацию и целевой сбор метрик/логов."""
        ...


class PassiveDiagnosticStrategy:
    """Безопасная стратегия без запуска shell-зондов (для BMC, NETCONF/gNMI, Serial и Replay)."""

    async def collect(
        self,
        command: str,
        stdout: str,
        stderr: str,
        exit_code: int,
        probe: ProbeRunner,
        *,
        max_log_lines: int = 25,
    ) -> DiagnosticSummary:
        """Классифицировать ошибку только по тексту stdout/stderr и коду возврата."""
        _ = probe
        t0 = time.monotonic()
        match = ErrorClassifier.classify(command, stdout, stderr, exit_code)
        raw_lines = (stderr.splitlines() or stdout.splitlines())[-max_log_lines:]
        relevant_logs = _sanitize_lines(raw_lines, max_lines=max_log_lines)
        port_conflict = (
            PortConflictInfo(port=match.port) if match.port is not None else None
        )
        vitals = SystemVitals()
        hint, actions = _build_hint_and_actions(
            match, vitals, port_conflict, relevant_logs, command
        )
        return DiagnosticSummary(
            category=match.category,
            root_cause_hint=hint,
            vitals=vitals,
            relevant_logs=relevant_logs,
            port_conflict=port_conflict,
            dmesg_tail=[],
            suggested_actions=actions,
            collection_duration_ms=(time.monotonic() - t0) * 1000.0,
        )


class LinuxDiagnosticStrategy:
    """Стратегия диагностического зондирования для Linux / POSIX хостов."""

    _VITALS_CMD = (
        "cat /proc/loadavg 2>/dev/null; "
        "echo '---MEM---'; "
        "head -n 6 /proc/meminfo 2>/dev/null; "
        "echo '---DF---'; "
        "df -Pm / /tmp 2>/dev/null; "
        "echo '---INODE---'; "
        "df -Pi / 2>/dev/null"
    )

    _SS_USER_RE = re.compile(r'\("([^"]+)",pid=(\d+)')
    _SS_ADDR_RE = re.compile(r"\s(\S+):(\d+)\s+\S+\s")
    _NETSTAT_USER_RE = re.compile(r"\b(\d+)/([^\s:]+)")

    @staticmethod
    def parse_vitals(output: str, oom_kill_count: int | None = None) -> SystemVitals:
        """Распарсить вывод агрегированной POSIX-команды витальных показателей."""
        cpu_load_1m: float | None = None
        mem_total_mb: int | None = None
        mem_avail_mb: int | None = None
        mem_free_mb: int | None = None
        disk_root_free_mb: int | None = None
        disk_tmp_free_mb: int | None = None
        disk_root_inodes_free: int | None = None

        sections = output.split("---MEM---")
        load_part = sections[0].strip() if sections else ""
        if load_part:
            tokens = load_part.split()
            if tokens:
                with contextlib.suppress(ValueError):
                    cpu_load_1m = float(tokens[0])

        rest = sections[1] if len(sections) > 1 else ""
        mem_and_df = rest.split("---DF---")
        mem_part = mem_and_df[0] if mem_and_df else ""
        for line in mem_part.splitlines():
            if line.startswith("MemTotal:"):
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    mem_total_mb = int(parts[1]) // 1024
            elif line.startswith("MemAvailable:"):
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    mem_avail_mb = int(parts[1]) // 1024
            elif line.startswith("MemFree:"):
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    mem_free_mb = int(parts[1]) // 1024

        if mem_avail_mb is None and mem_free_mb is not None:
            mem_avail_mb = mem_free_mb

        mem_ratio: float | None = None
        if mem_total_mb and mem_total_mb > 0 and mem_avail_mb is not None:
            mem_ratio = round(mem_avail_mb / mem_total_mb, 4)

        df_and_inode = (mem_and_df[1] if len(mem_and_df) > 1 else "").split("---INODE---")
        df_part = df_and_inode[0] if df_and_inode else ""
        df_data_lines = [
            ln.split()
            for ln in df_part.splitlines()
            if ln.strip() and not ln.startswith("Filesystem")
        ]
        for idx, cols in enumerate(df_data_lines):
            if len(cols) >= 6:
                avail_str = cols[-3]
                mount = cols[-1]
                if avail_str.isdigit():
                    val = int(avail_str)
                    if mount == "/":
                        if disk_root_free_mb is None:
                            disk_root_free_mb = val
                        if idx == 1 and disk_tmp_free_mb is None:
                            disk_tmp_free_mb = val
                    elif mount == "/tmp":
                        disk_tmp_free_mb = val
                    elif idx == 0 and disk_root_free_mb is None:
                        disk_root_free_mb = val
                    elif idx == 1 and disk_tmp_free_mb is None:
                        disk_tmp_free_mb = val

        inode_part = df_and_inode[1] if len(df_and_inode) > 1 else ""
        for ln in inode_part.splitlines():
            if ln.strip() and not ln.startswith("Filesystem"):
                cols = ln.split()
                if len(cols) >= 6 and cols[-3].isdigit():
                    disk_root_inodes_free = int(cols[-3])
                    break
                if len(cols) >= 4 and cols[3].isdigit():
                    disk_root_inodes_free = int(cols[3])
                    break

        return SystemVitals(
            cpu_load_1m=cpu_load_1m,
            memory_total_mb=mem_total_mb,
            memory_available_mb=mem_avail_mb,
            memory_free_ratio=mem_ratio,
            disk_root_free_mb=disk_root_free_mb,
            disk_tmp_free_mb=disk_tmp_free_mb,
            disk_root_inodes_free=disk_root_inodes_free,
            oom_kill_count=oom_kill_count,
        )

    @classmethod
    def parse_port_conflict(cls, port: int, ss_output: str) -> PortConflictInfo:
        """Извлечь PID, имя процесса и адрес прослушивания из вывода ``ss -tlpn`` или ``netstat``."""
        pid: int | None = None
        proc_name: str | None = None
        listen_addr = "0.0.0.0"
        port_token_re = re.compile(rf":(?:{port})(?!\d)")

        for line in ss_output.splitlines():
            if not port_token_re.search(line):
                continue
            for m_addr in cls._SS_ADDR_RE.finditer(f" {line} "):
                if int(m_addr.group(2)) == port:
                    raw_addr = m_addr.group(1)
                    listen_addr = raw_addr.split("%")[0] if "%" in raw_addr else raw_addr
                    break

            m_user = cls._SS_USER_RE.search(line)
            if m_user:
                proc_name = m_user.group(1)
                pid = int(m_user.group(2))
                break

            m_netstat = cls._NETSTAT_USER_RE.search(line)
            if m_netstat:
                pid = int(m_netstat.group(1))
                proc_name = m_netstat.group(2)
                break

        return PortConflictInfo(
            port=port,
            protocol="tcp",
            conflicting_pid=pid,
            conflicting_process=proc_name,
            listen_address=listen_addr,
        )

    async def _collect_vitals(self, probe: ProbeRunner) -> SystemVitals:
        res = await probe(self._VITALS_CMD)
        return self.parse_vitals(res.stdout)

    async def collect(
        self,
        command: str,
        stdout: str,
        stderr: str,
        exit_code: int,
        probe: ProbeRunner,
        *,
        max_log_lines: int = 25,
    ) -> DiagnosticSummary:
        """Собрать витальные показатели Linux и выполнить адресное зондирование по категории сбоя."""
        t0 = time.monotonic()
        match = ErrorClassifier.classify(command, stdout, stderr, exit_code)
        vitals = await self._collect_vitals(probe)

        relevant_logs: list[str] = []
        dmesg_tail: list[str] = []
        port_conflict: PortConflictInfo | None = None

        if match.service_unit is not None and match.category in (
            ErrorCategory.SERVICE_CRASH,
            ErrorCategory.PORT_CONFLICT,
            ErrorCategory.CONFIG_SYNTAX_ERROR,
            ErrorCategory.GENERIC_FAILURE,
        ):
            quoted_unit = shlex.quote(match.service_unit)
            j_cmd = (
                f"journalctl -u {quoted_unit} -n {max_log_lines} --no-pager --output=short-iso 2>/dev/null "
                f"|| systemctl status {quoted_unit} --no-pager -n {max_log_lines} 2>/dev/null"
            )
            j_res = await probe(j_cmd)
            if j_res.stdout.strip():
                relevant_logs = _sanitize_lines(j_res.stdout.splitlines(), max_lines=max_log_lines)
                secondary = ErrorClassifier.classify(
                    command, j_res.stdout, j_res.stderr, exit_code
                )
                if secondary.category != ErrorCategory.GENERIC_FAILURE and (
                    match.category in (ErrorCategory.SERVICE_CRASH, ErrorCategory.GENERIC_FAILURE)
                    or secondary.category == ErrorCategory.PORT_CONFLICT
                ):
                    match = ClassificationMatch(
                        category=secondary.category,
                        port=secondary.port or match.port,
                        service_unit=match.service_unit,
                        target_path=secondary.target_path or match.target_path,
                        conflicting_pid=secondary.conflicting_pid or match.conflicting_pid,
                        conflicting_process=secondary.conflicting_process or match.conflicting_process,
                        matched_signature=secondary.matched_signature or match.matched_signature,
                    )

        if match.category == ErrorCategory.PORT_CONFLICT and match.port is not None:
            ss_cmd = (
                f"ss -tlpn 'sport = :{match.port}' 2>/dev/null "
                f"|| netstat -tlpn 2>/dev/null | grep ':{match.port} '"
            )
            ss_res = await probe(ss_cmd)
            port_conflict = self.parse_port_conflict(match.port, ss_res.stdout)

        if (
            match.category == ErrorCategory.OUT_OF_MEMORY
            or (vitals.oom_kill_count is not None and vitals.oom_kill_count > 0)
        ):
            if match.category == ErrorCategory.GENERIC_FAILURE:
                match = ClassificationMatch(
                    category=ErrorCategory.OUT_OF_MEMORY,
                    service_unit=match.service_unit,
                    matched_signature="cgroup oom_kill > 0",
                )
            dmesg_cmd = (
                "dmesg -T 2>/dev/null | grep -i -E 'oom|killed process|out of memory' | tail -n 10 "
                "|| dmesg 2>/dev/null | grep -i -E 'oom|killed process|out of memory' | tail -n 10"
            )
            d_res = await probe(dmesg_cmd)
            if d_res.stdout.strip():
                dmesg_tail = _sanitize_lines(d_res.stdout.splitlines(), max_lines=10)

        if match.category == ErrorCategory.PERMISSION_DENIED and match.target_path:
            q_path = shlex.quote(match.target_path)
            perm_res = await probe(
                f"id -un 2>/dev/null; ls -ld {q_path} 2>/dev/null; getenforce 2>/dev/null"
            )
            if perm_res.stdout.strip():
                perm_lines = _sanitize_lines(perm_res.stdout.splitlines(), max_lines=10)
                relevant_logs = _sanitize_lines(
                    [*relevant_logs, *perm_lines], max_lines=max_log_lines
                )

        if not relevant_logs:
            fallback_lines = (stderr.splitlines() or stdout.splitlines())[-max_log_lines:]
            relevant_logs = _sanitize_lines(fallback_lines, max_lines=max_log_lines)

        hint, actions = _build_hint_and_actions(
            match, vitals, port_conflict, relevant_logs, command
        )
        return DiagnosticSummary(
            category=match.category,
            root_cause_hint=hint,
            vitals=vitals,
            relevant_logs=relevant_logs,
            port_conflict=port_conflict,
            dmesg_tail=dmesg_tail,
            suggested_actions=actions,
            collection_duration_ms=(time.monotonic() - t0) * 1000.0,
        )


def _extract_json_dict(stdout: str) -> dict[str, object] | None:
    """Извлечь JSON-объект из вывода PowerShell, игнорируя служебные баннеры и прогресс-строки."""
    text = (stdout or "").strip()
    if not text:
        return None
    for candidate in (text, *reversed(text.splitlines())):
        line = candidate.strip()
        if line.startswith("{") and line.endswith("}"):
            with contextlib.suppress(ValueError, TypeError):
                parsed = json.loads(line)
                if isinstance(parsed, dict):
                    return parsed
    return None


class WindowsDiagnosticStrategy:
    """Стратегия диагностического зондирования для Windows (WinRM / PowerShell)."""

    _WIN_VITALS_PS = (
        "powershell -NoProfile -NonInteractive -Command \""
        "$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue; "
        "$drv = Get-PSDrive -Name C -ErrorAction SilentlyContinue; "
        "@{FreeMemKB=$os.FreePhysicalMemory; TotalMemKB=$os.TotalVisibleMemorySize; "
        "FreeDiskBytes=$drv.Free} | ConvertTo-Json -Compress\""
    )

    async def collect(
        self,
        command: str,
        stdout: str,
        stderr: str,
        exit_code: int,
        probe: ProbeRunner,
        *,
        max_log_lines: int = 25,
    ) -> DiagnosticSummary:
        """Собрать диагностику на Windows-хосте через PowerShell."""
        t0 = time.monotonic()
        match = ErrorClassifier.classify(command, stdout, stderr, exit_code)

        vitals = SystemVitals()
        v_res = await probe(self._WIN_VITALS_PS)
        data = _extract_json_dict(v_res.stdout)
        if data is not None:
            with contextlib.suppress(ValueError, TypeError):
                total_kb = data.get("TotalMemKB")
                free_kb = data.get("FreeMemKB")
                free_disk = data.get("FreeDiskBytes")
                mem_total = int(str(total_kb)) // 1024 if total_kb is not None else None
                mem_avail = int(str(free_kb)) // 1024 if free_kb is not None else None
                ratio = (
                    round(mem_avail / mem_total, 4)
                    if mem_total and mem_avail is not None
                    else None
                )
                disk_mb = (
                    int(str(free_disk)) // (1024 * 1024)
                    if free_disk is not None
                    else None
                )
                vitals = SystemVitals(
                    memory_total_mb=mem_total,
                    memory_available_mb=mem_avail,
                    memory_free_ratio=ratio,
                    disk_root_free_mb=disk_mb,
                )

        port_conflict: PortConflictInfo | None = None
        if match.category == ErrorCategory.PORT_CONFLICT and match.port is not None:
            ps_port = (
                "powershell -NoProfile -NonInteractive -Command \""
                f"$c = Get-NetTCPConnection -LocalPort {match.port} -State Listen "
                "-ErrorAction SilentlyContinue | Select-Object -First 1; "
                "if ($c) { $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue; "
                "@{Port=$c.LocalPort; Pid=$c.OwningProcess; Process=$p.ProcessName; "
                "Addr=$c.LocalAddress} | ConvertTo-Json -Compress }\""
            )
            p_res = await probe(ps_port)
            p_data = _extract_json_dict(p_res.stdout)
            if p_data is not None:
                try:
                    raw_pid = p_data.get("Pid")
                    port_conflict = PortConflictInfo(
                        port=match.port,
                        protocol="tcp",
                        conflicting_pid=int(str(raw_pid)) if raw_pid is not None else None,
                        conflicting_process=(
                            str(p_data["Process"]) if p_data.get("Process") else None
                        ),
                        listen_address=str(p_data.get("Addr") or "0.0.0.0"),
                    )
                except (ValueError, TypeError):
                    port_conflict = PortConflictInfo(port=match.port)
            else:
                port_conflict = PortConflictInfo(port=match.port)

        relevant_logs: list[str] = []
        if match.category in (ErrorCategory.SERVICE_CRASH, ErrorCategory.GENERIC_FAILURE):
            ps_evt = (
                "powershell -NoProfile -NonInteractive -Command \""
                "Get-WinEvent -FilterHashtable @{LogName='System','Application'; Level=1,2} "
                f"-MaxEvents {min(max_log_lines, 10)} -ErrorAction SilentlyContinue | "
                "ForEach-Object { $_.TimeCreated.ToString('s') + ' [' + $_.ProviderName + '] ' + $_.Message }\""
            )
            e_res = await probe(ps_evt)
            if e_res.stdout.strip():
                relevant_logs = _sanitize_lines(e_res.stdout.splitlines(), max_lines=max_log_lines)

        if not relevant_logs:
            fallback_lines = (stderr.splitlines() or stdout.splitlines())[-max_log_lines:]
            relevant_logs = _sanitize_lines(fallback_lines, max_lines=max_log_lines)

        hint, actions = _build_hint_and_actions(
            match, vitals, port_conflict, relevant_logs, command
        )
        return DiagnosticSummary(
            category=match.category,
            root_cause_hint=hint,
            vitals=vitals,
            relevant_logs=relevant_logs,
            port_conflict=port_conflict,
            dmesg_tail=[],
            suggested_actions=actions,
            collection_duration_ms=(time.monotonic() - t0) * 1000.0,
        )


__all__ = [
    "DiagnosticStrategy",
    "LinuxDiagnosticStrategy",
    "PassiveDiagnosticStrategy",
    "WindowsDiagnosticStrategy",
    "_extract_json_dict",
]
