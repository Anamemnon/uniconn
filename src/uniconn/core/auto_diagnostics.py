# src/uniconn/core/auto_diagnostics.py
"""Движок автоматической классификации сбоев (ErrorClassifier) и кроссплатформенные стратегии зондирования."""

from __future__ import annotations

import contextlib
import json
import re
import shlex
import sys
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from .._logging import SecretMaskingFilter
from ..result import DiagnosticSummary, ErrorCategory, PortConflictInfo, Result, SystemVitals

if TYPE_CHECKING:
    from .connection import Connection

ProbeRunner = Callable[[str], Awaitable[Result]]


@dataclass(frozen=True, slots=True)
class ClassificationMatch:
    """Результат первичной или каскадной классификации ошибки."""

    category: ErrorCategory = ErrorCategory.GENERIC_FAILURE
    port: int | None = None
    service_unit: str | None = None
    target_path: str | None = None
    conflicting_pid: int | None = None
    conflicting_process: str | None = None
    matched_signature: str = ""


class ErrorClassifier:
    """Сигнатурный классификатор системных ошибок с извлечением контекстных параметров."""

    _PORT_CONFLICT_RE = re.compile(
        r"(?:"
        r"address already in use"
        r"|eaddrinuse"
        r"|failed to listen on (?:port|address)"
        r"|only one usage of each socket address"
        r"|bind\(\) to [^\s]+ failed"
        r"|port \d+ is already in use"
        r"|cannot assign requested address.*bind"
        r")",
        re.IGNORECASE,
    )
    _DISK_FULL_RE = re.compile(
        r"(?:"
        r"no space left on device"
        r"|disk full"
        r"|\benospc\b"
        r"|write error:\s*no space"
        r"|not enough space on the disk"
        r"|filesystem .* is full"
        r")",
        re.IGNORECASE,
    )
    _OOM_RE = re.compile(
        r"(?:"
        r"out of memory"
        r"|oom[-_]killer"
        r"|oom_kill_process"
        r"|cannot allocate memory"
        r"|\benomem\b"
        r"|fork failed:\s*cannot allocate memory"
        r"|memoryerror"
        r"|killed process \d+"
        r")",
        re.IGNORECASE,
    )
    _PACKAGE_LOCK_RE = re.compile(
        r"(?:"
        r"could not get lock /var/lib/(?:dpkg|apt)"
        r"|unable to acquire the dpkg frontend lock"
        r"|existing lock /var/run/yum\.pid"
        r"|unable to lock database"
        r"|waiting for cache lock:\s*could not get lock"
        r")",
        re.IGNORECASE,
    )
    _CONFIG_SYNTAX_RE = re.compile(
        r"(?:"
        r"configuration file .* test failed"
        r"|syntax error on line \d+"
        r"|nginx:\s*\[emerg\].*in /"
        r"|sshd_config.*bad configuration"
        r"|failed to parse (?:config|configuration)"
        r"|configtest failed"
        r"|unexpected token .* in configuration"
        r")",
        re.IGNORECASE,
    )
    _SERVICE_CRASH_RE = re.compile(
        r"(?:"
        r"job for [\w@.-]+ failed"
        r"|active:\s*failed"
        r"|status=[1-9]\d*/failure"
        r"|main process exited,\s*code=exited"
        r"|failed to start [\w@.-]+"
        r"|service ['\"]?[\w@.-]+['\"]? failed to start"
        r")",
        re.IGNORECASE,
    )
    _PERMISSION_DENIED_RE = re.compile(
        r"(?:"
        r"permission denied"
        r"|operation not permitted"
        r"|\beacces\b"
        r"|\beperm\b"
        r"|access is denied"
        r"|must be root"
        r"|are you root\?"
        r"|interactive authentication required"
        r"|sudo:\s*(?:a password is required|.*incorrect password|.*not in the sudoers)"
        r"|authentication failure"
        r")",
        re.IGNORECASE,
    )
    _COMMAND_NOT_FOUND_RE = re.compile(
        r"(?:"
        r"command not found"
        r"|is not recognized as an internal or external command"
        r"|the term ['\"][^'\"]+['\"] is not recognized"
        r"|no such file or directory.*exec"
        r")",
        re.IGNORECASE,
    )
    _NETWORK_UNREACHABLE_RE = re.compile(
        r"(?:"
        r"network is unreachable"
        r"|name or service not known"
        r"|temporary failure in name resolution"
        r"|connection refused"
        r"|no route to host"
        r"|connection timed out"
        r"|could not resolve host"
        r")",
        re.IGNORECASE,
    )

    _PORT_EXTRACT_PATTERNS = (
        re.compile(r"(?:0\.0\.0\.0|127\.0\.0\.1|\[::\]|\*):(\d{1,5})\b"),
        re.compile(r"\bport\s+#?(\d{1,5})\b", re.IGNORECASE),
        re.compile(r":(\d{2,5})\s+failed", re.IGNORECASE),
        re.compile(r"(?:--port|-p)\s+(\d{1,5})\b", re.IGNORECASE),
    )

    _SERVICE_EXTRACT_PATTERNS = (
        re.compile(r"job for ([\w@.-]+?)(?:\.service)? failed", re.IGNORECASE),
        re.compile(
            r"\bsystemctl\s+(?:-[\w=-]+\s+)*(?:start|restart|reload|status|try-restart|reload-or-restart)\s+(?:-[\w=-]+\s+)*([a-zA-Z0-9_@.:-]+)",
            re.IGNORECASE,
        ),
        re.compile(
            r"\bservice\s+([a-zA-Z0-9_@.-]+)\s+(?:start|restart|reload)",
            re.IGNORECASE,
        ),
        re.compile(r"([\w@.-]+)\.service:\s+main process exited", re.IGNORECASE),
    )

    _MISSING_CMD_EXTRACT_PATTERNS = (
        re.compile(r"(?:^|:\s+)([a-zA-Z0-9_./-]+):\s*command not found", re.IGNORECASE),
        re.compile(r"command not found:\s*([a-zA-Z0-9_./-]+)", re.IGNORECASE),
        re.compile(r"the term ['\"]([^'\"]+)['\"] is not recognized", re.IGNORECASE),
        re.compile(
            r"['\"]([^'\"]+)['\"] is not recognized as an internal or external command",
            re.IGNORECASE,
        ),
    )

    _LOCK_HOLDER_RE = re.compile(
        r"held by process (\d+)(?:\s*\(([^)]+)\))?",
        re.IGNORECASE,
    )
    _LOCK_PATH_RE = re.compile(r"(/var/(?:lib|run)/[\w./-]+lock[\w.-]*)", re.IGNORECASE)
    _PATH_EXTRACT_RE = re.compile(
        r"(?:cannot (?:open|access|create directory|remove|stat)|open|stat|chdir|permission denied:)\s*"
        r"['\"]?(/[^\s'\"]+)[ '\":]",
        re.IGNORECASE,
    )
    _FALLBACK_PATH_RE = re.compile(r"(?<![:\w/])(/(?:[\w.-]+/)*[\w.-]+)")

    @classmethod
    def extract_port(cls, text: str, command: str = "") -> int | None:
        """Извлечь номер TCP/UDP порта из текста ошибки или команды."""
        combined = f"{text}\n{command}"
        for pattern in cls._PORT_EXTRACT_PATTERNS:
            for match in pattern.finditer(combined):
                try:
                    port = int(match.group(1))
                    if 1 <= port <= 65535:
                        return port
                except ValueError:
                    continue
        return None

    @classmethod
    def extract_service_unit(cls, command: str, text: str = "") -> str | None:
        """Извлечь имя системного сервиса (systemd/init) из команды или текста ошибки."""
        combined = f"{text}\n{command}"
        for pattern in cls._SERVICE_EXTRACT_PATTERNS:
            match = pattern.search(combined)
            if match:
                unit = match.group(1).strip().strip("'\"")
                if unit and not unit.startswith("-"):
                    return unit
        return None

    @classmethod
    def extract_path(cls, text: str, command: str = "") -> str | None:
        """Извлечь путь к файлу или директории из текста ошибки или команды (игнорируя URL)."""
        match = cls._PATH_EXTRACT_RE.search(text)
        if match:
            return match.group(1)
        for source in (text, command):
            for fallback in cls._FALLBACK_PATH_RE.finditer(source):
                candidate = fallback.group(1).rstrip(":,;'\"")
                if len(candidate) > 1 and not candidate.startswith("//"):
                    return candidate
        return None

    @classmethod
    def extract_missing_command(cls, text: str, command: str = "") -> str:
        """Извлечь имя отсутствующего исполняемого файла из текста ошибки или самой команды."""
        for pattern in cls._MISSING_CMD_EXTRACT_PATTERNS:
            for line in text.splitlines():
                match = pattern.search(line)
                if match:
                    candidate = match.group(1).strip()
                    if candidate and candidate.lower() not in (
                        "bash",
                        "sh",
                        "zsh",
                        "dash",
                        "sudo",
                        "env",
                    ):
                        return candidate
        for token in command.strip().split():
            if "=" in token and not token.startswith("-"):
                continue
            if token in ("sudo", "env", "nohup", "time", "exec") or token.startswith("-"):
                continue
            return token.strip("'\"")
        return "binary"

    @classmethod
    def classify(
        cls,
        command: str,
        stdout: str,
        stderr: str,
        exit_code: int,
    ) -> ClassificationMatch:
        """Классифицировать ошибку выполнения по коду возврата, выводу и тексту команды."""
        combined = f"{stderr}\n{stdout}".strip()
        service_unit = cls.extract_service_unit(command, combined)

        # 1. PORT_CONFLICT (имеет наивысший приоритет, т.к. часто маскируется под падение сервиса)
        m_port = cls._PORT_CONFLICT_RE.search(combined)
        if m_port:
            return ClassificationMatch(
                category=ErrorCategory.PORT_CONFLICT,
                port=cls.extract_port(combined, command),
                service_unit=service_unit,
                matched_signature=m_port.group(0),
            )

        # 2. DISK_FULL
        m_disk = cls._DISK_FULL_RE.search(combined)
        if m_disk:
            return ClassificationMatch(
                category=ErrorCategory.DISK_FULL,
                target_path=cls.extract_path(combined, command),
                service_unit=service_unit,
                matched_signature=m_disk.group(0),
            )

        # 3. OUT_OF_MEMORY (включая SIGKILL exit_code == 137)
        m_oom = cls._OOM_RE.search(combined)
        if m_oom or exit_code == 137:
            return ClassificationMatch(
                category=ErrorCategory.OUT_OF_MEMORY,
                service_unit=service_unit,
                matched_signature=m_oom.group(0) if m_oom else "exit_code=137 (SIGKILL)",
            )

        # 4. PACKAGE_LOCK_CONFLICT
        m_lock = cls._PACKAGE_LOCK_RE.search(combined)
        if m_lock:
            holder = cls._LOCK_HOLDER_RE.search(combined)
            lock_path_m = cls._LOCK_PATH_RE.search(combined)
            return ClassificationMatch(
                category=ErrorCategory.PACKAGE_LOCK_CONFLICT,
                target_path=lock_path_m.group(1) if lock_path_m else None,
                conflicting_pid=int(holder.group(1)) if holder else None,
                conflicting_process=holder.group(2) if holder and holder.group(2) else None,
                matched_signature=m_lock.group(0),
            )

        # 5. CONFIG_SYNTAX_ERROR
        m_cfg = cls._CONFIG_SYNTAX_RE.search(combined)
        if m_cfg:
            return ClassificationMatch(
                category=ErrorCategory.CONFIG_SYNTAX_ERROR,
                target_path=cls.extract_path(combined, command),
                service_unit=service_unit,
                matched_signature=m_cfg.group(0),
            )

        # 6. COMMAND_NOT_FOUND (включая POSIX exit_code == 127)
        m_cmd = cls._COMMAND_NOT_FOUND_RE.search(combined)
        if m_cmd or exit_code == 127:
            return ClassificationMatch(
                category=ErrorCategory.COMMAND_NOT_FOUND,
                matched_signature=m_cmd.group(0) if m_cmd else "exit_code=127",
            )

        # 7. PERMISSION_DENIED (включая POSIX exit_code == 126)
        m_perm = cls._PERMISSION_DENIED_RE.search(combined)
        if m_perm or exit_code == 126:
            return ClassificationMatch(
                category=ErrorCategory.PERMISSION_DENIED,
                target_path=cls.extract_path(combined, command),
                service_unit=service_unit,
                matched_signature=m_perm.group(0) if m_perm else "exit_code=126",
            )

        # 8. SERVICE_CRASH
        m_svc = cls._SERVICE_CRASH_RE.search(combined)
        if m_svc or (service_unit is not None and exit_code != 0):
            return ClassificationMatch(
                category=ErrorCategory.SERVICE_CRASH,
                service_unit=service_unit,
                matched_signature=m_svc.group(0) if m_svc else f"service={service_unit}",
            )

        # 9. NETWORK_UNREACHABLE
        m_net = cls._NETWORK_UNREACHABLE_RE.search(combined)
        if m_net:
            return ClassificationMatch(
                category=ErrorCategory.NETWORK_UNREACHABLE,
                port=cls.extract_port(combined, command),
                matched_signature=m_net.group(0),
            )

        return ClassificationMatch(
            category=ErrorCategory.GENERIC_FAILURE,
            service_unit=service_unit,
        )


def _sanitize_lines(lines: list[str], max_lines: int = 25) -> list[str]:
    """Очистить список строк от пустых значений и замаскировать секреты."""
    cleaned: list[str] = []
    for raw in lines:
        stripped = raw.strip()
        if stripped:
            cleaned.append(SecretMaskingFilter._mask_string(stripped))
    return cleaned[-max_lines:]


def _build_hint_and_actions(
    match: ClassificationMatch,
    vitals: SystemVitals,
    port_conflict: PortConflictInfo | None,
    relevant_logs: list[str],
    command: str,
) -> tuple[str, list[str]]:
    """Сформировать лаконичное описание первопричины и список рекомендуемых шагов Self-Healing."""
    cat = match.category
    actions: list[str] = []

    if cat == ErrorCategory.PORT_CONFLICT:
        if port_conflict is not None:
            proc_desc = (
                f"process {port_conflict.conflicting_process!r} "
                f"(PID {port_conflict.conflicting_pid})"
                if port_conflict.conflicting_process and port_conflict.conflicting_pid
                else (
                    f"PID {port_conflict.conflicting_pid}"
                    if port_conflict.conflicting_pid
                    else (
                        f"process {port_conflict.conflicting_process!r}"
                        if port_conflict.conflicting_process
                        else "another process"
                    )
                )
            )
            hint = (
                f"Port {port_conflict.port}/{port_conflict.protocol} on "
                f"{port_conflict.listen_address} is already bound by {proc_desc}"
            )
            if port_conflict.conflicting_process:
                actions.append(
                    f"Stop conflicting service: systemctl stop {port_conflict.conflicting_process}"
                )
            if port_conflict.conflicting_pid:
                actions.append(f"Terminate process holding port: kill -9 {port_conflict.conflicting_pid}")
            actions.append(f"Inspect socket owner: ss -tlpn 'sport = :{port_conflict.port}'")
        elif match.port is not None:
            hint = f"Port {match.port}/tcp is already in use by another process"
            actions.append(f"Inspect process bound to port {match.port}: ss -tlpn 'sport = :{match.port}'")
        else:
            hint = "Socket bind failed because the target address/port is already in use"
            actions.append("Inspect listening TCP ports: ss -tlpn")
        return SecretMaskingFilter._mask_string(hint), actions

    if cat == ErrorCategory.DISK_FULL:
        if vitals.disk_root_inodes_free is not None and vitals.disk_root_inodes_free == 0:
            hint = "Filesystem inode table on '/' is exhausted (0 free inodes)"
            actions.append("Find directories with excessive small files: df -i && find /tmp /var -xdev -type f")
        elif vitals.disk_root_free_mb is not None:
            hint = (
                f"Insufficient disk space (root free: {vitals.disk_root_free_mb} MB"
                + (f", /tmp free: {vitals.disk_tmp_free_mb} MB)" if vitals.disk_tmp_free_mb is not None else ")")
            )
        else:
            hint = "Write failed due to exhausted disk space or inodes (ENOSPC)"
        actions.extend(
            [
                "Inspect filesystem usage and inodes: df -h && df -i",
                "Clean journald logs and package cache: journalctl --vacuum-size=100M && apt-get clean",
                "Find largest directories under /var and /tmp: du -xhd1 /var /tmp | sort -hr | head -n 10",
            ]
        )
        return SecretMaskingFilter._mask_string(hint), actions

    if cat == ErrorCategory.OUT_OF_MEMORY:
        oom_note = (
            f" (cgroup OOM kills: {vitals.oom_kill_count})"
            if vitals.oom_kill_count
            else ""
        )
        mem_note = (
            f" — available RAM: {vitals.memory_available_mb}/{vitals.memory_total_mb} MB"
            if vitals.memory_available_mb is not None and vitals.memory_total_mb is not None
            else ""
        )
        hint = f"Process terminated due to memory exhaustion / OOM killer{oom_note}{mem_note}"
        actions.extend(
            [
                "Check top memory-consuming processes: ps aux --sort=-%mem | head -n 10",
                "Inspect kernel OOM killer events: dmesg -T | grep -iE 'oom|killed process'",
                "Reduce worker concurrency or increase container/VM memory limit",
            ]
        )
        return SecretMaskingFilter._mask_string(hint), actions

    if cat == ErrorCategory.PACKAGE_LOCK_CONFLICT:
        proc_info = (
            f" by {match.conflicting_process or 'process'} (PID {match.conflicting_pid})"
            if match.conflicting_pid
            else ""
        )
        lock_file = match.target_path or "/var/lib/dpkg/lock-frontend"
        hint = f"Package manager database lock {lock_file} is held{proc_info}"
        if match.conflicting_pid:
            actions.append(f"Wait for PID {match.conflicting_pid} to finish or inspect: ps -fp {match.conflicting_pid}")
        actions.extend(
            [
                f"Check processes holding lock: fuser -v {lock_file}",
                "If no package manager is running, repair dpkg state: dpkg --configure -a",
            ]
        )
        return SecretMaskingFilter._mask_string(hint), actions

    if cat == ErrorCategory.CONFIG_SYNTAX_ERROR:
        path_note = f" in {match.target_path}" if match.target_path else ""
        hint = f"Configuration syntax validation failed{path_note}"
        if match.target_path:
            actions.append(f"Inspect configuration file around reported line: {match.target_path}")
        if match.service_unit:
            actions.append(f"Run configuration test for {match.service_unit} before restarting")
        else:
            actions.append("Validate syntax using the service's configtest flag (e.g. nginx -t, sshd -t)")
        return SecretMaskingFilter._mask_string(hint), actions

    if cat == ErrorCategory.PERMISSION_DENIED:
        path_note = f" for path {match.target_path!r}" if match.target_path else ""
        hint = f"Insufficient privileges or filesystem permission denied{path_note}"
        actions.append("Re-run command with elevated privileges (sudo=True)")
        if match.target_path:
            actions.append(f"Inspect ownership and permissions: ls -ld {shlex.quote(match.target_path)}")
        return SecretMaskingFilter._mask_string(hint), actions

    if cat == ErrorCategory.SERVICE_CRASH:
        unit = match.service_unit or "service"
        hint = f"Service unit {unit!r} failed to start or exited with non-zero status"
        if relevant_logs:
            hint = f"{hint}: {relevant_logs[-1][:140]}"
        actions.extend(
            [
                f"Inspect unit status and logs: systemctl status {unit} --no-pager",
                f"Verify service unit configuration: systemctl cat {unit}",
            ]
        )
        return SecretMaskingFilter._mask_string(hint), actions

    if cat == ErrorCategory.COMMAND_NOT_FOUND:
        logs_text = "\n".join(relevant_logs)
        missing_bin = ErrorClassifier.extract_missing_command(logs_text, command)
        hint = f"Executable {missing_bin!r} was not found in PATH"
        actions.extend(
            [
                f"Locate binary on filesystem: which {shlex.quote(missing_bin)} || whereis {shlex.quote(missing_bin)}",
                f"Install the package providing {missing_bin!r} via conn.state.ensure_package()",
            ]
        )
        return SecretMaskingFilter._mask_string(hint), actions

    if cat == ErrorCategory.NETWORK_UNREACHABLE:
        hint = f"Network connectivity or DNS resolution failed ({match.matched_signature or 'unreachable'})"
        actions.extend(
            [
                "Verify DNS configuration and routes: cat /etc/resolv.conf && ip route",
                "Check target endpoint reachability and firewall rules (ss -tlpn / nft list ruleset)",
            ]
        )
        return SecretMaskingFilter._mask_string(hint), actions

    hint = "Command exited with non-zero status"
    if relevant_logs:
        hint = f"{hint}: {relevant_logs[-1][:140]}"
    actions.append("Inspect stderr output and verify command arguments and environment")
    return SecretMaskingFilter._mask_string(hint), actions


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

        # Если сбой связан с системным сервисом — опрашиваем journalctl и проводим каскадную реклассификацию
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
                # Фаза 2: Каскадное уточнение категории по тексту логов юнита
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

        # Целевой зонд конфликта портов
        if match.category == ErrorCategory.PORT_CONFLICT and match.port is not None:
            ss_cmd = (
                f"ss -tlpn 'sport = :{match.port}' 2>/dev/null "
                f"|| netstat -tlpn 2>/dev/null | grep ':{match.port} '"
            )
            ss_res = await probe(ss_cmd)
            port_conflict = self.parse_port_conflict(match.port, ss_res.stdout)

        # Целевой зонд нехватки памяти / OOM Killer
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

        # Целевой зонд прав доступа
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


class ContainerDiagnosticStrategy(LinuxDiagnosticStrategy):
    """Стратегия зондирования для контейнеров (Docker / Podman / Kubernetes) с анализом cgroup v1/v2."""

    _CONTAINER_VITALS_CMD = (
        LinuxDiagnosticStrategy._VITALS_CMD
        + "; echo '---CGROUP---'; "
        "cat /sys/fs/cgroup/memory.events /sys/fs/cgroup/memory/memory.oom_control 2>/dev/null"
    )

    async def _collect_vitals(self, probe: ProbeRunner) -> SystemVitals:
        res = await probe(self._CONTAINER_VITALS_CMD)
        parts = res.stdout.split("---CGROUP---")
        base_out = parts[0] if parts else ""
        cgroup_out = parts[1] if len(parts) > 1 else ""
        oom_kills: int | None = None
        for line in cgroup_out.splitlines():
            tokens = line.strip().split()
            if len(tokens) == 2 and tokens[0] == "oom_kill" and tokens[1].isdigit():
                oom_kills = int(tokens[1])
                break
        return self.parse_vitals(base_out, oom_kill_count=oom_kills)


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


_PASSIVE_TRANSPORTS = frozenset(
    {"ipmi", "redfish", "netconf", "restconf", "gnmi", "replay", "serial", "uart"}
)
_CONTAINER_TRANSPORTS = frozenset({"docker", "podman", "kubectl"})
_WINDOWS_TRANSPORTS = frozenset({"winrm", "wsman"})


def resolve_diagnostic_strategy(conn: Connection) -> DiagnosticStrategy:
    """Выбрать оптимальную стратегию зондирования для текущего транспорта и ОС хоста."""
    t_name = conn.transport_name.lower()
    cfg_name = conn.config.transport.lower()
    if (
        t_name in _PASSIVE_TRANSPORTS
        or cfg_name in _PASSIVE_TRANSPORTS
        or hasattr(conn.transport, "cassette")
    ):
        return PassiveDiagnosticStrategy()
    if t_name in _CONTAINER_TRANSPORTS or cfg_name in _CONTAINER_TRANSPORTS:
        return ContainerDiagnosticStrategy()
    if t_name in _WINDOWS_TRANSPORTS or cfg_name in _WINDOWS_TRANSPORTS:
        return WindowsDiagnosticStrategy()
    cached_facts = getattr(conn, "_cached_facts", None)
    if cached_facts is not None and getattr(cached_facts, "os_family", "").lower() == "windows":
        return WindowsDiagnosticStrategy()
    if t_name == "local" and sys.platform == "win32":
        return WindowsDiagnosticStrategy()
    return LinuxDiagnosticStrategy()


__all__ = [
    "ClassificationMatch",
    "ContainerDiagnosticStrategy",
    "DiagnosticStrategy",
    "ErrorClassifier",
    "LinuxDiagnosticStrategy",
    "PassiveDiagnosticStrategy",
    "ProbeRunner",
    "WindowsDiagnosticStrategy",
    "resolve_diagnostic_strategy",
]
