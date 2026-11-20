# src/uniconn/core/_diag_classifier.py
"""Классификатор системных ошибок (ErrorClassifier) и генератор рекомендаций Self-Healing."""

from __future__ import annotations

import re
import shlex
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from .._logging import SecretMaskingFilter
from ..result import ErrorCategory, PortConflictInfo, Result, SystemVitals

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

        m_port = cls._PORT_CONFLICT_RE.search(combined)
        if m_port:
            return ClassificationMatch(
                category=ErrorCategory.PORT_CONFLICT,
                port=cls.extract_port(combined, command),
                service_unit=service_unit,
                matched_signature=m_port.group(0),
            )

        m_disk = cls._DISK_FULL_RE.search(combined)
        if m_disk:
            return ClassificationMatch(
                category=ErrorCategory.DISK_FULL,
                target_path=cls.extract_path(combined, command),
                service_unit=service_unit,
                matched_signature=m_disk.group(0),
            )

        m_oom = cls._OOM_RE.search(combined)
        if m_oom or exit_code == 137:
            return ClassificationMatch(
                category=ErrorCategory.OUT_OF_MEMORY,
                service_unit=service_unit,
                matched_signature=m_oom.group(0) if m_oom else "exit_code=137 (SIGKILL)",
            )

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

        m_cfg = cls._CONFIG_SYNTAX_RE.search(combined)
        if m_cfg:
            return ClassificationMatch(
                category=ErrorCategory.CONFIG_SYNTAX_ERROR,
                target_path=cls.extract_path(combined, command),
                service_unit=service_unit,
                matched_signature=m_cfg.group(0),
            )

        m_cmd = cls._COMMAND_NOT_FOUND_RE.search(combined)
        if m_cmd or exit_code == 127:
            return ClassificationMatch(
                category=ErrorCategory.COMMAND_NOT_FOUND,
                matched_signature=m_cmd.group(0) if m_cmd else "exit_code=127",
            )

        m_perm = cls._PERMISSION_DENIED_RE.search(combined)
        if m_perm or exit_code == 126:
            return ClassificationMatch(
                category=ErrorCategory.PERMISSION_DENIED,
                target_path=cls.extract_path(combined, command),
                service_unit=service_unit,
                matched_signature=m_perm.group(0) if m_perm else "exit_code=126",
            )

        m_svc = cls._SERVICE_CRASH_RE.search(combined)
        if m_svc or (service_unit is not None and exit_code != 0):
            return ClassificationMatch(
                category=ErrorCategory.SERVICE_CRASH,
                service_unit=service_unit,
                matched_signature=m_svc.group(0) if m_svc else f"service={service_unit}",
            )

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


__all__ = [
    "ClassificationMatch",
    "ErrorClassifier",
    "ProbeRunner",
    "_build_hint_and_actions",
    "_sanitize_lines",
]
