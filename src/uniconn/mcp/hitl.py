# src/uniconn/mcp/hitl.py
"""Движок классификации рисков (ActionRiskClassifier) и двухфазных согласований (ApprovalManager).

Реализует классификацию рисков команд/файлов, криптографическое связывание HMAC-SHA256
и каналы доставки уведомлений оператору (Human-in-the-Loop, MCP 2.0).
"""

from __future__ import annotations

import asyncio
import contextlib
import difflib
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import sys
import tempfile
import time
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from .._logging import SecretMaskingFilter
from ..exceptions import (
    ApprovalAlreadyConsumedError,
    ApprovalExpiredError,
    ApprovalRejectedError,
    ApprovalRequiredError,
    ApprovalTamperingError,
)
from ..hooks import DEFAULT_BLOCKED_PATTERNS
from .models import (
    ActionRiskTier,
    ApprovalRequest,
    ApprovalStatus,
    HITLPolicy,
    RiskAssessment,
)

DEFAULT_APPROVAL_STORE_PATH = Path.home() / ".uniconn" / "approvals.json"

# ─── Паттерны классификации рисков ──────────────────────────────────────────

_FORBIDDEN_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    *[
        (re.compile(pat, re.IGNORECASE), f"Matched forbidden blocklist pattern: {pat}")
        for pat in DEFAULT_BLOCKED_PATTERNS
    ],
    (
        re.compile(r"\brm\b.*--no-preserve-root", re.IGNORECASE),
        "Root filesystem deletion (--no-preserve-root) is strictly forbidden",
    ),
    (
        re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/\*", re.IGNORECASE),
        "Recursive deletion of root wildcard (/*) is strictly forbidden",
    ),
    (
        re.compile(r"\b(?:wipefs|fdisk|parted|sfdisk|gdisk)\b\s+/dev/", re.IGNORECASE),
        "Direct partition table manipulation on block device is forbidden",
    ),
    (
        re.compile(r"\bdd\b.*\bof=/dev/(?:sd[a-z]|vd[a-z]|nvme\d+n\d+|xvd[a-z])\b", re.IGNORECASE),
        "Raw block device overwrite via dd is strictly forbidden",
    ),
    (
        re.compile(r">\s*/dev/(?:sd[a-z]|vd[a-z]|nvme\d+n\d+)\b", re.IGNORECASE),
        "Direct shell redirection into raw block device is forbidden",
    ),
    (
        re.compile(
            r"\b(?:curl|wget)\b[^|;\n]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|ksh|python\d*|perl|ruby)\b",
            re.IGNORECASE,
        ),
        "Piping remote script download directly into shell interpreter is forbidden",
    ),
)

_DESTRUCTIVE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"\b(?:rm|rmdir|unlink|shred|truncate)\b"),
        "File or directory deletion/truncation command",
    ),
    (
        re.compile(r"\bfind\b.*\s-(?:delete|exec\s+rm\b)"),
        "Recursive file deletion via find",
    ),
    (
        re.compile(r"\bxargs\b.*\brm\b"),
        "Piped batch deletion via xargs rm",
    ),
    (
        re.compile(
            r"\bsystemctl\b(?:\s+-[a-zA-Z0-9_-]+)*\s+(?:stop|disable|mask|kill|poweroff|reboot|halt)\b"
        ),
        "Stopping, disabling, or masking a system service via systemctl",
    ),
    (
        re.compile(r"\bservice\s+\S+\s+(?:stop|force-reload)\b"),
        "Stopping a system service",
    ),
    (
        re.compile(r"\b(?:kill|pkill|killall)\b"),
        "Terminating running system processes",
    ),
    (
        re.compile(
            r"\b(?:iptables|ip6tables)\s+(?:-[a-zA-Z]*[FXZ]|--flush|--delete-chain)\b"
            r"|\bufw\s+(?:disable|reset|delete|deny|reject)\b"
            r"|\bnft\s+flush\b"
        ),
        "Destructive firewall rule modification or flush",
    ),
    (
        re.compile(
            r"\b(?:apt|apt-get|dpkg|yum|dnf|apk|pacman|zypper|helm|pip)\b.*"
            r"\b(?:remove|purge|erase|autoremove|uninstall|-R)\b"
        ),
        "Removing or purging installed packages",
    ),
    (
        re.compile(r"\b(?:userdel|groupdel|passwd\s+-l|chage)\b"),
        "Deleting or locking system user/group accounts",
    ),
    (
        re.compile(r"\bcrontab\s+-r\b"),
        "Removing scheduled cron jobs",
    ),
    (
        re.compile(r"\b(?:reboot|init\s+[06]|telinit\s+[06])\b"),
        "System reboot or runlevel change",
    ),
    (
        re.compile(
            r"\b(?:docker|podman)\s+(?:rm|rmi|stop|kill|system\s+prune|volume\s+rm)\b"
            r"|\bkubectl\s+(?:delete|drain|cordon)\b"
        ),
        "Destructive container or Kubernetes workload operation",
    ),
    (
        re.compile(r"\b(?:DROP\s+(?:DATABASE|TABLE|SCHEMA)|TRUNCATE\s+TABLE|DELETE\s+FROM)\b", re.IGNORECASE),
        "Destructive SQL database statement",
    ),
    (
        re.compile(r"(?:>>?|(?:\|\s*tee\b))\s*(?:/etc/|/boot/|/usr/|/var/lib/|/root/|/proc/sys/)"),
        "Overwriting or appending to protected system configuration path",
    ),
)

_MUTATING_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"\b(?:mkdir|touch|cp|mv|ln|install|chmod|chown|chgrp|chattr|setfacl)\b"),
        "Filesystem creation, move, or permission modification",
    ),
    (
        re.compile(r"\bsystemctl\b(?:\s+-[a-zA-Z0-9_-]+)*\s+(?:start|restart|reload|enable|daemon-reload)\b"),
        "Starting, restarting, or enabling a system service",
    ),
    (
        re.compile(r"\bservice\s+\S+\s+(?:start|restart|reload)\b"),
        "Starting or restarting a system service",
    ),
    (
        re.compile(
            r"\b(?:apt|apt-get|dpkg|yum|dnf|apk|pacman|zypper|pip|uv|npm)\b.*"
            r"\b(?:install|update|upgrade|add|sync)\b"
        ),
        "Installing or updating packages",
    ),
    (
        re.compile(r"\b(?:useradd|adduser|usermod|groupadd|sysctl\s+-w)\b"),
        "Modifying system users, groups, or kernel parameters",
    ),
    (
        re.compile(r"\bsed\b.*\s-i\b|\bpatch\b"),
        "In-place file editing",
    ),
    (
        re.compile(r"\bgit\s+(?:commit|push|checkout|merge|rebase|reset|clean|stash|pull)\b"),
        "Mutating Git repository state",
    ),
    (
        re.compile(
            r"\b(?:docker|podman)\s+(?:run|start|restart|exec|build|pull)\b"
            r"|\bkubectl\s+(?:apply|create|patch|scale|rollout)\b"
        ),
        "Mutating container or Kubernetes workload state",
    ),
    (
        re.compile(r"(?:>>?|\|\s*tee\b)\s*(?!/dev/null\b)\S+"),
        "Shell output redirection to file",
    ),
)

_SAFE_COMMANDS: frozenset[str] = frozenset(
    {
        "ls",
        "dir",
        "cat",
        "head",
        "tail",
        "less",
        "more",
        "grep",
        "egrep",
        "fgrep",
        "rg",
        "wc",
        "sort",
        "uniq",
        "cut",
        "tr",
        "awk",
        "df",
        "du",
        "free",
        "uptime",
        "uname",
        "hostname",
        "hostnamectl",
        "whoami",
        "id",
        "groups",
        "w",
        "who",
        "last",
        "ps",
        "pgrep",
        "pidof",
        "lsof",
        "lsblk",
        "lscpu",
        "lspci",
        "lsusb",
        "lsmod",
        "blkid",
        "mount",
        "findmnt",
        "stat",
        "file",
        "readlink",
        "realpath",
        "dirname",
        "basename",
        "which",
        "whereis",
        "type",
        "pwd",
        "date",
        "timedatectl",
        "locale",
        "env",
        "printenv",
        "echo",
        "printf",
        "true",
        "false",
        "test",
        "[",
        "md5sum",
        "sha1sum",
        "sha256sum",
        "sha512sum",
        "cksum",
        "ping",
        "ping6",
        "traceroute",
        "tracepath",
        "mtr",
        "dig",
        "nslookup",
        "host",
        "whois",
        "ss",
        "netstat",
        "ip",
        "ifconfig",
        "route",
        "arp",
        "ethtool",
        "journalctl",
        "dmesg",
        "vmstat",
        "iostat",
        "mpstat",
        "sar",
        "nproc",
        "getent",
        "getconf",
        "sysctl",
    }
)

_PROTECTED_PATH_PREFIXES: tuple[str, ...] = (
    "/etc/",
    "/boot/",
    "/usr/",
    "/var/lib/",
    "/root/",
    "/sbin/",
    "/bin/",
    "/lib/",
    "/lib64/",
    "/proc/sys/",
    "/sys/",
)

_FORBIDDEN_FILE_PREFIXES: tuple[str, ...] = (
    "/dev/sd",
    "/dev/vd",
    "/dev/nvme",
    "/dev/xvd",
    "/proc/sysrq-trigger",
    "/proc/kcore",
)

_WRAPPER_BINARIES: frozenset[str] = frozenset({"sudo", "env", "nohup", "nice", "time", "stdbuf"})
_SHELL_BINARIES: frozenset[str] = frozenset({"sh", "bash", "zsh", "dash", "ksh"})
_SUBSHELL_RE = re.compile(r"(?<!\$)\$\((?!\()([^()]+)\)|`([^`]+)`")

_OPTS_WITH_ARG_BY_BIN: dict[str, frozenset[str]] = {
    "systemctl": frozenset(
        {
            "-h",
            "--host",
            "-m",
            "--machine",
            "--root",
            "-t",
            "--type",
            "--state",
            "-p",
            "--property",
            "-n",
            "--lines",
            "-o",
            "--output",
        }
    ),
    "git": frozenset(
        {"-c", "-C", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env"}
    ),
    "docker": frozenset({"-h", "--host", "-c", "--context", "--config", "-l", "--log-level"}),
    "podman": frozenset(
        {"--url", "--context", "--root", "--runroot", "--log-level", "--cgroup-manager"}
    ),
    "kubectl": frozenset(
        {
            "-n",
            "--namespace",
            "--context",
            "--kubeconfig",
            "--cluster",
            "--user",
            "-s",
            "--server",
            "--as",
            "--as-group",
            "-v",
            "--v",
            "-l",
            "--selector",
            "-o",
            "--output",
        }
    ),
}


def _extract_first_subcommand(args: list[str], opts_with_arg: frozenset[str]) -> str | None:
    """Извлечь первую позиционную подкоманду, пропуская флаги и их аргументы."""
    idx = 0
    n = len(args)
    while idx < n:
        tok = args[idx]
        if tok == "--":
            return args[idx + 1] if idx + 1 < n else None
        if tok.startswith("-"):
            if "=" in tok:
                idx += 1
                continue
            if tok in opts_with_arg:
                idx += 2
                continue
            idx += 1
            continue
        return tok
    return None


def build_unified_diff(
    path: str,
    old_content: str | None,
    new_content: str,
    *,
    max_lines: int = 120,
) -> str:
    """Сформировать человекочитаемый unified diff с автоматическим маскированием секретов."""
    safe_old = SecretMaskingFilter._mask_string(old_content or "")
    safe_new = SecretMaskingFilter._mask_string(new_content)
    old_lines = safe_old.splitlines(keepends=True) if old_content is not None else []
    new_lines = safe_new.splitlines(keepends=True)
    from_file = "/dev/null" if old_content is None else f"a/{path.lstrip('/')}"
    to_file = f"b/{path.lstrip('/')}"

    diff_lines = list(
        difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile=from_file,
            tofile=to_file,
            lineterm="",
        )
    )
    if not diff_lines:
        return f"--- {from_file}\n+++ {to_file}\n@@ (no textual changes) @@"
    if len(diff_lines) > max_lines:
        truncated = diff_lines[:max_lines]
        truncated.append(f"... [diff truncated: {len(diff_lines) - max_lines} more lines]")
        diff_lines = truncated
    return "\n".join(line.rstrip("\r\n") for line in diff_lines)


def _split_shell_segments(command: str) -> list[str]:
    r"""Разбить составную shell-команду по операторам (; && || | & \n) с учётом кавычек."""
    segments: list[str] = []
    buf: list[str] = []
    in_single = False
    in_double = False
    escape = False
    i = 0
    n = len(command)

    while i < n:
        ch = command[i]
        if escape:
            buf.append(ch)
            escape = False
            i += 1
            continue
        if ch == "\\" and not in_single:
            escape = True
            buf.append(ch)
            i += 1
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            buf.append(ch)
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            buf.append(ch)
            i += 1
            continue

        if not in_single and not in_double:
            if ch in (";", "\n"):
                seg = "".join(buf).strip()
                if seg:
                    segments.append(seg)
                buf.clear()
                i += 1
                continue
            if ch in ("&", "|"):
                # Различаем перенаправление дескрипторов >&2 / &> от разделителей команд
                prev_ch = command[i - 1] if i > 0 else ""
                next_ch = command[i + 1] if i + 1 < n else ""
                if ch == "&" and (prev_ch == ">" or next_ch == ">"):
                    buf.append(ch)
                    i += 1
                    continue
                seg = "".join(buf).strip()
                if seg:
                    segments.append(seg)
                buf.clear()
                if next_ch == ch:
                    i += 2
                else:
                    i += 1
                continue

        buf.append(ch)
        i += 1

    tail = "".join(buf).strip()
    if tail:
        segments.append(tail)

    # Извлекаем также команды внутри $(...) и `...` (игнорируя арифметику $((...)))
    probe_str = re.sub(r"\$\(\(.*?\)\)", "0", command)
    for _ in range(4):
        found_any = False
        for match in _SUBSHELL_RE.finditer(probe_str):
            sub_cmd = (match.group(1) or match.group(2) or "").strip()
            if sub_cmd and sub_cmd not in segments:
                segments.append(sub_cmd)
                found_any = True
        if not found_any:
            break
        probe_str = _SUBSHELL_RE.sub("SUBSHELL", probe_str)

    return segments


class ActionRiskClassifier:
    """Детерминированный классификатор рисков команд и инструментов ИИ-агента."""

    @classmethod
    def classify_command(
        cls,
        command: str,
        *,
        sudo: bool = False,
        is_production: bool = False,
        policy: HITLPolicy | None = None,
        _depth: int = 0,
    ) -> RiskAssessment:
        """Оценить уровень риска shell-команды (включая цепочки и вложенные оболочки)."""
        cmd_stripped = command.strip()
        if not cmd_stripped:
            return RiskAssessment(
                risk_tier=ActionRiskTier.TIER_0_SAFE,
                reasons=("Empty command",),
                is_production=is_production,
                requires_approval=False,
            )

        reasons: list[str] = []
        max_tier = ActionRiskTier.TIER_0_SAFE

        # 1. Глобальная проверка цельной строки на FORBIDDEN (включая fork-бомбу)
        for regex, reason in _FORBIDDEN_PATTERNS:
            if regex.search(cmd_stripped):
                return RiskAssessment(
                    risk_tier=ActionRiskTier.TIER_3_FORBIDDEN,
                    reasons=(reason,),
                    is_production=is_production,
                    requires_approval=False,
                )

        segments = _split_shell_segments(cmd_stripped) or [cmd_stripped]
        for seg in segments:
            seg_tier, seg_reasons = cls._classify_single_segment(
                seg,
                sudo=sudo,
                is_production=is_production,
                policy=policy,
                _depth=_depth,
            )
            if seg_tier.severity > max_tier.severity:
                max_tier = seg_tier
            for r in seg_reasons:
                if r not in reasons:
                    reasons.append(r)

        if sudo and max_tier == ActionRiskTier.TIER_1_MUTATING and is_production:
            max_tier = ActionRiskTier.TIER_2_DESTRUCTIVE
            reasons.append("Privileged (sudo=True) mutating command on a production host")
        elif sudo and max_tier == ActionRiskTier.TIER_0_SAFE and not reasons:
            reasons.append("Read-only inspection command executed with sudo")

        if not reasons:
            reasons.append(f"Classified as {max_tier.value}")

        requires_appr = (
            policy.requires_approval(max_tier, is_production=is_production)
            if policy is not None
            else (
                max_tier == ActionRiskTier.TIER_2_DESTRUCTIVE
                or (is_production and max_tier == ActionRiskTier.TIER_1_MUTATING)
            )
        )
        return RiskAssessment(
            risk_tier=max_tier,
            reasons=tuple(reasons),
            is_production=is_production,
            requires_approval=requires_appr,
        )

    @classmethod
    def _classify_single_segment(
        cls,
        segment: str,
        *,
        sudo: bool = False,
        is_production: bool = False,
        policy: HITLPolicy | None = None,
        _depth: int = 0,
    ) -> tuple[ActionRiskTier, list[str]]:
        seg_reasons: list[str] = []
        seg_stripped = segment.strip()
        if not seg_stripped:
            return ActionRiskTier.TIER_0_SAFE, seg_reasons

        for regex, reason in _FORBIDDEN_PATTERNS:
            if regex.search(seg_stripped):
                return ActionRiskTier.TIER_3_FORBIDDEN, [reason]

        try:
            tokens = shlex.split(seg_stripped)
        except ValueError:
            tokens = seg_stripped.split()

        effective_sudo = sudo
        unwrapped_tokens, had_sudo, nested_shell_cmd = cls._unwrap_command_tokens(tokens)
        if had_sudo:
            effective_sudo = True

        if nested_shell_cmd and _depth < 4:
            sub_assessment = cls.classify_command(
                nested_shell_cmd,
                sudo=effective_sudo,
                is_production=is_production,
                policy=policy,
                _depth=_depth + 1,
            )
            return sub_assessment.risk_tier, list(sub_assessment.reasons)

        for regex, reason in _DESTRUCTIVE_PATTERNS:
            if regex.search(seg_stripped):
                seg_reasons.append(reason)
                return ActionRiskTier.TIER_2_DESTRUCTIVE, seg_reasons

        for regex, reason in _MUTATING_PATTERNS:
            if regex.search(seg_stripped):
                seg_reasons.append(reason)
                return ActionRiskTier.TIER_1_MUTATING, seg_reasons

        if not unwrapped_tokens:
            return ActionRiskTier.TIER_0_SAFE, seg_reasons

        base_bin = os.path.basename(unwrapped_tokens[0]).lower()
        rest_args = [t.lower() for t in unwrapped_tokens[1:]]

        # Специальные случаи команд из _SAFE_COMMANDS с мутирующими флагами
        ip_mut_flags = ("add", "del", "delete", "set", "flush", "change", "replace")
        if base_bin == "ip" and any(a in ip_mut_flags for a in rest_args):
            return ActionRiskTier.TIER_2_DESTRUCTIVE, ["Network interface or routing table modification via ip"]
        if base_bin == "sysctl" and any(a == "-w" or "=" in a for a in rest_args):
            return ActionRiskTier.TIER_1_MUTATING, ["Kernel parameter modification via sysctl"]
        if base_bin == "systemctl":
            systemctl_ro = (
                "status",
                "is-active",
                "is-enabled",
                "is-failed",
                "show",
                "list-units",
                "list-unit-files",
                "cat",
            )
            sub = _extract_first_subcommand(rest_args, _OPTS_WITH_ARG_BY_BIN["systemctl"])
            if sub is not None:
                if sub in systemctl_ro:
                    return ActionRiskTier.TIER_0_SAFE, ["Read-only systemctl inspection"]
                if sub in ("stop", "disable", "mask", "kill", "poweroff", "reboot"):
                    return ActionRiskTier.TIER_2_DESTRUCTIVE, [f"Destructive systemctl action: {sub}"]
                return ActionRiskTier.TIER_1_MUTATING, [f"Mutating systemctl action: {sub}"]
            return ActionRiskTier.TIER_0_SAFE, ["Read-only systemctl inspection"]
        if base_bin == "find":
            if any(a in ("-delete", "-exec", "-execdir") for a in rest_args):
                return ActionRiskTier.TIER_1_MUTATING, ["find with command execution or modification flags"]
            return ActionRiskTier.TIER_0_SAFE, ["Read-only find search"]
        if base_bin == "git":
            git_ro = ("status", "log", "diff", "show", "branch", "remote", "rev-parse", "describe", "ls-files")
            sub = _extract_first_subcommand(rest_args, _OPTS_WITH_ARG_BY_BIN["git"])
            if sub is not None:
                if sub in git_ro:
                    return ActionRiskTier.TIER_0_SAFE, ["Read-only git inspection"]
                return ActionRiskTier.TIER_1_MUTATING, [f"Git operation: {sub}"]
            return ActionRiskTier.TIER_0_SAFE, ["Read-only git inspection"]
        if base_bin in ("docker", "podman", "kubectl"):
            container_ro = (
                "ps",
                "images",
                "inspect",
                "logs",
                "version",
                "info",
                "stats",
                "top",
                "get",
                "describe",
                "cluster-info",
            )
            sub = _extract_first_subcommand(rest_args, _OPTS_WITH_ARG_BY_BIN[base_bin])
            if sub is not None:
                if sub in container_ro:
                    return ActionRiskTier.TIER_0_SAFE, [f"Read-only {base_bin} inspection"]
                return ActionRiskTier.TIER_1_MUTATING, [f"Container/cluster operation: {base_bin} {sub}"]
            return ActionRiskTier.TIER_0_SAFE, [f"Read-only {base_bin} inspection"]

        if base_bin in _SAFE_COMMANDS:
            return ActionRiskTier.TIER_0_SAFE, [f"Safe read-only command ({base_bin})"]

        if effective_sudo:
            return ActionRiskTier.TIER_2_DESTRUCTIVE, [
                f"Unrecognized command ({base_bin!r}) executed with sudo privileges"
            ]

        return ActionRiskTier.TIER_1_MUTATING, [
            f"Unrecognized or potentially mutating command ({base_bin!r})"
        ]

    @staticmethod
    def _unwrap_command_tokens(tokens: list[str]) -> tuple[list[str], bool, str | None]:
        """Снять префиксы env-переменных, sudo/env/nohup и обнаружить sh -c / bash -c."""
        idx = 0
        n = len(tokens)
        had_sudo = False
        sudo_opts_with_arg = {"-u", "-g", "-C", "-D", "-R", "-T", "-U", "-h", "-p", "-r", "-t"}

        while idx < n:
            tok = tokens[idx]
            if "=" in tok and not tok.startswith("-") and tok.split("=", 1)[0].isidentifier():
                idx += 1
                continue
            base = os.path.basename(tok).lower()
            if base == "sudo":
                had_sudo = True
                idx += 1
                while idx < n and tokens[idx].startswith("-"):
                    opt = tokens[idx]
                    idx += 1
                    if opt in sudo_opts_with_arg and idx < n:
                        idx += 1
                continue
            if base in _WRAPPER_BINARIES:
                idx += 1
                while idx < n and tokens[idx].startswith("-"):
                    idx += 1
                continue
            if base == "timeout" and idx + 1 < n:
                idx += 1
                while idx < n and tokens[idx].startswith("-"):
                    idx += 1
                if idx < n:
                    idx += 1  # Пропускаем значение длительности таймаута
                continue
            break

        remaining = tokens[idx:]
        if not remaining:
            return [], had_sudo, None

        first_base = os.path.basename(remaining[0]).lower()
        if first_base in _SHELL_BINARIES:
            for i in range(1, len(remaining) - 1):
                if remaining[i] in ("-c", "-lc", "-ic"):
                    return remaining, had_sudo, remaining[i + 1]

        return remaining, had_sudo, None

    @classmethod
    def classify_file_write(
        cls,
        path: str,
        *,
        file_exists: bool = False,
        is_production: bool = False,
        policy: HITLPolicy | None = None,
    ) -> RiskAssessment:
        """Оценить уровень риска записи файла (uniconn_write_file)."""
        norm_path = path.strip() or "/"
        reasons: list[str] = []

        for forbidden_prefix in _FORBIDDEN_FILE_PREFIXES:
            if norm_path.startswith(forbidden_prefix) or norm_path in ("/", "/etc/shadow", "/etc/sudoers"):
                return RiskAssessment(
                    risk_tier=ActionRiskTier.TIER_3_FORBIDDEN,
                    reasons=(f"Writing to critical device or security file {norm_path!r} is forbidden",),
                    is_production=is_production,
                    requires_approval=False,
                )

        tier = ActionRiskTier.TIER_1_MUTATING
        if any(norm_path.startswith(prefix) for prefix in _PROTECTED_PATH_PREFIXES) or "/.ssh/" in norm_path:
            tier = ActionRiskTier.TIER_2_DESTRUCTIVE
            reasons.append(f"Target path {norm_path!r} is inside a protected system directory")
        elif file_exists:
            tier = ActionRiskTier.TIER_2_DESTRUCTIVE
            reasons.append(f"Overwriting existing file {norm_path!r}")
        else:
            reasons.append(f"Creating or writing file {norm_path!r}")

        requires_appr = (
            policy.requires_approval(tier, is_production=is_production)
            if policy is not None
            else (
                tier == ActionRiskTier.TIER_2_DESTRUCTIVE
                or (is_production and tier == ActionRiskTier.TIER_1_MUTATING)
            )
        )
        return RiskAssessment(
            risk_tier=tier,
            reasons=tuple(reasons),
            is_production=is_production,
            requires_approval=requires_appr,
        )

    @classmethod
    def classify_tool_call(
        cls,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        is_production: bool = False,
        file_exists: bool = False,
        policy: HITLPolicy | None = None,
    ) -> RiskAssessment:
        """Классифицировать любой вызов MCP-инструмента по имени и аргументам."""
        if tool_name == "uniconn_run":
            cmd = str(arguments.get("command") or "")
            sudo = bool(arguments.get("sudo", False))
            return cls.classify_command(
                cmd,
                sudo=sudo,
                is_production=is_production,
                policy=policy,
            )
        if tool_name == "uniconn_write_file":
            path = str(arguments.get("path") or "")
            return cls.classify_file_write(
                path,
                file_exists=file_exists,
                is_production=is_production,
                policy=policy,
            )
        return RiskAssessment(
            risk_tier=ActionRiskTier.TIER_0_SAFE,
            reasons=(f"Read-only or metadata tool ({tool_name})",),
            is_production=is_production,
            requires_approval=False,
        )


# ─── Каналы доставки запросов оператору ──────────────────────────────────────


class ApprovalChannel(Protocol):
    """Протокол канала уведомления оператора о новой заявке HITL."""

    async def notify(self, request: ApprovalRequest) -> dict[str, Any] | None:
        """Отправить уведомление оператору и опционально вернуть синхронное решение."""


class TerminalApprovalChannel:
    """Безопасный для JSON-RPC stdio терминальный канал (рендеринг строго в sys.stderr)."""

    def __init__(
        self,
        *,
        stream: Any = None,
        interactive_tty: bool = False,
    ) -> None:
        """Инициализировать терминальный канал (по умолчанию поток sys.stderr)."""
        self._stream = stream
        self._interactive_tty = interactive_tty

    async def notify(self, request: ApprovalRequest) -> dict[str, Any] | None:
        """Вывести Rich-панель заявки в stderr (никогда в stdout) и опционально опросить /dev/tty."""
        target_stream = self._stream if self._stream is not None else sys.stderr
        try:
            from rich.console import Console
            from rich.panel import Panel

            console = Console(file=target_stream, force_terminal=False)
            lines = [
                f"[bold]Request ID[/bold] : {request.approval_id}",
                f"[bold]Target Host[/bold]: {request.target_host}",
                f"[bold]Tool[/bold]       : {request.tool_name}",
                f"[bold]Risk Tier[/bold]  : {request.risk_tier.value}",
            ]
            if request.command:
                lines.append(f"[bold]Command[/bold]    : {SecretMaskingFilter._mask_string(request.command)}")
            if request.sudo:
                lines.append("[bold]Privileges[/bold] : sudo=True")
            if request.risk_reasons:
                lines.append(f"[bold]Reasons[/bold]    : {'; '.join(request.risk_reasons)}")
            if request.diff:
                lines.append(f"\n[bold]Diff[/bold]:\n{request.diff}")
            lines.append(f"\n[bold]Approve via CLI[/bold]: uniconn approval approve {request.approval_id}")
            lines.append(f"[bold]Reject via CLI[/bold] : uniconn approval reject {request.approval_id}")

            panel = Panel(
                "\n".join(lines),
                title=f"[uniconn-mcp] ACTION REQUIRES APPROVAL (Tier: {request.risk_tier.value})",
                border_style="red" if request.risk_tier == ActionRiskTier.TIER_2_DESTRUCTIVE else "yellow",
            )
            console.print(panel)
        except Exception:
            summary = (
                f"[uniconn-mcp] ACTION REQUIRES APPROVAL ({request.risk_tier.value}) "
                f"id={request.approval_id} host={request.target_host} "
                f"cmd={SecretMaskingFilter._mask_string(request.command or request.tool_name)}\n"
            )
            with contextlib.suppress(Exception):
                target_stream.write(summary)
                target_stream.flush()

        if self._interactive_tty:
            return await asyncio.to_thread(self._prompt_controlling_tty, request)
        return None

    @staticmethod
    def _prompt_controlling_tty(request: ApprovalRequest) -> dict[str, Any] | None:
        """Прочитать ответ [y/N] напрямую из управляющего терминала (/dev/tty), не трогая sys.stdin."""
        tty_path = "CONIN$" if os.name == "nt" else "/dev/tty"
        try:
            with open(tty_path, encoding="utf-8") as tty_in:
                sys.stderr.write(f"Approve {request.approval_id}? [y/N]: ")
                sys.stderr.flush()
                answer = tty_in.readline().strip().lower()
                if answer in ("y", "yes", "approve"):
                    return {
                        "decision": "APPROVED",
                        "decided_by": os.environ.get("USER") or os.environ.get("USERNAME") or "tty_operator",
                        "reason": "Approved interactively via controlling TTY",
                    }
                if answer in ("n", "no", "reject"):
                    return {
                        "decision": "REJECTED",
                        "decided_by": os.environ.get("USER") or os.environ.get("USERNAME") or "tty_operator",
                        "reason": "Rejected interactively via controlling TTY",
                    }
        except OSError:
            return None
        return None


class WebhookApprovalChannel:
    """Канал отправки запросов согласования во внешний Webhook (Slack/Telegram/Custom API) с HMAC-SHA256."""

    def __init__(
        self,
        url: str,
        *,
        secret: str | None = None,
        timeout: float = 5.0,
        sender: Callable[[str, bytes, dict[str, str], float], dict[str, Any] | None] | None = None,
    ) -> None:
        """Инициализировать Webhook-канал с URL и опциональным секретом подписи."""
        self.url = url
        self.secret = secret or ""
        self.timeout = timeout
        self._sender = sender

    def sign_payload(self, body: bytes) -> str:
        """Вычислить заголовок подписи X-Uniconn-Signature (sha256=<hex>)."""
        digest = hmac.new(self.secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        return f"sha256={digest}"

    async def notify(self, request: ApprovalRequest) -> dict[str, Any] | None:
        """Отправить подписанный JSON-запрос на корпоративный вебхук."""
        payload = {
            "event": "approval_requested",
            "approval": request.to_public_dict(),
        }
        raw_body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "X-Uniconn-Event": "approval_requested",
            "X-Uniconn-Signature": self.sign_payload(raw_body),
        }
        if self._sender is not None:
            return await asyncio.to_thread(self._sender, self.url, raw_body, headers, self.timeout)
        return await asyncio.to_thread(self._default_send, self.url, raw_body, headers, self.timeout)

    @staticmethod
    def _default_send(
        url: str,
        body: bytes,
        headers: dict[str, str],
        timeout: float,
    ) -> dict[str, Any] | None:
        if not url.lower().startswith(("http://", "https://")):
            return None
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with contextlib.suppress(Exception), urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_bytes = resp.read(16384)
            if resp_bytes:
                data = json.loads(resp_bytes.decode("utf-8", errors="replace"))
                if isinstance(data, dict):
                    return data
        return None


# ─── Менеджер жизненного цикла заявок (ApprovalManager) ──────────────────────


def _normalize_parameters_for_hmac(parameters: Mapping[str, Any] | None) -> dict[str, Any]:
    """Нормализовать словарь параметров инструмента с маскированием секретов и SHA-256 для контента."""
    if not parameters:
        return {}
    excluded = {"approval_id", "wait_for_approval"}
    cleaned: dict[str, Any] = {}
    for k, v in sorted(parameters.items()):
        if k in excluded:
            continue
        if k == "content" and isinstance(v, str):
            cleaned["content_sha256"] = hashlib.sha256(v.encode("utf-8")).hexdigest()
        elif isinstance(v, str):
            cleaned[str(k)] = SecretMaskingFilter._mask_string(v)
        else:
            cleaned[str(k)] = v
    return cleaned


class ApprovalManager:
    """Потокобезопасный менеджер двухфазных согласований (HITL) с контролем HMAC и IPC-файлом."""

    def __init__(
        self,
        policy: HITLPolicy | None = None,
        *,
        secret: str | None = None,
        store_path: str | Path | None = None,
        channels: Sequence[ApprovalChannel] | None = None,
    ) -> None:
        """Инициализировать менеджер заявок согласования."""
        self.policy = policy or HITLPolicy(enabled=True)
        resolved_store = store_path or self.policy.store_path or os.environ.get("UNICONN_APPROVAL_STORE")
        self.store_path: Path | None = Path(resolved_store).expanduser() if resolved_store else None
        self._lock = asyncio.Lock()
        self._requests: dict[str, ApprovalRequest] = {}
        self._events: dict[str, asyncio.Event] = {}

        env_secret = os.environ.get("UNICONN_HITL_SECRET")
        self._secret: str = secret or self.policy.webhook_secret or env_secret or ""
        if self.store_path is not None:
            self._load_from_disk_sync()
        if not self._secret:
            self._secret = secrets.token_hex(32)
            if self.store_path is not None:
                self._save_to_disk_sync()

        if channels is not None:
            self._channels: list[ApprovalChannel] = list(channels)
        else:
            self._channels = self._build_default_channels()

    def _build_default_channels(self) -> list[ApprovalChannel]:
        built: list[ApprovalChannel] = []
        chan_set = {c.strip().lower() for c in self.policy.channels if c.strip()}
        if "terminal" in chan_set:
            built.append(TerminalApprovalChannel(interactive_tty=False))
        if "webhook" in chan_set and self.policy.webhook_url:
            built.append(
                WebhookApprovalChannel(
                    self.policy.webhook_url,
                    secret=self.policy.webhook_secret or self._secret,
                )
            )
        return built

    def compute_hmac(
        self,
        *,
        approval_id: str,
        target_host: str,
        tool_name: str,
        command: str | None = None,
        sudo: bool = False,
        cwd: str | None = None,
        parameters: Mapping[str, Any] | None = None,
        diff: str | None = None,
    ) -> str:
        """Вычислить HMAC-SHA256 подпись канонического представления параметров операции."""
        norm_cmd = SecretMaskingFilter._mask_string((command or "").strip())
        norm_diff = SecretMaskingFilter._mask_string(diff or "")
        canonical_dict = {
            "approval_id": approval_id,
            "target_host": target_host.strip(),
            "tool_name": tool_name.strip(),
            "command": norm_cmd,
            "sudo": bool(sudo),
            "cwd": (cwd or "").strip(),
            "parameters": _normalize_parameters_for_hmac(parameters),
            "diff_sha256": hashlib.sha256(norm_diff.encode("utf-8")).hexdigest(),
        }
        canonical_json = json.dumps(
            canonical_dict,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hmac.new(
            self._secret.encode("utf-8"),
            canonical_json.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def verify_request_hmac(
        self,
        request: ApprovalRequest,
        *,
        target_host: str,
        tool_name: str,
        command: str | None = None,
        sudo: bool = False,
        cwd: str | None = None,
        parameters: Mapping[str, Any] | None = None,
    ) -> bool:
        """Проверить неизменность параметров операции относительно подписанной заявки."""
        expected = self.compute_hmac(
            approval_id=request.approval_id,
            target_host=target_host,
            tool_name=tool_name,
            command=command,
            sudo=sudo,
            cwd=cwd,
            parameters=parameters,
            diff=request.diff,
        )
        return hmac.compare_digest(request.hmac_signature, expected)

    def _load_from_disk_sync(self) -> None:
        if self.store_path is None or not self.store_path.is_file():
            return
        with contextlib.suppress(Exception):
            raw_text = self.store_path.read_text(encoding="utf-8")
            data = json.loads(raw_text)
            if not isinstance(data, dict):
                return
            file_secret = data.get("hmac_secret")
            if isinstance(file_secret, str) and file_secret and not self._secret:
                self._secret = file_secret
            raw_reqs = data.get("requests")
            if isinstance(raw_reqs, dict):
                for appr_id, item in raw_reqs.items():
                    if isinstance(item, dict):
                        req = ApprovalRequest.model_validate(item)
                        self._requests[str(appr_id)] = req
                        if req.status != ApprovalStatus.PENDING and appr_id in self._events:
                            self._events[appr_id].set()

    def _save_to_disk_sync(self) -> None:
        if self.store_path is None:
            return
        self.store_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload = {
            "hmac_secret": self._secret,
            "updated_at": datetime.now(UTC).isoformat(),
            "requests": {
                k: v.model_dump(mode="json")
                for k, v in self._requests.items()
            },
        }
        serialized = json.dumps(payload, ensure_ascii=False, indent=2)
        fd, tmp_name = tempfile.mkstemp(
            prefix=".approvals_",
            suffix=".tmp",
            dir=str(self.store_path.parent),
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as tmp_file:
                tmp_file.write(serialized)
            with contextlib.suppress(OSError):
                os.chmod(tmp_name, 0o600)
            os.replace(tmp_name, self.store_path)
        except Exception:
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)
            raise

    def _write_audit_entry(self, event: str, request: ApprovalRequest, **extra: Any) -> None:
        audit_path_str = self.policy.audit_log_path
        if not audit_path_str:
            return
        audit_path = Path(audit_path_str).expanduser()
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        entry: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "event": event,
            "approval_id": request.approval_id,
            "status": request.status.value,
            "target_host": request.target_host,
            "tool_name": request.tool_name,
            "command": SecretMaskingFilter._mask_string(request.command) if request.command else None,
            "sudo": request.sudo,
            "risk_tier": request.risk_tier.value,
            "decided_by": request.decided_by,
            "decision_reason": SecretMaskingFilter._mask_string(request.decision_reason)
            if request.decision_reason
            else None,
            **extra,
        }
        with contextlib.suppress(Exception), audit_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def _expire_stale_unlocked(self, now: datetime | None = None) -> bool:
        ref = now or datetime.now(UTC)
        changed = False
        for appr_id, req in self._requests.items():
            if req.status == ApprovalStatus.PENDING and req.is_expired(ref):
                req.status = ApprovalStatus.EXPIRED
                changed = True
                if appr_id in self._events:
                    self._events[appr_id].set()
                self._write_audit_entry("approval.expired", req)
        return changed

    async def create_request(
        self,
        *,
        target_host: str,
        tool_name: str,
        risk_tier: ActionRiskTier,
        risk_reasons: Sequence[str] = (),
        command: str | None = None,
        sudo: bool = False,
        cwd: str | None = None,
        parameters: Mapping[str, Any] | None = None,
        diff: str | None = None,
        agent_id: str | None = None,
        timeout_seconds: float | None = None,
        deduplicate: bool = True,
    ) -> ApprovalRequest:
        """Создать новую заявку на согласование (или вернуть идентичную активную PENDING-заявку)."""
        async with self._lock:
            self._load_from_disk_sync()
            self._expire_stale_unlocked()

            norm_host = target_host.strip()
            norm_tool = tool_name.strip()
            norm_cwd = (cwd or "").strip() or None
            norm_params = _normalize_parameters_for_hmac(parameters)
            masked_cmd = SecretMaskingFilter._mask_string(command.strip()) if command is not None else None
            masked_diff = SecretMaskingFilter._mask_string(diff) if diff is not None else None

            if deduplicate:
                for existing in self._requests.values():
                    if (
                        existing.status == ApprovalStatus.PENDING
                        and not existing.is_expired()
                        and existing.target_host == norm_host
                        and existing.tool_name == norm_tool
                        and existing.command == masked_cmd
                        and existing.sudo == bool(sudo)
                        and existing.cwd == norm_cwd
                        and existing.parameters == norm_params
                        and existing.diff == masked_diff
                    ):
                        return existing

            approval_id = f"appr_{secrets.token_hex(6)}"
            now = datetime.now(UTC)
            ttl = float(timeout_seconds if timeout_seconds is not None else self.policy.timeout_seconds)
            expires_at = now + timedelta(seconds=max(0.1, ttl))

            sig = self.compute_hmac(
                approval_id=approval_id,
                target_host=norm_host,
                tool_name=norm_tool,
                command=masked_cmd,
                sudo=sudo,
                cwd=norm_cwd,
                parameters=norm_params,
                diff=masked_diff,
            )

            req = ApprovalRequest(
                approval_id=approval_id,
                created_at=now,
                expires_at=expires_at,
                agent_id=agent_id,
                target_host=norm_host,
                tool_name=norm_tool,
                command=masked_cmd,
                sudo=bool(sudo),
                cwd=norm_cwd,
                parameters=norm_params,
                risk_tier=risk_tier,
                risk_reasons=list(risk_reasons),
                diff=masked_diff,
                status=ApprovalStatus.PENDING,
                hmac_signature=sig,
            )
            self._requests[approval_id] = req
            self._events[approval_id] = asyncio.Event()
            self._save_to_disk_sync()
            self._write_audit_entry("approval.requested", req)

        # Оповещаем подключённые каналы (например, stderr или webhook)
        for channel in self._channels:
            with contextlib.suppress(Exception):
                chan_resp = await channel.notify(req)
                if isinstance(chan_resp, dict):
                    decision = str(chan_resp.get("decision") or "").upper()
                    by_user = str(chan_resp.get("decided_by") or "channel_operator")
                    reason = chan_resp.get("reason")
                    if decision == "APPROVED":
                        await self.approve(
                            req.approval_id,
                            decided_by=by_user,
                            reason=str(reason) if reason else None,
                        )
                    elif decision == "REJECTED":
                        await self.reject(
                            req.approval_id,
                            decided_by=by_user,
                            reason=str(reason) if reason else None,
                        )

        return await self.get_request(req.approval_id)

    async def get_request(self, approval_id: str) -> ApprovalRequest:
        """Получить заявку по ID с актуализацией статуса истечения таймаута."""
        async with self._lock:
            self._load_from_disk_sync()
            changed = self._expire_stale_unlocked()
            if changed:
                self._save_to_disk_sync()
            req = self._requests.get(approval_id.strip())
            if req is None:
                raise KeyError(f"Approval request {approval_id!r} not found")
            return req

    async def list_requests(
        self,
        *,
        status: ApprovalStatus | str | None = None,
    ) -> list[ApprovalRequest]:
        """Вернуть список всех заявок (опционально отфильтрованный по статусу)."""
        async with self._lock:
            self._load_from_disk_sync()
            if self._expire_stale_unlocked():
                self._save_to_disk_sync()
            items = list(self._requests.values())
            if status is not None:
                target_status = ApprovalStatus(str(status).upper())
                items = [r for r in items if r.status == target_status]
            return sorted(items, key=lambda r: r.created_at, reverse=True)

    async def approve(
        self,
        approval_id: str,
        *,
        decided_by: str = "operator",
        reason: str | None = None,
    ) -> ApprovalRequest:
        """Одобрить заявку оператором (PENDING -> APPROVED)."""
        async with self._lock:
            self._load_from_disk_sync()
            self._expire_stale_unlocked()
            req = self._requests.get(approval_id.strip())
            if req is None:
                raise KeyError(f"Approval request {approval_id!r} not found")
            if req.status == ApprovalStatus.CONSUMED:
                raise ApprovalAlreadyConsumedError(
                    f"Approval {approval_id!r} has already been consumed",
                    approval_id=approval_id,
                    approval_request=req,
                )
            if req.status == ApprovalStatus.EXPIRED or req.is_expired():
                req.status = ApprovalStatus.EXPIRED
                self._save_to_disk_sync()
                raise ApprovalExpiredError(
                    f"Approval {approval_id!r} has expired at {req.expires_at.isoformat()}",
                    approval_id=approval_id,
                    approval_request=req,
                )
            if req.status == ApprovalStatus.REJECTED:
                raise ApprovalRejectedError(
                    f"Approval {approval_id!r} was already rejected by {req.decided_by!r}",
                    approval_id=approval_id,
                    decided_by=req.decided_by,
                    decision_reason=req.decision_reason,
                    approval_request=req,
                )

            req.status = ApprovalStatus.APPROVED
            req.decided_by = decided_by.strip() or "operator"
            req.decided_at = datetime.now(UTC)
            req.decision_reason = reason
            self._save_to_disk_sync()
            self._write_audit_entry("approval.approved", req)
            if approval_id in self._events:
                self._events[approval_id].set()
            return req

    async def reject(
        self,
        approval_id: str,
        *,
        decided_by: str = "operator",
        reason: str | None = None,
    ) -> ApprovalRequest:
        """Отклонить заявку оператором (PENDING -> REJECTED)."""
        async with self._lock:
            self._load_from_disk_sync()
            self._expire_stale_unlocked()
            req = self._requests.get(approval_id.strip())
            if req is None:
                raise KeyError(f"Approval request {approval_id!r} not found")
            if req.status == ApprovalStatus.CONSUMED:
                raise ApprovalAlreadyConsumedError(
                    f"Approval {approval_id!r} has already been consumed",
                    approval_id=approval_id,
                    approval_request=req,
                )

            req.status = ApprovalStatus.REJECTED
            req.decided_by = decided_by.strip() or "operator"
            req.decided_at = datetime.now(UTC)
            req.decision_reason = reason
            self._save_to_disk_sync()
            self._write_audit_entry("approval.rejected", req)
            if approval_id in self._events:
                self._events[approval_id].set()
            return req

    async def wait_for_decision(
        self,
        approval_id: str,
        *,
        timeout: float | None = None,
        poll_interval: float = 0.1,
    ) -> ApprovalRequest:
        """Ожидать решения оператора (в памяти или через межпроцессный JSON-стор)."""
        req = await self.get_request(approval_id)
        if req.status != ApprovalStatus.PENDING:
            return req

        max_wait = (
            min(float(timeout), req.remaining_seconds())
            if timeout is not None
            else req.remaining_seconds()
        )
        deadline = time.monotonic() + max(0.01, max_wait)
        ev = self._events.setdefault(approval_id, asyncio.Event())

        while time.monotonic() < deadline:
            req = await self.get_request(approval_id)
            if req.status != ApprovalStatus.PENDING:
                return req
            step = min(poll_interval, max(0.01, deadline - time.monotonic()))
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(ev.wait(), timeout=step)
            if ev.is_set():
                return await self.get_request(approval_id)

        return await self.get_request(approval_id)

    async def verify_and_consume(
        self,
        approval_id: str,
        *,
        target_host: str,
        tool_name: str,
        command: str | None = None,
        sudo: bool = False,
        cwd: str | None = None,
        parameters: Mapping[str, Any] | None = None,
    ) -> ApprovalRequest:
        """Проверить статус и HMAC-подпись одобренной заявки и атомарно погасить одноразовый токен."""
        async with self._lock:
            self._load_from_disk_sync()
            self._expire_stale_unlocked()
            req = self._requests.get(approval_id.strip())
            if req is None:
                raise KeyError(f"Approval request {approval_id!r} not found")

            if req.status == ApprovalStatus.CONSUMED:
                self._write_audit_entry("approval.replay_blocked", req)
                raise ApprovalAlreadyConsumedError(
                    f"Single-use approval token {approval_id!r} has already been consumed",
                    approval_id=approval_id,
                    approval_request=req,
                    command=command,
                    host=target_host,
                )

            if req.status == ApprovalStatus.EXPIRED or req.is_expired():
                req.status = ApprovalStatus.EXPIRED
                self._save_to_disk_sync()
                raise ApprovalExpiredError(
                    f"Approval request {approval_id!r} expired at {req.expires_at.isoformat()}",
                    approval_id=approval_id,
                    approval_request=req,
                    command=command,
                    host=target_host,
                )

            if req.status == ApprovalStatus.REJECTED:
                raise ApprovalRejectedError(
                    f"Action rejected by operator ({req.decided_by or 'operator'}): "
                    f"{req.decision_reason or 'No reason provided'}",
                    approval_id=approval_id,
                    decided_by=req.decided_by,
                    decision_reason=req.decision_reason,
                    approval_request=req,
                    command=command,
                    host=target_host,
                )

            if req.status == ApprovalStatus.PENDING:
                raise ApprovalRequiredError(
                    f"Approval request {approval_id!r} is still PENDING operator confirmation",
                    approval_id=approval_id,
                    approval_request=req,
                    command=command,
                    host=target_host,
                )

            if not self.verify_request_hmac(
                req,
                target_host=target_host,
                tool_name=tool_name,
                command=command,
                sudo=sudo,
                cwd=cwd,
                parameters=parameters,
            ):
                masked_cmd = SecretMaskingFilter._mask_string(command) if command is not None else None
                self._write_audit_entry(
                    "approval.tampering_detected",
                    req,
                    attempted_host=target_host,
                    attempted_tool=tool_name,
                    attempted_command=masked_cmd,
                    attempted_sudo=sudo,
                )
                raise ApprovalTamperingError(
                    f"HMAC signature mismatch for approval {approval_id!r}: "
                    "target host, command, sudo flag, or parameters do not match the approved request",
                    approval_id=approval_id,
                    approval_request=req,
                    command=command,
                    host=target_host,
                )

            req.status = ApprovalStatus.CONSUMED
            req.consumed_at = datetime.now(UTC)
            self._save_to_disk_sync()
            self._write_audit_entry("approval.consumed", req)
            return req


__all__ = [
    "DEFAULT_APPROVAL_STORE_PATH",
    "ActionRiskClassifier",
    "ApprovalChannel",
    "ApprovalManager",
    "TerminalApprovalChannel",
    "WebhookApprovalChannel",
    "build_unified_diff",
]
