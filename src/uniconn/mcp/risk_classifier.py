# src/uniconn/mcp/risk_classifier.py
"""Детерминированный классификатор рисков команд и файловых операций (ActionRiskClassifier).

Выделен из ``uniconn.mcp.hitl`` для модульности и переиспользует примитивы
синтаксического разбора и нормализации путей из ``uniconn.security.ast_parser``.
"""

from __future__ import annotations

import difflib
import os
import re
import shlex
from collections.abc import Mapping
from typing import Any

from .._logging import SecretMaskingFilter
from ..hooks import DEFAULT_BLOCKED_PATTERNS
from ..security.ast_parser import (
    _OPTS_WITH_ARG_BY_BIN,
    _SHELL_BINARIES,
    _SUDO_OPTS_WITH_ARG,
    _TRAVERSAL_SYSTEM_ROOTS,
    _WRAPPER_BINARIES,
    _WRAPPER_OPTS_WITH_ARG,
    CommandASTParser,
    normalize_target_path,
)
from .models import (
    ActionRiskTier,
    HITLPolicy,
    RiskAssessment,
)

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
        re.compile(r"\brm\s+-[a-zA-Z]*(?:rf|fr)[a-zA-Z]*\s+/(?:\*|$|\s)", re.IGNORECASE),
        "Recursive deletion of root filesystem (/ or /*) is strictly forbidden",
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
            r"\b(?:curl|wget)\b[^|;\n]*\|\s*(?:sudo\s+|doas\s+)?(?:sh|bash|zsh|dash|ksh|python\d*|perl|ruby)\b",
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
    r"""Разбить составную shell-команду по операторам и извлечь подстановки через CommandASTParser."""
    segments, _, _ = CommandASTParser._tokenize_top_level_segments(command)
    probe_str = re.sub(r"\$\(\(.*?\)\)", "0", command)
    for sub_cmd, _depth in CommandASTParser._extract_subshell_commands(probe_str):
        if sub_cmd and sub_cmd not in segments:
            segments.append(sub_cmd)
    return segments


def _resolve_normalized_write_path(raw_path: str) -> str:
    """Нормализовать путь записи файла и раскрыть попытки относительного path traversal к системным корням."""
    cleaned = raw_path.strip().replace("\\", "/") or "/"
    if "../" in cleaned or cleaned.startswith(".."):
        rel_tail = cleaned
        while rel_tail.startswith(("../", "./")):
            rel_tail = rel_tail[3:] if rel_tail.startswith("../") else rel_tail[2:]
        rel_tail = rel_tail.lstrip("/")
        if any(
            rel_tail == root.rstrip("/") or rel_tail.startswith(root)
            for root in _TRAVERSAL_SYSTEM_ROOTS
        ):
            return normalize_target_path("/" + rel_tail)
    return normalize_target_path(cleaned)


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
        ast: Any = None,
        _depth: int = 0,
        _preparsed_ast: Any = None,
    ) -> RiskAssessment:
        """Оценить уровень риска shell-команды (включая AST-анализ, обфускацию и вложенные оболочки)."""
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

        # 2. Глубокий синтаксический AST-разбор (детекция обфускации и косвенных вызовов)
        ast_obj = ast if ast is not None else _preparsed_ast
        if ast_obj is None and _depth == 0:
            ast_obj = CommandASTParser.parse(cmd_stripped, sudo=sudo)

        if ast_obj is not None and getattr(ast_obj, "is_obfuscated", False):
            obf_reasons = tuple(
                getattr(ast_obj, "obfuscation_reasons", ()) or ("Obfuscated command syntax detected",)
            )
            return RiskAssessment(
                risk_tier=ActionRiskTier.TIER_3_FORBIDDEN,
                reasons=obf_reasons,
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

        if ast_obj is not None:
            dest_sev = ActionRiskTier.TIER_2_DESTRUCTIVE.severity
            if getattr(ast_obj, "has_destructive_verbs", False) and max_tier.severity < dest_sev:
                max_tier = ActionRiskTier.TIER_2_DESTRUCTIVE
                ast_execs = ", ".join(getattr(ast_obj, "executables", ()))
                reasons.append(f"AST analysis detected nested destructive operation ({ast_execs})")
            if getattr(ast_obj, "complexity_exceeded", False) and max_tier.severity < dest_sev:
                max_tier = ActionRiskTier.TIER_2_DESTRUCTIVE
                reasons.append("Command exceeds AST complexity threshold (opaque script)")

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

        # Специальные случаи команд из _SAFE_COMMANDS с мутирующими/деструктивными флагами
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
            if "-delete" in rest_args:
                return ActionRiskTier.TIER_2_DESTRUCTIVE, ["Recursive file deletion via find -delete"]
            if any(a in ("-exec", "-execdir", "-ok") for a in rest_args):
                return ActionRiskTier.TIER_1_MUTATING, ["find with command execution flags"]
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
        """Снять префиксы env-переменных, sudo/doas/pkexec/su/env/nohup и обнаружить sh -c / su -c."""
        idx = 0
        n = len(tokens)
        had_sudo = False

        while idx < n:
            tok = tokens[idx]
            if "=" in tok and not tok.startswith("-") and tok.split("=", 1)[0].isidentifier():
                idx += 1
                continue
            base = os.path.basename(tok).lower()
            if base in ("sudo", "doas", "pkexec"):
                had_sudo = True
                idx += 1
                while idx < n and tokens[idx].startswith("-"):
                    opt = tokens[idx]
                    idx += 1
                    if opt == "--":
                        break
                    if opt in _SUDO_OPTS_WITH_ARG and idx < n:
                        idx += 1
                continue
            if base in ("su", "runuser"):
                had_sudo = True
                idx += 1
                while idx < n:
                    cur = tokens[idx]
                    if cur in ("-c", "--command") and idx + 1 < n:
                        return tokens[idx:], True, tokens[idx + 1]
                    if cur.startswith("--command="):
                        return tokens[idx:], True, cur.split("=", 1)[1]
                    if cur == "--":
                        idx += 1
                        break
                    if cur.startswith("-"):
                        idx += 2 if cur in ("-s", "--shell", "-u", "-g", "-G") and idx + 1 < n else 1
                        continue
                    if idx + 1 < n and tokens[idx + 1].startswith("-"):
                        idx += 1
                        continue
                    break
                continue
            if base == "chroot" and idx + 1 < n:
                idx += 1
                while idx < n and tokens[idx].startswith("-"):
                    opt = tokens[idx]
                    idx += 1
                    if opt in ("--userspec", "--groups") and idx < n:
                        idx += 1
                if idx + 1 < n:
                    idx += 1
                continue
            if base == "timeout" and idx + 1 < n:
                idx += 1
                while idx < n and tokens[idx].startswith("-"):
                    opt = tokens[idx]
                    idx += 1
                    if opt in ("-k", "--kill-after", "-s", "--signal") and idx < n:
                        idx += 1
                if idx < n:
                    idx += 1  # Пропускаем значение длительности таймаута
                continue
            if base in _WRAPPER_BINARIES:
                w_opts = _WRAPPER_OPTS_WITH_ARG.get(base, frozenset())
                idx += 1
                while idx < n and tokens[idx].startswith("-"):
                    opt = tokens[idx]
                    idx += 1
                    if opt == "--":
                        break
                    if opt in w_opts and idx < n:
                        idx += 1
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
        norm_path = _resolve_normalized_write_path(path)
        reasons: list[str] = []

        if norm_path in ("/", "/etc/shadow", "/etc/gshadow", "/etc/sudoers") or norm_path.startswith(
            (*_FORBIDDEN_FILE_PREFIXES, "/etc/sudoers.d/")
        ):
            return RiskAssessment(
                risk_tier=ActionRiskTier.TIER_3_FORBIDDEN,
                reasons=(f"Writing to critical device or security file {norm_path!r} is forbidden",),
                is_production=is_production,
                requires_approval=False,
            )

        tier = ActionRiskTier.TIER_1_MUTATING
        if (
            any(
                norm_path == prefix.rstrip("/") or norm_path.startswith(prefix)
                for prefix in _PROTECTED_PATH_PREFIXES
            )
            or "/.ssh/" in norm_path
            or norm_path.endswith("/.ssh")
        ):
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


__all__ = [
    "_DESTRUCTIVE_PATTERNS",
    "_FORBIDDEN_FILE_PREFIXES",
    "_FORBIDDEN_PATTERNS",
    "_MUTATING_PATTERNS",
    "_PROTECTED_PATH_PREFIXES",
    "_SAFE_COMMANDS",
    "ActionRiskClassifier",
    "_extract_first_subcommand",
    "_split_shell_segments",
    "build_unified_diff",
]
