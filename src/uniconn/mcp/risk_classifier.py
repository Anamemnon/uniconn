# src/uniconn/mcp/risk_classifier.py
"""Детерминированный классификатор рисков команд и файловых операций (ActionRiskClassifier).

Выделен из ``uniconn.mcp.hitl`` для модульности и переиспользует примитивы
синтаксического разбора и нормализации путей из ``uniconn.security.ast_parser``.
"""

from __future__ import annotations

import difflib
import re
from collections.abc import Mapping, Sequence
from typing import Any

from .._logging import SecretMaskingFilter
from ..hooks import DEFAULT_BLOCKED_PATTERNS
from ..security.ast_parser import (
    _SHELL_BINARIES,
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
        re.compile(r"\brm\s+-[a-zA-Z]*(?:rf|fr)[a-zA-Z]*\s+/(?:\*|$|\s|['\";|&)])", re.IGNORECASE),
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

_FORBIDDEN_READ_EXACT: frozenset[str] = frozenset(
    {
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/sudoers",
        "/etc/master.passwd",
        "/etc/security/opasswd",
        "/dev/mem",
        "/dev/kmem",
        "/dev/port",
        "/proc/kcore",
        "/proc/kmem",
    }
)

_FORBIDDEN_READ_PREFIXES: tuple[str, ...] = (
    *_FORBIDDEN_FILE_PREFIXES,
    "/etc/sudoers.d/",
    "/var/run/secrets/",
    "/run/secrets/",
)

_FORBIDDEN_READ_REGEXES: tuple[re.Pattern[str], ...] = (
    re.compile(r"^/proc/(?:\d+|self|thread-self)/(?:environ|mem)$"),
    re.compile(r"/\.ssh/id_[^/]+(?<!\.pub)$", re.IGNORECASE),
    re.compile(r"^/etc/ssh/ssh_host_[^/]+_key$"),
    re.compile(r"/\.(?:aws/credentials|kube/config)$", re.IGNORECASE),
    re.compile(
        r"(?:^|/|[a-z]:/?)windows/(?:system32/config|repair)/(?:sam|security|system|default)$",
        re.IGNORECASE,
    ),
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
    """Нормализовать целевой путь и раскрыть попытки path traversal."""
    return normalize_target_path(raw_path) or "/"


_MUTATING_EXECUTABLES: frozenset[str] = frozenset(
    {
        "mkdir",
        "touch",
        "cp",
        "mv",
        "ln",
        "install",
        "chmod",
        "chown",
        "chgrp",
        "chattr",
        "setfacl",
        "useradd",
        "adduser",
        "usermod",
        "groupadd",
        "patch",
    }
)
_PACKAGE_MANAGERS: frozenset[str] = frozenset(
    {"apt", "apt-get", "dpkg", "yum", "dnf", "apk", "pacman", "zypper", "helm", "pip", "uv", "npm"}
)
_DESTRUCTIVE_PKG_VERBS: frozenset[str] = frozenset({"remove", "purge", "erase", "autoremove", "uninstall", "del"})
_MUTATING_PKG_VERBS: frozenset[str] = frozenset({"install", "update", "upgrade", "add", "sync"})
_OUTPUT_REDIRECT_TARGET_RE = re.compile(r"^(?:\d*>>?|&>>?)\s*(\S+)")
_AWK_BINARIES: frozenset[str] = frozenset({"awk", "gawk", "mawk", "nawk"})
_AWK_EXEC_OR_WRITE_RE = re.compile(
    r"\bsystem\s*\(|\bgetline\b|\|\s*&?\s*['\"]|(?<![<>!=])>{1,2}\s*['\"$A-Za-z/]",
    re.IGNORECASE,
)
_NO_FILE_READ_COMMANDS: frozenset[str] = frozenset({"echo", "printf", "true", "false"})
_SYSTEMCTL_RO_SUBCOMMANDS: frozenset[str] = frozenset(
    {"status", "is-active", "is-enabled", "is-failed", "show", "list-units", "list-unit-files", "cat"}
)
_GIT_RO_SUBCOMMANDS: frozenset[str] = frozenset(
    {"status", "log", "diff", "show", "branch", "remote", "rev-parse", "describe", "ls-files"}
)
_CONTAINER_RO_SUBCOMMANDS: frozenset[str] = frozenset(
    {"ps", "images", "inspect", "logs", "version", "info", "stats", "top", "get", "describe", "cluster-info"}
)
_FIND_MUTATING_FLAGS: frozenset[str] = frozenset(
    {"-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprintf", "-fls"}
)


def _match_forbidden_read_path(raw_path: str) -> str | None:
    """Вернуть нормализованный путь, если он указывает на запрещённый секрет, ключ или устройство."""
    if not raw_path or raw_path.startswith("-"):
        return None
    norm_path = _resolve_normalized_write_path(raw_path)
    norm_lower = norm_path.lower()
    if (
        norm_path in _FORBIDDEN_READ_EXACT
        or norm_path.startswith(_FORBIDDEN_READ_PREFIXES)
        or any(pat.search(norm_lower) for pat in _FORBIDDEN_READ_REGEXES)
    ):
        return norm_path
    return None


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
        """Оценить уровень риска shell-команды на базе единого AST ``CommandASTParser``."""
        del _depth
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

        def _elevate(tier: ActionRiskTier, msg: str | None = None) -> None:
            nonlocal max_tier
            if tier.severity > max_tier.severity:
                max_tier = tier
            if msg and msg not in reasons:
                reasons.append(msg)

        # 1. Глобальная проверка цельной строки на FORBIDDEN (включая fork-бомбу и raw-device редиректы)
        for regex, reason in _FORBIDDEN_PATTERNS:
            if regex.search(cmd_stripped):
                return RiskAssessment(
                    risk_tier=ActionRiskTier.TIER_3_FORBIDDEN,
                    reasons=(reason,),
                    is_production=is_production,
                    requires_approval=False,
                )

        # 2. Единый глубокий AST-разбор через CommandASTParser (без дублирования развёртки обёрток)
        ast_obj = ast if ast is not None else _preparsed_ast
        if ast_obj is None:
            ast_obj = CommandASTParser.parse(cmd_stripped, sudo=sudo)

        if getattr(ast_obj, "is_obfuscated", False):
            obf_reasons = tuple(
                getattr(ast_obj, "obfuscation_reasons", ()) or ("Obfuscated command syntax detected",)
            )
            return RiskAssessment(
                risk_tier=ActionRiskTier.TIER_3_FORBIDDEN,
                reasons=obf_reasons,
                is_production=is_production,
                requires_approval=False,
            )

        atomic_commands = tuple(getattr(ast_obj, "atomic_commands", ()) or ())
        for idx, atom in enumerate(atomic_commands):
            # Если shell (bash -c '...') уже распакован в дочерние AtomicCommand, саму обёртку пропускаем
            is_unwrapped_shell_carrier = (
                atom.executable in _SHELL_BINARIES
                and any(flag in atom.flags for flag in ("-c", "-lc", "-ic"))
                and any(
                    f"{atom.executable} " in w
                    for child in atomic_commands[idx + 1 :]
                    for w in getattr(child, "wrappers", ())
                )
            )
            if is_unwrapped_shell_carrier:
                continue

            atom_tier, atom_reasons = cls._classify_atomic_command(atom, inherited_sudo=sudo)
            for msg in atom_reasons:
                _elevate(atom_tier, msg)
            if not atom_reasons:
                _elevate(atom_tier)

        # 3. Агрегированные признаки AST (деструктивные SQL-выражения и превышение лимитов сложности)
        dest_sev = ActionRiskTier.TIER_2_DESTRUCTIVE.severity
        if getattr(ast_obj, "has_destructive_verbs", False) and max_tier.severity < dest_sev:
            ast_execs = ", ".join(getattr(ast_obj, "executables", ()))
            _elevate(
                ActionRiskTier.TIER_2_DESTRUCTIVE,
                f"AST analysis detected nested destructive operation ({ast_execs})",
            )
        if getattr(ast_obj, "complexity_exceeded", False) and max_tier.severity < dest_sev:
            _elevate(
                ActionRiskTier.TIER_2_DESTRUCTIVE,
                "Command exceeds AST complexity threshold (opaque script)",
            )

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
    def _classify_redirect_or_tee(cls, atom: Any) -> tuple[ActionRiskTier, list[str]]:
        """Оценить риск перенаправлений вывода (``>``, ``>>``) и записи через ``tee``."""
        tier = ActionRiskTier.TIER_0_SAFE
        reasons: list[str] = []

        def _check_target(target: str) -> None:
            nonlocal tier
            norm = _resolve_normalized_write_path(target)
            if norm == "/dev/null" or norm.startswith("&"):
                return
            if any(norm == p.rstrip("/") or norm.startswith(p) for p in _PROTECTED_PATH_PREFIXES):
                tier = ActionRiskTier.TIER_2_DESTRUCTIVE
                reasons.append("Overwriting or appending to protected system configuration path")
            elif tier.severity < ActionRiskTier.TIER_1_MUTATING.severity:
                tier = ActionRiskTier.TIER_1_MUTATING
                reasons.append("Shell output redirection to file")

        for redir in getattr(atom, "redirects", ()):
            match = _OUTPUT_REDIRECT_TARGET_RE.search(redir.strip())
            if match:
                _check_target(match.group(1))

        if atom.executable == "tee":
            for arg in atom.arguments:
                _check_target(arg)

        return tier, reasons

    @staticmethod
    def _classify_package_manager(
        sub: str | None,
        args_lower: list[str],
        flags_dict: Mapping[str, Any],
    ) -> tuple[ActionRiskTier, str] | None:
        verb = sub or (args_lower[0] if args_lower else None)
        if verb in _DESTRUCTIVE_PKG_VERBS or any(k.startswith("-R") for k in flags_dict):
            return ActionRiskTier.TIER_2_DESTRUCTIVE, "Removing or purging installed packages"
        if verb in _MUTATING_PKG_VERBS or any(a in _MUTATING_PKG_VERBS for a in args_lower):
            return ActionRiskTier.TIER_1_MUTATING, "Installing or updating packages"
        return None

    @staticmethod
    def _classify_container_cli(
        base_bin: str,
        sub: str | None,
        args_lower: list[str],
    ) -> tuple[ActionRiskTier, str]:
        if (
            base_bin in ("docker", "podman")
            and sub in ("system", "volume")
            and any(a in ("prune", "rm") for a in args_lower)
        ):
            return ActionRiskTier.TIER_2_DESTRUCTIVE, "Destructive container or Kubernetes workload operation"
        if sub is None or sub in _CONTAINER_RO_SUBCOMMANDS:
            return ActionRiskTier.TIER_0_SAFE, f"Read-only {base_bin} inspection"
        return ActionRiskTier.TIER_1_MUTATING, f"Container/cluster operation: {base_bin} {sub}"

    @staticmethod
    def _classify_awk(args: Sequence[Any], flags_dict: Mapping[str, Any]) -> tuple[ActionRiskTier, str]:
        script_parts = [str(a) for a in args]
        script_parts.extend(str(v) for v in flags_dict.values() if isinstance(v, str))
        joined_args = " ".join(script_parts)
        if _AWK_EXEC_OR_WRITE_RE.search(joined_args) or "-f" in flags_dict or "--file" in flags_dict:
            return (
                ActionRiskTier.TIER_2_DESTRUCTIVE,
                "awk script with external command execution, file output, or script file",
            )
        return ActionRiskTier.TIER_1_MUTATING, "awk scripting interpreter may execute commands or write files"

    @classmethod
    def _classify_special_binary(
        cls,
        base_bin: str,
        sub: str | None,
        args: Sequence[Any],
        args_lower: list[str],
        flags_dict: Mapping[str, Any],
    ) -> tuple[ActionRiskTier, str] | None:
        """Разобрать команды со смешанными read-only и mutating подкомандами/флагами."""
        if base_bin in _PACKAGE_MANAGERS:
            return cls._classify_package_manager(sub, args_lower, flags_dict)
        if base_bin in _AWK_BINARIES:
            return cls._classify_awk(args, flags_dict)
        if base_bin == "ip":
            ip_mut = ("add", "del", "delete", "set", "flush", "change", "replace")
            if sub in ip_mut or any(a in ip_mut for a in args_lower):
                return ActionRiskTier.TIER_2_DESTRUCTIVE, "Network interface or routing table modification via ip"
            return ActionRiskTier.TIER_0_SAFE, "Safe read-only command (ip)"
        if base_bin == "sysctl":
            if "-w" in flags_dict or any("=" in a for a in args_lower):
                return ActionRiskTier.TIER_1_MUTATING, "Kernel parameter modification via sysctl"
            return ActionRiskTier.TIER_0_SAFE, "Safe read-only command (sysctl)"
        if base_bin == "systemctl":
            if sub is None or sub in _SYSTEMCTL_RO_SUBCOMMANDS:
                return ActionRiskTier.TIER_0_SAFE, "Read-only systemctl inspection"
            return ActionRiskTier.TIER_1_MUTATING, f"Mutating systemctl action: {sub}"
        if base_bin == "service":
            if sub is None or sub == "status":
                return ActionRiskTier.TIER_0_SAFE, "Read-only service inspection"
            return ActionRiskTier.TIER_1_MUTATING, f"Starting or restarting a system service ({sub})"
        if base_bin == "find":
            if any(k in flags_dict for k in _FIND_MUTATING_FLAGS):
                return ActionRiskTier.TIER_1_MUTATING, "find with command execution or file output flags"
            return ActionRiskTier.TIER_0_SAFE, "Read-only find search"
        if base_bin == "git":
            if sub is None or sub in _GIT_RO_SUBCOMMANDS:
                return ActionRiskTier.TIER_0_SAFE, "Read-only git inspection"
            return ActionRiskTier.TIER_1_MUTATING, f"Git operation: {sub}"
        if base_bin in ("docker", "podman", "kubectl"):
            return cls._classify_container_cli(base_bin, sub, args_lower)
        if base_bin == "command":
            is_lookup_flag = any(
                k.startswith("-") and not k.startswith("--") and ("v" in k[1:] or "V" in k[1:])
                for k in flags_dict
            )
            if is_lookup_flag:
                return ActionRiskTier.TIER_0_SAFE, "Safe read-only command lookup (command -v/-V)"
            return ActionRiskTier.TIER_1_MUTATING, "Command builtin execution"
        if base_bin == "sed" and (
            "-i" in flags_dict or "--in-place" in flags_dict or any(k.startswith("-i") for k in flags_dict)
        ):
            return ActionRiskTier.TIER_1_MUTATING, "In-place file editing"
        return None

    @classmethod
    def _classify_atomic_command(
        cls,
        atom: Any,
        *,
        inherited_sudo: bool = False,
    ) -> tuple[ActionRiskTier, list[str]]:
        """Классифицировать одиночный ``AtomicCommand``, уже очищенный от обёрток парсером AST."""
        best_tier, reasons = cls._classify_redirect_or_tee(atom)
        base_bin = str(atom.executable or "").lower()
        sub = atom.subcommand.lower() if atom.subcommand else None
        args_lower = [str(a).lower() for a in atom.arguments]
        flags_dict = atom.flags
        effective_sudo = bool(atom.is_sudo or inherited_sudo)

        def _pick(tier: ActionRiskTier, msg: str) -> tuple[ActionRiskTier, list[str]]:
            if best_tier.severity > tier.severity:
                return best_tier, reasons
            return tier, [msg] if msg else reasons

        # Проверка критически запрещённых атомарных операций (после раскрытия обёрток/подстановок)
        if base_bin == "rm":
            has_recursive = any(k in flags_dict for k in ("-r", "-R", "--recursive"))
            targets_root = any(
                str(a).strip() in ("/", "/*") or normalize_target_path(str(a)) in ("/", "/*")
                for a in atom.arguments
            )
            if "--no-preserve-root" in flags_dict or (has_recursive and targets_root):
                return _pick(
                    ActionRiskTier.TIER_3_FORBIDDEN,
                    "Recursive deletion of root filesystem (/ or /*) is strictly forbidden",
                )
        if base_bin == "mkfs" or base_bin.startswith("mkfs."):
            return _pick(
                ActionRiskTier.TIER_3_FORBIDDEN,
                f"Formatting filesystem ({base_bin}) is strictly forbidden",
            )

        # Запрет чтения/доступа к критическим секретным файлам и raw-устройствам через shell-команды
        if base_bin not in _NO_FILE_READ_COMMANDS:
            candidate_paths: list[str] = []
            for raw_arg in atom.arguments:
                arg_str = str(raw_arg)
                candidate_paths.append(arg_str)
                if "=" in arg_str:
                    _, rhs = arg_str.split("=", 1)
                    if rhs:
                        candidate_paths.append(rhs)
            for flag_val in flags_dict.values():
                if isinstance(flag_val, str) and flag_val:
                    candidate_paths.append(flag_val)
            for redir in atom.redirects:
                redir_target = re.sub(r"^(?:\d*>>?|\d*<|&>>?|>&\d+)\s*", "", str(redir)).strip().strip("'\"")
                if redir_target:
                    candidate_paths.append(redir_target)
            for candidate in candidate_paths:
                forbidden_path = _match_forbidden_read_path(candidate)
                if forbidden_path is not None:
                    return _pick(
                        ActionRiskTier.TIER_3_FORBIDDEN,
                        f"Accessing sensitive credential, key, or device path {forbidden_path!r} is forbidden",
                    )

        # Проверка опасных перенаправлений в сырых устройствах/защищённых файлах в аргументах
        if CommandASTParser._is_atomic_destructive(atom):
            return _pick(
                ActionRiskTier.TIER_2_DESTRUCTIVE,
                f"Destructive operation ({base_bin}{f' {sub}' if sub else ''})",
            )

        if base_bin in ("iptables", "ip6tables") and any(
            k in ("-F", "-X", "-Z", "--flush", "--delete-chain") for k in flags_dict
        ):
            return _pick(ActionRiskTier.TIER_2_DESTRUCTIVE, "Destructive firewall rule modification or flush")

        if base_bin in ("passwd", "chage") and (base_bin == "chage" or "-l" in flags_dict):
            return _pick(ActionRiskTier.TIER_2_DESTRUCTIVE, "Deleting or locking system user/group accounts")

        special = cls._classify_special_binary(base_bin, sub, atom.arguments, args_lower, flags_dict)
        if special is not None:
            return _pick(special[0], special[1])

        if base_bin in _MUTATING_EXECUTABLES:
            return _pick(ActionRiskTier.TIER_1_MUTATING, f"Mutating command ({base_bin})")

        if base_bin in _SAFE_COMMANDS or (base_bin == "tee" and best_tier != ActionRiskTier.TIER_0_SAFE):
            msg = "" if (base_bin == "tee" and reasons) else f"Safe read-only command ({base_bin})"
            return _pick(ActionRiskTier.TIER_0_SAFE, msg)

        if effective_sudo:
            return _pick(
                ActionRiskTier.TIER_2_DESTRUCTIVE,
                f"Unrecognized command ({base_bin!r}) executed with sudo privileges",
            )
        return _pick(
            ActionRiskTier.TIER_1_MUTATING,
            f"Unrecognized or potentially mutating command ({base_bin!r})",
        )

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

        if (
            norm_path in ("/", "/etc/sudoers")
            or norm_path in _FORBIDDEN_READ_EXACT
            or norm_path.startswith((*_FORBIDDEN_FILE_PREFIXES, "/etc/sudoers.d/"))
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
    def classify_file_read(
        cls,
        path: str,
        *,
        is_production: bool = False,
        policy: HITLPolicy | None = None,
    ) -> RiskAssessment:
        """Оценить уровень риска чтения файла (uniconn_read_file)."""
        del policy
        norm_path = _resolve_normalized_write_path(path)
        if _match_forbidden_read_path(path) is not None:
            return RiskAssessment(
                risk_tier=ActionRiskTier.TIER_3_FORBIDDEN,
                reasons=(f"Reading sensitive credential, key, or device path {norm_path!r} is forbidden",),
                is_production=is_production,
                requires_approval=False,
            )
        return RiskAssessment(
            risk_tier=ActionRiskTier.TIER_0_SAFE,
            reasons=(f"Read-only file access ({norm_path!r})",),
            is_production=is_production,
            requires_approval=False,
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
        if tool_name == "uniconn_read_file":
            path = str(arguments.get("path") or "")
            return cls.classify_file_read(
                path,
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
