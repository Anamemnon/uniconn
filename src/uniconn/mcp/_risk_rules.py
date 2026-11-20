# src/uniconn/mcp/_risk_rules.py
"""Статические таблицы рисков, паттерны и вспомогательные функции для ActionRiskClassifier."""

from __future__ import annotations

import difflib
import re
from typing import Any

from .._logging import SecretMaskingFilter
from ..hooks import DEFAULT_BLOCKED_PATTERNS
from ..security.ast_parser import CommandASTParser, normalize_target_path

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
    (re.compile(r"\b(?:rm|rmdir|unlink|shred|truncate)\b"), "File or directory deletion/truncation command"),
    (re.compile(r"\bfind\b.*\s-(?:delete|exec\s+rm\b)"), "Recursive file deletion via find"),
    (re.compile(r"\bxargs\b.*\brm\b"), "Piped batch deletion via xargs rm"),
    (
        re.compile(r"\bsystemctl\b(?:\s+-[a-zA-Z0-9_-]+)*\s+(?:stop|disable|mask|kill|poweroff|reboot|halt)\b"),
        "Stopping, disabling, or masking a system service via systemctl",
    ),
    (re.compile(r"\bservice\s+\S+\s+(?:stop|force-reload)\b"), "Stopping a system service"),
    (re.compile(r"\b(?:kill|pkill|killall)\b"), "Terminating running system processes"),
    (
        re.compile(
            r"\b(?:iptables|ip6tables)\s+(?:-[a-zA-Z]*[FXZ]|--flush|--delete-chain)\b"
            r"|\bufw\s+(?:disable|reset|delete|deny|reject)\b|\bnft\s+flush\b"
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
    (re.compile(r"\b(?:userdel|groupdel|passwd\s+-l|chage)\b"), "Deleting or locking system user/group accounts"),
    (re.compile(r"\bcrontab\s+-r\b"), "Removing scheduled cron jobs"),
    (re.compile(r"\b(?:reboot|init\s+[06]|telinit\s+[06])\b"), "System reboot or runlevel change"),
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
    (re.compile(r"\bservice\s+\S+\s+(?:start|restart|reload)\b"), "Starting or restarting a system service"),
    (
        re.compile(
            r"\b(?:apt|apt-get|dpkg|yum|dnf|apk|pacman|zypper|pip|uv|npm)\b.*\b(?:install|update|upgrade|add|sync)\b"
        ),
        "Installing or updating packages",
    ),
    (
        re.compile(r"\b(?:useradd|adduser|usermod|groupadd|sysctl\s+-w)\b"),
        "Modifying system users, groups, or kernel parameters",
    ),
    (re.compile(r"\bsed\b.*\s-i\b|\bpatch\b"), "In-place file editing"),
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
    (re.compile(r"(?:>>?|\|\s*tee\b)\s*(?!/dev/null\b)\S+"), "Shell output redirection to file"),
)

_SAFE_COMMANDS: frozenset[str] = frozenset(
    {
        "ls", "dir", "cat", "head", "tail", "less", "more", "grep", "egrep", "fgrep", "rg", "wc",
        "sort", "uniq", "cut", "tr", "df", "du", "free", "uptime", "uname", "hostname", "hostnamectl",
        "whoami", "id", "groups", "w", "who", "last", "ps", "pgrep", "pidof", "lsof", "lsblk", "lscpu",
        "lspci", "lsusb", "lsmod", "blkid", "mount", "findmnt", "stat", "file", "readlink", "realpath",
        "dirname", "basename", "which", "whereis", "type", "pwd", "date", "timedatectl", "locale",
        "env", "printenv", "echo", "printf", "true", "false", "test", "[", "md5sum", "sha1sum",
        "sha256sum", "sha512sum", "cksum", "ping", "ping6", "traceroute", "tracepath", "mtr", "dig",
        "nslookup", "host", "whois", "ss", "netstat", "ip", "ifconfig", "route", "arp", "ethtool",
        "journalctl", "dmesg", "vmstat", "iostat", "mpstat", "sar", "nproc", "getent", "getconf", "sysctl",
    }
)

_PROTECTED_PATH_PREFIXES: tuple[str, ...] = (
    "/etc/", "/boot/", "/usr/", "/var/lib/", "/root/", "/sbin/", "/bin/", "/lib/", "/lib64/", "/proc/sys/", "/sys/",
)
_FORBIDDEN_FILE_PREFIXES: tuple[str, ...] = (
    "/dev/sd", "/dev/vd", "/dev/nvme", "/dev/xvd", "/proc/sysrq-trigger", "/proc/kcore",
)
_FORBIDDEN_READ_EXACT: frozenset[str] = frozenset(
    {
        "/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/master.passwd", "/etc/security/opasswd",
        "/dev/mem", "/dev/kmem", "/dev/port", "/proc/kcore", "/proc/kmem",
    }
)
_FORBIDDEN_READ_PREFIXES: tuple[str, ...] = (
    *_FORBIDDEN_FILE_PREFIXES, "/etc/sudoers.d/", "/var/run/secrets/", "/run/secrets/",
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

_PS_FORBIDDEN_CMDLETS: frozenset[str] = frozenset(
    {"format-volume", "clear-disk", "initialize-disk", "remove-partition", "invoke-expression"}
)
_PS_DESTRUCTIVE_CMDLETS: frozenset[str] = frozenset(
    {
        "remove-item", "remove-itemproperty", "clear-content", "clear-item", "clear-eventlog",
        "stop-computer", "restart-computer", "stop-service", "remove-service", "stop-process",
        "disable-netfirewallrule", "remove-netfirewallrule", "disable-windowsoptionalfeature",
        "uninstall-windowsfeature", "remove-localuser", "remove-localgroupmember",
        "remove-aduser", "remove-adcomputer", "set-executionpolicy",
    }
)
_PS_MUTATING_CMDLETS: frozenset[str] = frozenset(
    {
        "set-content", "add-content", "out-file", "set-itemproperty", "new-item", "new-itemproperty",
        "copy-item", "move-item", "rename-item", "start-service", "restart-service", "set-service",
        "start-process", "enable-netfirewallrule", "new-netfirewallrule", "enable-windowsoptionalfeature",
        "install-windowsfeature", "install-module", "install-package", "new-localuser",
        "set-localuser", "add-localgroupmember", "invoke-webrequest", "invoke-restmethod",
    }
)
_PS_SAFE_CMDLETS: frozenset[str] = frozenset(
    {
        "get-process", "get-service", "get-childitem", "get-content", "get-date", "get-location",
        "get-item", "get-itemproperty", "get-host", "get-computerinfo", "get-ciminstance",
        "get-wmiobject", "get-netipaddress", "get-netadapter", "get-netroute", "get-nettcpconnection",
        "get-netfirewallrule", "get-eventlog", "get-winevent", "get-volume", "get-disk", "get-psdrive",
        "get-localuser", "get-localgroup", "get-acl", "get-filehash", "get-hotfix", "get-module",
        "write-output", "write-host", "test-connection", "test-netconnection", "test-path",
        "select-object", "where-object", "sort-object", "group-object", "measure-object",
        "format-table", "format-list", "convertto-json", "convertfrom-json", "out-string", "select-string",
    }
)
_PS_CRITICAL_ROOT_RE = re.compile(r"^(?:[a-z]:[/\\]*|[a-z]:[/\\]+windows(?:[/\\].*)?|/+|\*)$", re.IGNORECASE)
_PS_CARRIER_BINARIES: frozenset[str] = frozenset({"powershell", "powershell.exe", "pwsh", "pwsh.exe"})
_WINDOWS_UTILITY_BINARIES: frozenset[str] = frozenset(
    {
        "reg", "reg.exe", "sc", "sc.exe", "net", "net.exe", "vssadmin", "vssadmin.exe",
        "bcdedit", "bcdedit.exe", "diskpart", "diskpart.exe", "del", "erase",
    }
)
_ALL_PS_DISPATCH_BINARIES: frozenset[str] = (
    _PS_FORBIDDEN_CMDLETS
    | _PS_DESTRUCTIVE_CMDLETS
    | _PS_MUTATING_CMDLETS
    | _PS_SAFE_CMDLETS
    | _WINDOWS_UTILITY_BINARIES
)

_MUTATING_EXECUTABLES: frozenset[str] = frozenset(
    {
        "mkdir", "touch", "cp", "mv", "ln", "install", "chmod", "chown", "chgrp",
        "chattr", "setfacl", "useradd", "adduser", "usermod", "groupadd", "patch",
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
_NO_FILE_READ_COMMANDS: frozenset[str] = frozenset({"echo", "printf", "true", "false", "write-output", "write-host"})
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
        difflib.unified_diff(old_lines, new_lines, fromfile=from_file, tofile=to_file, lineterm="")
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


def _collect_atom_candidate_paths(atom: Any) -> list[str]:
    """Собрать все пути из аргументов, флагов и редиректов атомарной команды."""
    candidate_paths: list[str] = []
    for raw_arg in atom.arguments:
        arg_str = str(raw_arg)
        candidate_paths.append(arg_str)
        if "=" in arg_str:
            _, rhs = arg_str.split("=", 1)
            if rhs:
                candidate_paths.append(rhs)
    for flag_val in atom.flags.values():
        if isinstance(flag_val, str) and flag_val:
            candidate_paths.append(flag_val)
    for redir in atom.redirects:
        redir_target = re.sub(r"^(?:\d*>>?|\d*<|&>>?|>&\d+)\s*", "", str(redir)).strip().strip("'\"")
        if redir_target:
            candidate_paths.append(redir_target)
    return candidate_paths
