# src/uniconn/security/_ast_rules.py
"""Таблицы бинарников, нормализация путей и детекторы обфускации для CommandASTParser."""

from __future__ import annotations

import base64
import binascii
import posixpath
import re

_WRAPPER_BINARIES: frozenset[str] = frozenset(
    {
        "sudo",
        "doas",
        "pkexec",
        "su",
        "runuser",
        "chroot",
        "nsenter",
        "watch",
        "strace",
        "ltrace",
        "env",
        "nohup",
        "nice",
        "time",
        "stdbuf",
        "chrt",
        "ionice",
        "taskset",
        "setsid",
        "busybox",
    }
)
_SHELL_BINARIES: frozenset[str] = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash", "csh", "tcsh"})
_INLINE_SCRIPT_BINS: dict[str, tuple[str, ...]] = {
    "python": ("-c",),
    "python2": ("-c",),
    "python3": ("-c",),
    "perl": ("-e", "-E"),
    "ruby": ("-e",),
    "node": ("-e", "--eval", "-p", "--print"),
    "nodejs": ("-e", "--eval"),
    "php": ("-r",),
    "lua": ("-e",),
}

_SUDO_OPTS_WITH_ARG: frozenset[str] = frozenset(
    {"-u", "-g", "-C", "-D", "-R", "-T", "-U", "-h", "-p", "-r", "-t", "-L", "--user"}
)
_WRAPPER_OPTS_WITH_ARG: dict[str, frozenset[str]] = {
    "watch": frozenset({"-n", "--interval", "-d", "--differences"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "ionice": frozenset({"-c", "--class", "-n", "--classdata", "-p", "--pid", "-P", "-u"}),
    "taskset": frozenset({"-c", "--cpu-list"}),
    "stdbuf": frozenset({"-i", "--input", "-o", "--output", "-e", "--error"}),
    "strace": frozenset({"-e", "-o", "-p", "-s", "-u", "-E"}),
    "ltrace": frozenset({"-e", "-o", "-p", "-s", "-u", "-l"}),
    "nsenter": frozenset({"-t", "--target", "-F"}),
}
_XARGS_OPTS_WITH_ARG: frozenset[str] = frozenset(
    {"-a", "--arg-file", "-d", "--delimiter", "-E", "-e", "-I", "-i", "-L", "-l", "-n", "-P", "-s"}
)
_OPTS_WITH_ARG_BY_BIN: dict[str, frozenset[str]] = {
    "systemctl": frozenset(
        {"-h", "--host", "-m", "-M", "--machine", "--root", "-t", "--type", "--state", "-p", "--property", "-n", "-o"}
    ),
    "git": frozenset({"-c", "-C", "--git-dir", "--work-tree", "--namespace"}),
    "docker": frozenset({"-h", "--host", "-c", "--context", "--config", "-l", "--log-level"}),
    "podman": frozenset({"--url", "--context", "--root", "--runroot", "--log-level"}),
    "kubectl": frozenset(
        {"-n", "--namespace", "--context", "--kubeconfig", "--cluster", "--user", "-s", "--server", "-l", "-o"}
    ),
    "ip": frozenset({"-n", "-netns", "-V", "-rc", "-b", "-batch"}),
    "service": frozenset(),
}

_TRAVERSAL_SYSTEM_ROOTS: tuple[str, ...] = (
    "etc/",
    "boot/",
    "root/",
    "proc/",
    "sys/",
    "dev/",
    "usr/",
    "lib/",
    "lib64/",
    "sbin/",
    "bin/",
    "var/",
)
_WIN_DRIVE_PATH_RE = re.compile(r"^([A-Za-z]:)(.*)$")


def _resolve_relative_system_traversal(norm_rel: str) -> str | None:
    """Распознать относительный путь вида ``../../etc/shadow`` или ``../Windows/...``."""
    rel_tail = norm_rel
    while rel_tail.startswith(("../", "./")):
        rel_tail = rel_tail[3:] if rel_tail.startswith("../") else rel_tail[2:]
    rel_tail = rel_tail.lstrip("/")
    if not rel_tail:
        return None
    if any(rel_tail == root.rstrip("/") or rel_tail.startswith(root) for root in _TRAVERSAL_SYSTEM_ROOTS):
        return "/" + rel_tail
    rel_lower = rel_tail.lower()
    if rel_lower == "windows" or rel_lower.startswith("windows/"):
        return "/" + rel_tail
    return None


def normalize_target_path(raw_path: str) -> str:
    """Нормализовать целевой путь (POSIX/Windows/``~``) для защиты от path traversal."""
    cleaned = raw_path.strip().replace("\\", "/")
    if not cleaned:
        return ""

    if cleaned.startswith(("//?/", "//./", "/??/")):
        tail = cleaned[4:]
        cleaned = "//" + tail[4:] if tail[:4].lower() == "unc/" else tail

    if cleaned.startswith("~"):
        norm_tilde = posixpath.normpath(cleaned)
        if norm_tilde.startswith("~"):
            return norm_tilde
        cleaned = norm_tilde

    drive_match = _WIN_DRIVE_PATH_RE.match(cleaned)
    if drive_match is not None:
        drive, rest = drive_match.groups()
        if not rest:
            return f"{drive}/"
        if rest.startswith("/") or ".." in rest.split("/"):
            norm_rest = posixpath.normpath("/" + rest.lstrip("/"))
            return f"{drive}{norm_rest}"
        return f"{drive}{posixpath.normpath(rest)}"

    norm = posixpath.normpath(cleaned)
    if cleaned.startswith("/"):
        if norm.startswith("//"):
            return "/" + norm.lstrip("/")
        return norm

    resolved_traversal = _resolve_relative_system_traversal(norm)
    if resolved_traversal is not None:
        return posixpath.normpath(resolved_traversal)
    return norm


_DESTRUCTIVE_EXECUTABLES: frozenset[str] = frozenset(
    {
        "rm",
        "rmdir",
        "unlink",
        "shred",
        "truncate",
        "wipefs",
        "mkfs",
        "fdisk",
        "parted",
        "sfdisk",
        "gdisk",
        "dd",
        "kill",
        "pkill",
        "killall",
        "reboot",
        "shutdown",
        "poweroff",
        "halt",
        "init",
        "telinit",
        "userdel",
        "groupdel",
        "dropdb",
    }
)
_DESTRUCTIVE_SUBCOMMANDS: dict[str, frozenset[str]] = {
    "systemctl": frozenset({"stop", "disable", "mask", "kill", "poweroff", "reboot", "halt", "isolate"}),
    "service": frozenset({"stop", "force-reload"}),
    "docker": frozenset({"rm", "rmi", "stop", "kill", "prune"}),
    "podman": frozenset({"rm", "rmi", "stop", "kill", "prune"}),
    "kubectl": frozenset({"delete", "drain", "cordon", "taint"}),
    "ufw": frozenset({"disable", "reset", "delete", "deny", "reject"}),
    "nft": frozenset({"flush", "delete", "destroy"}),
    "ip": frozenset({"del", "delete", "flush"}),
    "apt": frozenset({"remove", "purge", "autoremove"}),
    "apt-get": frozenset({"remove", "purge", "autoremove"}),
    "dnf": frozenset({"remove", "erase", "autoremove"}),
    "yum": frozenset({"remove", "erase", "autoremove"}),
    "apk": frozenset({"del"}),
    "pacman": frozenset({"-r", "-rs", "-rns", "--remove"}),
    "zypper": frozenset({"rm", "remove"}),
    "helm": frozenset({"uninstall", "delete"}),
}

_SUBSHELL_RE = re.compile(r"(?<!\$)\$\((?!\()([^()]+)\)|`([^`]+)`")
_REDIRECT_RE = re.compile(r"(?:\d*>>?|\d*<(?!<<)|&>>?|>&\d+)\s*(\S+)?")
_BASE64_PIPE_RE = re.compile(
    r"(?:echo|printf)\s+(?:-[eEn]+\s+)*(['\"]?)([A-Za-z0-9+/=]{6,})\1\s*\|\s*"
    r"(?:base64\s+(?:-[A-Za-z]+\s+)*(?:-d|--decode|-D)|openssl\s+enc\s+-d\s+-base64)",
    re.IGNORECASE,
)
_BASE64_HERESTRING_RE = re.compile(
    r"(?:base64\s+(?:-[A-Za-z]+\s+)*(?:-d|--decode|-D)|openssl\s+enc\s+-d\s+-base64)"
    r"\s*<<<\s*(['\"]?)([A-Za-z0-9+/=]{6,})\1",
    re.IGNORECASE,
)
_HEX_ESCAPE_RE = re.compile(r"\\x[0-9a-fA-F]{2}|\\[0-7]{3}")
_ANSI_C_QUOTE_RE = re.compile(r"\$'([^']*)'")
_VAR_CONCAT_EXEC_RE = re.compile(r"^(?:\$\{?[A-Za-z_]\w*\}?){2,}$|^\$\{?[A-Za-z_]\w*\}?$")
_GLOB_OBFUSCATED_BIN_RE = re.compile(r"^/(?:usr/)?(?:s?bin)/.*[?*\[\]].*$")
_INLINE_DESTRUCTIVE_RE = re.compile(
    r"\b(?:shutil\.rmtree|os\.(?:remove|unlink|rmdir|system|popen|exec\w*|spawn\w*)"
    r"|subprocess\.(?:run|Popen|call|check_call|check_output)"
    r"|pty\.spawn|pathlib\.Path\([^)]*\)\.unlink|FileUtils\.rm_rf"
    r"|fs\.(?:rmSync|unlinkSync|rmdirSync)|child_process\.exec"
    r"|system\s*\(|exec\s*\(|eval\s*\(|base64\.b64decode)\b"
)
_SQL_DESTRUCTIVE_RE = re.compile(
    r"\b(?:DROP\s+(?:DATABASE|TABLE|SCHEMA)|TRUNCATE\s+TABLE|DELETE\s+FROM)\b",
    re.IGNORECASE,
)
_IFS_EXPAND_RE = re.compile(r"^\$(?:\{IFS(?:[^A-Za-z0-9_}]|\})|IFS(?![A-Za-z0-9_]))")


def _decode_ansi_c_escapes(raw: str) -> str:
    r"""Раскодировать последовательности \xHH и \OOO внутри строк для выявления скрытых команд."""

    def _replace_hex(m: re.Match[str]) -> str:
        try:
            return chr(int(m.group(0)[2:], 16))
        except ValueError:
            return m.group(0)

    def _replace_oct(m: re.Match[str]) -> str:
        try:
            return chr(int(m.group(0)[1:], 8))
        except ValueError:
            return m.group(0)

    step1 = re.sub(r"\\x[0-9a-fA-F]{2}", _replace_hex, raw)
    return re.sub(r"\\[0-7]{3}", _replace_oct, step1)


def _is_quote_spliced_token(raw_token: str) -> bool:
    r"""Проверить, содержит ли сырой токен исполняемого файла обфускацию кавычками/бэкслешами.

    Чисто закавыченный целиком путь вроде ``"/usr/bin/ls"`` или ``'/bin/echo'`` НЕ считается
    обфускацией, тогда как ``r'm'``, ``'r'm``, ``"r"m`` или ``r\m`` распознаются как склейка.
    """
    tok = raw_token.strip()
    if not tok or tok.startswith(("-", "$", "(")) or "=" in tok:
        return False
    if len(tok) >= 2 and tok[0] in ("'", '"') and tok[-1] == tok[0]:
        inner = tok[1:-1]
        if not any(c in inner for c in ("'", '"', "\\")):
            return False
    return any(c in tok for c in ("'", '"', "\\"))


def _contains_unquoted_ifs(raw: str) -> bool:
    """Проверить наличие раскрытия ``$IFS`` или ``${IFS}`` вне одинарных и двойных кавычек."""
    in_single = False
    in_double = False
    escape = False
    i = 0
    n = len(raw)
    while i < n:
        ch = raw[i]
        if escape:
            escape = False
            i += 1
            continue
        if ch == "\\" and not in_single:
            escape = True
            i += 1
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            i += 1
            continue
        if not in_single and not in_double and ch == "$" and _IFS_EXPAND_RE.match(raw[i:]):
            return True
        i += 1
    return False


def _has_brace_expansion(raw_word: str) -> bool:
    """Проверить наличие bash-раскрытия фигурных скобок ``{a,b}`` вне кавычек и ``${...}``."""
    if "{" not in raw_word or "}" not in raw_word:
        return False
    in_single = False
    in_double = False
    escape = False
    brace_has_comma: list[bool] = []
    i = 0
    n = len(raw_word)
    while i < n:
        ch = raw_word[i]
        if escape:
            escape = False
            i += 1
            continue
        if ch == "\\" and not in_single:
            escape = True
            i += 1
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            i += 1
            continue
        if not in_single and not in_double:
            if ch == "{":
                prev_unescaped = i > 0 and raw_word[i - 1] == "$" and not (i > 1 and raw_word[i - 2] == "\\")
                if not prev_unescaped:
                    brace_has_comma.append(False)
            elif ch == "," and brace_has_comma:
                brace_has_comma[-1] = True
            elif ch == "}" and brace_has_comma and brace_has_comma.pop():
                return True
        i += 1
    return False


def _split_raw_shell_words(segment: str) -> list[str]:
    """Разбить сегмент на сырые слова (сохраняя кавычки и бэкслеши) синхронно с shlex."""
    words: list[str] = []
    buf: list[str] = []
    in_single = False
    in_double = False
    escape = False
    for ch in segment:
        if escape:
            buf.append(ch)
            escape = False
            continue
        if ch == "\\" and not in_single:
            buf.append(ch)
            escape = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            buf.append(ch)
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            buf.append(ch)
            continue
        if ch.isspace() and not in_single and not in_double:
            if buf:
                words.append("".join(buf))
                buf.clear()
            continue
        buf.append(ch)
    if buf:
        words.append("".join(buf))
    return words


def extract_base64_payloads(raw: str) -> list[str]:
    """Раскодировать явные base64-строки (из пайпов и <<< here-string) для глубокого AST-анализа."""
    decoded_list: list[str] = []
    for pattern in (_BASE64_PIPE_RE, _BASE64_HERESTRING_RE):
        for match in pattern.finditer(raw):
            b64_token = match.group(2).strip()
            try:
                padded = b64_token + "=" * ((4 - len(b64_token) % 4) % 4)
                raw_bytes = base64.b64decode(padded, validate=False)
                text = raw_bytes.decode("utf-8", errors="ignore").strip()
                if (
                    text
                    and text not in decoded_list
                    and all(31 < ord(c) < 127 or c in "\n\r\t" for c in text)
                ):
                    decoded_list.append(text)
            except (binascii.Error, ValueError):
                continue
    return decoded_list


def detect_global_obfuscation(raw: str, reasons: list[str]) -> None:
    """Проверить глобальные признаки обфускации на уровне сырой командной строки."""
    if _HEX_ESCAPE_RE.search(raw):
        decoded_preview = _decode_ansi_c_escapes(raw)
        reasons.append(f"Hex or octal escape sequences detected in command ({decoded_preview[:60]!r})")
    for ansi_match in _ANSI_C_QUOTE_RE.finditer(raw):
        inner = ansi_match.group(1)
        if "\\x" in inner or re.search(r"\\[0-7]{2,3}", inner):
            reasons.append("ANSI-C quoting ($'...') with encoded characters detected")
            break
    if _contains_unquoted_ifs(raw):
        msg = "Shell $IFS variable delimiter obfuscation detected"
        if msg not in reasons:
            reasons.append(msg)
