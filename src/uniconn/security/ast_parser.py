# src/uniconn/security/ast_parser.py
"""Синтаксический анализатор shell-команд (CommandASTParser) и детектор обфускации.

Выполняет глубокую декомпозицию командных строк в дерево атомарных вызовов
(AtomicCommand / ParsedCommandAST), раскрывает косвенные обёртки (sudo, env,
timeout, sh -c, find -exec, xargs, docker/kubectl exec), инспектирует
инлайн-скрипты (python -c, perl -e, ruby -e, node -e, awk) и выявляет техники
обхода регулярных выражений (base64, hex/octal printf, eval, склейка переменных).
"""

from __future__ import annotations

import base64
import binascii
import os
import posixpath
import re
import shlex
from dataclasses import dataclass, field
from typing import Any

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
        {"-h", "--host", "-m", "--machine", "--root", "-t", "--type", "--state", "-p", "--property", "-n", "-o"}
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


def normalize_target_path(raw_path: str) -> str:
    """Нормализовать POSIX-путь (схлопнуть ``//``, ``/./`` и ``/../``) для защиты от path traversal."""
    cleaned = raw_path.strip().replace("\\", "/")
    if not cleaned or cleaned.startswith("~"):
        return cleaned
    if cleaned.startswith(("../", "./")):
        rel_tail = cleaned
        while rel_tail.startswith(("../", "./")):
            rel_tail = rel_tail[3:] if rel_tail.startswith("../") else rel_tail[2:]
        rel_tail = rel_tail.lstrip("/")
        if any(
            rel_tail == root.rstrip("/") or rel_tail.startswith(root)
            for root in _TRAVERSAL_SYSTEM_ROOTS
        ):
            cleaned = "/" + rel_tail
    norm = posixpath.normpath(cleaned)
    if cleaned.startswith("/") and norm.startswith("//"):
        norm = "/" + norm.lstrip("/")
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


@dataclass(frozen=True, slots=True)
class AtomicCommand:
    """Атомарная команда внутри конвейера, цепочки или косвенной обёртки."""

    executable: str
    raw_executable: str = ""
    subcommand: str | None = None
    arguments: tuple[str, ...] = ()
    flags: dict[str, str | bool] = field(default_factory=dict)
    env_assignments: dict[str, str] = field(default_factory=dict)
    redirects: tuple[str, ...] = ()
    wrappers: tuple[str, ...] = ()
    is_sudo: bool = False
    is_obfuscated: bool = False
    subshell_depth: int = 0

    @property
    def args(self) -> tuple[str, ...]:
        """Алиас позиционных аргументов команды."""
        return self.arguments

    def to_dict(self) -> dict[str, Any]:
        """Сериализовать атомарную команду в JSON-совместимый словарь."""
        return {
            "executable": self.executable,
            "raw_executable": self.raw_executable or self.executable,
            "subcommand": self.subcommand,
            "arguments": list(self.arguments),
            "args": list(self.arguments),
            "flags": dict(self.flags),
            "env_assignments": dict(self.env_assignments),
            "redirects": list(self.redirects),
            "wrappers": list(self.wrappers),
            "is_sudo": self.is_sudo,
            "is_obfuscated": self.is_obfuscated,
            "subshell_depth": self.subshell_depth,
        }


@dataclass(frozen=True, slots=True)
class ParsedCommandAST:
    """Синтаксическое дерево (AST) разобранной shell-команды."""

    raw_command: str
    atomic_commands: tuple[AtomicCommand, ...] = ()
    executables: tuple[str, ...] = ()
    subcommands: tuple[str, ...] = ()
    target_paths: tuple[str, ...] = ()
    has_pipes: bool = False
    has_subshells: bool = False
    has_background_ops: bool = False
    has_inline_script: bool = False
    has_destructive_verbs: bool = False
    is_obfuscated: bool = False
    obfuscation_reasons: tuple[str, ...] = ()
    complexity_exceeded: bool = False
    max_depth: int = 0

    @property
    def commands(self) -> tuple[AtomicCommand, ...]:
        """Алиас списка атомарных команд ``atomic_commands``."""
        return self.atomic_commands

    @property
    def verbs(self) -> tuple[str, ...]:
        """Алиас списка исполняемых бинарников ``executables``."""
        return self.executables

    @property
    def pipeline_length(self) -> int:
        """Общее число атомарных команд в цепочке или пайплайне."""
        return len(self.atomic_commands)

    def to_dict(self) -> dict[str, Any]:
        """Сериализовать дерево команды в формат контекстного документа авторизации."""
        serialized_cmds = [cmd.to_dict() for cmd in self.atomic_commands]
        return {
            "raw_command": self.raw_command,
            "executables": list(self.executables),
            "verbs": list(self.executables),
            "subcommands": list(self.subcommands),
            "targets": list(self.target_paths),
            "target_paths": list(self.target_paths),
            "has_pipes": self.has_pipes,
            "has_subshells": self.has_subshells,
            "has_background_ops": self.has_background_ops,
            "has_inline_script": self.has_inline_script,
            "has_destructive_verbs": self.has_destructive_verbs,
            "is_obfuscated": self.is_obfuscated,
            "obfuscation_reasons": list(self.obfuscation_reasons),
            "complexity_exceeded": self.complexity_exceeded,
            "pipeline_length": len(self.atomic_commands),
            "max_depth": self.max_depth,
            "atomic_commands": serialized_cmds,
            "commands": serialized_cmds,
        }


class CommandASTParser:
    """Детерминированный синтаксический анализатор shell-команд для Policy-as-Code Guardrails."""

    MAX_COMMAND_LENGTH: int = 4096
    MAX_SEGMENTS: int = 64
    MAX_RECURSION_DEPTH: int = 6

    @classmethod
    def parse(
        cls,
        command: str,
        *,
        sudo: bool = False,
        max_depth: int | None = None,
        max_pipeline_length: int | None = None,
    ) -> ParsedCommandAST:
        """Разобрать shell-строку в иерархическую структуру ``ParsedCommandAST``."""
        raw = command.strip()
        if not raw:
            return ParsedCommandAST(raw_command="")

        eff_max_depth = max_depth if max_depth is not None else cls.MAX_RECURSION_DEPTH
        eff_max_segments = max_pipeline_length if max_pipeline_length is not None else cls.MAX_SEGMENTS

        complexity_exceeded = len(raw) > cls.MAX_COMMAND_LENGTH or raw.count("\n") > 50
        obfuscation_reasons: list[str] = []
        atomic_list: list[AtomicCommand] = []
        has_inline_script = False

        segments, has_pipes, has_bg = cls._tokenize_top_level_segments(raw)
        if len(segments) > eff_max_segments:
            complexity_exceeded = True
            segments = segments[:eff_max_segments]

        probe_no_arith = re.sub(r"\$\(\(.*?\)\)", "0", raw)
        sub_cmds_with_depth = cls._extract_subshell_commands(probe_no_arith)
        has_subshells = bool(sub_cmds_with_depth)

        cls._detect_global_obfuscation(raw, obfuscation_reasons)

        # Раскрываем base64-пайплайны в памяти, чтобы увидеть спрятанную команду
        decoded_payloads = cls._extract_base64_payloads(raw)
        for dec_cmd in decoded_payloads:
            reason = f"Base64-encoded command payload detected ({dec_cmd!r})"
            if reason not in obfuscation_reasons:
                obfuscation_reasons.append(reason)

        # Отслеживаем присваивания однобуквенных/коротких переменных для склейки (C1="r"; C2="m"; $C1$C2)
        var_table: dict[str, str] = {}

        work_queue: list[tuple[str, tuple[str, ...], bool, int]] = [
            (seg, (), sudo, 0) for seg in segments
        ]
        for dec_cmd in decoded_payloads:
            work_queue.append((dec_cmd, ("base64 -d",), sudo, 1))

        # Добавляем команды из $(...) и `...` с учётом глубины вложенности
        for sub_c, sub_depth in sub_cmds_with_depth:
            for sub_dec in cls._extract_base64_payloads(sub_c):
                reason = f"Base64-encoded command payload detected ({sub_dec!r})"
                if reason not in obfuscation_reasons:
                    obfuscation_reasons.append(reason)
                work_queue.append((sub_dec, ("subshell", "base64 -d"), sudo, sub_depth + 1))
            sub_segs, sub_p, sub_b = cls._tokenize_top_level_segments(sub_c)
            if sub_p:
                has_pipes = True
            if sub_b:
                has_bg = True
            for s_item in sub_segs:
                work_queue.append((s_item, ("subshell",), sudo, sub_depth))

        observed_max_depth = 0
        idx = 0
        while idx < len(work_queue):
            seg_str, inherited_wrappers, inherited_sudo, depth = work_queue[idx]
            idx += 1
            observed_max_depth = max(observed_max_depth, depth)
            if depth > eff_max_depth:
                complexity_exceeded = True
                continue

            parsed_atoms, nested_cmds, inline_flag = cls._parse_single_segment(
                seg_str,
                inherited_wrappers=inherited_wrappers,
                inherited_sudo=inherited_sudo,
                var_table=var_table,
                obfuscation_reasons=obfuscation_reasons,
                subshell_depth=depth,
            )
            if inline_flag:
                has_inline_script = True
            atomic_list.extend(parsed_atoms)
            for nested_cmd_str, nested_wrap, nested_sudo in nested_cmds:
                sub_segs, sub_pipes, sub_bg = cls._tokenize_top_level_segments(nested_cmd_str)
                if sub_pipes:
                    has_pipes = True
                if sub_bg:
                    has_bg = True
                for s_item in sub_segs:
                    work_queue.append((s_item, nested_wrap, nested_sudo, depth + 1))

        if len(atomic_list) > eff_max_segments:
            complexity_exceeded = True

        # Проверяем пайплайны вида `... | sh` / `... | bash` / `... | python`
        interp_bins = _SHELL_BINARIES | set(_INLINE_SCRIPT_BINS.keys())
        feeder_bins = ("curl", "wget", "fetch", "base64", "xxd", "openssl", "printf", "echo")
        if has_pipes and len(atomic_list) >= 2:
            for pos in range(1, len(atomic_list)):
                prev_atom = atomic_list[pos - 1]
                curr_atom = atomic_list[pos]
                if (
                    curr_atom.executable in interp_bins
                    and not curr_atom.arguments
                    and prev_atom.executable in feeder_bins
                ):
                    r_msg = (
                        f"Piping output of {prev_atom.executable!r} directly into "
                        f"interpreter {curr_atom.executable!r}"
                    )
                    if r_msg not in obfuscation_reasons:
                        obfuscation_reasons.append(r_msg)

        is_obf = bool(obfuscation_reasons) or any(a.is_obfuscated for a in atomic_list)
        if is_obf:
            atomic_list = [
                AtomicCommand(
                    executable=a.executable,
                    raw_executable=a.raw_executable,
                    subcommand=a.subcommand,
                    arguments=a.arguments,
                    flags=a.flags,
                    env_assignments=a.env_assignments,
                    redirects=a.redirects,
                    wrappers=a.wrappers,
                    is_sudo=a.is_sudo,
                    is_obfuscated=bool(a.is_obfuscated),
                    subshell_depth=a.subshell_depth,
                )
                for a in atomic_list
            ]

        executables: list[str] = []
        subcommands: list[str] = []
        target_paths: list[str] = []
        has_destructive = bool(_SQL_DESTRUCTIVE_RE.search(raw))

        for atom in atomic_list:
            if atom.executable and atom.executable not in executables:
                executables.append(atom.executable)
            if atom.subcommand and atom.subcommand not in subcommands:
                subcommands.append(atom.subcommand)
            if cls._is_atomic_destructive(atom):
                has_destructive = True
            for p_candidate in cls._extract_paths_from_atomic(atom):
                if p_candidate not in target_paths:
                    target_paths.append(p_candidate)

        return ParsedCommandAST(
            raw_command=raw,
            atomic_commands=tuple(atomic_list),
            executables=tuple(executables),
            subcommands=tuple(subcommands),
            target_paths=tuple(target_paths),
            has_pipes=has_pipes,
            has_subshells=has_subshells,
            has_background_ops=has_bg,
            has_inline_script=has_inline_script,
            has_destructive_verbs=has_destructive,
            is_obfuscated=is_obf,
            obfuscation_reasons=tuple(obfuscation_reasons),
            complexity_exceeded=complexity_exceeded,
            max_depth=observed_max_depth,
        )

    @classmethod
    def _tokenize_top_level_segments(cls, command: str) -> tuple[list[str], bool, bool]:
        r"""Разбить командную строку по операторам (; && || | & \n) с учётом кавычек и скобок."""
        segments: list[str] = []
        buf: list[str] = []
        in_single = False
        in_double = False
        escape = False
        paren_depth = 0
        has_pipes = False
        has_bg = False
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
                if ch == "(":
                    paren_depth += 1
                    buf.append(ch)
                    i += 1
                    continue
                if ch == ")" and paren_depth > 0:
                    paren_depth -= 1
                    buf.append(ch)
                    i += 1
                    continue
                if paren_depth == 0:
                    if ch in (";", "\n"):
                        seg = "".join(buf).strip()
                        if seg:
                            segments.append(seg)
                        buf.clear()
                        i += 1
                        continue
                    if ch in ("&", "|"):
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
                        if ch == "|" and next_ch != "|":
                            has_pipes = True
                        if ch == "&" and next_ch != "&":
                            has_bg = True
                        i += 2 if next_ch == ch else 1
                        continue

            buf.append(ch)
            i += 1

        tail = "".join(buf).strip()
        if tail:
            segments.append(tail)
        return segments, has_pipes, has_bg

    @classmethod
    def _extract_subshell_commands(cls, probe_str: str, base_depth: int = 1) -> list[tuple[str, int]]:
        """Извлечь вложенные команды из $(...) и обратных кавычек `...` с учётом баланса скобок."""
        extracted: list[tuple[str, int]] = []
        seen: set[str] = set()

        def _scan(text: str, current_depth: int) -> None:
            if current_depth > cls.MAX_RECURSION_DEPTH + 1:
                return
            i = 0
            n = len(text)
            in_single = False
            escape = False
            while i < n:
                ch = text[i]
                if escape:
                    escape = False
                    i += 1
                    continue
                if ch == "\\" and not in_single:
                    escape = True
                    i += 1
                    continue
                if ch == "'":
                    in_single = not in_single
                    i += 1
                    continue
                if not in_single:
                    # Подстановка $(...) и process substitution <(...), >(...) с балансом скобок
                    if (
                        ch in ("$", "<", ">")
                        and i + 1 < n
                        and text[i + 1] == "("
                        and (ch == "$" or i == 0 or text[i - 1] not in ("<", ">"))
                    ):
                        if ch == "$" and i + 2 < n and text[i + 2] == "(":
                            i += 3
                            continue
                        p_depth = 1
                        j = i + 2
                        sub_single = False
                        sub_double = False
                        sub_esc = False
                        while j < n and p_depth > 0:
                            c2 = text[j]
                            if sub_esc:
                                sub_esc = False
                                j += 1
                                continue
                            if c2 == "\\" and not sub_single:
                                sub_esc = True
                                j += 1
                                continue
                            if c2 == "'" and not sub_double:
                                sub_single = not sub_single
                            elif c2 == '"' and not sub_single:
                                sub_double = not sub_double
                            elif not sub_single and not sub_double:
                                if c2 == "(":
                                    p_depth += 1
                                elif c2 == ")":
                                    p_depth -= 1
                            j += 1
                        inner = text[i + 2 : j - 1].strip() if p_depth == 0 else text[i + 2 :].strip()
                        if inner and inner not in seen:
                            seen.add(inner)
                            extracted.append((inner, current_depth))
                            _scan(inner, current_depth + 1)
                        i = j
                        continue
                    # Обратные кавычки `...`
                    if ch == "`":
                        j = i + 1
                        sub_esc = False
                        while j < n:
                            if sub_esc:
                                sub_esc = False
                                j += 1
                                continue
                            if text[j] == "\\":
                                sub_esc = True
                                j += 1
                                continue
                            if text[j] == "`":
                                break
                            j += 1
                        inner = text[i + 1 : j].strip()
                        if inner and inner not in seen:
                            seen.add(inner)
                            extracted.append((inner, current_depth))
                            _scan(inner, current_depth + 1)
                        i = j + 1
                        continue
                i += 1

        _scan(probe_str, base_depth)
        return extracted

    @classmethod
    def _extract_base64_payloads(cls, raw: str) -> list[str]:
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

    @classmethod
    def _detect_global_obfuscation(cls, raw: str, reasons: list[str]) -> None:
        """Проверить глобальные признаки обфускации на уровне сырой командной строки."""
        if _HEX_ESCAPE_RE.search(raw):
            decoded_preview = _decode_ansi_c_escapes(raw)
            reasons.append(f"Hex or octal escape sequences detected in command ({decoded_preview[:60]!r})")
        for ansi_match in _ANSI_C_QUOTE_RE.finditer(raw):
            inner = ansi_match.group(1)
            if "\\x" in inner or re.search(r"\\[0-7]{2,3}", inner):
                reasons.append("ANSI-C quoting ($'...') with encoded characters detected")
                break

    @classmethod
    def _parse_single_segment(
        cls,
        segment: str,
        *,
        inherited_wrappers: tuple[str, ...],
        inherited_sudo: bool,
        var_table: dict[str, str],
        obfuscation_reasons: list[str],
        subshell_depth: int = 0,
    ) -> tuple[list[AtomicCommand], list[tuple[str, tuple[str, ...], bool]], bool]:
        """Разобрать одиночный сегмент пайплайна/цепочки в AtomicCommand и список вложенных команд."""
        seg_clean = segment.strip()
        if not seg_clean or seg_clean.startswith("#"):
            return [], [], False

        # Извлекаем редиректы до shlex.split
        redirects: list[str] = []
        for redir_match in _REDIRECT_RE.finditer(seg_clean):
            full_redir = redir_match.group(0).strip()
            if full_redir:
                redirects.append(full_redir)

        segment_obf = False
        raw_words = _split_raw_shell_words(seg_clean)
        try:
            tokens = shlex.split(seg_clean, posix=True)
        except ValueError:
            tokens = seg_clean.split()

        if not tokens:
            return [], [], False

        env_assignments: dict[str, str] = {}
        wrappers: list[str] = list(inherited_wrappers)
        effective_sudo = inherited_sudo
        idx = 0
        n = len(tokens)

        # 1. Снимаем ведущие присваивания переменных окружения и обёртки (sudo, doas, pkexec, su, env, timeout...)
        while idx < n:
            tok = tokens[idx]
            if "=" in tok and not tok.startswith("-") and tok.split("=", 1)[0].isidentifier():
                k, v = tok.split("=", 1)
                env_assignments[k] = v
                var_table[k] = v
                if k in ("LD_PRELOAD", "LD_LIBRARY_PATH") or (
                    k == "PATH" and any(p.startswith(("/tmp", "/var/tmp", "/dev/shm", ".")) for p in v.split(":"))
                ):
                    segment_obf = True
                    msg = f"Suspicious environment hijack assignment ({k}={v!r})"
                    if msg not in obfuscation_reasons:
                        obfuscation_reasons.append(msg)
                idx += 1
                continue

            base_tok = os.path.basename(tok).lower()
            if base_tok in ("sudo", "doas", "pkexec"):
                effective_sudo = True
                wrappers.append(base_tok)
                idx += 1
                while idx < n and tokens[idx].startswith("-"):
                    opt = tokens[idx]
                    idx += 1
                    if opt == "--":
                        break
                    if opt in _SUDO_OPTS_WITH_ARG and idx < n:
                        idx += 1
                continue

            if base_tok in ("su", "runuser"):
                effective_sudo = True
                wrappers.append(base_tok)
                idx += 1
                while idx < n:
                    cur = tokens[idx]
                    if cur in ("-c", "--command") and idx + 1 < n:
                        return (
                            [],
                            [(tokens[idx + 1], (*wrappers, f"{base_tok} -c"), True)],
                            False,
                        )
                    if cur.startswith("--command="):
                        return (
                            [],
                            [(cur.split("=", 1)[1], (*wrappers, f"{base_tok} -c"), True)],
                            False,
                        )
                    if cur == "--":
                        idx += 1
                        break
                    if cur.startswith("-"):
                        idx += 2 if cur in ("-s", "--shell", "-u", "-g", "-G") and idx + 1 < n else 1
                        continue
                    # Имя целевого пользователя (например, `su root -c "..."`)
                    if idx + 1 < n and tokens[idx + 1].startswith("-"):
                        idx += 1
                        continue
                    break
                continue

            if base_tok == "chroot" and idx + 1 < n:
                wrappers.append("chroot")
                idx += 1
                while idx < n and tokens[idx].startswith("-"):
                    opt = tokens[idx]
                    idx += 1
                    if opt in ("--userspec", "--groups") and idx < n:
                        idx += 1
                if idx + 1 < n:
                    idx += 1  # Пропускаем NEWROOT перед исполняемой командой
                continue

            if base_tok == "env":
                wrappers.append("env")
                idx += 1
                while idx < n:
                    cur = tokens[idx]
                    if cur in ("-S", "--split-string") and idx + 1 < n:
                        return (
                            [],
                            [(tokens[idx + 1], (*wrappers, "env -S"), effective_sudo)],
                            False,
                        )
                    if cur.startswith("-"):
                        idx += 1
                        continue
                    if "=" in cur and cur.split("=", 1)[0].isidentifier():
                        ek, ev = cur.split("=", 1)
                        env_assignments[ek] = ev
                        var_table[ek] = ev
                        idx += 1
                        continue
                    break
                continue

            if base_tok == "timeout" and idx + 1 < n:
                wrappers.append("timeout")
                idx += 1
                while idx < n and tokens[idx].startswith("-"):
                    opt = tokens[idx]
                    idx += 1
                    if opt in ("-k", "--kill-after", "-s", "--signal") and idx < n:
                        idx += 1
                if idx < n:
                    idx += 1  # Пропускаем значение длительности
                continue

            if base_tok in _WRAPPER_BINARIES:
                wrappers.append(base_tok)
                w_opts = _WRAPPER_OPTS_WITH_ARG.get(base_tok, frozenset())
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
            return [], [], False

        raw_exec = remaining[0]
        raw_word_for_exec = raw_words[idx] if idx < len(raw_words) else raw_exec
        if _is_quote_spliced_token(raw_word_for_exec):
            segment_obf = True
            msg = f"Quote or backslash obfuscation inside executable token ({raw_word_for_exec!r})"
            if msg not in obfuscation_reasons:
                obfuscation_reasons.append(msg)

        # Подстановка известных переменных при склейке ($C1$C2 -> rm)
        resolved_exec = raw_exec
        if "$" in raw_exec:
            if _VAR_CONCAT_EXEC_RE.match(raw_exec):
                segment_obf = True
                msg = f"Dynamic variable expansion in executable name ({raw_exec!r})"
                if msg not in obfuscation_reasons:
                    obfuscation_reasons.append(msg)
            for vk, vv in var_table.items():
                resolved_exec = resolved_exec.replace(f"${{{vk}}}", vv).replace(f"${vk}", vv)

        if _GLOB_OBFUSCATED_BIN_RE.match(raw_exec):
            segment_obf = True
            msg = f"Wildcard glob obfuscation in system executable path ({raw_exec!r})"
            if msg not in obfuscation_reasons:
                obfuscation_reasons.append(msg)

        exec_name = os.path.basename(resolved_exec).lower() or resolved_exec.lower()
        rest = remaining[1:]

        # Проверка eval / base64 -d / xxd -r
        if exec_name == "eval":
            segment_obf = True
            eval_arg = " ".join(rest).strip()
            decoded_eval = _decode_ansi_c_escapes(eval_arg)
            msg = "Dynamic shell 'eval' execution is forbidden by AST guardrails"
            if msg not in obfuscation_reasons:
                obfuscation_reasons.append(msg)
            atom = AtomicCommand(
                executable="eval",
                raw_executable=raw_exec,
                arguments=tuple(rest),
                env_assignments=env_assignments,
                redirects=tuple(redirects),
                wrappers=tuple(wrappers),
                is_sudo=effective_sudo,
                is_obfuscated=True,
                subshell_depth=subshell_depth,
            )
            nested = [(decoded_eval, (*wrappers, "eval"), effective_sudo)] if decoded_eval else []
            return [atom], nested, False

        if exec_name == "base64" and any(a in ("-d", "--decode", "-D") for a in rest):
            segment_obf = True
            msg = "Base64 payload decoding (base64 -d) detected in command pipeline"
            if msg not in obfuscation_reasons:
                obfuscation_reasons.append(msg)

        if exec_name == "xxd" and "-r" in rest:
            segment_obf = True
            msg = "Hex payload decoding (xxd -r) detected in command pipeline"
            if msg not in obfuscation_reasons:
                obfuscation_reasons.append(msg)

        flags, pos_args = cls._parse_flags_and_args(exec_name, rest)
        subcmd = cls._extract_subcommand(exec_name, rest)
        nested_commands: list[tuple[str, tuple[str, ...], bool]] = []
        has_inline = False

        # 2. Раскрытие sh -c / bash -c
        if exec_name in _SHELL_BINARIES:
            for i, arg in enumerate(rest):
                if arg in ("-c", "-lc", "-ic") and i + 1 < len(rest):
                    nested_commands.append((rest[i + 1], (*wrappers, f"{exec_name} {arg}"), effective_sudo))
                    break

        # 3. Инспекция инлайн-скриптов: python3 -c, perl -e, ruby -e, node -e, php -r, awk
        if exec_name in _INLINE_SCRIPT_BINS:
            inline_flags = _INLINE_SCRIPT_BINS[exec_name]
            for i, arg in enumerate(rest):
                if arg in inline_flags and i + 1 < len(rest):
                    has_inline = True
                    code_body = rest[i + 1]
                    if _INLINE_DESTRUCTIVE_RE.search(code_body):
                        segment_obf = True
                        msg = f"Inline {exec_name} script contains destructive or system-execution call"
                        if msg not in obfuscation_reasons:
                            obfuscation_reasons.append(msg)
                    break
        elif exec_name in ("awk", "gawk", "mawk", "nawk"):
            joined_awk = " ".join(rest)
            if "system(" in joined_awk:
                has_inline = True
                segment_obf = True
                msg = "Inline awk system() command execution detected"
                if msg not in obfuscation_reasons:
                    obfuscation_reasons.append(msg)

        # 4. Раскрытие find ... -exec / -execdir / -ok
        if exec_name == "find":
            for i, arg in enumerate(rest):
                if arg in ("-exec", "-execdir", "-ok") and i + 1 < len(rest):
                    exec_tokens: list[str] = []
                    for sub_tok in rest[i + 1 :]:
                        if sub_tok in (";", r"\;", "+"):
                            break
                        if sub_tok != "{}":
                            exec_tokens.append(sub_tok)
                    if exec_tokens:
                        nested_commands.append(
                            (shlex.join(exec_tokens), (*wrappers, f"find {arg}"), effective_sudo)
                        )

        # 5. Раскрытие xargs <cmd>
        if exec_name == "xargs":
            x_idx = 0
            while x_idx < len(rest):
                xt = rest[x_idx]
                if xt.startswith("-"):
                    if xt in _XARGS_OPTS_WITH_ARG and x_idx + 1 < len(rest):
                        x_idx += 2
                    else:
                        x_idx += 1
                    continue
                break
            xargs_target = rest[x_idx:]
            if xargs_target:
                nested_commands.append(
                    (shlex.join(xargs_target), (*wrappers, "xargs"), effective_sudo)
                )

        # 6. Раскрытие docker/podman/kubectl exec
        if exec_name in ("docker", "podman") and subcmd == "exec":
            try:
                exec_pos = rest.index("exec")
                after_exec = rest[exec_pos + 1 :]
                c_idx = 0
                container_arg_opts = ("-u", "--user", "-w", "--workdir", "-e", "--env")
                while c_idx < len(after_exec) and after_exec[c_idx].startswith("-"):
                    if after_exec[c_idx] in container_arg_opts and c_idx + 1 < len(after_exec):
                        c_idx += 2
                    else:
                        c_idx += 1
                if c_idx + 1 < len(after_exec):
                    container_cmd = after_exec[c_idx + 1 :]
                    nested_commands.append(
                        (shlex.join(container_cmd), (*wrappers, f"{exec_name} exec"), effective_sudo)
                    )
            except ValueError:
                pass
        elif exec_name == "kubectl" and subcmd == "exec" and "--" in rest:
            sep_idx = rest.index("--")
            if sep_idx + 1 < len(rest):
                k8s_cmd = rest[sep_idx + 1 :]
                nested_commands.append(
                    (shlex.join(k8s_cmd), (*wrappers, "kubectl exec"), effective_sudo)
                )

        atom = AtomicCommand(
            executable=exec_name,
            raw_executable=raw_exec,
            subcommand=subcmd,
            arguments=tuple(pos_args),
            flags=flags,
            env_assignments=env_assignments,
            redirects=tuple(redirects),
            wrappers=tuple(wrappers),
            is_sudo=effective_sudo,
            is_obfuscated=segment_obf,
            subshell_depth=subshell_depth,
        )
        return [atom], nested_commands, has_inline

    @staticmethod
    def _parse_flags_and_args(
        executable: str,
        tokens: list[str],
    ) -> tuple[dict[str, str | bool], list[str]]:
        """Отделить флаги (короткие и длинные) от позиционных аргументов."""
        flags: dict[str, str | bool] = {}
        pos_args: list[str] = []
        opts_with_arg = _OPTS_WITH_ARG_BY_BIN.get(executable, frozenset())
        idx = 0
        n = len(tokens)
        after_double_dash = False

        while idx < n:
            tok = tokens[idx]
            if after_double_dash:
                pos_args.append(tok)
                idx += 1
                continue
            if tok == "--":
                after_double_dash = True
                idx += 1
                continue
            if tok.startswith("--") and len(tok) > 2:
                if "=" in tok:
                    fk, fv = tok.split("=", 1)
                    flags[fk] = fv
                elif tok in opts_with_arg and idx + 1 < n:
                    flags[tok] = tokens[idx + 1]
                    idx += 2
                    continue
                else:
                    flags[tok] = True
                idx += 1
                continue
            if tok.startswith("-") and len(tok) > 1 and not tok[1:].isdigit():
                if "=" in tok:
                    fk, fv = tok.split("=", 1)
                    flags[fk] = fv
                elif tok in opts_with_arg and idx + 1 < n:
                    flags[tok] = tokens[idx + 1]
                    idx += 2
                    continue
                else:
                    flags[tok] = True
                    # Также разворачиваем комбинированные короткие флаги вроде -rf -> -r, -f
                    if len(tok) > 2 and tok[1:].isalpha():
                        for ch in tok[1:]:
                            flags[f"-{ch}"] = True
                idx += 1
                continue

            pos_args.append(tok)
            idx += 1

        return flags, pos_args

    @staticmethod
    def _extract_subcommand(executable: str, tokens: list[str]) -> str | None:
        """Извлечь первую позиционную подкоманду для инструментов вроде systemctl, git, docker, kubectl."""
        subcmd_bins = {
            "systemctl",
            "git",
            "docker",
            "podman",
            "kubectl",
            "ip",
            "apt",
            "apt-get",
            "dnf",
            "yum",
            "apk",
            "zypper",
            "ufw",
            "nft",
            "helm",
        }
        if executable == "service":
            pos = [t for t in tokens if not t.startswith("-")]
            return pos[1].lower() if len(pos) >= 2 else None
        if executable not in subcmd_bins:
            return None

        opts_with_arg = _OPTS_WITH_ARG_BY_BIN.get(executable, frozenset())
        idx = 0
        n = len(tokens)
        while idx < n:
            tok = tokens[idx]
            if tok == "--":
                return tokens[idx + 1].lower() if idx + 1 < n else None
            if tok.startswith("-"):
                if "=" in tok:
                    idx += 1
                    continue
                if tok in opts_with_arg:
                    idx += 2
                    continue
                idx += 1
                continue
            return tok.lower()
        return None

    @staticmethod
    def _is_atomic_destructive(atom: AtomicCommand) -> bool:
        """Определить, несёт ли атомарная команда деструктивное действие."""
        if atom.executable in _DESTRUCTIVE_EXECUTABLES:
            return True
        dest_subs = _DESTRUCTIVE_SUBCOMMANDS.get(atom.executable)
        if dest_subs and atom.subcommand in dest_subs:
            return True
        if atom.executable == "pacman" and any(k.startswith("-R") for k in atom.flags):
            return True
        if atom.executable in ("iptables", "ip6tables") and any(
            k in ("-F", "-X", "-Z", "--flush", "--delete-chain") for k in atom.flags
        ):
            return True
        if atom.executable == "find" and ("-delete" in atom.flags or "-delete" in atom.arguments):
            return True
        return bool(atom.executable == "crontab" and "-r" in atom.flags)

    @staticmethod
    def _extract_paths_from_atomic(atom: AtomicCommand) -> list[str]:
        """Извлечь целевые пути файловой системы и блочных устройств из аргументов и редиректов."""
        paths: list[str] = []

        def _add_candidate(raw_val: str) -> None:
            cleaned = raw_val.strip()
            if not cleaned:
                return
            if cleaned.startswith(("/", "./", "../", "~")):
                if cleaned not in paths:
                    paths.append(cleaned)
                norm = normalize_target_path(cleaned)
                if norm and norm not in paths:
                    paths.append(norm)
            if "../" in cleaned or cleaned.startswith(".."):
                rel_tail = cleaned.replace("\\", "/")
                while rel_tail.startswith(("../", "./")):
                    rel_tail = rel_tail[3:] if rel_tail.startswith("../") else rel_tail[2:]
                rel_tail = rel_tail.lstrip("/")
                if any(
                    rel_tail == root.rstrip("/") or rel_tail.startswith(root)
                    for root in _TRAVERSAL_SYSTEM_ROOTS
                ):
                    abs_target = normalize_target_path("/" + rel_tail)
                    if abs_target not in paths:
                        paths.append(abs_target)

        for arg in atom.arguments:
            cleaned = arg.strip()
            if cleaned.startswith("of="):
                cleaned = cleaned[3:]
            _add_candidate(cleaned)
        for redir in atom.redirects:
            m = re.search(r"((?:/|\.\.?/)[^\s>;|&]+)", redir)
            if m:
                _add_candidate(m.group(1))
        return paths


__all__ = [
    "AtomicCommand",
    "CommandASTParser",
    "ParsedCommandAST",
    "normalize_target_path",
]
