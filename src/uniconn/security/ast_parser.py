# src/uniconn/security/ast_parser.py
"""Синтаксический анализатор shell-команд (CommandASTParser) и детектор обфускации.

Выполняет глубокую декомпозицию командных строк в дерево атомарных вызовов
(AtomicCommand / ParsedCommandAST), раскрывает косвенные обёртки (sudo, env,
timeout, sh -c, find -exec, xargs, docker/kubectl exec), инспектирует
инлайн-скрипты (python -c, perl -e, ruby -e, node -e, awk) и выявляет техники
обхода регулярных выражений (base64, hex/octal printf, eval, склейка переменных).
"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field
from typing import Any

from ._ast_rules import (
    _DESTRUCTIVE_EXECUTABLES,
    _DESTRUCTIVE_SUBCOMMANDS,
    _GLOB_OBFUSCATED_BIN_RE,
    _INLINE_DESTRUCTIVE_RE,
    _INLINE_SCRIPT_BINS,
    _OPTS_WITH_ARG_BY_BIN,
    _REDIRECT_RE,
    _SHELL_BINARIES,
    _SQL_DESTRUCTIVE_RE,
    _SUDO_OPTS_WITH_ARG,
    _VAR_CONCAT_EXEC_RE,
    _WIN_DRIVE_PATH_RE,
    _WRAPPER_BINARIES,
    _WRAPPER_OPTS_WITH_ARG,
    _XARGS_OPTS_WITH_ARG,
    _decode_ansi_c_escapes,
    _has_brace_expansion,
    _is_quote_spliced_token,
    _split_raw_shell_words,
    detect_global_obfuscation,
    extract_base64_payloads,
    normalize_target_path,
)


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


def _scan_paren_inner(text: str, start: int) -> tuple[str, int]:
    """Просканировать содержимое ``$(...)`` или ``<(...)`` / ``>(...)`` с учётом баланса скобок."""
    n = len(text)
    p_depth = 1
    j = start
    sub_single = False
    sub_double = False
    sub_esc = False
    while j < n and p_depth > 0:
        c2 = text[j]
        if sub_esc:
            sub_esc = False
        elif c2 == "\\" and not sub_single:
            sub_esc = True
        elif c2 == "'" and not sub_double:
            sub_single = not sub_single
        elif c2 == '"' and not sub_single:
            sub_double = not sub_double
        elif not sub_single and not sub_double:
            if c2 == "(":
                p_depth += 1
            elif c2 == ")":
                p_depth -= 1
        j += 1
    inner = text[start : j - 1].strip() if p_depth == 0 else text[start:].strip()
    return inner, j


def _scan_backtick_inner(text: str, start: int) -> tuple[str, int]:
    """Просканировать содержимое в обратных кавычках `` `...` ``."""
    n = len(text)
    j = start
    sub_esc = False
    while j < n:
        if sub_esc:
            sub_esc = False
        elif text[j] == "\\":
            sub_esc = True
        elif text[j] == "`":
            break
        j += 1
    return text[start:j].strip(), j + 1


class CommandASTParser:
    """Детерминированный синтаксический анализатор shell-команд для Policy-as-Code Guardrails."""

    MAX_COMMAND_LENGTH: int = 4096
    MAX_SEGMENTS: int = 64
    MAX_RECURSION_DEPTH: int = 6

    _extract_base64_payloads = staticmethod(extract_base64_payloads)
    _detect_global_obfuscation = staticmethod(detect_global_obfuscation)

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

        detect_global_obfuscation(raw, obfuscation_reasons)

        decoded_payloads = extract_base64_payloads(raw)
        for dec_cmd in decoded_payloads:
            reason = f"Base64-encoded command payload detected ({dec_cmd!r})"
            if reason not in obfuscation_reasons:
                obfuscation_reasons.append(reason)

        var_table: dict[str, str] = {}
        work_queue: list[tuple[str, tuple[str, ...], bool, int]] = [(seg, (), sudo, 0) for seg in segments]
        for dec_cmd in decoded_payloads:
            work_queue.append((dec_cmd, ("base64 -d",), sudo, 1))

        for sub_c, sub_depth in sub_cmds_with_depth:
            for sub_dec in extract_base64_payloads(sub_c):
                reason = f"Base64-encoded command payload detected ({sub_dec!r})"
                if reason not in obfuscation_reasons:
                    obfuscation_reasons.append(reason)
                work_queue.append((sub_dec, ("subshell", "base64 -d"), sudo, sub_depth + 1))
            sub_segs, sub_p, sub_b = cls._tokenize_top_level_segments(sub_c)
            has_pipes = has_pipes or sub_p
            has_bg = has_bg or sub_b
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
                has_pipes = has_pipes or sub_pipes
                has_bg = has_bg or sub_bg
                for s_item in sub_segs:
                    work_queue.append((s_item, nested_wrap, nested_sudo, depth + 1))

        if len(atomic_list) > eff_max_segments:
            complexity_exceeded = True

        cls._flag_pipe_to_interpreter(atomic_list, has_pipes, obfuscation_reasons)
        is_obf = bool(obfuscation_reasons) or any(a.is_obfuscated for a in atomic_list)

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

    @staticmethod
    def _flag_pipe_to_interpreter(
        atomic_list: list[AtomicCommand],
        has_pipes: bool,
        obfuscation_reasons: list[str],
    ) -> None:
        if not (has_pipes and len(atomic_list) >= 2):
            return
        interp_bins = _SHELL_BINARIES | set(_INLINE_SCRIPT_BINS.keys())
        feeder_bins = ("curl", "wget", "fetch", "base64", "xxd", "openssl", "printf", "echo")
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
                elif ch == ")" and paren_depth > 0:
                    paren_depth -= 1
                elif paren_depth == 0:
                    if ch in (";", "\n"):
                        if seg := "".join(buf).strip():
                            segments.append(seg)
                        buf.clear()
                        i += 1
                        continue
                    if ch in ("&", "|"):
                        prev_ch = command[i - 1] if i > 0 else ""
                        next_ch = command[i + 1] if i + 1 < n else ""
                        if not (ch == "&" and (prev_ch == ">" or next_ch == ">")):
                            if seg := "".join(buf).strip():
                                segments.append(seg)
                            buf.clear()
                            has_pipes = has_pipes or (ch == "|" and next_ch != "|")
                            has_bg = has_bg or (ch == "&" and next_ch != "&")
                            i += 2 if next_ch == ch else 1
                            continue

            buf.append(ch)
            i += 1

        if tail := "".join(buf).strip():
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
                    if (
                        ch in ("$", "<", ">")
                        and i + 1 < n
                        and text[i + 1] == "("
                        and (ch == "$" or i == 0 or text[i - 1] not in ("<", ">"))
                    ):
                        if ch == "$" and i + 2 < n and text[i + 2] == "(":
                            i += 3
                            continue
                        inner, i = _scan_paren_inner(text, i + 2)
                        if inner and inner not in seen:
                            seen.add(inner)
                            extracted.append((inner, current_depth))
                            _scan(inner, current_depth + 1)
                        continue
                    if ch == "`":
                        inner, i = _scan_backtick_inner(text, i + 1)
                        if inner and inner not in seen:
                            seen.add(inner)
                            extracted.append((inner, current_depth))
                            _scan(inner, current_depth + 1)
                        continue
                i += 1

        _scan(probe_str, base_depth)
        return extracted

    @staticmethod
    def _consume_su_wrapper(
        tokens: list[str],
        idx: int,
        base_tok: str,
        wrappers: list[str],
    ) -> tuple[int, tuple[str, tuple[str, ...], bool] | None]:
        n = len(tokens)
        wrappers.append(base_tok)
        idx += 1
        while idx < n:
            cur = tokens[idx]
            if cur in ("-c", "--command") and idx + 1 < n:
                return idx, (tokens[idx + 1], (*wrappers, f"{base_tok} -c"), True)
            if cur.startswith("--command="):
                return idx, (cur.split("=", 1)[1], (*wrappers, f"{base_tok} -c"), True)
            if cur == "--":
                return idx + 1, None
            if cur.startswith("-"):
                idx += 2 if cur in ("-s", "--shell", "-u", "-g", "-G") and idx + 1 < n else 1
                continue
            if idx + 1 < n and tokens[idx + 1].startswith("-"):
                idx += 1
                continue
            break
        return idx, None

    @staticmethod
    def _consume_env_wrapper(
        tokens: list[str],
        idx: int,
        wrappers: list[str],
        env_assignments: dict[str, str],
        var_table: dict[str, str],
    ) -> tuple[int, tuple[str, tuple[str, ...], bool] | None, bool]:
        n = len(tokens)
        wrappers.append("env")
        idx += 1
        while idx < n:
            cur = tokens[idx]
            if cur in ("-S", "--split-string") and idx + 1 < n:
                return idx, (tokens[idx + 1], (*wrappers, "env -S"), False), True
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
        return idx, None, False

    @classmethod
    def _strip_wrappers(
        cls,
        tokens: list[str],
        *,
        inherited_wrappers: tuple[str, ...],
        inherited_sudo: bool,
        var_table: dict[str, str],
        obfuscation_reasons: list[str],
    ) -> tuple[
        int,
        dict[str, str],
        list[str],
        bool,
        bool,
        tuple[str, tuple[str, ...], bool] | None,
    ]:
        env_assignments: dict[str, str] = {}
        wrappers: list[str] = list(inherited_wrappers)
        effective_sudo = inherited_sudo
        segment_obf = False
        idx = 0
        n = len(tokens)

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
                idx, early_nested = cls._consume_su_wrapper(tokens, idx, base_tok, wrappers)
                if early_nested is not None:
                    return idx, env_assignments, wrappers, effective_sudo, segment_obf, early_nested
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
                    idx += 1
                continue

            if base_tok == "env":
                idx, env_nested, is_split = cls._consume_env_wrapper(
                    tokens, idx, wrappers, env_assignments, var_table
                )
                if is_split and env_nested is not None:
                    return idx, env_assignments, wrappers, effective_sudo, segment_obf, (
                        env_nested[0], env_nested[1], effective_sudo
                    )
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
                    idx += 1
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

        return idx, env_assignments, wrappers, effective_sudo, segment_obf, None

    @staticmethod
    def _resolve_obfuscated_executable(
        raw_exec: str,
        raw_word_for_exec: str,
        var_table: dict[str, str],
        obfuscation_reasons: list[str],
    ) -> tuple[str, bool]:
        segment_obf = False
        if _is_quote_spliced_token(raw_word_for_exec):
            segment_obf = True
            msg = f"Quote or backslash obfuscation inside executable token ({raw_word_for_exec!r})"
            if msg not in obfuscation_reasons:
                obfuscation_reasons.append(msg)

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
        return exec_name, segment_obf

    @staticmethod
    def _extract_nested_wrapper_commands(
        exec_name: str,
        subcmd: str | None,
        rest: list[str],
        wrappers: list[str],
        effective_sudo: bool,
        obfuscation_reasons: list[str],
    ) -> tuple[list[tuple[str, tuple[str, ...], bool]], bool, bool]:
        nested_commands: list[tuple[str, tuple[str, ...], bool]] = []
        has_inline = False
        segment_obf = False

        if exec_name in _SHELL_BINARIES:
            for i, arg in enumerate(rest):
                if arg in ("-c", "-lc", "-ic") and i + 1 < len(rest):
                    nested_commands.append((rest[i + 1], (*wrappers, f"{exec_name} {arg}"), effective_sudo))
                    break

        if exec_name in _INLINE_SCRIPT_BINS:
            inline_flags = _INLINE_SCRIPT_BINS[exec_name]
            for i, arg in enumerate(rest):
                if arg in inline_flags and i + 1 < len(rest):
                    has_inline = True
                    if _INLINE_DESTRUCTIVE_RE.search(rest[i + 1]):
                        segment_obf = True
                        msg = f"Inline {exec_name} script contains destructive or system-execution call"
                        if msg not in obfuscation_reasons:
                            obfuscation_reasons.append(msg)
                    break
        elif exec_name in ("awk", "gawk", "mawk", "nawk") and "system(" in " ".join(rest):
            has_inline = True
            segment_obf = True
            msg = "Inline awk system() command execution detected"
            if msg not in obfuscation_reasons:
                obfuscation_reasons.append(msg)

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

        if exec_name == "xargs":
            x_idx = 0
            while x_idx < len(rest):
                xt = rest[x_idx]
                if xt.startswith("-"):
                    x_idx += 2 if xt in _XARGS_OPTS_WITH_ARG and x_idx + 1 < len(rest) else 1
                    continue
                break
            if rest[x_idx:]:
                nested_commands.append(
                    (shlex.join(rest[x_idx:]), (*wrappers, "xargs"), effective_sudo)
                )

        if exec_name in ("docker", "podman") and subcmd == "exec" and "exec" in rest:
            after_exec = rest[rest.index("exec") + 1 :]
            c_idx = 0
            container_arg_opts = ("-u", "--user", "-w", "--workdir", "-e", "--env")
            while c_idx < len(after_exec) and after_exec[c_idx].startswith("-"):
                c_idx += 2 if after_exec[c_idx] in container_arg_opts and c_idx + 1 < len(after_exec) else 1
            if c_idx + 1 < len(after_exec):
                nested_commands.append(
                    (shlex.join(after_exec[c_idx + 1 :]), (*wrappers, f"{exec_name} exec"), effective_sudo)
                )
        elif exec_name == "kubectl" and subcmd == "exec" and "--" in rest:
            sep_idx = rest.index("--")
            if sep_idx + 1 < len(rest):
                nested_commands.append(
                    (shlex.join(rest[sep_idx + 1 :]), (*wrappers, "kubectl exec"), effective_sudo)
                )

        return nested_commands, has_inline, segment_obf

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

        redirects = [
            m.group(0).strip() for m in _REDIRECT_RE.finditer(seg_clean) if m.group(0).strip()
        ]

        segment_obf = False
        raw_words = _split_raw_shell_words(seg_clean)
        for rw in raw_words:
            if _has_brace_expansion(rw):
                segment_obf = True
                msg = f"Shell brace expansion obfuscation detected ({rw!r})"
                if msg not in obfuscation_reasons:
                    obfuscation_reasons.append(msg)
        try:
            tokens = shlex.split(seg_clean, posix=True)
        except ValueError:
            tokens = seg_clean.split()
        if not tokens:
            return [], [], False

        idx, env_assignments, wrappers, effective_sudo, wrapper_obf, early_nested = cls._strip_wrappers(
            tokens,
            inherited_wrappers=inherited_wrappers,
            inherited_sudo=inherited_sudo,
            var_table=var_table,
            obfuscation_reasons=obfuscation_reasons,
        )
        segment_obf = segment_obf or wrapper_obf
        if early_nested is not None:
            return [], [early_nested], False

        remaining = tokens[idx:]
        if not remaining:
            return [], [], False

        raw_exec = remaining[0]
        raw_word_for_exec = raw_words[idx] if idx < len(raw_words) else raw_exec
        exec_name, exec_obf = cls._resolve_obfuscated_executable(
            raw_exec, raw_word_for_exec, var_table, obfuscation_reasons
        )
        segment_obf = segment_obf or exec_obf
        rest = remaining[1:]

        if exec_name == "eval":
            decoded_eval = _decode_ansi_c_escapes(" ".join(rest).strip())
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
        nested_commands, has_inline, nested_obf = cls._extract_nested_wrapper_commands(
            exec_name, subcmd, rest, wrappers, effective_sudo, obfuscation_reasons
        )
        segment_obf = segment_obf or nested_obf

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
            is_long = tok.startswith("--") and len(tok) > 2
            is_short = tok.startswith("-") and len(tok) > 1 and not tok[1:].isdigit()
            if is_long or is_short:
                if "=" in tok:
                    fk, fv = tok.split("=", 1)
                    flags[fk] = fv
                elif (tok in opts_with_arg or tok.lower() in opts_with_arg) and idx + 1 < n:
                    flags[tok] = tokens[idx + 1]
                    idx += 2
                    continue
                else:
                    flags[tok] = True
                    if is_short and not is_long and len(tok) > 2 and tok[1:].isalpha():
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
                if "=" not in tok and (tok in opts_with_arg or tok.lower() in opts_with_arg):
                    idx += 2
                else:
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
            is_path_like = (
                cleaned.startswith(("/", "./", "../", "~", "\\\\"))
                or bool(_WIN_DRIVE_PATH_RE.match(cleaned))
                or "../" in cleaned
                or "..\\" in cleaned
            )
            if not is_path_like:
                return
            if cleaned.startswith(("/", "./", "../", "~")) and cleaned not in paths:
                paths.append(cleaned)
            norm = normalize_target_path(cleaned)
            if norm and norm not in paths:
                paths.append(norm)

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
