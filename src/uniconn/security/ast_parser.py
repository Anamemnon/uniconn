# src/uniconn/security/ast_parser.py
"""Синтаксический анализатор shell- и PowerShell-команд (CommandASTParser).

Поддерживает:
- грамматический разбор POSIX/Bash через опциональный ``tree-sitter-bash`` (extra ``uniconn[security]``)
  с автоматическим fallback на встроенный детерминированный парсер;
- встроенный кроссплатформенный Python-парсер PowerShell AST (включая ``-EncodedCommand``,
  нормализацию алиасов и детекцию бэктик-обфускации);
- fail-closed фиксацию синтаксических ошибок (``syntax_errors``) и обфускации.
"""

from __future__ import annotations

import os
import re
import shlex
from typing import Literal

from ._ast_models import AtomicCommand, ParsedCommandAST
from ._ast_posix_scan import (
    _detect_builtin_syntax_errors,
    _unwrap_grouped_segment,
    extract_builtin_heredocs,
    extract_subshell_commands,
    tokenize_top_level_segments,
)
from ._ast_powershell import PowerShellASTParser, is_powershell_command
from ._ast_rules import (
    _DESTRUCTIVE_EXECUTABLES,
    _DESTRUCTIVE_SUBCOMMANDS,
    _GLOB_OBFUSCATED_BIN_RE,
    _HERESTRING_RE,
    _INLINE_DESTRUCTIVE_RE,
    _OPTS_WITH_ARG_BY_BIN,
    _REDIRECT_RE,
    _SHELL_BINARIES,
    _SHELL_COMBINED_C_FLAG_RE,
    _SHELL_CONTROL_PREFIX_KEYWORDS,
    _SHELL_CONTROL_SKIP_KEYWORDS,
    _SQL_DESTRUCTIVE_RE,
    _SUDO_OPTS_WITH_ARG,
    _VAR_CONCAT_EXEC_RE,
    _WIN_DRIVE_PATH_RE,
    _WRAPPER_BINARIES,
    _WRAPPER_OPTS_WITH_ARG,
    _XARGS_OPTS_WITH_ARG,
    _decode_ansi_c_escapes,
    _get_inline_script_flags,
    _has_brace_expansion,
    _is_interpreter_binary,
    _is_quote_spliced_token,
    _split_raw_shell_words,
    detect_global_obfuscation,
    extract_base64_payloads,
    normalize_target_path,
)
from ._ast_treesitter import extract_bash_grammar, is_treesitter_available

ASTDialectOption = Literal["auto", "posix", "powershell"]
ASTBackendOption = Literal["auto", "tree-sitter", "builtin"]


class CommandASTParser:
    """Детерминированный синтаксический анализатор shell- и PowerShell-команд для Policy-as-Code."""

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
        dialect: ASTDialectOption = "auto",
        backend: ASTBackendOption = "auto",
        max_depth: int | None = None,
        max_pipeline_length: int | None = None,
    ) -> ParsedCommandAST:
        """Разобрать shell- или PowerShell-строку в иерархическую структуру ``ParsedCommandAST``."""
        raw = command.strip()
        if not raw:
            eff_dialect: Literal["posix", "powershell"] = "powershell" if dialect == "powershell" else "posix"
            eff_backend = "powershell-ast" if eff_dialect == "powershell" else (
                "tree-sitter-bash" if backend != "builtin" and is_treesitter_available() else "builtin"
            )
            return ParsedCommandAST(raw_command="", dialect=eff_dialect, parser_backend=eff_backend)

        if dialect == "powershell" or (dialect == "auto" and is_powershell_command(raw)):
            return PowerShellASTParser.parse(
                raw,
                sudo=sudo,
                max_depth=max_depth,
                max_pipeline_length=max_pipeline_length,
            )

        return cls._parse_posix(
            raw,
            sudo=sudo,
            backend=backend,
            max_depth=max_depth,
            max_pipeline_length=max_pipeline_length,
        )

    @classmethod
    def _parse_posix(
        cls,
        raw: str,
        *,
        sudo: bool,
        backend: ASTBackendOption,
        max_depth: int | None,
        max_pipeline_length: int | None,
    ) -> ParsedCommandAST:
        """Разобрать POSIX/Bash команду (через ``tree-sitter-bash`` при наличии или встроенный fallback)."""
        eff_max_depth = max_depth if max_depth is not None else cls.MAX_RECURSION_DEPTH
        eff_max_segments = max_pipeline_length if max_pipeline_length is not None else cls.MAX_SEGMENTS

        complexity_exceeded = len(raw) > cls.MAX_COMMAND_LENGTH or raw.count("\n") > 50
        obfuscation_reasons: list[str] = []
        syntax_errors: list[str] = []
        atomic_list: list[AtomicCommand] = []
        has_inline_script = False

        ts_result = (
            extract_bash_grammar(raw, max_depth=eff_max_depth)
            if backend in ("auto", "tree-sitter")
            else None
        )

        work_queue: list[tuple[str, tuple[str, ...], bool, int]] = []
        heredoc_payloads: list[str] = []
        if ts_result is not None:
            parser_backend = "tree-sitter-bash"
            has_pipes = ts_result.has_pipes
            has_bg = ts_result.has_background_ops
            has_subshells = ts_result.has_subshells
            syntax_errors.extend(ts_result.syntax_errors)
            heredoc_payloads.extend(ts_result.heredoc_payloads)
            ts_segs = list(ts_result.segments)
            if len(ts_segs) > eff_max_segments:
                complexity_exceeded = True
                ts_segs = ts_segs[:eff_max_segments]
            for seg_txt, seg_wraps, seg_depth in ts_segs:
                work_queue.append((seg_txt, seg_wraps, sudo, seg_depth))
            sub_cmds_with_depth = list(ts_result.subshell_commands)
            # Дополнительно проверяем вложенные подстановки, которые могли быть внутри строк/арифметики
            for extra_sub, extra_depth in cls._extract_subshell_commands(raw):
                if all(existing != extra_sub for existing, _ in sub_cmds_with_depth):
                    sub_cmds_with_depth.append((extra_sub, extra_depth))
                    has_subshells = True
        else:
            parser_backend = "builtin"
            syntax_errors.extend(_detect_builtin_syntax_errors(raw))
            heredoc_payloads.extend(extract_builtin_heredocs(raw))
            segments, has_pipes, has_bg = cls._tokenize_top_level_segments(raw)
            if len(segments) > eff_max_segments:
                complexity_exceeded = True
                segments = segments[:eff_max_segments]
            for seg in segments:
                work_queue.append((seg, (), sudo, 0))
            sub_cmds_with_depth = cls._extract_subshell_commands(raw)
            has_subshells = bool(sub_cmds_with_depth)

        detect_global_obfuscation(raw, obfuscation_reasons)

        decoded_payloads = extract_base64_payloads(raw)
        for dec_cmd in decoded_payloads:
            reason = f"Base64-encoded command payload detected ({dec_cmd!r})"
            if reason not in obfuscation_reasons:
                obfuscation_reasons.append(reason)
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

        var_table: dict[str, str] = {}
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
                if ts_result is not None:
                    nested_ts = extract_bash_grammar(nested_cmd_str, max_depth=max(1, eff_max_depth - depth))
                    if nested_ts is not None:
                        has_pipes = has_pipes or nested_ts.has_pipes
                        has_bg = has_bg or nested_ts.has_background_ops
                        has_subshells = has_subshells or nested_ts.has_subshells
                        for err_msg in nested_ts.syntax_errors:
                            if err_msg not in syntax_errors:
                                syntax_errors.append(err_msg)
                        for n_seg, n_wraps, n_dep in nested_ts.segments:
                            work_queue.append((n_seg, (*nested_wrap, *n_wraps), nested_sudo, depth + 1 + n_dep))
                        for n_sub, n_sdep in nested_ts.subshell_commands:
                            work_queue.append((n_sub, (*nested_wrap, "subshell"), nested_sudo, depth + 1 + n_sdep))
                        continue
                sub_segs, sub_pipes, sub_bg = cls._tokenize_top_level_segments(nested_cmd_str)
                has_pipes = has_pipes or sub_pipes
                has_bg = has_bg or sub_bg
                for s_item in sub_segs:
                    work_queue.append((s_item, nested_wrap, nested_sudo, depth + 1))

        # Если в команде есть интерпретатор (sh/bash/python/perl/ruby/...) и heredoc-тело,
        # разбираем содержимое heredoc как исполняемый вложенный код (закрывает `bash << 'EOF'`).
        if heredoc_payloads and any(_is_interpreter_binary(a.executable) for a in atomic_list):
            has_inline_script = True
            heredoc_sudo = sudo or any(a.is_sudo for a in atomic_list if _is_interpreter_binary(a.executable))
            for hd_body in heredoc_payloads:
                if _INLINE_DESTRUCTIVE_RE.search(hd_body):
                    hd_msg = "Inline destructive script payload inside interpreter heredoc detected"
                    if hd_msg not in obfuscation_reasons:
                        obfuscation_reasons.append(hd_msg)
                hd_segs, hd_p, hd_b = cls._tokenize_top_level_segments(hd_body)
                has_pipes = has_pipes or hd_p
                has_bg = has_bg or hd_b
                for hd_seg in hd_segs[:eff_max_segments]:
                    hd_atoms, _, hd_inl = cls._parse_single_segment(
                        hd_seg,
                        inherited_wrappers=("heredoc",),
                        inherited_sudo=heredoc_sudo,
                        var_table=var_table,
                        obfuscation_reasons=obfuscation_reasons,
                        subshell_depth=1,
                    )
                    if hd_inl:
                        has_inline_script = True
                    atomic_list.extend(hd_atoms)

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
            dialect="posix",
            parser_backend=parser_backend,
            syntax_errors=tuple(syntax_errors),
        )

    @staticmethod
    def _flag_pipe_to_interpreter(
        atomic_list: list[AtomicCommand],
        has_pipes: bool,
        obfuscation_reasons: list[str],
    ) -> None:
        if not (has_pipes and len(atomic_list) >= 2):
            return
        for pos in range(1, len(atomic_list)):
            prev_atom = atomic_list[pos - 1]
            curr_atom = atomic_list[pos]
            if not _is_interpreter_binary(curr_atom.executable):
                continue
            reads_stdin = not curr_atom.arguments or "-" in curr_atom.arguments or "-s" in curr_atom.flags
            if reads_stdin:
                r_msg = (
                    f"Piping output of {prev_atom.executable!r} directly into "
                    f"interpreter {curr_atom.executable!r}"
                )
                if r_msg not in obfuscation_reasons:
                    obfuscation_reasons.append(r_msg)

    @classmethod
    def _tokenize_top_level_segments(cls, command: str) -> tuple[list[str], bool, bool]:
        r"""Разбить командную строку по операторам (; && || | & \n) с учётом кавычек и скобок."""
        return tokenize_top_level_segments(command)

    @classmethod
    def _extract_subshell_commands(cls, probe_str: str, base_depth: int = 1) -> list[tuple[str, int]]:
        """Извлечь вложенные команды из $(...) и обратных кавычек `...` с учётом баланса скобок."""
        return extract_subshell_commands(
            probe_str,
            base_depth=base_depth,
            max_recursion_depth=cls.MAX_RECURSION_DEPTH,
        )

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
    ) -> tuple[int, dict[str, str], list[str], bool, bool, tuple[str, tuple[str, ...], bool] | None]:
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
                    return (
                        idx,
                        env_assignments,
                        wrappers,
                        effective_sudo,
                        segment_obf,
                        (env_nested[0], env_nested[1], effective_sudo),
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

            if base_tok in _SHELL_CONTROL_PREFIX_KEYWORDS:
                idx += 1
                continue

            if base_tok == "command":
                look_idx = idx + 1
                is_lookup_only = False
                while look_idx < n and tokens[look_idx].startswith("-"):
                    opt = tokens[look_idx]
                    if opt == "--":
                        look_idx += 1
                        break
                    if any(flag_ch in ("v", "V") for flag_ch in opt[1:]):
                        is_lookup_only = True
                    look_idx += 1
                if is_lookup_only:
                    break
                wrappers.append("command")
                idx = look_idx
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
            i = 0
            while i < len(rest):
                arg = rest[i]
                if arg == "--":
                    break
                if arg in ("-o", "+o") and i + 1 < len(rest):
                    i += 2
                    continue
                if (arg == "--command" or _SHELL_COMBINED_C_FLAG_RE.fullmatch(arg)) and i + 1 < len(rest):
                    nested_commands.append((rest[i + 1], (*wrappers, f"{exec_name} {arg}"), effective_sudo))
                    break
                if arg.startswith("--command="):
                    nested_commands.append(
                        (arg.split("=", 1)[1], (*wrappers, f"{exec_name} --command"), effective_sudo)
                    )
                    break
                i += 1

        inline_flags = _get_inline_script_flags(exec_name)
        if inline_flags is not None:
            short_chars = {f[1] for f in inline_flags if len(f) == 2 and f.startswith("-")}
            for i, arg in enumerate(rest):
                if arg == "--":
                    break
                code_payload: str | None = None
                is_combined_short = (
                    arg.startswith("-")
                    and not arg.startswith("--")
                    and len(arg) > 2
                    and arg[1:].isalpha()
                    and any(ch in short_chars for ch in arg[1:])
                )
                if (arg in inline_flags or is_combined_short) and i + 1 < len(rest):
                    code_payload = rest[i + 1]
                elif any(arg.startswith(f"{f}=") for f in inline_flags if f.startswith("--")):
                    code_payload = arg.split("=", 1)[1]
                if code_payload is not None:
                    has_inline = True
                    if _INLINE_DESTRUCTIVE_RE.search(code_payload):
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
                    exec_tokens = [t for t in rest[i + 1 :] if t != "{}"]
                    trimmed: list[str] = []
                    for sub_tok in exec_tokens:
                        if sub_tok in (";", r"\;", "+"):
                            break
                        trimmed.append(sub_tok)
                    if trimmed:
                        nested_commands.append(
                            (shlex.join(trimmed), (*wrappers, f"find {arg}"), effective_sudo)
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
                nested_commands.append((shlex.join(rest[x_idx:]), (*wrappers, "xargs"), effective_sudo))

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

        grouped_inner, grouped_kind = _unwrap_grouped_segment(seg_clean)
        if grouped_inner is not None and grouped_kind is not None:
            return [], [(grouped_inner, (*inherited_wrappers, grouped_kind), inherited_sudo)], False

        redirects = [m.group(0).strip() for m in _REDIRECT_RE.finditer(seg_clean) if m.group(0).strip()]
        herestring_payloads: list[str] = []
        for hs_match in _HERESTRING_RE.finditer(seg_clean):
            hs_val = next((g for g in hs_match.groups() if g is not None), "")
            if hs_val:
                herestring_payloads.append(hs_val)

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

        while tokens and tokens[-1] in _SHELL_CONTROL_SKIP_KEYWORDS:
            tokens.pop()
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
        if not remaining or remaining[0] in _SHELL_CONTROL_SKIP_KEYWORDS:
            return [], [], False

        if remaining[0].startswith("(") and remaining[-1].endswith(")"):
            sub_inner, sub_kind = _unwrap_grouped_segment(" ".join(remaining))
            if sub_inner is not None and sub_kind is not None:
                return [], [(sub_inner, (*wrappers, sub_kind), effective_sudo)], False

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

        if exec_name in (".", "source"):
            segment_obf = True
            msg = f"Dynamic shell script sourcing ({exec_name!r}) bypasses static command inspection"
            if msg not in obfuscation_reasons:
                obfuscation_reasons.append(msg)

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

        if herestring_payloads and _is_interpreter_binary(exec_name):
            for hs_payload in herestring_payloads:
                if exec_name in _SHELL_BINARIES:
                    nested_commands.append((hs_payload, (*wrappers, f"{exec_name} <<<"), effective_sudo))
                    if "$" in hs_payload or "`" in hs_payload:
                        segment_obf = True
                        msg = f"Dynamic here-string execution into shell {exec_name!r}"
                        if msg not in obfuscation_reasons:
                            obfuscation_reasons.append(msg)
                else:
                    has_inline = True
                    if _INLINE_DESTRUCTIVE_RE.search(hs_payload) or "$" in hs_payload:
                        segment_obf = True
                        msg = f"Here-string script execution into interpreter {exec_name!r}"
                        if msg not in obfuscation_reasons:
                            obfuscation_reasons.append(msg)

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
    def _parse_flags_and_args(executable: str, tokens: list[str]) -> tuple[dict[str, str | bool], list[str]]:
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
            "systemctl", "git", "docker", "podman", "kubectl", "ip", "apt",
            "apt-get", "dnf", "yum", "apk", "zypper", "ufw", "nft", "helm",
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
                idx += 2 if ("=" not in tok and (tok in opts_with_arg or tok.lower() in opts_with_arg)) else 1
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
    "ASTBackendOption",
    "ASTDialectOption",
    "AtomicCommand",
    "CommandASTParser",
    "ParsedCommandAST",
    "PowerShellASTParser",
    "is_powershell_command",
    "is_treesitter_available",
    "normalize_target_path",
]
