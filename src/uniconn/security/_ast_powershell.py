# src/uniconn/security/_ast_powershell.py
"""Встроенный кроссплатформенный Python-лексер и AST-анализатор PowerShell команд.

Работает на Linux, macOS и Windows без внешнего бинарника ``pwsh``:
- распознаёт cmdlet'ы, алиасы (``iex``, ``iwr``, ``rm``, ``saps`` и др.) и конвейеры;
- декодирует ``-EncodedCommand`` / ``-ec`` / ``-e`` (UTF-16LE Base64) и рекурсивно разбирает тело;
- выявляет обфускацию обратным апострофом (``I`EX``), Unicode-кавычками, ``[char]`` / ``-join``,
  ``[System.Convert]::FromBase64String`` и скачивание в память (``DownloadString``);
- фиксирует синтаксические аномалии (незакрытые кавычки/скобки, битый Base64) в режиме fail-closed.
"""

from __future__ import annotations

import base64
import binascii
import os
import re

from ._ast_models import AtomicCommand, ParsedCommandAST
from ._ast_rules import _SQL_DESTRUCTIVE_RE, normalize_target_path

_PS_SINGLE_QUOTES: frozenset[str] = frozenset({"'", "\u2018", "\u2019", "\u201a", "\u201b"})
_PS_DOUBLE_QUOTES: frozenset[str] = frozenset({'"', "\u201c", "\u201d", "\u201e"})

_PS_SHELL_BINARIES: frozenset[str] = frozenset({"powershell", "powershell.exe", "pwsh", "pwsh.exe"})
_PS_ENCODED_FLAGS: frozenset[str] = frozenset(
    {"-e", "-ec", "-en", "-enc", "-enco", "-encod", "-encoded", "-encodedcommand", "/e", "/ec", "/encodedcommand"}
)
_PS_COMMAND_FLAGS: frozenset[str] = frozenset({"-c", "-co", "-com", "-comm", "-command", "/c", "/command"})
_PS_SWITCH_FLAGS: frozenset[str] = frozenset(
    {
        "-recurse",
        "-r",
        "-force",
        "-f",
        "-whatif",
        "-confirm",
        "-verbose",
        "-debug",
        "-quiet",
        "-noprofile",
        "-nop",
        "-noninteractive",
        "-noni",
        "-nologo",
        "-nol",
        "-all",
        "-removedata",
        "-bypass",
        "-passthru",
        "-wait",
        "-nonewwindow",
    }
)

_PS_ALIASES: dict[str, str] = {
    "iex": "invoke-expression",
    "iwr": "invoke-webrequest",
    "irm": "invoke-restmethod",
    "icm": "invoke-command",
    "ii": "invoke-item",
    "saps": "start-process",
    "start": "start-process",
    "spps": "stop-process",
    "kill": "stop-process",
    "rm": "remove-item",
    "del": "remove-item",
    "erase": "remove-item",
    "rd": "remove-item",
    "ri": "remove-item",
    "rmdir": "remove-item",
    "rp": "remove-itemproperty",
    "sp": "set-itemproperty",
    "si": "set-item",
    "sc": "set-content",
    "ac": "add-content",
    "clc": "clear-content",
    "ni": "new-item",
    "md": "new-item",
    "mkdir": "new-item",
    "cpi": "copy-item",
    "cp": "copy-item",
    "copy": "copy-item",
    "mi": "move-item",
    "mv": "move-item",
    "move": "move-item",
    "rni": "rename-item",
    "ren": "rename-item",
    "gc": "get-content",
    "cat": "get-content",
    "type": "get-content",
    "gci": "get-childitem",
    "dir": "get-childitem",
    "ls": "get-childitem",
    "gps": "get-process",
    "ps": "get-process",
    "gsv": "get-service",
    "sasv": "start-service",
    "spsv": "stop-service",
    "gp": "get-itemproperty",
    "gi": "get-item",
    "gl": "get-location",
    "pwd": "get-location",
    "sl": "set-location",
    "cd": "set-location",
    "echo": "write-output",
    "write": "write-output",
    "%": "foreach-object",
    "foreach": "foreach-object",
    "?": "where-object",
    "where": "where-object",
    "curl": "invoke-webrequest",
    "wget": "invoke-webrequest",
}

_PS_DESTRUCTIVE_CMDLETS: frozenset[str] = frozenset(
    {
        "remove-item",
        "remove-itemproperty",
        "clear-content",
        "clear-item",
        "clear-disk",
        "format-volume",
        "initialize-disk",
        "remove-partition",
        "stop-computer",
        "restart-computer",
        "stop-service",
        "remove-service",
        "stop-process",
        "remove-localuser",
        "disable-localuser",
        "remove-localgroupmember",
        "disable-netfirewallrule",
        "remove-netfirewallrule",
        "set-netfirewallprofile",
        "disable-windowsoptionalfeature",
        "uninstall-windowsfeature",
        "uninstall-package",
        "remove-appxpackage",
        "clear-eventlog",
        "remove-eventlog",
        "vssadmin",
        "bcdedit",
        "cipher",
        "diskpart",
        "wbadmin",
    }
)

_PS_CMDLET_VERB_PREFIXES: tuple[str, ...] = (
    "get-",
    "set-",
    "new-",
    "remove-",
    "clear-",
    "stop-",
    "start-",
    "restart-",
    "invoke-",
    "add-",
    "enable-",
    "disable-",
    "test-",
    "write-",
    "read-",
    "out-",
    "format-",
    "select-",
    "where-",
    "foreach-",
    "install-",
    "uninstall-",
    "export-",
    "import-",
    "convertto-",
    "convertfrom-",
    "register-",
    "unregister-",
    "resolve-",
    "copy-",
    "move-",
    "rename-",
)

_PS_DETECT_RE = re.compile(
    r"(?:^|\s|;|&|\|)(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b"
    r"|-(?:EncodedCommand|NoProfile|NonInteractive|ExecutionPolicy|WindowStyle)\b"
    r"|\b(?:HKLM|HKCU|HKCR|HKU|HKCC):\\"
    r"|\$env:[A-Za-z_]"
    r"|\[(?:System\.)?(?:Convert|Text\.Encoding|Net\.WebClient|Net\.ServicePointManager|Diagnostics\.Process)\]"
    r"|\bNew-Object\b"
    r"|\|\s*(?:iex|invoke-expression|foreach-object|where-object)\b"
    r"|\b[A-Za-z]+`[A-Za-z-]*[A-Za-z]\b",
    re.IGNORECASE,
)

_PS_OBFUSCATION_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"\[(?:System\.)?Convert\]::FromBase64String", re.IGNORECASE),
        "PowerShell Base64 decoding via [System.Convert]::FromBase64String detected",
    ),
    (
        re.compile(r"\.(?:DownloadString|DownloadData|DownloadFile)\s*\(", re.IGNORECASE),
        "PowerShell remote payload download via WebClient detected",
    ),
    (
        re.compile(r"(?:\[\s*char\s*\]\s*\d+.*){3,}|-join\s*\(\s*\[char\[\]\]", re.IGNORECASE),
        "PowerShell character-code array obfuscation ([char]/join) detected",
    ),
    (
        re.compile(r"\$\{\s*[^}]+\s*\}\s*\(|&\s*\(\s*['\"][^'\"]+['\"]\s*\+", re.IGNORECASE),
        "PowerShell dynamic invocation via string concatenation detected",
    ),
    (
        re.compile(r"Set-ExecutionPolicy\s+(?:-\w+\s+)*(?:Bypass|Unrestricted)\b", re.IGNORECASE),
        "PowerShell execution policy bypass detected",
    ),
)

_PS_PATH_RE = re.compile(
    r"^(?:[A-Za-z]:[\\/]|\\\\|HK(?:LM|CU|CR|U|CC):[\\/]|Registry::)",
    re.IGNORECASE,
)


def is_powershell_command(command: str) -> bool:
    """Определить, относится ли команда к диалекту PowerShell."""
    stripped = command.strip()
    if not stripped:
        return False
    if _PS_DETECT_RE.search(stripped):
        return True
    first_word = stripped.split(None, 1)[0].replace("`", "").strip("'\"").lower()
    if first_word in _PS_SHELL_BINARIES or first_word in ("iex", "iwr", "irm", "saps", "spps", "gsv", "sasv", "spsv"):
        return True
    if first_word in ("del", "erase", "ri", "rd") and (
        re.search(r"(?:^|\s)-(?:recurse|force|path|literalpath)\b", stripped, re.IGNORECASE)
        or re.search(r"\b[A-Za-z]:\\", stripped)
    ):
        return True
    if any(first_word.startswith(prefix) for prefix in _PS_CMDLET_VERB_PREFIXES) and "-" in first_word:
        return True
    return any(
        re.search(rf"(?:^|[|;&\s]){re.escape(prefix)}[A-Za-z][A-Za-z0-9]*\b", stripped, re.IGNORECASE)
        for prefix in (
            "invoke-",
            "remove-item",
            "set-itemproperty",
            "remove-itemproperty",
            "stop-service",
            "start-service",
            "restart-service",
            "stop-computer",
            "restart-computer",
            "format-volume",
            "clear-disk",
            "get-process",
            "get-service",
            "get-childitem",
            "get-content",
            "set-content",
            "new-item",
            "start-process",
            "stop-process",
            "disable-netfirewallrule",
            "set-executionpolicy",
            "disable-windowsoptionalfeature",
        )
    )


def _decode_ps_encoded_command(b64_payload: str) -> tuple[str | None, str | None]:
    """Раскодировать аргумент PowerShell ``-EncodedCommand`` (UTF-16LE Base64)."""
    cleaned = re.sub(r"\s+", "", b64_payload.strip().strip("'\""))
    if not cleaned:
        return None, "Empty PowerShell -EncodedCommand payload"
    padded = cleaned + "=" * ((4 - len(cleaned) % 4) % 4)
    try:
        raw_bytes = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError) as exc:
        return None, f"Invalid Base64 in PowerShell -EncodedCommand ({exc})"
    if not raw_bytes:
        return None, "Empty decoded PowerShell -EncodedCommand payload"
    try:
        if len(raw_bytes) % 2 == 0:
            decoded = raw_bytes.decode("utf-16-le")
            if decoded.strip():
                return decoded.strip(), None
    except UnicodeDecodeError:
        pass
    try:
        decoded_utf8 = raw_bytes.decode("utf-8")
        if decoded_utf8.strip():
            return decoded_utf8.strip(), None
    except UnicodeDecodeError:
        pass
    return None, "Failed to decode PowerShell -EncodedCommand payload as UTF-16LE/UTF-8"


def _strip_ps_backticks(token: str) -> tuple[str, bool]:
    """Удалить обфусцирующие бэктики из имени команды PowerShell (например ``I`EX`` -> ``IEX``)."""
    if "`" not in token:
        return token, False
    out: list[str] = []
    i = 0
    n = len(token)
    obfuscated = False
    while i < n:
        if token[i] == "`" and i + 1 < n:
            nxt = token[i + 1]
            if nxt.isalpha() or nxt in "-_.":
                obfuscated = True
                out.append(nxt)
                i += 2
                continue
        out.append(token[i])
        i += 1
    return "".join(out), obfuscated


def _scan_ps_segments_and_subexprs(
    command: str,
    syntax_errors: list[str],
) -> tuple[list[str], list[str], bool]:
    r"""Разбить PowerShell-строку на сегменты по ``;``, ``|``, ``&&``, ``||``, ``\\n`` и извлечь ``$(...)``."""
    segments: list[str] = []
    subexprs: list[str] = []
    buf: list[str] = []
    has_pipes = False

    in_single: str | None = None
    in_double: str | None = None
    paren_depth = 0
    brace_depth = 0
    i = 0
    n = len(command)

    while i < n:
        ch = command[i]

        # Комментарии PowerShell: блочные <# ... #> и строчные # ...
        if in_single is None and in_double is None:
            if ch == "<" and i + 1 < n and command[i + 1] == "#":
                end_comment = command.find("#>", i + 2)
                if end_comment == -1:
                    syntax_errors.append("Unclosed PowerShell block comment (<#)")
                    break
                i = end_comment + 2
                continue
            if ch == "#" and (i == 0 or command[i - 1].isspace() or command[i - 1] in ";|&({"):
                nl_idx = command.find("\n", i + 1)
                if nl_idx == -1:
                    break
                i = nl_idx
                continue

        # Here-strings @' ... '@ и @" ... "@
        if in_single is None and in_double is None and ch == "@" and i + 1 < n and command[i + 1] in ("'", '"'):
            quote_mark = command[i + 1]
            end_marker = f"\n{quote_mark}@"
            end_idx = command.find(end_marker, i + 2)
            if end_idx == -1:
                syntax_errors.append(f"Unclosed PowerShell here-string (@{quote_mark})")
                buf.append(command[i:])
                break
            body = command[i + 2 : end_idx]
            if quote_mark == '"':
                hs_idx = 0
                hs_len = len(body)
                while hs_idx < hs_len:
                    if body[hs_idx] == "`" and hs_idx + 1 < hs_len:
                        hs_idx += 2
                        continue
                    if body[hs_idx] == "$" and hs_idx + 1 < hs_len and body[hs_idx + 1] == "(":
                        inner, next_hs, closed = _extract_balanced_block(body, hs_idx + 2, "(", ")")
                        if not closed:
                            syntax_errors.append(
                                "Unclosed PowerShell subexpression '$(' inside double-quoted here-string"
                            )
                        if inner:
                            subexprs.append(inner)
                        hs_idx = next_hs
                        continue
                    hs_idx += 1
            buf.append(command[i : end_idx + len(end_marker)])
            i = end_idx + len(end_marker)
            continue

        if in_single is not None:
            buf.append(ch)
            if ch in _PS_SINGLE_QUOTES:
                if i + 1 < n and command[i + 1] in _PS_SINGLE_QUOTES:
                    buf.append(command[i + 1])
                    i += 2
                    continue
                in_single = None
            i += 1
            continue

        if in_double is not None:
            if ch == "`" and i + 1 < n:
                buf.append(ch)
                buf.append(command[i + 1])
                i += 2
                continue
            if ch == "$" and i + 1 < n and command[i + 1] == "(":
                inner, next_i, closed = _extract_balanced_block(command, i + 2, "(", ")")
                if not closed:
                    syntax_errors.append("Unclosed PowerShell subexpression '$(' inside double-quoted string")
                if inner:
                    subexprs.append(inner)
                buf.append(command[i:next_i])
                i = next_i
                continue
            buf.append(ch)
            if ch in _PS_DOUBLE_QUOTES:
                in_double = None
            i += 1
            continue

        if ch == "`" and i + 1 < n:
            buf.append(ch)
            buf.append(command[i + 1])
            i += 2
            continue

        if ch in _PS_SINGLE_QUOTES:
            in_single = ch
            buf.append(ch)
            i += 1
            continue

        if ch in _PS_DOUBLE_QUOTES:
            in_double = ch
            buf.append(ch)
            i += 1
            continue

        if ch == "$" and i + 1 < n and command[i + 1] == "(":
            inner, next_i, closed = _extract_balanced_block(command, i + 2, "(", ")")
            if not closed:
                syntax_errors.append("Unclosed PowerShell subexpression '$('")
            if inner:
                subexprs.append(inner)
            buf.append(command[i:next_i])
            i = next_i
            continue

        if ch == "(":
            paren_depth += 1
            buf.append(ch)
            i += 1
            continue
        if ch == ")":
            if paren_depth == 0:
                syntax_errors.append("Unmatched closing parenthesis ')' in PowerShell command")
            else:
                paren_depth -= 1
            buf.append(ch)
            i += 1
            continue
        if ch == "{":
            brace_depth += 1
            buf.append(ch)
            i += 1
            continue
        if ch == "}":
            if brace_depth == 0:
                syntax_errors.append("Unmatched closing brace '}' in PowerShell command")
            else:
                brace_depth -= 1
            buf.append(ch)
            i += 1
            continue

        if paren_depth == 0 and brace_depth == 0:
            if ch in (";", "\n"):
                if seg := "".join(buf).strip():
                    segments.append(seg)
                buf.clear()
                i += 1
                continue
            if ch == "|":
                next_ch = command[i + 1] if i + 1 < n else ""
                if seg := "".join(buf).strip():
                    segments.append(seg)
                buf.clear()
                if next_ch == "|":
                    i += 2
                else:
                    has_pipes = True
                    i += 1
                continue
            if ch == "&" and i + 1 < n and command[i + 1] == "&":
                if seg := "".join(buf).strip():
                    segments.append(seg)
                buf.clear()
                i += 2
                continue

        buf.append(ch)
        i += 1

    if in_single is not None:
        syntax_errors.append("Unclosed single-quoted string in PowerShell command")
    if in_double is not None:
        syntax_errors.append("Unclosed double-quoted string in PowerShell command")
    if paren_depth > 0:
        syntax_errors.append("Unclosed parenthesis '(' in PowerShell command")
    if brace_depth > 0:
        syntax_errors.append("Unclosed script block '{' in PowerShell command")

    if tail := "".join(buf).strip():
        segments.append(tail)

    return segments, subexprs, has_pipes


def _extract_balanced_block(text: str, start: int, open_ch: str, close_ch: str) -> tuple[str, int, bool]:
    """Извлечь содержимое сбалансированного блока ``(...)`` или ``{...}`` с учётом PowerShell-кавычек."""
    depth = 1
    in_single = False
    in_double = False
    i = start
    n = len(text)
    while i < n and depth > 0:
        ch = text[i]
        if in_single:
            if ch in _PS_SINGLE_QUOTES:
                if i + 1 < n and text[i + 1] in _PS_SINGLE_QUOTES:
                    i += 2
                    continue
                in_single = False
            i += 1
            continue
        if in_double:
            if ch == "`" and i + 1 < n:
                i += 2
                continue
            if ch in _PS_DOUBLE_QUOTES:
                in_double = False
            i += 1
            continue
        if ch == "`" and i + 1 < n:
            i += 2
            continue
        if ch in _PS_SINGLE_QUOTES:
            in_single = True
        elif ch in _PS_DOUBLE_QUOTES:
            in_double = True
        elif ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
        i += 1
    closed = depth == 0
    inner = text[start : i - 1].strip() if closed else text[start:].strip()
    return inner, i, closed


def _tokenize_ps_words(segment: str) -> list[str]:
    """Разбить одиночный сегмент PowerShell на слова с сохранением строк в кавычках и блоков ``{...}``."""
    tokens: list[str] = []
    buf: list[str] = []
    in_single = False
    in_double = False
    brace_depth = 0
    paren_depth = 0
    i = 0
    n = len(segment)

    while i < n:
        ch = segment[i]
        if in_single:
            if ch in _PS_SINGLE_QUOTES:
                if i + 1 < n and segment[i + 1] in _PS_SINGLE_QUOTES:
                    buf.append(ch)
                    i += 2
                    continue
                in_single = False
                i += 1
                continue
            buf.append(ch)
            i += 1
            continue
        if in_double:
            if ch == "`" and i + 1 < n:
                buf.append(segment[i + 1])
                i += 2
                continue
            if ch in _PS_DOUBLE_QUOTES:
                in_double = False
                i += 1
                continue
            buf.append(ch)
            i += 1
            continue
        if ch in _PS_SINGLE_QUOTES and brace_depth == 0 and paren_depth == 0:
            in_single = True
            i += 1
            continue
        if ch in _PS_DOUBLE_QUOTES and brace_depth == 0 and paren_depth == 0:
            in_double = True
            i += 1
            continue
        if ch == "{":
            brace_depth += 1
            buf.append(ch)
            i += 1
            continue
        if ch == "}" and brace_depth > 0:
            brace_depth -= 1
            buf.append(ch)
            i += 1
            continue
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
        if ch.isspace() and brace_depth == 0 and paren_depth == 0:
            if buf:
                tokens.append("".join(buf))
                buf.clear()
            i += 1
            continue
        buf.append(ch)
        i += 1

    if buf:
        tokens.append("".join(buf))
    return tokens


class PowerShellASTParser:
    """Кроссплатформенный Python-анализатор AST для команд PowerShell / WinRM."""

    MAX_COMMAND_LENGTH: int = 8192
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
        """Разобрать команду PowerShell в унифицированный ``ParsedCommandAST``."""
        raw = command.strip()
        if not raw:
            return ParsedCommandAST(raw_command="", dialect="powershell", parser_backend="powershell-ast")

        eff_max_depth = max_depth if max_depth is not None else cls.MAX_RECURSION_DEPTH
        eff_max_segments = max_pipeline_length if max_pipeline_length is not None else cls.MAX_SEGMENTS

        complexity_exceeded = len(raw) > cls.MAX_COMMAND_LENGTH or raw.count("\n") > 80
        obfuscation_reasons: list[str] = []
        syntax_errors: list[str] = []
        atomic_list: list[AtomicCommand] = []
        has_pipes = False
        has_subshells = False
        has_inline_script = False

        for pat, reason in _PS_OBFUSCATION_PATTERNS:
            if pat.search(raw) and reason not in obfuscation_reasons:
                obfuscation_reasons.append(reason)

        top_segs, top_subs, top_pipes = _scan_ps_segments_and_subexprs(raw, syntax_errors)
        has_pipes = top_pipes
        has_subshells = bool(top_subs)
        if len(top_segs) > eff_max_segments:
            complexity_exceeded = True
            top_segs = top_segs[:eff_max_segments]

        work_queue: list[tuple[str, tuple[str, ...], int]] = [(s, (), 0) for s in top_segs]
        for sub in top_subs:
            work_queue.append((sub, ("subexpression",), 1))

        observed_max_depth = 0
        idx = 0
        while idx < len(work_queue):
            seg_str, wrappers, depth = work_queue[idx]
            idx += 1
            observed_max_depth = max(observed_max_depth, depth)
            if depth > eff_max_depth:
                complexity_exceeded = True
                continue

            atoms, nested, seg_inline = cls._parse_segment(
                seg_str,
                wrappers=wrappers,
                sudo=sudo,
                depth=depth,
                obfuscation_reasons=obfuscation_reasons,
                syntax_errors=syntax_errors,
            )
            has_inline_script = has_inline_script or seg_inline
            atomic_list.extend(atoms)

            for nested_cmd, nested_wrappers in nested:
                sub_segs, sub_exprs, sub_pipes = _scan_ps_segments_and_subexprs(nested_cmd, syntax_errors)
                has_pipes = has_pipes or sub_pipes
                if sub_exprs:
                    has_subshells = True
                for s_item in sub_segs:
                    work_queue.append((s_item, nested_wrappers, depth + 1))
                for se_item in sub_exprs:
                    work_queue.append((se_item, (*nested_wrappers, "subexpression"), depth + 2))

        if len(atomic_list) > eff_max_segments:
            complexity_exceeded = True

        # Проверка пайпа загрузки в Invoke-Expression (iwr ... | iex)
        if has_pipes and len(atomic_list) >= 2:
            for pos in range(1, len(atomic_list)):
                if atomic_list[pos].executable == "invoke-expression":
                    prev_exec = atomic_list[pos - 1].executable
                    msg = f"Piping {prev_exec!r} output directly into PowerShell Invoke-Expression (iex)"
                    if msg not in obfuscation_reasons:
                        obfuscation_reasons.append(msg)

        executables: list[str] = []
        subcommands: list[str] = []
        target_paths: list[str] = []
        has_destructive = bool(_SQL_DESTRUCTIVE_RE.search(raw))

        for atom in atomic_list:
            if atom.executable and atom.executable not in executables:
                executables.append(atom.executable)
            if atom.subcommand and atom.subcommand not in subcommands:
                subcommands.append(atom.subcommand)
            if cls._is_ps_atomic_destructive(atom):
                has_destructive = True
            for p_cand in cls._extract_ps_paths(atom):
                if p_cand not in target_paths:
                    target_paths.append(p_cand)

        is_obf = bool(obfuscation_reasons) or any(a.is_obfuscated for a in atomic_list)

        return ParsedCommandAST(
            raw_command=raw,
            atomic_commands=tuple(atomic_list),
            executables=tuple(executables),
            subcommands=tuple(subcommands),
            target_paths=tuple(target_paths),
            has_pipes=has_pipes,
            has_subshells=has_subshells,
            has_background_ops=False,
            has_inline_script=has_inline_script,
            has_destructive_verbs=has_destructive,
            is_obfuscated=is_obf,
            obfuscation_reasons=tuple(obfuscation_reasons),
            complexity_exceeded=complexity_exceeded,
            max_depth=observed_max_depth,
            dialect="powershell",
            parser_backend="powershell-ast",
            syntax_errors=tuple(syntax_errors),
        )

    @classmethod
    def _parse_segment(
        cls,
        segment: str,
        *,
        wrappers: tuple[str, ...],
        sudo: bool,
        depth: int,
        obfuscation_reasons: list[str],
        syntax_errors: list[str],
    ) -> tuple[list[AtomicCommand], list[tuple[str, tuple[str, ...]]], bool]:
        tokens = _tokenize_ps_words(segment.strip())
        if not tokens:
            return [], [], False

        nested: list[tuple[str, tuple[str, ...]]] = []
        has_inline = False
        seg_obf = False
        cur_wrappers = list(wrappers)

        # Оператор вызова & или . (dot-sourcing)
        idx = 0
        if tokens[0] in ("&", "."):
            op = tokens[0]
            cur_wrappers.append(f"ps:{op}")
            idx = 1
            if op == "." and len(tokens) > 1:
                seg_obf = True
                msg = "PowerShell dot-sourcing script execution bypasses static inspection"
                if msg not in obfuscation_reasons:
                    obfuscation_reasons.append(msg)
            if idx >= len(tokens):
                return [], [], False

        raw_exec = tokens[idx]
        rest = tokens[idx + 1 :]

        # Снятие обфускации обратным апострофом
        deobf_exec, had_backtick = _strip_ps_backticks(raw_exec)
        if had_backtick:
            seg_obf = True
            msg = f"PowerShell backtick obfuscation inside command name ({raw_exec!r})"
            if msg not in obfuscation_reasons:
                obfuscation_reasons.append(msg)

        # Нормализация имени бинарника/cmdlet'а и алиасов
        clean_exec = os.path.basename(deobf_exec.replace("\\", "/")).lower()
        if clean_exec.endswith(".exe") and clean_exec not in _PS_SHELL_BINARIES:
            clean_exec = clean_exec[:-4]
        canonical_exec = _PS_ALIASES.get(clean_exec, clean_exec)

        # Перенаправления (> / >> / 2>)
        redirects: list[str] = []
        clean_rest: list[str] = []
        r_idx = 0
        while r_idx < len(rest):
            tok = rest[r_idx]
            if re.fullmatch(r"(?:\d|\*)?>>?", tok) and r_idx + 1 < len(rest):
                redirects.append(f"{tok} {rest[r_idx + 1]}")
                r_idx += 2
                continue
            if re.match(r"^(?:\d|\*)?>>?\S+", tok):
                redirects.append(tok)
                r_idx += 1
                continue
            clean_rest.append(tok)
            r_idx += 1

        # Парсинг флагов и позиционных аргументов
        flags: dict[str, str | bool] = {}
        pos_args: list[str] = []
        p_idx = 0
        while p_idx < len(clean_rest):
            tok = clean_rest[p_idx]
            tok_lower = tok.lower()
            if tok.startswith("-") and len(tok) > 1 and not tok[1:].isdigit():
                if ":" in tok:
                    fk, fv = tok.split(":", 1)
                    flags[fk.lower()] = fv
                    p_idx += 1
                    continue
                if canonical_exec in _PS_SHELL_BINARIES and tok_lower in _PS_COMMAND_FLAGS:
                    tail_tokens = clean_rest[p_idx + 1 :]
                    flags[tok_lower] = " ".join(tail_tokens) if tail_tokens else True
                    break
                if tok_lower in _PS_SWITCH_FLAGS:
                    flags[tok_lower] = True
                    p_idx += 1
                    continue
                if p_idx + 1 < len(clean_rest) and not clean_rest[p_idx + 1].startswith("-"):
                    flags[tok_lower] = clean_rest[p_idx + 1]
                    p_idx += 2
                    continue
                flags[tok_lower] = True
                p_idx += 1
                continue
            pos_args.append(tok)
            p_idx += 1

        # Распаковка powershell/pwsh -EncodedCommand / -Command
        if canonical_exec in _PS_SHELL_BINARIES:
            for fk, fv in flags.items():
                if fk in _PS_ENCODED_FLAGS and isinstance(fv, str):
                    has_inline = True
                    decoded, err = _decode_ps_encoded_command(fv)
                    if err is not None:
                        seg_obf = True
                        syntax_errors.append(err)
                        obf_msg = f"Malformed PowerShell -EncodedCommand payload: {err}"
                        if obf_msg not in obfuscation_reasons:
                            obfuscation_reasons.append(obf_msg)
                    elif decoded:
                        nested.append((decoded, (*cur_wrappers, f"{canonical_exec} -EncodedCommand")))
                elif fk in _PS_COMMAND_FLAGS and isinstance(fv, str):
                    has_inline = True
                    inner_cmd = fv.strip()
                    if inner_cmd.startswith("{") and inner_cmd.endswith("}"):
                        inner_cmd = inner_cmd[1:-1].strip()
                    if inner_cmd:
                        nested.append((inner_cmd, (*cur_wrappers, f"{canonical_exec} -Command")))

        # Invoke-Expression (iex) — динамическое исполнение кода
        if canonical_exec == "invoke-expression":
            has_inline = True
            seg_obf = True
            msg = "Dynamic PowerShell 'Invoke-Expression' (iex) execution is forbidden by AST guardrails"
            if msg not in obfuscation_reasons:
                obfuscation_reasons.append(msg)
            payload = " ".join(pos_args).strip()
            if payload:
                nested.append((payload, (*cur_wrappers, "invoke-expression")))

        # Извлечение вложенных script blocks ({ ... }) у ForEach-Object / Invoke-Command
        if canonical_exec in ("foreach-object", "invoke-command"):
            for arg in pos_args:
                if arg.startswith("{") and arg.endswith("}"):
                    inner = arg[1:-1].strip()
                    if inner:
                        has_inline = True
                        nested.append((inner, (*cur_wrappers, canonical_exec)))
            for fv in flags.values():
                if isinstance(fv, str) and fv.startswith("{") and fv.endswith("}"):
                    inner = fv[1:-1].strip()
                    if inner:
                        has_inline = True
                        nested.append((inner, (*cur_wrappers, canonical_exec)))

        subcmd: str | None = None
        if canonical_exec in ("reg", "net", "sc", "netsh", "vssadmin", "bcdedit") and pos_args:
            subcmd = pos_args[0].lower()

        atom = AtomicCommand(
            executable=canonical_exec,
            raw_executable=raw_exec,
            subcommand=subcmd,
            arguments=tuple(pos_args),
            flags=flags,
            redirects=tuple(redirects),
            wrappers=tuple(cur_wrappers),
            is_sudo=sudo,
            is_obfuscated=seg_obf,
            subshell_depth=depth,
        )
        return [atom], nested, has_inline

    @staticmethod
    def _is_ps_atomic_destructive(atom: AtomicCommand) -> bool:
        """Определить, является ли PowerShell-команда деструктивной."""
        if atom.executable in _PS_DESTRUCTIVE_CMDLETS:
            return True
        if atom.executable == "reg" and atom.subcommand in ("delete", "import"):
            return True
        if atom.executable == "net" and atom.subcommand in ("user", "localgroup", "stop"):
            return True
        return bool(atom.executable == "sc" and atom.subcommand in ("delete", "stop", "config"))

    @staticmethod
    def _extract_ps_paths(atom: AtomicCommand) -> list[str]:
        r"""Извлечь пути Windows ФС и реестра (``C:\\...``, ``HKLM:\\...``) из аргументов и флагов."""
        paths: list[str] = []

        def _add(val: str) -> None:
            cleaned = val.strip().strip("'\"")
            if not cleaned:
                return
            if _PS_PATH_RE.match(cleaned) or cleaned.startswith(("/", "./", "../")) or "..\\" in cleaned:
                norm = normalize_target_path(cleaned)
                if norm and norm not in paths:
                    paths.append(norm)

        for arg in atom.arguments:
            _add(arg)
        for fv in atom.flags.values():
            if isinstance(fv, str):
                _add(fv)
        for redir in atom.redirects:
            parts = redir.split(None, 1)
            if len(parts) == 2:
                _add(parts[1])
        return paths


__all__ = [
    "PowerShellASTParser",
    "is_powershell_command",
]
