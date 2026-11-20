# src/uniconn/security/_ast_posix_scan.py
"""Низкоуровневый сканер POSIX/Bash токенов, подстановок, heredoc-блоков и баланса синтаксиса."""

from __future__ import annotations

import re

_HEREDOC_START_RE = re.compile(r"<<-?\s*(?:'([^']+)'|\"([^\"]+)\"|([A-Za-z0-9_.-]+))")


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


def _scan_arith_inner(text: str, start: int) -> tuple[str, int]:
    """Просканировать содержимое арифметической подстановки ``$((...))`` до балансного ``))``."""
    n = len(text)
    p_depth = 2
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
    inner = text[start : max(start, j - 2)].strip() if p_depth == 0 else text[start:].strip()
    return inner, j


def _unwrap_grouped_segment(seg_clean: str) -> tuple[str | None, str | None]:
    """Раскрыть внешнюю группировку subshell ``(cmd)`` или ``{ cmd; }`` (включая редиректы после неё)."""
    if seg_clean.startswith("("):
        inner, end_idx = _scan_paren_inner(seg_clean, 1)
        if inner and end_idx <= len(seg_clean):
            trailing = seg_clean[end_idx:].strip()
            if not trailing or trailing.startswith((">", "<", "2>", "1>", "&>")):
                return inner, "subshell"
    if seg_clean.startswith("{") and len(seg_clean) > 1 and seg_clean[1].isspace():
        body = seg_clean[1:].strip()
        if body.endswith("}"):
            body = body[:-1].strip().rstrip(";").strip()
        if body:
            return body, "group"
    return None, None


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


def _detect_builtin_syntax_errors(command: str) -> list[str]:
    """Проверить баланс кавычек, обратных кавычек и скобок в POSIX-строке (fail-closed fallback)."""
    errors: list[str] = []
    in_single = False
    in_double = False
    in_backtick = False
    escape = False
    paren_depth = 0
    for ch in command:
        if escape:
            escape = False
            continue
        if ch == "\\" and not in_single:
            escape = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            continue
        if ch == "`" and not in_single:
            in_backtick = not in_backtick
            continue
        if not in_single and not in_double:
            if ch == "(":
                paren_depth += 1
            elif ch == ")":
                paren_depth -= 1
    if in_single:
        errors.append("Unclosed single quote in POSIX shell command")
    if in_double:
        errors.append("Unclosed double quote in POSIX shell command")
    if in_backtick:
        errors.append("Unclosed backtick command substitution in POSIX shell command")
    if paren_depth > 0:
        errors.append("Unclosed parenthesis '(' in POSIX shell command")
    return errors


def tokenize_top_level_segments(command: str) -> tuple[list[str], bool, bool]:
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


def extract_subshell_commands(
    probe_str: str,
    *,
    base_depth: int = 1,
    max_recursion_depth: int = 6,
) -> list[tuple[str, int]]:
    """Извлечь вложенные команды из ``$(...)``, ``<(...)``, ``>(...)`` и обратных кавычек `` `...` ``."""
    extracted: list[tuple[str, int]] = []
    seen: set[str] = set()

    def _scan(text: str, current_depth: int) -> None:
        if current_depth > max_recursion_depth + 1:
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
                        arith_inner, i = _scan_arith_inner(text, i + 3)
                        if arith_inner:
                            _scan(arith_inner, current_depth)
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


def extract_builtin_heredocs(command: str) -> list[str]:
    """Извлечь тела heredoc-блоков (``<< EOF ... EOF``) для встроенного POSIX-парсера."""
    if "<<" not in command or "\n" not in command:
        return []
    lines = command.splitlines()
    payloads: list[str] = []
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        match = _HEREDOC_START_RE.search(line)
        if match and "<<<" not in line:
            delim = match.group(1) or match.group(2) or match.group(3)
            if delim:
                body_lines: list[str] = []
                idx += 1
                while idx < len(lines):
                    if lines[idx].strip() == delim:
                        break
                    body_lines.append(lines[idx])
                    idx += 1
                body_text = "\n".join(body_lines).strip()
                if body_text:
                    payloads.append(body_text)
        idx += 1
    return payloads


__all__ = [
    "_detect_builtin_syntax_errors",
    "_scan_arith_inner",
    "_scan_backtick_inner",
    "_scan_paren_inner",
    "_unwrap_grouped_segment",
    "extract_builtin_heredocs",
    "extract_subshell_commands",
    "tokenize_top_level_segments",
]
