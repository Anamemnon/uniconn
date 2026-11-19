# src/uniconn/security/regex_safety.py
"""Валидация регулярных выражений с защитой от синтаксических ошибок и ReDoS."""

from __future__ import annotations

import re

from ..exceptions import ConfigurationError

_DEFAULT_MAX_REGEX_LENGTH = 512
_BACKREF_RE = re.compile(r"\\(?:[1-9]\d*|k<[A-Za-z_]\w*>)")
_CHAINED_ATOM_RE = re.compile(r"(?:([A-Za-z0-9_])[\+\*]\1[\+\*]\1[\+\*]|(\\[wdsWDS])[\+\*]\2[\+\*]\2[\+\*])")


def _has_quantifier_after(pattern: str, pos: int) -> tuple[bool, bool]:
    """Определить наличие квантификатора в позиции ``pos`` и является ли он неограниченным."""
    if pos >= len(pattern):
        return False, False
    ch = pattern[pos]
    if ch in ("+", "*"):
        return True, True
    if ch == "?":
        return True, False
    if ch == "{":
        close = pattern.find("}", pos + 1)
        if close != -1:
            body = pattern[pos + 1 : close]
            if re.fullmatch(r"\d+(?:,\d*)?", body):
                is_unbounded = "," in body and body.endswith(",")
                if "," in body and not is_unbounded:
                    low_s, high_s = body.split(",", 1)
                    is_unbounded = high_s == "" or (int(high_s) - int(low_s)) > 3
                return True, is_unbounded
    return False, False


def _split_top_level_alternatives(group_body: str) -> list[str]:
    """Разбить тело группы по верхнеуровневому ``|`` с учётом экранирования и вложенных групп."""
    alts: list[str] = []
    buf: list[str] = []
    depth = 0
    in_cc = False
    cc_first = False
    i = 0
    n = len(group_body)
    while i < n:
        ch = group_body[i]
        if ch == "\\":
            buf.append(group_body[i : i + 2])
            i += 2
            continue
        if in_cc:
            buf.append(ch)
            if ch == "]" and not cc_first:
                in_cc = False
            cc_first = False
            i += 1
            continue
        if ch == "[":
            in_cc = True
            cc_first = True
            buf.append(ch)
            if i + 1 < n and group_body[i + 1] == "^":
                buf.append("^")
                i += 2
                continue
            i += 1
            continue
        if ch == "(":
            depth += 1
            buf.append(ch)
        elif ch == ")":
            depth = max(0, depth - 1)
            buf.append(ch)
        elif ch == "|" and depth == 0:
            alts.append("".join(buf))
            buf.clear()
        else:
            buf.append(ch)
        i += 1
    alts.append("".join(buf))
    return alts


def _has_overlapping_alternatives(group_body: str) -> bool:
    """Проверить наличие дублирующихся или явно пересекающихся альтернатив в повторяемой группе."""
    # Убрать префикс non-capturing/named group вроде ?:, ?P<name>, ?i:
    cleaned = re.sub(r"^\?(?::|P<[^>]+>|[aiLmsux-]+:)", "", group_body)
    alts = _split_top_level_alternatives(cleaned)
    if len(alts) < 2:
        return False
    seen: set[str] = set()
    for alt in alts:
        if not alt:
            return True
        if alt in seen:
            return True
        seen.add(alt)
    # Проверка тривиального префиксного пересечения (например, (a|ab)+ или (\w|\d)+)
    if any(a == "." or a == "\\w" for a in alts):
        return True
    for idx, left in enumerate(alts):
        for right in alts[idx + 1 :]:
            if (left.startswith(right) or right.startswith(left)) and min(len(left), len(right)) > 0:
                return True
    return False


def _detect_nested_quantifier_redos(pattern: str) -> str | None:
    """Обнаружить конструкции ReDoS: вложенные квантификаторы, перекрывающиеся альтернативы, backrefs, цепочки."""
    # Стек для открытых скобок: [start_index, has_inner_rep, has_backref]
    group_stack: list[list[int | bool]] = []
    in_char_class = False
    cc_just_opened = False
    unbounded_wildcards = 0
    i = 0
    n = len(pattern)

    while i < n:
        ch = pattern[i]
        if ch == "\\":
            # Проверка обратных ссылок \1.. или \k<name> с квантификатором или внутри повторяемой группы
            if i + 1 < n and (pattern[i + 1].isdigit() or pattern[i + 1] == "k"):
                m = _BACKREF_RE.match(pattern, i)
                if m:
                    has_q, is_unb = _has_quantifier_after(pattern, m.end())
                    if has_q and is_unb:
                        return "Quantified backreference detected (potential ReDoS)"
                    if group_stack:
                        group_stack[-1][2] = True
                    i = m.end()
                    continue
            i += 2
            continue
        if in_char_class:
            if ch == "]" and not cc_just_opened:
                in_char_class = False
            cc_just_opened = False
            i += 1
            continue
        if ch == "[":
            in_char_class = True
            cc_just_opened = True
            if i + 1 < n and pattern[i + 1] == "^":
                i += 2
                continue
            i += 1
            continue
        if ch == "(":
            group_stack.append([i, False, False])
            i += 1
            continue
        if ch == ")":
            start_idx = 0
            inner_has_rep = False
            inner_has_backref = False
            if group_stack:
                frame = group_stack.pop()
                start_idx = int(frame[0])
                inner_has_rep = bool(frame[1])
                inner_has_backref = bool(frame[2])
            has_q, is_unbounded = _has_quantifier_after(pattern, i + 1)
            if has_q and is_unbounded:
                if inner_has_rep:
                    return "Nested quantifier on repeating group detected (potential ReDoS)"
                if inner_has_backref:
                    return "Quantified group containing backreference detected (potential ReDoS)"
                group_body = pattern[start_idx + 1 : i]
                if _has_overlapping_alternatives(group_body):
                    return "Overlapping alternation inside quantified group detected (potential ReDoS)"
            if group_stack:
                if inner_has_rep or is_unbounded:
                    group_stack[-1][1] = True
                if inner_has_backref:
                    group_stack[-1][2] = True
            i += 1
            continue
        if ch == "." and _has_quantifier_after(pattern, i + 1)[1]:
            unbounded_wildcards += 1
            if unbounded_wildcards >= 3:
                return "Excessive chained unbounded wildcards detected (potential polynomial ReDoS)"
        if (ch in ("+", "*") or (ch == "{" and _has_quantifier_after(pattern, i)[1])) and group_stack:
            group_stack[-1][1] = True
        i += 1

    # Проверка цепочек повторяющихся одинаковых атомов с квантификатором (например, a+a+a+ или \w+\w+\w+)
    if _CHAINED_ATOM_RE.search(pattern):
        return "Polynomial chained quantifiers detected (potential ReDoS)"

    return None


def validate_safe_regex(
    pattern: str,
    *,
    max_length: int = _DEFAULT_MAX_REGEX_LENGTH,
    flags: int = 0,
) -> re.Pattern[str]:
    """Провалидировать и скомпилировать регулярное выражение с защитой от ReDoS.

    Args:
        pattern: Исходная строка регулярного выражения.
        max_length: Максимально допустимая длина паттерна (по умолчанию 512 символов).
        flags: Флаги ``re.compile``.

    Returns:
        Скомпилированный объект ``re.Pattern[str]``.

    Raises:
        ConfigurationError: При пустом, слишком длинном, синтаксически неверном
            или потенциально уязвимом к ReDoS регулярном выражении.

    """
    if not isinstance(pattern, str) or not pattern:
        raise ConfigurationError("Regular expression pattern must be a non-empty string")
    if len(pattern) > max_length:
        raise ConfigurationError(
            f"Regular expression exceeds maximum allowed length of {max_length} characters "
            f"(got {len(pattern)})"
        )

    redos_reason = _detect_nested_quantifier_redos(pattern)
    if redos_reason is not None:
        raise ConfigurationError(f"{redos_reason}: {pattern!r}")

    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        raise ConfigurationError(f"Invalid regular expression {pattern!r}: {exc}") from exc


__all__ = ["validate_safe_regex"]
