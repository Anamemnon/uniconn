# src/uniconn/security/regex_safety.py
"""Валидация регулярных выражений с защитой от синтаксических ошибок и ReDoS."""

from __future__ import annotations

import re

from ..exceptions import ConfigurationError

_DEFAULT_MAX_REGEX_LENGTH = 512


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


def _detect_nested_quantifier_redos(pattern: str) -> str | None:
    """Обнаружить вложенные квантификаторы (``(a+)+``, ``(.*)+``, ``(a|b+)*``), вызывающие ReDoS."""
    # Стек для отслеживания открытых скобок: [содержит_ли_группа_квантификатор_повторения]
    group_stack: list[bool] = []
    in_char_class = False
    i = 0
    n = len(pattern)

    while i < n:
        ch = pattern[i]
        if ch == "\\":
            i += 2
            continue
        if in_char_class:
            if ch == "]":
                in_char_class = False
            i += 1
            continue
        if ch == "[":
            in_char_class = True
            i += 1
            continue
        if ch == "(":
            # Lookahead / lookbehind / non-capturing тоже учитываются
            group_stack.append(False)
            i += 1
            continue
        if ch == ")":
            inner_has_rep = group_stack.pop() if group_stack else False
            has_q, is_unbounded = _has_quantifier_after(pattern, i + 1)
            if has_q and inner_has_rep and is_unbounded:
                return "Nested quantifier on repeating group detected (potential ReDoS)"
            if group_stack and (inner_has_rep or is_unbounded):
                group_stack[-1] = True
            i += 1
            continue
        if ch in ("+", "*") or (ch == "{" and _has_quantifier_after(pattern, i)[1]):
            if group_stack:
                group_stack[-1] = True
            # Проверка двойных подряд идущих квантификаторов вроде a** или a+*
            next_idx = i + 1
            if ch == "{":
                close = pattern.find("}", i + 1)
                next_idx = close + 1 if close != -1 else i + 1
            if next_idx < n and pattern[next_idx] in ("+", "*"):
                # *?, +?, *+, ++ в Python допустимы только как lazy/possessive; два символа с {..} подозрительны
                pass
        i += 1

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
