# src/uniconn/core/_shell_quoting.py
"""Единые утилиты безопасного экранирования для PowerShell/cmd.exe, валидации env и парсинга bool."""

from __future__ import annotations

import base64
import re
from typing import Any

_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_CMD_UNSAFE_RE = re.compile(r'["&|<>^%!\r\n\x00;`$()]')
_TRUE_STRINGS = frozenset({"1", "true", "yes", "on", "y"})
_FALSE_STRINGS = frozenset({"0", "false", "no", "off", "n", ""})


_PS_SINGLE_QUOTES: tuple[str, ...] = ("'", "\u2018", "\u2019", "\u201a", "\u201b")


def ps_quote(value: str) -> str:
    """Экранировать строку как безопасный литерал PowerShell в одинарных кавычках.

    Удваивает ASCII-апостроф и все Unicode-варианты одинарных кавычек, которые парсер
    PowerShell интерпретирует как закрывающий делимитер строкового литерала.
    """
    text = str(value)
    if "\x00" in text:
        raise ValueError("NUL byte is not allowed in PowerShell string literal")
    for q in _PS_SINGLE_QUOTES:
        if q in text:
            text = text.replace(q, q + q)
    return "'" + text + "'"


def ps_encoded_command(script: str) -> str:
    """Сформировать инъекционно-безопасную команду ``powershell -NoProfile -NonInteractive -EncodedCommand ...``."""
    if "\x00" in script:
        raise ValueError("NUL byte is not allowed in PowerShell script")
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    return f"powershell -NoProfile -NonInteractive -EncodedCommand {encoded}"


def has_cmd_metacharacters(value: str) -> bool:
    """Проверить, содержит ли строка метасимволы ``cmd.exe`` или управляющие символы."""
    return bool(_CMD_UNSAFE_RE.search(value))


def validate_env_key(key: Any) -> str:
    """Проверить корректность имени переменной окружения (защита от инъекции ключей)."""
    key_str = str(key)
    if not _ENV_KEY_RE.fullmatch(key_str):
        raise ValueError(f"Invalid environment variable name: {key_str!r}")
    return key_str


def validate_windows_interpreter(interpreter: str) -> str:
    """Проверить путь/имя интерпретатора Python на Windows на отсутствие shell-инъекции."""
    cleaned = interpreter.strip()
    if not cleaned:
        raise ValueError("Empty python_interpreter is not allowed")
    if any(
        ch in cleaned
        for ch in (
            '"', "'", "\u2018", "\u2019", "\u201a", "\u201b",
            "`", "$", ";", "|", "&", "<", ">", "\r", "\n", "\x00",
        )
    ):
        raise ValueError(f"Unsafe characters in python_interpreter: {interpreter!r}")
    return cleaned


def parse_bool(value: Any, *, default: bool = False) -> bool:
    """Безопасно преобразовать значение опции (bool, int, str) в ``bool``.

    В отличие от встроенного ``bool("false") == True``, корректно обрабатывает
    строки ``"false"``, ``"0"``, ``"no"``, ``"off"``, ``""`` как ``False``.
    """
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        norm = value.strip().lower()
        if norm in _TRUE_STRINGS:
            return True
        if norm in _FALSE_STRINGS:
            return False
    return bool(value)


def parse_verify_ssl(value: Any, *, default: bool = True) -> bool | str:
    """Нормализовать ``verify_ssl``/``verify``: булевы строки в ``bool``, путь к CA — как ``str``."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return default
        norm = stripped.lower()
        if norm in _TRUE_STRINGS:
            return True
        if norm in _FALSE_STRINGS:
            return False
        return stripped
    return bool(value)


__all__ = [
    "has_cmd_metacharacters",
    "parse_bool",
    "parse_verify_ssl",
    "ps_encoded_command",
    "ps_quote",
    "validate_env_key",
    "validate_windows_interpreter",
]
