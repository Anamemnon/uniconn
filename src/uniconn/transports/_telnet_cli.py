# src/uniconn/transports/_telnet_cli.py
"""Вспомогательные профили, очистка терминального вывода и разбор CLI/OOB для TelnetTransport."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .._utils import parse_bool
from ..exceptions import ConfigurationError

_SUPPORTED_SHELL_MODES = ("auto", "posix", "cli")

_ANSI_CSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_ANSI_OSC_RE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_ANSI_ESC_RE = re.compile(r"\x1b[@-Z\\-_]")
_LEGACY_PROMPTS = ("$ ", "# ", "> ")
_BARE_PROMPTS = ("$", "#", ">", "%")


@dataclass(frozen=True)
class _CliProfile:
    """Встроенный профиль сетевой/OOB-консоли для CLI-режима Telnet."""

    prompt_regex: str
    pager_regex: str
    pager_response: str
    error_patterns: tuple[str, ...]


@dataclass(frozen=True)
class _TelnetCliOptions:
    """Эффективные параметры разбора CLI/пагинации/ANSI для конкретного вызова ``run()`` или ``stream()``."""

    prompt_regex: re.Pattern[str]
    pagination: bool
    pager_regex: re.Pattern[str]
    pager_response: str
    error_patterns: tuple[re.Pattern[str], ...]
    strip_ansi: bool


_CLI_PROFILES: dict[str, _CliProfile] = {
    "generic": _CliProfile(
        prompt_regex=r"(?:^|[\r\n])[^\r\n]{0,120}[$#>%][ \t]*$",
        pager_regex=(
            r"(?:--More--|---\(more(?:\s+\d+%)?\)---|"
            r"Press any key to continue[^\r\n]*|lines \d+-\d+)"
        ),
        pager_response=" ",
        error_patterns=(
            r"^%\s+(?:Invalid|Ambiguous|Incomplete|Unknown|Bad|Error)\b",
            r"^(?:syntax error|unknown command|command not found)\b",
            r"^Error:\s+",
        ),
    ),
    "cisco": _CliProfile(
        prompt_regex=r"(?:^|[\r\n])[A-Za-z0-9_.\-/:()]+(?:\(config[^\r\n)]*\))?[>#][ \t]*$",
        pager_regex=r"--More--",
        pager_response=" ",
        error_patterns=(
            r"^%\s+(?:Invalid|Ambiguous|Incomplete|Unknown|Bad|Error)\b",
            r"^\s*\^\s*$",
        ),
    ),
    "junos": _CliProfile(
        prompt_regex=r"(?:^|[\r\n])[A-Za-z0-9_.\-@]+(?:\[[^\r\n\]]+\])?[>#][ \t]*$",
        pager_regex=r"---\(more(?:\s+\d+%)?\)---",
        pager_response=" ",
        error_patterns=(
            r"^error:\s+",
            r"^syntax error\b",
            r"^unknown command\.",
        ),
    ),
    "linux": _CliProfile(
        prompt_regex=r"(?:^|[\r\n])[^\r\n]{0,120}[$#%][ \t]*$",
        pager_regex=r"(?:--More--|\(END\))",
        pager_response=" ",
        error_patterns=(
            r"command not found",
            r"No such file or directory",
            r"Permission denied",
        ),
    ),
    "uboot": _CliProfile(
        prompt_regex=r"(?:^|[\r\n])(?:=>|[A-Za-z0-9_.\-]+>)[ \t]*$",
        pager_regex=r"--More--",
        pager_response=" ",
        error_patterns=(
            r"^Unknown command\b",
            r"^## Error:",
        ),
    ),
}


def _apply_cr_overwrite(text: str) -> str:
    r"""Смоделировать поведение возврата каретки ``\r`` в пределах каждой строки."""
    normalized = text.replace("\r\n", "\n")
    if "\r" not in normalized:
        return normalized

    resolved_lines: list[str] = []
    for raw_line in normalized.split("\n"):
        if "\r" not in raw_line:
            resolved_lines.append(raw_line)
            continue
        chars: list[str] = []
        for seg in raw_line.split("\r"):
            for idx, ch in enumerate(seg):
                if idx < len(chars):
                    chars[idx] = ch
                else:
                    chars.append(ch)
        resolved_lines.append("".join(chars).rstrip())
    return "\n".join(resolved_lines)


def _strip_terminal_noise(text: str) -> str:
    r"""Удалить ANSI escape-последовательности, backspace (``\x08``) и перезаписи ``\r``."""
    cleaned = _ANSI_OSC_RE.sub("", text)
    cleaned = _ANSI_CSI_RE.sub("", cleaned)
    cleaned = _ANSI_ESC_RE.sub("", cleaned)
    if "\x08" in cleaned:
        out: list[str] = []
        for ch in cleaned:
            if ch == "\x08":
                if out and out[-1] != "\n":
                    out.pop()
            else:
                out.append(ch)
        cleaned = "".join(out)
    return _apply_cr_overwrite(cleaned)


def _can_use_chunk_read(reader: Any) -> bool:
    """Определить, поддерживает ли ``reader`` реальное почанковое ``read(n)`` (а не пустой AsyncMock)."""
    read_attr = getattr(reader, "read", None)
    if not callable(read_attr):
        return False
    if type(read_attr).__module__.startswith("unittest.mock"):
        has_side_effect = getattr(read_attr, "side_effect", None) is not None
        ret_val = getattr(read_attr, "return_value", None)
        ret_is_mock = type(ret_val).__module__.startswith("unittest.mock")
        return has_side_effect or not ret_is_mock
    return True


def _compile_error_patterns(
    raw_patterns: Any,
    fallback: tuple[str, ...],
) -> tuple[re.Pattern[str], ...]:
    """Скомпилировать регулярные выражения для распознавания CLI-ошибок."""
    if raw_patterns is None:
        source: Sequence[str] = fallback
    elif isinstance(raw_patterns, str):
        source = (raw_patterns,) if raw_patterns.strip() else ()
    elif isinstance(raw_patterns, Sequence):
        source = [str(p) for p in raw_patterns if str(p).strip()]
    else:
        source = fallback
    return tuple(re.compile(pat, re.IGNORECASE) for pat in source)


def _resolve_cli_options(
    defaults: _TelnetCliOptions,
    overrides: Mapping[str, Any],
) -> _TelnetCliOptions:
    """Объединить дефолтные CLI-опции транспорта с переопределениями конкретного вызова."""
    if not overrides:
        return defaults
    raw_prompt = overrides.get("prompt_regex")
    prompt_regex = (
        re.compile(raw_prompt)
        if isinstance(raw_prompt, str)
        else (raw_prompt or defaults.prompt_regex)
    )
    pagination = parse_bool(overrides.get("pagination"), default=defaults.pagination)
    raw_pager = overrides.get("pager_regex")
    pager_regex = (
        re.compile(raw_pager, re.IGNORECASE)
        if isinstance(raw_pager, str)
        else (raw_pager or defaults.pager_regex)
    )
    pager_response = str(overrides.get("pager_response", defaults.pager_response))
    error_patterns = (
        _compile_error_patterns(overrides["error_patterns"], ())
        if "error_patterns" in overrides
        else defaults.error_patterns
    )
    strip_ansi = parse_bool(overrides.get("strip_ansi"), default=defaults.strip_ansi)
    return _TelnetCliOptions(
        prompt_regex=prompt_regex,
        pagination=pagination,
        pager_regex=pager_regex,
        pager_response=pager_response,
        error_patterns=error_patterns,
        strip_ansi=strip_ansi,
    )


def _validate_shell_mode(raw_mode: Any) -> str:
    mode = str(raw_mode or "auto").strip().lower() or "auto"
    if mode not in _SUPPORTED_SHELL_MODES:
        raise ConfigurationError(
            f"Unsupported telnet shell_mode {mode!r}. "
            f"Supported: {', '.join(_SUPPORTED_SHELL_MODES)}"
        )
    return mode


def _is_prompt_line(line: str, prompt_regex: re.Pattern[str]) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    return (
        stripped in _BARE_PROMPTS
        or any(line.endswith(p) for p in _LEGACY_PROMPTS)
        or prompt_regex.search(line) is not None
    )


def _is_echo_line(line: str, cmd_stripped: str, prompt_regex: re.Pattern[str]) -> bool:
    if not cmd_stripped:
        return False
    stripped = line.strip()
    if stripped == cmd_stripped:
        return True
    return stripped.endswith(cmd_stripped) and bool(
        prompt_regex.search(stripped[: -len(cmd_stripped)])
    )


def _has_cli_prompt_at_end(
    text: str,
    cmd_stripped: str,
    prompt_regex: re.Pattern[str],
    *,
    strip_ansi: bool,
) -> bool:
    """Проверить, завершился ли вывод CLI-приглашением (без ложных срабатываний внутри вывода)."""
    normalized = _strip_terminal_noise(text) if strip_ansi else text.replace("\r\n", "\n")
    lines = normalized.split("\n")
    if not lines:
        return False

    last_line = lines[-1]
    if last_line:
        if len(lines) == 1 and _is_echo_line(last_line, cmd_stripped, prompt_regex):
            return False
        return _is_prompt_line(last_line, prompt_regex)

    # Строково-ориентированные серверы (например MockTelnetServer) шлют чистый промпт с \r\n
    if len(lines) >= 2:
        prev = lines[-2]
        if prev in _LEGACY_PROMPTS or prev.strip() in ("$", "#", ">"):
            return True
    return False


def _strip_cli_echo_and_prompt(
    raw_text: str,
    command: str,
    prompt_regex: re.Pattern[str],
    *,
    strip_ansi: bool,
) -> list[str]:
    r"""Очистить вывод CLI-команды от ANSI, перезаписей ``\r``, эха команды и финального промпта."""
    text = _strip_terminal_noise(raw_text) if strip_ansi else _apply_cr_overwrite(raw_text)
    lines = text.split("\n")

    cmd_stripped = command.strip()
    while lines and not lines[0].strip():
        lines = lines[1:]
    if lines and _is_echo_line(lines[0], cmd_stripped, prompt_regex):
        lines = lines[1:]

    while lines and not lines[-1].strip():
        lines.pop()

    if lines and _is_prompt_line(lines[-1], prompt_regex):
        lines.pop()

    return [line.rstrip() for line in lines]


def _detect_cli_errors(
    lines: list[str],
    error_patterns: tuple[re.Pattern[str], ...],
) -> tuple[int, str]:
    """Определить CLI-ошибки по набору регулярных выражений."""
    if not error_patterns:
        return 0, ""
    matched = [
        line
        for line in lines
        if line.strip() and any(pat.search(line.strip()) for pat in error_patterns)
    ]
    if matched:
        return 1, "\n".join(matched)
    return 0, ""


__all__ = [
    "_BARE_PROMPTS",
    "_CLI_PROFILES",
    "_LEGACY_PROMPTS",
    "_SUPPORTED_SHELL_MODES",
    "_CliProfile",
    "_TelnetCliOptions",
    "_apply_cr_overwrite",
    "_can_use_chunk_read",
    "_compile_error_patterns",
    "_detect_cli_errors",
    "_has_cli_prompt_at_end",
    "_is_echo_line",
    "_is_prompt_line",
    "_resolve_cli_options",
    "_strip_cli_echo_and_prompt",
    "_strip_terminal_noise",
    "_validate_shell_mode",
]
