# src/uniconn/parsing/detector.py
"""Автоматическое определение спецификации парсера по сигнатуре команды и формату вывода."""

from __future__ import annotations

import posixpath
import re
import shlex

_ENV_ASSIGN_RE: re.Pattern[str] = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")

_SUDO_ARG_FLAGS: frozenset[str] = frozenset({"-u", "-g", "-p", "-r", "-t", "-C", "-h", "-U"})

_SIMPLE_BINARY_MAP: dict[str, str] = {
    "df": "df",
    "uptime": "uptime",
    "ps": "ps",
    "free": "free",
    "mount": "mount",
    "ss": "ss",
    "netstat": "ss",
    "lsof": "lsof",
    "sysctl": "sysctl",
    "env": "kv",
    "printenv": "kv",
}


def _tokenize_command(command: str) -> list[str]:
    """Разбить команду на токены с распаковкой sudo, переменных окружения и sh -c."""
    cmd_str = command.strip()
    if not cmd_str:
        return []

    try:
        tokens = shlex.split(cmd_str)
    except ValueError:
        tokens = cmd_str.split()

    while tokens:
        # 1. Пропуск ведущих переменных окружения (LANG=C, LC_ALL=POSIX)
        if _ENV_ASSIGN_RE.match(tokens[0]):
            tokens.pop(0)
            continue

        base = posixpath.basename(tokens[0].replace("\\", "/"))

        # 2. Пропуск утилиты env и её флагов
        if base == "env" and len(tokens) > 1:
            tokens.pop(0)
            while tokens and (tokens[0].startswith("-") or _ENV_ASSIGN_RE.match(tokens[0])):
                flag = tokens.pop(0)
                if flag in ("-u", "--unset", "-C", "--chdir") and tokens:
                    tokens.pop(0)
            continue

        # 3. Распаковка sudo и его аргументов
        if base == "sudo":
            tokens.pop(0)
            while tokens and tokens[0].startswith("-"):
                flag = tokens.pop(0)
                if flag == "--":
                    break
                if flag in _SUDO_ARG_FLAGS and tokens:
                    tokens.pop(0)
            continue

        # 4. Распаковка оболочек sh -c / bash -c
        if base in ("sh", "bash", "zsh", "dash", "ash", "ksh") and len(tokens) >= 3:
            for idx, tok in enumerate(tokens[1:], start=1):
                if tok == "-c" and idx + 1 < len(tokens):
                    return _tokenize_command(tokens[idx + 1])
                if not tok.startswith("-"):
                    break

        break

    return tokens


def _has_json_flag(tokens: list[str]) -> bool:
    """Проверить наличие флагов вывода в формате JSON в токенах команды."""
    for idx, tok in enumerate(tokens):
        if tok in ("-j", "-json", "--json", "--format=json", "--output=json", "-o=json"):
            return True
        if tok in ("-o", "--output", "--format") and idx + 1 < len(tokens):
            nxt = tokens[idx + 1].lower()
            if nxt == "json" or nxt.startswith("json"):
                return True
    return False


def _detect_network_cli(tokens: list[str]) -> str | None:
    """Распознать команды сетевого оборудования (Cisco IOS / Arista / Juniper)."""
    lower_tokens = [t.lower() for t in tokens]
    if not lower_tokens or lower_tokens[0] not in ("show", "sh"):
        return None

    rest = lower_tokens[1:]
    joined = " ".join(rest)

    if joined.startswith(("ip interface brief", "ip int brief", "ip int br")):
        return "cisco_ios_show_ip_int_brief"

    if joined.startswith(("interfaces status", "int status")):
        return "cisco_ios_show_interfaces_status"

    if joined.startswith("ip route"):
        return "cisco_ios_show_ip_route"

    if joined.startswith(("version", "ver")):
        return "cisco_ios_show_version"

    return None


def _detect_from_content(text: str) -> str | None:
    """Определить формат (json / jsonl) по структуре самого текста вывода."""
    stripped = text.strip()
    if not stripped:
        return None

    if (stripped.startswith("{") and stripped.endswith("}")) or (
        stripped.startswith("[") and stripped.endswith("]")
    ):
        lines = [line.strip() for line in stripped.splitlines() if line.strip()]
        if (
            len(lines) > 1
            and stripped.startswith("{")
            and all(line.startswith("{") and line.endswith("}") for line in lines)
        ):
            return "jsonl"
        return "json"

    return None


def detect_parser_spec(command: str | None, text: str = "") -> str | None:
    """Автоматически определить каноническую спецификацию парсера по команде или выводу."""
    if command:
        # Если команда содержит пайп, анализируем последний сегмент (например, '... | jq')
        first_stmt = command.split(";")[0].split("&&")[0].strip()
        tokens = _tokenize_command(first_stmt)

        if tokens:
            if _has_json_flag(tokens):
                return "json"

            binary = posixpath.basename(tokens[0].replace("\\", "/")).lower()
            sub_tokens = [t for t in tokens[1:] if not t.startswith("-")]
            subcmd = sub_tokens[0].lower() if sub_tokens else ""

            if binary in ("docker", "podman"):
                if subcmd == "inspect":
                    return "json"
                if subcmd in ("ps", "images", "volume", "network"):
                    return "table"

            if binary in ("kubectl", "oc"):
                if _has_json_flag(tokens):
                    return "json"
                if subcmd in ("get", "top"):
                    return "table"

            if binary in _SIMPLE_BINARY_MAP:
                return _SIMPLE_BINARY_MAP[binary]

            if binary == "ip":
                if subcmd.startswith("r"):
                    return "ip_route"
                if subcmd.startswith(("a", "l")):
                    return "ip_addr"
                return "ip_addr"

            if binary == "systemctl":
                if subcmd == "status":
                    return "systemctl_status"
                if subcmd in ("list-units", "list-unit-files", "list-timers", "list-sockets"):
                    return "table"

            net_spec = _detect_network_cli(tokens)
            if net_spec is not None:
                return net_spec

    return _detect_from_content(text)


__all__ = ["detect_parser_spec"]
