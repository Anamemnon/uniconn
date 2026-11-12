# src/uniconn/parsing/engines/textfsm_engine.py
"""Адаптер интеграции с TextFSM и каталогом сетевых шаблонов ntc-templates."""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

from ...exceptions import OptionalDependencyError, ParserNotFoundError, ParsingError

try:
    import textfsm as _textfsm_mod  # type: ignore[import-not-found,import-untyped]
except ImportError:
    _textfsm_mod = None  # type: ignore[assignment]

try:
    from ntc_templates.parse import (  # type: ignore[import-not-found,import-untyped]
        parse_output as _ntc_parse_output,
    )
except ImportError:
    _ntc_parse_output = None  # type: ignore[assignment]


class TextFSMEngine:
    """Движок парсинга вывода сетевого оборудования через ``TextFSM`` и ``ntc-templates``."""

    name: str = "textfsm"

    @staticmethod
    def is_available() -> bool:
        """Проверить, установлена ли библиотека ``textfsm``."""
        return _textfsm_mod is not None

    @staticmethod
    def has_ntc_templates() -> bool:
        """Проверить, установлен ли пакет ``ntc-templates``."""
        return _ntc_parse_output is not None

    def can_parse(self, spec: str) -> bool:
        """Проверить, является ли спецификация шаблоном TextFSM."""
        if _textfsm_mod is None:
            return False
        return spec.endswith((".textfsm", ".fsm")) or "Value " in spec

    def parse(self, text: str, spec: str, **kwargs: Any) -> list[dict[str, Any]]:
        """Распарсить текст по шаблону ``TextFSM`` или имени шаблона из ``ntc-templates``."""
        if _textfsm_mod is None:
            raise OptionalDependencyError(
                "Parsing with 'textfsm' requires the textfsm library. "
                "Install with: pip install 'uniconn[parsing]'"
            )

        # 1. Прямой шаблон TextFSM (строка с 'Value ...' или путь к файлу .textfsm/.fsm)
        template_text = self._resolve_direct_template(spec)
        if template_text is not None:
            return self._parse_with_textfsm_template(text, template_text)

        # 2. Разрешение через ntc-templates (например, "cisco_ios_show_ip_int_brief")
        platform: str | None = kwargs.get("platform")
        command: str | None = kwargs.get("command")
        if platform is None or command is None:
            inferred = self._split_ntc_spec(spec)
            if inferred is not None:
                platform, command = inferred

        if platform and command and _ntc_parse_output is not None:
            try:
                rows = _ntc_parse_output(platform=platform, command=command, data=text)
                return self._enrich_network_aliases(spec, rows)
            except Exception as exc:
                raise ParsingError(
                    f"ntc-templates failed for platform={platform!r}, command={command!r}: {exc}"
                ) from exc

        if _ntc_parse_output is None:
            raise OptionalDependencyError(
                f"Template {spec!r} is not a local file and 'ntc-templates' is not installed. "
                "Install with: pip install 'uniconn[parsing]'"
            )

        raise ParserNotFoundError(f"TextFSM template not found for spec: {spec!r}")

    @staticmethod
    def _resolve_direct_template(spec: str) -> str | None:
        """Вернуть текст шаблона TextFSM, если передана встроенная строка или путь к файлу."""
        if "Value " in spec and "Start" in spec:
            return spec
        if "\n" not in spec:
            path = Path(spec)
            if path.is_file():
                return path.read_text(encoding="utf-8")
            if spec.endswith((".textfsm", ".fsm")):
                raise ParserNotFoundError(f"TextFSM template file not found: {spec!r}")
        return None

    @staticmethod
    def _parse_with_textfsm_template(text: str, template_text: str) -> list[dict[str, Any]]:
        """Выполнить разбор текста через ``textfsm.TextFSM`` и вернуть список словарей."""
        if _textfsm_mod is None:
            raise OptionalDependencyError("TextFSM parsing requires the textfsm library.")
        try:
            fsm = _textfsm_mod.TextFSM(io.StringIO(template_text))
            raw_rows = fsm.ParseText(text)
            headers = [h.lower() for h in fsm.header]
            return [dict(zip(headers, row, strict=False)) for row in raw_rows]
        except Exception as exc:
            raise ParsingError(f"TextFSM parsing error: {exc}") from exc

    @staticmethod
    def _split_ntc_spec(spec: str) -> tuple[str, str] | None:
        """Разделить строку вида ``cisco_ios_show_ip_int_brief`` на ``(platform, command)``."""
        known_prefixes = (
            "cisco_ios_xe_",
            "cisco_ios_xr_",
            "cisco_ios_",
            "cisco_nxos_",
            "cisco_asa_",
            "arista_eos_",
            "juniper_junos_",
            "mikrotik_routeros_",
            "huawei_vrp_",
            "linux_",
        )
        lower_spec = spec.lower()
        for prefix in known_prefixes:
            if lower_spec.startswith(prefix):
                platform = prefix[:-1]
                cmd = lower_spec[len(prefix) :].replace("_", " ")
                return platform, cmd
        if "_show_" in lower_spec:
            plat, cmd_part = lower_spec.split("_show_", 1)
            return plat, f"show {cmd_part.replace('_', ' ')}"
        return None

    @staticmethod
    def _enrich_network_aliases(
        spec: str, rows: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Добавить совместимые алиасы полей (например, ``interface`` <-> ``intf``)."""
        for row in rows:
            if "interface" in row and "intf" not in row:
                row["intf"] = row["interface"]
            elif "intf" in row and "interface" not in row:
                row["interface"] = row["intf"]
            if "ip_address" in row and "ipaddr" not in row:
                row["ipaddr"] = row["ip_address"]
            elif "ipaddr" in row and "ip_address" not in row:
                row["ip_address"] = row["ipaddr"]
            if "protocol" in row and "proto" not in row:
                row["proto"] = row["protocol"]
            elif "proto" in row and "protocol" not in row:
                row["protocol"] = row["proto"]
        return rows


__all__ = ["TextFSMEngine"]
