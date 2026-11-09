# src/uniconn/parsing/engines/jc_engine.py
"""Адаптер интеграции с библиотекой jc (100+ парсеров системных утилит Linux/macOS/Windows)."""

from __future__ import annotations

from typing import Any

from ...exceptions import OptionalDependencyError, ParserNotFoundError, ParsingError

try:
    import jc as _jc_mod
except ImportError:
    _jc_mod = None  # type: ignore[assignment]

_JC_SPEC_ALIASES: dict[str, str] = {
    "systemctl_status": "systemctl-status",
    "ip_route": "ip-route",
    "ip_addr": "ip-address",
    "ss": "ss",
    "netstat": "netstat",
}


class JCEngine:
    """Движок парсинга вывода стандартных системных утилит на базе библиотеки ``jc``."""

    name: str = "jc"

    @staticmethod
    def is_available() -> bool:
        """Проверить, установлена ли библиотека ``jc`` в текущем окружении."""
        return _jc_mod is not None

    def can_parse(self, spec: str) -> bool:
        """Проверить, поддерживается ли парсер библиотекой ``jc``."""
        if _jc_mod is None:
            return False
        target = _JC_SPEC_ALIASES.get(spec, spec)
        try:
            parsers = _jc_mod.parser_mod_list()
            return target in parsers or target.replace("-", "_") in parsers
        except Exception:
            return False

    def parse(self, text: str, spec: str, **kwargs: Any) -> Any:
        """Распарсить текст с помощью указанного парсера ``jc``."""
        if _jc_mod is None:
            raise OptionalDependencyError(
                "Parsing with 'jc' requires the jc library. "
                "Install with: pip install 'uniconn[parsing]'"
            )

        target = _JC_SPEC_ALIASES.get(spec, spec)
        raw: bool = bool(kwargs.get("raw", False))
        quiet: bool = bool(kwargs.get("quiet", True))

        try:
            parsed = _jc_mod.parse(target, text, raw=raw, quiet=quiet)
        except Exception as exc:
            err_msg = str(exc)
            if "not found" in err_msg.lower() or "module" in err_msg.lower():
                raise ParserNotFoundError(
                    f"JC parser {target!r} not found: {exc}"
                ) from exc
            raise ParsingError(f"JC parsing failed for {target!r}: {exc}") from exc

        return self._normalize_output(spec, parsed)

    @staticmethod
    def _normalize_output(spec: str, data: Any) -> Any:
        """Обогатить результат унифицированными алиасами полей для совместимости со схемами."""
        norm_spec = spec.lower().replace("-", "_")
        if norm_spec == "df" and isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    if "size" not in item:
                        for k in ("1k_blocks", "1024_blocks", "blocks", "total"):
                            if k in item:
                                item["size"] = item[k]
                                break
                    if "use_percent" in item and "percent_used" not in item:
                        item["percent_used"] = item["use_percent"]
                    elif "percent_used" in item and "use_percent" not in item:
                        item["use_percent"] = item["percent_used"]
                    if "avail" in item and "available" not in item:
                        item["available"] = item["avail"]
        elif norm_spec in ("ip_route", "iproute") and isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    if "destination" not in item and "ip" in item:
                        item["destination"] = item["ip"]
                    elif "ip" not in item and "destination" in item:
                        item["ip"] = item["destination"]
        elif norm_spec == "uptime" and isinstance(data, dict):
            if "load_1m" not in data and "load_average_1m" in data:
                data["load_1m"] = data["load_average_1m"]
            if "load_5m" not in data and "load_average_5m" in data:
                data["load_5m"] = data["load_average_5m"]
            if "load_15m" not in data and "load_average_15m" in data:
                data["load_15m"] = data["load_average_15m"]
        return data


__all__ = ["JCEngine"]
