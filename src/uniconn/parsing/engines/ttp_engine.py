# src/uniconn/parsing/engines/ttp_engine.py
"""Адаптер интеграции с шаблонным парсером TTP (Template Text Parser)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ...exceptions import OptionalDependencyError, ParserNotFoundError, ParsingError

try:
    from ttp import ttp as _ttp_cls
except ImportError:
    _ttp_cls = None  # type: ignore[assignment]


class TTPEngine:
    """Движок декларативного парсинга по Jinja-подобным шаблонам ``ttp``."""

    name: str = "ttp"

    @staticmethod
    def is_available() -> bool:
        """Проверить, установлена ли библиотека ``ttp``."""
        return _ttp_cls is not None

    def can_parse(self, spec: str) -> bool:
        """Проверить, является ли спецификация путём к файлу ``.ttp`` или встроенным шаблоном."""
        if _ttp_cls is None:
            return False
        return spec.endswith(".ttp") or "<group" in spec

    def parse(self, text: str, spec: str, **kwargs: Any) -> Any:
        """Распарсить текст по шаблону ``ttp`` (из строки или файла)."""
        if _ttp_cls is None:
            raise OptionalDependencyError(
                "Parsing with 'ttp' requires the ttp library. "
                "Install with: pip install 'uniconn[parsing]'"
            )

        template_content = self._resolve_template(spec)
        try:
            parser = _ttp_cls(data=text, template=template_content)
            parser.parse()
            res = parser.result(format="raw")
        except Exception as exc:
            raise ParsingError(f"TTP parsing failed: {exc}") from exc

        # TTP обычно возвращает вложенный список вида [[{...}]]
        if isinstance(res, list) and len(res) == 1 and isinstance(res[0], list):
            inner = res[0]
            if len(inner) == 1:
                return inner[0]
            return inner
        if isinstance(res, list) and len(res) == 1:
            return res[0]
        return res

    @staticmethod
    def _resolve_template(spec: str) -> str:
        """Прочитать содержимое файла шаблона, если передан путь, иначе вернуть строку как шаблон."""
        if "\n" not in spec and "<group" not in spec and "{{" not in spec:
            path = Path(spec)
            if path.is_file():
                return path.read_text(encoding="utf-8")
            if spec.endswith(".ttp"):
                raise ParserNotFoundError(f"TTP template file not found: {spec!r}")
        return spec


__all__ = ["TTPEngine"]
