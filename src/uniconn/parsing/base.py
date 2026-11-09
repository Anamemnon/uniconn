# src/uniconn/parsing/base.py
"""Базовые протоколы, утилиты очистки ANSI и типы спецификаций подсистемы парсинга."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any, Protocol, TypeVar, runtime_checkable

from ..exceptions import OptionalDependencyError, ParserNotFoundError, ParsingError

T = TypeVar("T")

ParseSpec = bool | str | type[Any] | Callable[[str], Any] | None

_ANSI_ESCAPE_RE: re.Pattern[str] = re.compile(
    r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])"
)


def strip_ansi(text: str) -> str:
    """Быстро удалить управляющие ANSI/VT100 escape-последовательности из текста."""
    if "\x1b" not in text:
        return text
    return _ANSI_ESCAPE_RE.sub("", text)


@runtime_checkable
class ParsingEngine(Protocol):
    """Протокол движка семантического парсинга текстового вывода CLI."""

    name: str

    def can_parse(self, spec: str) -> bool:
        """Проверить, поддерживает ли данный движок указанную спецификацию без префикса."""
        ...

    def parse(self, text: str, spec: str, **kwargs: Any) -> Any:
        """Преобразовать очищенный текстовый вывод в структурированные данные Python."""
        ...


__all__ = [
    "OptionalDependencyError",
    "ParseSpec",
    "ParserNotFoundError",
    "ParsingEngine",
    "ParsingError",
    "strip_ansi",
]
