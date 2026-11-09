# src/uniconn/parsing/__init__.py
"""Подсистема структурированного семантического парсинга вывода CLI (uniconn.parsing)."""

from .base import (
    OptionalDependencyError,
    ParserNotFoundError,
    ParseSpec,
    ParsingEngine,
    ParsingError,
    strip_ansi,
)
from .detector import detect_parser_spec
from .engines import (
    BuiltinEngine,
    JCEngine,
    NativeJsonEngine,
    TextFSMEngine,
    TTPEngine,
)
from .registry import ParsingRegistry, default_registry, parse_output

__all__ = [
    "BuiltinEngine",
    "JCEngine",
    "NativeJsonEngine",
    "OptionalDependencyError",
    "ParseSpec",
    "ParserNotFoundError",
    "ParsingEngine",
    "ParsingError",
    "ParsingRegistry",
    "TTPEngine",
    "TextFSMEngine",
    "default_registry",
    "detect_parser_spec",
    "parse_output",
    "strip_ansi",
]
