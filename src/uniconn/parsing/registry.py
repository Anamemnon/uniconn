# src/uniconn/parsing/registry.py
"""Центральный реестр движков семантического парсинга и адаптер схем Pydantic."""

from __future__ import annotations

import dataclasses
import types
from collections.abc import Callable
from typing import Any, get_origin

from pydantic import BaseModel, TypeAdapter, ValidationError

from ..exceptions import OptionalDependencyError, ParserNotFoundError, ParsingError
from .base import ParseSpec, ParsingEngine, strip_ansi
from .detector import detect_parser_spec
from .engines import (
    BuiltinEngine,
    JCEngine,
    NativeJsonEngine,
    TextFSMEngine,
    TTPEngine,
)


def _is_schema_type(spec: Any) -> bool:
    """Проверить, является ли спецификация типом Pydantic BaseModel, dataclass или GenericAlias."""
    if spec is None or isinstance(spec, bool | str):
        return False
    origin = get_origin(spec)
    if origin is not None or isinstance(spec, types.GenericAlias):
        return True
    if isinstance(spec, type):
        if issubclass(spec, BaseModel) or dataclasses.is_dataclass(spec):
            return True
        # TypedDict
        if hasattr(spec, "__annotations__") and hasattr(spec, "__total__"):
            return True
    return False


def _is_list_schema(spec: Any) -> bool:
    """Определить, ожидает ли схема коллекцию элементов (list / tuple / set)."""
    origin = get_origin(spec)
    return origin in (list, tuple, set, frozenset)


def _is_dict_spec(spec: Any) -> bool:
    """Определить, возвращает ли спецификация словарь / объект."""
    if _is_schema_type(spec) and not _is_list_schema(spec):
        return True
    if isinstance(spec, str):
        low = spec.lower()
        if low in (
            "uptime",
            "free",
            "kv",
            "env",
            "sysctl",
            "systemctl_status",
            "json",
            "cisco_ios_show_version",
        ):
            return True
    return False


class ParsingRegistry:
    """Центральный реестр движков парсинга, пользовательских парсеров и автодетектора."""

    def __init__(self) -> None:
        """Инициализировать реестр со стандартным набором движков."""
        self._engines: dict[str, ParsingEngine] = {}
        self._custom_parsers: dict[str, Callable[[str], Any] | str] = {}
        self._json_engine = NativeJsonEngine()
        self._builtin_engine = BuiltinEngine()
        self._jc_engine = JCEngine()
        self._textfsm_engine = TextFSMEngine()
        self._ttp_engine = TTPEngine()

        for eng in (
            self._json_engine,
            self._builtin_engine,
            self._jc_engine,
            self._textfsm_engine,
            self._ttp_engine,
        ):
            self.register_engine(eng)

    def register_engine(self, engine: ParsingEngine) -> None:
        """Зарегистрировать движок семантического парсинга по его имени."""
        self._engines[engine.name.lower()] = engine

    def get_engine(self, name: str) -> ParsingEngine:
        """Получить зарегистрированный движок по имени или выбросить ``ParserNotFoundError``."""
        key = name.lower()
        if key not in self._engines:
            raise ParserNotFoundError(f"Parsing engine {name!r} is not registered.")
        return self._engines[key]

    def register_parser(
        self, name: str, parser: Callable[[str], Any] | str
    ) -> None:
        """Зарегистрировать именованный пользовательский парсер (функцию или алиас спецификации)."""
        self._custom_parsers[name] = parser

    def detect_spec(self, command: str | None, text: str = "") -> str | None:
        """Автоматически определить спецификацию парсера по команде и тексту вывода."""
        return detect_parser_spec(command, text)

    def parse(
        self,
        text: str,
        spec: ParseSpec = "auto",
        *,
        command: str | None = None,
        dry_run: bool = False,
        **kwargs: Any,
    ) -> Any:
        """Распарсить текстовый вывод в соответствии с указанной спецификацией."""
        clean_text = strip_ansi(text)

        if dry_run and not clean_text.strip():
            target_spec = spec
            if target_spec in (True, "auto", None):
                target_spec = self.detect_spec(command, clean_text)
            if target_spec is not None:
                if _is_list_schema(target_spec):
                    return []
                if _is_dict_spec(target_spec):
                    if _is_schema_type(target_spec):
                        return None
                    return {}
            return []

        # 1. Схема данных (Pydantic BaseModel, list[BaseModel], dataclass, TypedDict)
        if _is_schema_type(spec):
            return self._parse_with_schema(
                clean_text, spec, command=command, **kwargs
            )

        # 2. Пользовательская функция-парсер Callable[[str], Any]
        if callable(spec):
            try:
                return spec(clean_text)
            except ParsingError:
                raise
            except Exception as exc:
                raise ParsingError(
                    f"Custom parser callable failed: {exc}",
                    command=command,
                    stdout=text,
                ) from exc

        # 3. Автоопределение при spec in (True, "auto", None)
        resolved_spec: str | None
        if spec in (True, "auto", None):
            resolved_spec = self.detect_spec(command, clean_text)
            if not resolved_spec:
                raise ParserNotFoundError(
                    f"Could not auto-detect parser for command={command!r}.",
                    command=command,
                    stdout=text,
                )
        elif isinstance(spec, str):
            resolved_spec = spec.strip()
        else:
            raise ParserNotFoundError(
                f"Unsupported parser specification: {spec!r}",
                command=command,
            )

        if not resolved_spec:
            raise ParserNotFoundError(
                "Parser specification cannot be empty.",
                command=command,
            )

        # 4. Проверка зарегистрированных пользовательских парсеров
        if resolved_spec in self._custom_parsers:
            custom_target = self._custom_parsers[resolved_spec]
            if callable(custom_target):
                return custom_target(clean_text)
            resolved_spec = custom_target

        # 5. Явный префикс движка вида "engine:sub_spec" (исключая пути Windows C:\ и многострочные шаблоны)
        if (
            ":" in resolved_spec
            and "\n" not in resolved_spec
            and not (len(resolved_spec) > 2 and resolved_spec[1] == ":" and resolved_spec[2] in ("\\", "/"))
        ):
            engine_name, sub_spec = resolved_spec.split(":", 1)
            engine = self.get_engine(engine_name)
            return engine.parse(clean_text, sub_spec, **kwargs)

        # 6. Разрешение спецификации без префикса с умным фолбэком
        return self._dispatch_unprefixed(clean_text, resolved_spec, command=command, **kwargs)

    def _dispatch_unprefixed(
        self,
        clean_text: str,
        spec: str,
        *,
        command: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """Маршрутизировать спецификацию без префикса между JSON, внешними и встроенными движками."""
        if self._json_engine.can_parse(spec):
            return self._json_engine.parse(clean_text, spec, **kwargs)

        # Для сетевых шаблонов вида cisco_ios_*: сначала пробуем ntc-templates (если установлен), затем builtin
        if spec.lower().startswith(("cisco_", "arista_", "juniper_", "huawei_", "mikrotik_")):
            if self._textfsm_engine.is_available() and self._textfsm_engine.has_ntc_templates():
                try:
                    return self._textfsm_engine.parse(clean_text, spec, **kwargs)
                except ParsingError:
                    if not self._builtin_engine.can_parse(spec):
                        raise
            if self._builtin_engine.can_parse(spec):
                return self._builtin_engine.parse(clean_text, spec, **kwargs)

        # Для встроенных спецификаций (table, kv, df, ps, uptime, free и др.):
        # если речь о системной утилите и установлен jc — используем jc с фолбэком на builtin
        if spec.lower() not in ("table", "kv", "env") and self._jc_engine.can_parse(spec):
            try:
                return self._jc_engine.parse(clean_text, spec, **kwargs)
            except (OptionalDependencyError, ParserNotFoundError, ParsingError):
                if not self._builtin_engine.can_parse(spec):
                    raise

        if self._builtin_engine.can_parse(spec):
            return self._builtin_engine.parse(clean_text, spec, **kwargs)

        for engine in self._engines.values():
            if engine.can_parse(spec):
                return engine.parse(clean_text, spec, **kwargs)

        raise ParserNotFoundError(
            f"No parsing engine found for spec: {spec!r}",
            command=command,
            stdout=clean_text,
        )

    def _parse_with_schema(
        self,
        clean_text: str,
        schema_type: Any,
        *,
        command: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """Распарсить текст в структуру данных и провалидировать через ``pydantic.TypeAdapter``."""
        using_spec: str | None = kwargs.pop("using", None)
        if using_spec is None:
            using_spec = self.detect_spec(command, clean_text)
        if using_spec is None:
            stripped = clean_text.strip()
            if stripped.startswith(("{", "[")):
                using_spec = "json"
            elif _is_list_schema(schema_type):
                using_spec = "table"
            else:
                using_spec = "kv"

        raw_data = self.parse(clean_text, using_spec, command=command, **kwargs)
        try:
            adapter: TypeAdapter[Any] = TypeAdapter(schema_type)
            return adapter.validate_python(raw_data)
        except ValidationError as val_err:
            raise ParsingError(
                f"Schema validation failed for {schema_type!r}: {val_err}",
                command=command,
                stdout=clean_text,
            ) from val_err


default_registry = ParsingRegistry()


def parse_output(
    text: str,
    spec: ParseSpec = "auto",
    *,
    command: str | None = None,
    **kwargs: Any,
) -> Any:
    """Удобная функция верхнего уровня для разбора текста через ``default_registry``."""
    return default_registry.parse(text, spec, command=command, **kwargs)


__all__ = [
    "ParsingRegistry",
    "default_registry",
    "parse_output",
]
