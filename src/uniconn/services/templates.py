# src/uniconn/services/templates.py
"""Сервис рендеринга конфигурационных шаблонов (string.Template и опциональный Jinja2)."""

from __future__ import annotations

import string
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from ..exceptions import UniconnError


class TemplateEngine:
    """Рендерит конфигурационные шаблоны из строк или файлов."""

    @staticmethod
    def _render_raw(
        raw_template: str,
        context: Mapping[str, Any] | None = None,
        engine: Literal["auto", "string", "jinja2"] = "auto",
        *,
        is_jinja_ext: bool = False,
    ) -> str:
        ctx = dict(context or {})
        chosen_engine = engine
        if chosen_engine == "auto":
            has_jinja = is_jinja_ext or "{{" in raw_template or "{%" in raw_template
            chosen_engine = "jinja2" if has_jinja else "string"

        if chosen_engine == "jinja2":
            try:
                import jinja2  # type: ignore[import-not-found]
                from jinja2.sandbox import SandboxedEnvironment  # type: ignore[import-not-found]
            except ImportError as exc:
                if engine == "auto":
                    return string.Template(raw_template).safe_substitute(ctx)
                raise UniconnError(
                    "Jinja2 template engine requested, but 'jinja2' is not installed. "
                    "Install it via 'pip install uniconn[templates]' or use engine='string'."
                ) from exc
            env = SandboxedEnvironment(
                autoescape=False,
                keep_trailing_newline=True,
                undefined=jinja2.StrictUndefined,
            )
            return env.from_string(raw_template).render(**ctx)

        if chosen_engine == "string":
            return string.Template(raw_template).safe_substitute(ctx)

        raise ValueError(f"Unsupported template engine: {engine!r}")

    @classmethod
    def render_string(
        cls,
        template: str,
        context: Mapping[str, Any] | None = None,
        engine: Literal["auto", "string", "jinja2"] = "auto",
    ) -> str:
        """Отрендерить шаблон строго из строки (без обращения к файловой системе)."""
        return cls._render_raw(template, context=context, engine=engine, is_jinja_ext=False)

    @classmethod
    def render_file(
        cls,
        template_path: str | Path,
        context: Mapping[str, Any] | None = None,
        engine: Literal["auto", "string", "jinja2"] = "auto",
    ) -> str:
        """Отрендерить шаблон из локального файла."""
        path_obj = Path(template_path)
        if not path_obj.is_file():
            raise FileNotFoundError(f"Template file not found: {path_obj}")
        raw_template = path_obj.read_text(encoding="utf-8")
        is_jinja_ext = path_obj.suffix.lower() in (".j2", ".jinja", ".jinja2")
        return cls._render_raw(raw_template, context=context, engine=engine, is_jinja_ext=is_jinja_ext)

    @classmethod
    def render(
        cls,
        template_str_or_path: str | Path,
        context: Mapping[str, Any] | None = None,
        engine: Literal["auto", "string", "jinja2"] = "auto",
        *,
        allow_file_path: bool = False,
    ) -> str:
        """Отрендерить конфигурационный шаблон со словарём переменных ``context``.

        Для предотвращения случайного чтения локальных файлов при передаче ``str``
        чтение с диска выполняется только если передан объект ``Path`` либо явно
        указан флаг ``allow_file_path=True``.
        """
        if isinstance(template_str_or_path, Path):
            return cls.render_file(template_str_or_path, context=context, engine=engine)

        if allow_file_path:
            candidate = Path(template_str_or_path)
            try:
                is_existing_file = (
                    "\n" not in template_str_or_path
                    and len(template_str_or_path) < 4096
                    and candidate.is_file()
                )
            except OSError:
                is_existing_file = False
            if is_existing_file:
                return cls.render_file(candidate, context=context, engine=engine)

        return cls.render_string(template_str_or_path, context=context, engine=engine)


def render_template(
    template_str_or_path: str | Path,
    context: Mapping[str, Any] | None = None,
    engine: Literal["auto", "string", "jinja2"] = "auto",
    *,
    allow_file_path: bool = False,
) -> str:
    """Публичная функция рендеринга шаблона (делегирует в ``TemplateEngine.render``)."""
    return TemplateEngine.render(
        template_str_or_path=template_str_or_path,
        context=context,
        engine=engine,
        allow_file_path=allow_file_path,
    )
