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
    def render(
        template_str_or_path: str | Path,
        context: Mapping[str, Any] | None = None,
        engine: Literal["auto", "string", "jinja2"] = "auto",
    ) -> str:
        """Отрендерить конфигурационный шаблон со словарём переменных ``context``."""
        ctx = dict(context or {})
        is_jinja_ext = False

        if isinstance(template_str_or_path, Path):
            if not template_str_or_path.is_file():
                raise FileNotFoundError(
                    f"Template file not found: {template_str_or_path}"
                )
            raw_template = template_str_or_path.read_text(encoding="utf-8")
            is_jinja_ext = template_str_or_path.suffix.lower() in (
                ".j2",
                ".jinja",
                ".jinja2",
            )
        else:
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
                raw_template = candidate.read_text(encoding="utf-8")
                is_jinja_ext = candidate.suffix.lower() in (
                    ".j2",
                    ".jinja",
                    ".jinja2",
                )
            else:
                raw_template = template_str_or_path

        chosen_engine = engine
        if chosen_engine == "auto":
            has_jinja = (
                is_jinja_ext or "{{" in raw_template or "{%" in raw_template
            )
            chosen_engine = "jinja2" if has_jinja else "string"

        if chosen_engine == "jinja2":
            try:
                import jinja2  # type: ignore[import-not-found]
            except ImportError as exc:
                if engine == "auto":
                    return string.Template(raw_template).safe_substitute(ctx)
                raise UniconnError(
                    "Jinja2 template engine requested, but 'jinja2' is not installed. "
                    "Install it via 'pip install jinja2' or use engine='string'."
                ) from exc
            env = jinja2.Environment(
                autoescape=False,
                keep_trailing_newline=True,
                undefined=jinja2.StrictUndefined,
            )
            return env.from_string(raw_template).render(**ctx)

        if chosen_engine == "string":
            return string.Template(raw_template).safe_substitute(ctx)

        raise ValueError(f"Unsupported template engine: {engine!r}")


def render_template(
    template_str_or_path: str | Path,
    context: Mapping[str, Any] | None = None,
    engine: Literal["auto", "string", "jinja2"] = "auto",
) -> str:
    """Публичная функция рендеринга шаблона (делегирует в ``TemplateEngine.render``)."""
    return TemplateEngine.render(
        template_str_or_path=template_str_or_path,
        context=context,
        engine=engine,
    )
