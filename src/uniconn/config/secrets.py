# src/uniconn/config/secrets.py
"""Разрешение внешних секретов по URI-схемам ``env://`` и ``file://``."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote

from pydantic import SecretStr

from ..exceptions import ConfigurationError

_SECRET_SCHEMES = ("env://", "file://")


class SecretResolver:
    """Резолвер секретных значений из переменных окружения (``env://``) и файлов (``file://``).

    Поддерживает опциональный query-параметр ``?default=<fallback>`` на случай
    отсутствия переменной окружения или файла секрета.
    """

    @staticmethod
    def is_secret_ref(value: Any) -> bool:
        """Проверить, является ли значение строкой или ``SecretStr`` со схемой ``env://`` или ``file://``."""
        if isinstance(value, SecretStr):
            raw = value.get_secret_value()
            return raw.startswith(_SECRET_SCHEMES)
        if isinstance(value, str):
            return value.startswith(_SECRET_SCHEMES)
        return False

    @classmethod
    def resolve(
        cls,
        value: str,
        *,
        env: Mapping[str, str] | None = None,
    ) -> str:
        """Разрешить одиночную строку со схемой ``env://`` или ``file://``."""
        return cls.resolve_str(value, env=env)

    @classmethod
    def resolve_str(
        cls,
        value: str,
        *,
        env: Mapping[str, str] | None = None,
    ) -> str:
        """Разрешить одиночную строку со схемой ``env://`` или ``file://``."""
        if value.startswith("env://"):
            return cls._resolve_env(value, env=env)
        if value.startswith("file://"):
            return cls._resolve_file(value)
        return value

    @classmethod
    def _resolve_env(
        cls,
        uri: str,
        *,
        env: Mapping[str, str] | None = None,
    ) -> str:
        rest = uri[len("env://") :]
        var_name, has_query, query_str = rest.partition("?")
        var_name = unquote(var_name).strip()
        if not var_name:
            raise ConfigurationError(f"Empty environment variable name in secret reference: {uri!r}")

        params = parse_qs(query_str, keep_blank_values=True) if has_query else {}
        env_map = os.environ if env is None else env

        if var_name in env_map:
            return env_map[var_name]
        if params.get("default"):
            return params["default"][0]

        raise ConfigurationError(
            f"Environment variable {var_name!r} is not set and no '?default=' fallback provided in {uri!r}"
        )

    @classmethod
    def _resolve_file(cls, uri: str) -> str:
        rest = uri[len("file://") :]
        raw_path, has_query, query_str = rest.partition("?")
        decoded_path = unquote(raw_path).strip()
        if not decoded_path:
            raise ConfigurationError(f"Empty file path in secret reference: {uri!r}")

        params = parse_qs(query_str, keep_blank_values=True) if has_query else {}
        file_path = Path(decoded_path).expanduser()

        try:
            content = file_path.read_text(encoding="utf-8")
            return content.rstrip("\r\n")
        except OSError as exc:
            if params.get("default"):
                return params["default"][0]
            raise ConfigurationError(
                f"Failed to read secret file {str(file_path)!r} referenced by {uri!r}: {exc}"
            ) from exc

    @classmethod
    def resolve_value(
        cls,
        value: Any,
        *,
        env: Mapping[str, str] | None = None,
    ) -> Any:
        """Рекурсивно разрешить секретные URI в строке, ``SecretStr``, списке или словаре."""
        if isinstance(value, SecretStr):
            raw = value.get_secret_value()
            if raw.startswith(_SECRET_SCHEMES):
                return SecretStr(cls.resolve_str(raw, env=env))
            return value
        if isinstance(value, str):
            if value.startswith(_SECRET_SCHEMES):
                return cls.resolve_str(value, env=env)
            return value
        if isinstance(value, Mapping):
            return cls.resolve_mapping(value, env=env)
        if isinstance(value, list):
            return [cls.resolve_value(item, env=env) for item in value]
        if isinstance(value, tuple):
            return tuple(cls.resolve_value(item, env=env) for item in value)
        return value

    @classmethod
    def resolve_mapping(
        cls,
        data: Mapping[str, Any],
        *,
        env: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        """Рекурсивно разрешить все ``env://`` и ``file://`` ссылки в словаре конфигурации."""
        return {str(k): cls.resolve_value(v, env=env) for k, v in data.items()}


__all__ = ["SecretResolver"]
