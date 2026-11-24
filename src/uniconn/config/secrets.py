# src/uniconn/config/secrets.py
"""Разрешение внешних секретов по URI-схемам (встроенные ``env://``, ``file://`` и плагины ``uniconn.secrets``)."""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Protocol, runtime_checkable
from urllib.parse import parse_qs, unquote

from pydantic import SecretStr

from ..exceptions import ConfigurationError

_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*$")


@runtime_checkable
class SecretBackend(Protocol):
    """Контракт бэкенда разрешения секретных URI для группы ``uniconn.secrets``."""

    def resolve(
        self,
        uri: str,
        *,
        env: Mapping[str, str] | None = None,
        base_dir: str | Path | None = None,
    ) -> str:
        """Разрешить URI-ссылку секрета (например, ``vault://secret/path``) в строковое значение."""
        ...


class EnvSecretBackend:
    """Встроенный бэкенд секретов для схемы ``env://<VAR>[?default=<fallback>]``."""

    scheme: str = "env"

    def resolve(
        self,
        uri: str,
        *,
        env: Mapping[str, str] | None = None,
        base_dir: str | Path | None = None,
    ) -> str:
        """Прочитать значение переменной окружения с поддержкой ``?default=``."""
        _ = base_dir
        if not uri.lower().startswith("env://"):
            raise ConfigurationError(f"EnvSecretBackend expects an 'env://' URI, got: {uri!r}")
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


class FileSecretBackend:
    """Встроенный бэкенд секретов для схемы ``file://<path>[?default=<fallback>]``."""

    scheme: str = "file"

    def resolve(
        self,
        uri: str,
        *,
        env: Mapping[str, str] | None = None,
        base_dir: str | Path | None = None,
    ) -> str:
        """Прочитать секрет из файла с проверкой выхода за пределы ``base_dir``."""
        _ = env
        if not uri.lower().startswith("file://"):
            raise ConfigurationError(f"FileSecretBackend expects a 'file://' URI, got: {uri!r}")
        rest = uri[len("file://") :]
        raw_path, has_query, query_str = rest.partition("?")
        decoded_path = unquote(raw_path).strip()
        if not decoded_path:
            raise ConfigurationError(f"Empty file path in secret reference: {uri!r}")

        params = parse_qs(query_str, keep_blank_values=True) if has_query else {}
        file_path = Path(decoded_path).expanduser()

        if base_dir is not None:
            resolved_base = Path(base_dir).expanduser().resolve()
            candidate = (
                (resolved_base / file_path).resolve()
                if not file_path.is_absolute()
                else file_path.resolve()
            )
            if not candidate.is_relative_to(resolved_base):
                raise ConfigurationError(
                    f"Secret file path {str(file_path)!r} escapes allowed base_dir {str(resolved_base)!r}"
                )
            file_path = candidate

        try:
            content = file_path.read_text(encoding="utf-8")
            return content.rstrip("\r\n")
        except OSError as exc:
            if params.get("default"):
                return params["default"][0]
            raise ConfigurationError(
                f"Failed to read secret file {str(file_path)!r} referenced by {uri!r}: {exc}"
            ) from exc


_ENV_BACKEND = EnvSecretBackend()
_FILE_BACKEND = FileSecretBackend()


def _normalize_scheme(scheme: str) -> str:
    """Нормализовать имя URI-схемы секрета (например, ``'Vault://'`` -> ``'vault'``)."""
    norm = scheme.strip().rstrip(":/").lower()
    if not norm or not _SCHEME_RE.match(norm):
        raise ConfigurationError(f"Invalid secret URI scheme: {scheme!r}")
    return norm


def _extract_scheme(value: str) -> str | None:
    """Извлечь нормализованную схему из строки ``<scheme>://...`` или вернуть ``None``."""
    sep_idx = value.find("://")
    if sep_idx <= 0:
        return None
    candidate = value[:sep_idx].lower()
    if not _SCHEME_RE.match(candidate):
        return None
    return candidate


def _instantiate_backend(obj: Any, scheme: str) -> SecretBackend:
    """Преобразовать класс, фабричную функцию или экземпляр плагина в готовый ``SecretBackend``."""
    if obj is EnvSecretBackend:
        return _ENV_BACKEND
    if obj is FileSecretBackend:
        return _FILE_BACKEND
    if isinstance(obj, SecretBackend) and not isinstance(obj, type):
        return obj
    instance = obj() if isinstance(obj, type) or callable(obj) else obj
    if not isinstance(instance, SecretBackend):
        raise ConfigurationError(
            f"Secret backend for scheme {scheme!r} must implement SecretBackend protocol (resolve method)"
        )
    return instance


class SecretResolver:
    """Резолвер секретных значений из встроенных (``env://``, ``file://``) и подключаемых URI-схем.

    Поддерживает:
    - встроенные схемы ``env://`` и ``file://`` с опциональным ``?default=<fallback>``;
    - автоматическое обнаружение пользовательских схем через ``entry_points`` (``uniconn.secrets``);
    - программную регистрацию через ``SecretResolver.register_backend(scheme, backend)``.
    """

    # Кэш инстансов бэкендов вида {scheme: (cache_version, source_plugin_obj, backend_instance)}
    # Автоматически инвалидируется при clear_cache(), register(), unregister() или подмене entry_points.
    _instance_cache: dict[str, tuple[int, Any, SecretBackend]] = {}

    @classmethod
    def register_backend(
        cls,
        scheme: str,
        backend: SecretBackend | type[SecretBackend] | Callable[[], SecretBackend],
    ) -> None:
        """Зарегистрировать пользовательский ``SecretBackend`` для указанной URI-схемы."""
        from ..plugins._loader import PluginLoader

        norm_scheme = _normalize_scheme(scheme)
        instance = _instantiate_backend(backend, norm_scheme)
        cls._instance_cache.pop(norm_scheme, None)
        PluginLoader.register("uniconn.secrets", norm_scheme, instance)

    @classmethod
    def unregister_backend(cls, scheme: str) -> bool:
        """Удалить программно зарегистрированный бэкенд секретов."""
        from ..plugins._loader import PluginLoader

        norm_scheme = _normalize_scheme(scheme)
        cls._instance_cache.pop(norm_scheme, None)
        return PluginLoader.unregister("uniconn.secrets", norm_scheme)

    @classmethod
    def list_schemes(cls) -> list[str]:
        """Вернуть отсортированный список всех доступных URI-схем секретов."""
        from ..plugins._loader import PluginLoader

        return PluginLoader.list_available("uniconn.secrets")

    @classmethod
    def get_backend(cls, scheme: str) -> SecretBackend:
        """Получить экземпляр ``SecretBackend`` для указанной схемы (с кэшированием инстанса)."""
        from ..plugins._loader import PluginLoader

        norm_scheme = _normalize_scheme(scheme)
        loaded = PluginLoader.load("uniconn.secrets", norm_scheme)
        version = PluginLoader.cache_version("uniconn.secrets")

        cached = cls._instance_cache.get(norm_scheme)
        if cached is not None and cached[0] == version and cached[1] is loaded:
            return cached[2]

        instance = _instantiate_backend(loaded, norm_scheme)
        cls._instance_cache[norm_scheme] = (version, loaded, instance)
        return instance

    @classmethod
    def is_secret_ref(cls, value: Any) -> bool:
        """Проверить, является ли значение строкой или ``SecretStr`` с известной схемой секрета."""
        raw: str
        if isinstance(value, SecretStr):
            raw = value.get_secret_value()
        elif isinstance(value, str):
            raw = value
        else:
            return False

        scheme = _extract_scheme(raw)
        if scheme is None:
            return False
        if scheme in ("env", "file"):
            return True
        return scheme in cls.list_schemes()

    @classmethod
    def resolve(
        cls,
        value: str,
        *,
        env: Mapping[str, str] | None = None,
        base_dir: str | Path | None = None,
    ) -> str:
        """Разрешить одиночную строку со схемой секрета."""
        return cls.resolve_str(value, env=env, base_dir=base_dir)

    @classmethod
    def resolve_str(
        cls,
        value: str,
        *,
        env: Mapping[str, str] | None = None,
        base_dir: str | Path | None = None,
    ) -> str:
        """Разрешить одиночную строку со схемой ``env://``, ``file://`` или подключённой схемой."""
        scheme = _extract_scheme(value)
        if scheme is None:
            return value

        if scheme not in ("env", "file") and scheme not in cls.list_schemes():
            return value

        backend = cls.get_backend(scheme)
        return backend.resolve(value, env=env, base_dir=base_dir)

    @classmethod
    def _resolve_env(
        cls,
        uri: str,
        *,
        env: Mapping[str, str] | None = None,
    ) -> str:
        return _ENV_BACKEND.resolve(uri, env=env)

    @classmethod
    def _resolve_file(
        cls,
        uri: str,
        *,
        base_dir: str | Path | None = None,
    ) -> str:
        return _FILE_BACKEND.resolve(uri, base_dir=base_dir)

    @classmethod
    def resolve_value(
        cls,
        value: Any,
        *,
        env: Mapping[str, str] | None = None,
        base_dir: str | Path | None = None,
    ) -> Any:
        """Рекурсивно разрешить секретные URI в строке, ``SecretStr``, списке или словаре."""
        if isinstance(value, SecretStr):
            raw = value.get_secret_value()
            resolved = cls.resolve_str(raw, env=env, base_dir=base_dir)
            return SecretStr(resolved) if resolved is not raw else value
        if isinstance(value, str):
            return cls.resolve_str(value, env=env, base_dir=base_dir)
        if isinstance(value, Mapping):
            return cls.resolve_mapping(value, env=env, base_dir=base_dir)
        if isinstance(value, list):
            return [cls.resolve_value(item, env=env, base_dir=base_dir) for item in value]
        if isinstance(value, tuple):
            return tuple(cls.resolve_value(item, env=env, base_dir=base_dir) for item in value)
        return value

    @classmethod
    def resolve_mapping(
        cls,
        data: Mapping[str, Any],
        *,
        env: Mapping[str, str] | None = None,
        base_dir: str | Path | None = None,
    ) -> dict[str, Any]:
        """Рекурсивно разрешить все зарегистрированные секретные ссылки в словаре конфигурации."""
        return {
            str(k): cls.resolve_value(v, env=env, base_dir=base_dir)
            for k, v in data.items()
        }


__all__ = [
    "EnvSecretBackend",
    "FileSecretBackend",
    "SecretBackend",
    "SecretResolver",
]
