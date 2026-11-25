# src/uniconn/plugins/_loader.py
"""Унифицированный загрузчик плагинов ``uniconn`` на базе ``importlib.metadata.entry_points``.

Поддерживает пять канонических групп точек расширения:
    - ``uniconn.transports`` — реализации ``BaseTransport``
    - ``uniconn.storage`` — реализации ``StateStore``
    - ``uniconn.inventory`` — реализации ``InventoryProvider``
    - ``uniconn.secrets`` — реализации ``SecretBackend``
    - ``uniconn.hitl_channels`` — реализации ``ApprovalChannel``
"""

from __future__ import annotations

import inspect
import logging
from dataclasses import dataclass
from importlib import import_module
from importlib.metadata import EntryPoint, entry_points
from typing import Any, Literal

from ..exceptions import ConfigurationError, PluginNotFoundError, TransportNotFoundError
from ..transports.base import BaseTransport

logger = logging.getLogger(__name__)

PLUGIN_GROUPS: dict[str, str] = {
    "transports": "uniconn.transports",
    "storage": "uniconn.storage",
    "inventory": "uniconn.inventory",
    "secrets": "uniconn.secrets",
    "hitl_channels": "uniconn.hitl_channels",
}

_CANONICAL_GROUPS: tuple[str, ...] = tuple(PLUGIN_GROUPS.values())


@dataclass(frozen=True, slots=True)
class PluginInfo:
    """Метаданные обнаруженного плагина в заданной группе расширения."""

    group: str
    name: str
    source: Literal["registered", "entry_point", "builtin"]
    target: str | None = None


_BUILTIN_FALLBACKS: dict[str, dict[str, tuple[str, str]]] = {
    "uniconn.transports": {
        "local": ("..transports._local", "LocalTransport"),
        "ssh": ("..transports._ssh", "SSHTransport"),
        "telnet": ("..transports._telnet", "TelnetTransport"),
        "serial": ("..transports._serial", "SerialTransport"),
        "uart": ("..transports._serial", "SerialTransport"),
        "ipmi": ("..transports.bmc._ipmi", "IPMITransport"),
        "redfish": ("..transports.bmc._redfish", "RedfishTransport"),
        "winrm": ("..transports._winrm", "WinRMTransport"),
        "wsman": ("..transports._winrm", "WinRMTransport"),
        "replay": ("..transports.replay", "ReplayTransport"),
        "qga": ("..transports.virtualization.qga", "QgaTransport"),
        "qemu-ga": ("..transports.virtualization.qga", "QgaTransport"),
        "pve": ("..transports.virtualization.pve", "PveTransport"),
        "netconf": ("..transports.network.netconf", "NetconfTransport"),
        "restconf": ("..transports.network.restconf", "RestconfTransport"),
        "gnmi": ("..transports.network.gnmi", "GnmiTransport"),
    },
    "uniconn.storage": {
        "memory": ("..mcp.storage", "InMemoryStateStore"),
        "sqlite": ("..mcp.storage", "SQLiteStateStore"),
    },
    "uniconn.inventory": {
        "file": ("..config.inventory_providers", "FileInventoryProvider"),
        "static": ("..config.inventory_providers", "StaticInventoryProvider"),
    },
    "uniconn.secrets": {
        "env": ("..config.secrets", "EnvSecretBackend"),
        "file": ("..config.secrets", "FileSecretBackend"),
    },
    "uniconn.hitl_channels": {
        "terminal": ("..mcp.hitl", "TerminalApprovalChannel"),
        "webhook": ("..mcp.hitl", "WebhookApprovalChannel"),
    },
}


def _describe_target(obj: Any) -> str:
    """Сформировать читаемое описание модуля и имени загруженного объекта."""
    mod = getattr(obj, "__module__", None)
    qualname = getattr(obj, "__qualname__", None) or getattr(type(obj), "__qualname__", None)
    if mod and qualname:
        return f"{mod}:{qualname}"
    return repr(obj)


def _callable_accepts_kwarg(fn: Any, param_name: str) -> bool:
    """Проверить через ``inspect.signature``, принимает ли вызываемый объект именованный аргумент."""
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return False
    for param in sig.parameters.values():
        if param.kind is inspect.Parameter.VAR_KEYWORD:
            return True
        if param.name == param_name and param.kind in (
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        ):
            return True
    return False


def _callable_has_explicit_kwarg(fn: Any, param_name: str) -> bool:
    """Проверить, объявлен ли у вызываемого объекта явный именованный параметр ``param_name`` (без ``**kwargs``)."""
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return False
    param = sig.parameters.get(param_name)
    return param is not None and param.kind in (
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
        inspect.Parameter.KEYWORD_ONLY,
    )


def _callable_accepts_positional(fn: Any, count: int = 1) -> bool:
    """Проверить через ``inspect.signature``, принимает ли вызываемый объект ``count`` позиционных аргументов."""
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return False
    positional = 0
    for param in sig.parameters.values():
        if param.kind is inspect.Parameter.VAR_POSITIONAL:
            return True
        if param.kind in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        ):
            positional += 1
    return positional >= count


def _validate_protocol(obj: Any, protocol: type[Any], *, group: str, name: str) -> None:
    """Проверить соответствие загруженного плагина ожидаемому ABC или ``@runtime_checkable Protocol``."""
    is_valid = False
    if isinstance(obj, type):
        try:
            is_valid = issubclass(obj, protocol)
        except TypeError:
            is_valid = False
        if not is_valid:
            try:
                is_valid = isinstance(obj, protocol)
            except TypeError:
                is_valid = False
    else:
        try:
            is_valid = isinstance(obj, protocol)
        except TypeError:
            is_valid = False

    if not is_valid:
        proto_name = getattr(protocol, "__name__", repr(protocol))
        raise ConfigurationError(
            f"Plugin {name!r} in group {group!r} ({_describe_target(obj)}) "
            f"does not satisfy required contract {proto_name}"
        )


class PluginLoader:
    """Унифицированный реестр и динамический загрузчик плагинов через ``entry_points``."""

    _cache: dict[str, dict[str, Any]] = {g: {} for g in _CANONICAL_GROUPS}
    _registered: dict[str, dict[str, Any]] = {g: {} for g in _CANONICAL_GROUPS}
    _ep_cache: dict[str, dict[str, EntryPoint]] = {}
    _ep_func_ref: Any = None
    _group_versions: dict[str, int] = dict.fromkeys(_CANONICAL_GROUPS, 0)

    @classmethod
    def normalize_group(cls, group: str) -> str:
        """Нормализовать короткое или полное имя группы (например, ``'storage'`` -> ``'uniconn.storage'``)."""
        raw = group.strip()
        if not raw:
            raise ConfigurationError("Plugin group name must not be empty")
        lowered = raw.lower()
        if lowered in PLUGIN_GROUPS:
            return PLUGIN_GROUPS[lowered]
        return raw

    @classmethod
    def normalize_name(cls, name: str, *, group: str | None = None) -> str:
        """Нормализовать имя плагина (trim + lowercase) и проверить на непустоту."""
        norm = name.strip().lower()
        if not norm:
            if group:
                raise ConfigurationError(f"Plugin name for group {group!r} must not be empty")
            raise ConfigurationError("Plugin name must not be empty")
        return norm

    @classmethod
    def _group_cache(cls, canonical_group: str) -> dict[str, Any]:
        bucket = cls._cache.get(canonical_group)
        if bucket is None:
            bucket = {}
            cls._cache[canonical_group] = bucket
        return bucket

    @classmethod
    def _group_registered(cls, canonical_group: str) -> dict[str, Any]:
        bucket = cls._registered.get(canonical_group)
        if bucket is None:
            bucket = {}
            cls._registered[canonical_group] = bucket
        return bucket

    @classmethod
    def cache_version(cls, group: str) -> int:
        """Вернуть монотонный счётчик изменений кэша и регистраций для указанной группы."""
        canonical_group = cls.normalize_group(group)
        return cls._group_versions.get(canonical_group, 0)

    @classmethod
    def _bump_version(cls, canonical_group: str) -> None:
        cls._group_versions[canonical_group] = cls._group_versions.get(canonical_group, 0) + 1

    @classmethod
    def _get_entry_points(cls, canonical_group: str) -> dict[str, EntryPoint]:
        """Вернуть карту ``{normalized_name: EntryPoint}`` для группы с авто-сбросом при подмене ``entry_points``."""
        if cls._ep_func_ref is not entry_points:
            cls._ep_cache.clear()
            cls._ep_func_ref = entry_points
            for grp in tuple(cls._group_versions):
                cls._bump_version(grp)

        cached = cls._ep_cache.get(canonical_group)
        if cached is not None:
            return cached

        eps = entry_points(group=canonical_group)
        mapping: dict[str, EntryPoint] = {}
        for ep in eps:
            key = ep.name.strip().lower()
            if key:
                mapping.setdefault(key, ep)
        cls._ep_cache[canonical_group] = mapping
        return mapping

    @classmethod
    def validate_contract(cls, obj: Any, protocol: type[Any], *, group: str, name: str) -> None:
        """Проверить соответствие объекта/класса плагина заданному протоколу или базовому классу."""
        _validate_protocol(obj, protocol, group=cls.normalize_group(group), name=name)

    @classmethod
    def register(cls, group: str, name: str, plugin: Any) -> None:
        """Программно зарегистрировать плагин в указанной группе (имеет приоритет над ``entry_points``)."""
        canonical_group = cls.normalize_group(group)
        norm_name = cls.normalize_name(name, group=canonical_group)
        cls._group_registered(canonical_group)[norm_name] = plugin
        cls._group_cache(canonical_group).pop(norm_name, None)
        cls._bump_version(canonical_group)

    @classmethod
    def unregister(cls, group: str, name: str) -> bool:
        """Удалить программно зарегистрированный плагин и сбросить его запись в кэше."""
        canonical_group = cls.normalize_group(group)
        norm_name = cls.normalize_name(name, group=canonical_group)
        cls._group_cache(canonical_group).pop(norm_name, None)
        removed = cls._group_registered(canonical_group).pop(norm_name, None) is not None
        cls._bump_version(canonical_group)
        return removed

    @classmethod
    def load(
        cls,
        group: str,
        name: str,
        *,
        protocol: type[Any] | None = None,
    ) -> Any:
        """Загрузить плагин по группе и имени (программная регистрация -> кэш -> entry_points -> builtin).

        Args:
            group: Короткое (``"storage"``, ``"inventory"``, ``"secrets"``, ``"hitl_channels"``,
                ``"transports"``) или полное (``"uniconn.*"``) имя группы.
            name: Имя плагина в группе (без учёта регистра).
            protocol: Опциональный ``Protocol`` или базовый класс для проверки контракта.

        Returns:
            Загруженный класс, фабрика или экземпляр плагина.

        Raises:
            PluginNotFoundError: Если плагин не найден или не удалось его импортировать.
            ConfigurationError: Если плагин не соответствует ``protocol``.

        """
        canonical_group = cls.normalize_group(group)
        norm_name = cls.normalize_name(name, group=canonical_group)

        registered = cls._group_registered(canonical_group)
        if norm_name in registered:
            obj = registered[norm_name]
            if protocol is not None:
                _validate_protocol(obj, protocol, group=canonical_group, name=norm_name)
            return obj

        cache = cls._group_cache(canonical_group)
        if norm_name in cache:
            obj = cache[norm_name]
            if protocol is not None:
                _validate_protocol(obj, protocol, group=canonical_group, name=norm_name)
            return obj

        eps = cls._get_entry_points(canonical_group)
        builtins_map = _BUILTIN_FALLBACKS.get(canonical_group, {})
        error_cls: type[PluginNotFoundError] = (
            TransportNotFoundError if canonical_group == "uniconn.transports" else PluginNotFoundError
        )

        if norm_name in eps:
            try:
                loaded = eps[norm_name].load()
            except Exception as exc:
                label = "transport" if canonical_group == "uniconn.transports" else "plugin"
                raise error_cls(
                    f"Failed to load {label} {norm_name!r} from group {canonical_group!r}: {exc}",
                    group=canonical_group,
                    plugin_name=norm_name,
                    available=cls.list_available(canonical_group),
                ) from exc
        elif norm_name in builtins_map:
            mod_path, attr_name = builtins_map[norm_name]
            try:
                mod = import_module(mod_path, package=__package__)
                loaded = getattr(mod, attr_name)
            except Exception as exc:
                label = "transport" if canonical_group == "uniconn.transports" else "plugin"
                raise error_cls(
                    f"Failed to load builtin {label} {norm_name!r} from group {canonical_group!r}: {exc}",
                    group=canonical_group,
                    plugin_name=norm_name,
                    available=cls.list_available(canonical_group),
                ) from exc
        else:
            available = cls.list_available(canonical_group)
            if canonical_group == "uniconn.transports":
                raise TransportNotFoundError(
                    f"Transport '{norm_name}' not found. "
                    f"Available: {', '.join(available)}. "
                    f"Install with: pip install uniconn[{norm_name}]",
                    group=canonical_group,
                    plugin_name=norm_name,
                    available=available,
                )
            avail_str = ", ".join(available) if available else "none"
            raise PluginNotFoundError(
                f"Plugin '{norm_name}' not found in group '{canonical_group}'. Available: {avail_str}",
                group=canonical_group,
                plugin_name=norm_name,
                available=available,
            )

        if protocol is not None:
            _validate_protocol(loaded, protocol, group=canonical_group, name=norm_name)

        cache[norm_name] = loaded
        logger.debug("Loaded plugin: %s[%s] -> %s", canonical_group, norm_name, loaded)
        return loaded

    @classmethod
    def instantiate(
        cls,
        group: str,
        name: str,
        *args: Any,
        protocol: type[Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        """Загрузить и инстанцировать плагин (поддерживает классы, фабричные функции и готовые экземпляры)."""
        canonical_group = cls.normalize_group(group)
        norm_name = cls.normalize_name(name, group=canonical_group)
        loaded = cls.load(canonical_group, norm_name)

        is_already_instance = (
            protocol is not None
            and not isinstance(loaded, type)
            and isinstance(loaded, protocol)
        )
        if is_already_instance:
            if args or kwargs:
                raise ConfigurationError(
                    f"Plugin {norm_name!r} in group {canonical_group!r} is already instantiated "
                    "and does not accept constructor arguments"
                )
            instance = loaded
        elif isinstance(loaded, type) or callable(loaded):
            instance = loaded(*args, **kwargs)
        else:
            instance = loaded

        if protocol is not None:
            _validate_protocol(instance, protocol, group=canonical_group, name=norm_name)
        return instance

    @classmethod
    def list_available(cls, group: str) -> list[str]:
        """Вернуть отсортированный список имён всех доступных плагинов в указанной группе."""
        canonical_group = cls.normalize_group(group)
        names: set[str] = set(cls._group_registered(canonical_group).keys())
        names.update(cls._get_entry_points(canonical_group).keys())
        names.update(_BUILTIN_FALLBACKS.get(canonical_group, {}).keys())
        return sorted(names)

    @classmethod
    def discover(cls, group: str | None = None) -> list[PluginInfo]:
        """Вернуть структурированный список обнаруженных плагинов (для одной группы или всех пяти)."""
        groups = [cls.normalize_group(group)] if group is not None else list(_CANONICAL_GROUPS)
        discovered: list[PluginInfo] = []
        for canonical_group in groups:
            seen: dict[str, PluginInfo] = {}
            for name, (mod_path, attr_name) in _BUILTIN_FALLBACKS.get(canonical_group, {}).items():
                seen[name] = PluginInfo(
                    group=canonical_group,
                    name=name,
                    source="builtin",
                    target=f"{mod_path}:{attr_name}",
                )
            for name, ep in cls._get_entry_points(canonical_group).items():
                seen[name] = PluginInfo(
                    group=canonical_group,
                    name=name,
                    source="entry_point",
                    target=ep.value,
                )
            for name, obj in cls._group_registered(canonical_group).items():
                seen[name] = PluginInfo(
                    group=canonical_group,
                    name=name,
                    source="registered",
                    target=_describe_target(obj),
                )
            for name in sorted(seen):
                discovered.append(seen[name])
        return discovered

    @classmethod
    def clear_cache(
        cls,
        group: str | None = None,
        *,
        include_registered: bool = False,
    ) -> None:
        """Очистить кэш загруженных плагинов и ``entry_points`` (для тестирования)."""
        if group is None:
            for bucket in cls._cache.values():
                bucket.clear()
            cls._ep_cache.clear()
            if include_registered:
                for bucket in cls._registered.values():
                    bucket.clear()
            for grp in set(cls._group_versions) | set(cls._cache) | set(cls._registered):
                cls._bump_version(grp)
            return

        canonical_group = cls.normalize_group(group)
        cls._group_cache(canonical_group).clear()
        cls._ep_cache.pop(canonical_group, None)
        if include_registered:
            cls._group_registered(canonical_group).clear()
        cls._bump_version(canonical_group)


class TransportLoader:
    """Динамическая загрузка транспортов через ``entry_points`` (специализация ``PluginLoader``)."""

    _cache: dict[str, type[BaseTransport]] = PluginLoader._cache["uniconn.transports"]

    @classmethod
    def get(cls, transport_name: str) -> type[BaseTransport]:
        """Получить класс транспорта по имени.

        Args:
            transport_name: Название транспорта (ssh, uart, ipmi, etc.)

        Returns:
            Класс транспорта

        Raises:
            TransportNotFoundError: Если транспорт не найден

        """
        return PluginLoader.load("uniconn.transports", transport_name)

    @classmethod
    def list_available(cls) -> list[str]:
        """Список доступных транспортов."""
        return PluginLoader.list_available("uniconn.transports")

    @classmethod
    def clear_cache(cls) -> None:
        """Очистить кэш транспортов (для тестирования)."""
        PluginLoader.clear_cache("uniconn.transports")


__all__ = [
    "PLUGIN_GROUPS",
    "PluginInfo",
    "PluginLoader",
    "TransportLoader",
    "_callable_accepts_kwarg",
    "_callable_accepts_positional",
    "_callable_has_explicit_kwarg",
]
