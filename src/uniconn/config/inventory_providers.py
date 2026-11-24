# src/uniconn/config/inventory_providers.py
"""Асинхронный контракт динамического инвентаря (``InventoryProvider``), TTL-кэш и встроенные адаптеры."""

from __future__ import annotations

import asyncio
import copy
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Protocol, runtime_checkable
from weakref import WeakKeyDictionary

from ..exceptions import ConfigurationError
from .inventory import InventoryLoader

_INVENTORY_FILE_SUFFIXES: frozenset[str] = frozenset({".yaml", ".yml", ".json", ".toml"})


@runtime_checkable
class InventoryProvider(Protocol):
    """Минимальный асинхронный контракт поставщика динамического инвентаря хостов."""

    async def load(self) -> list[dict[str, Any]]:
        """Асинхронно загрузить и вернуть список словарей конфигураций хостов."""
        ...


def validate_inventory_entries(loaded: Any) -> list[dict[str, Any]]:
    """Проверить, что ``InventoryProvider.load()`` вернул последовательность отображений хостов."""
    if not isinstance(loaded, list | tuple):
        raise ConfigurationError(
            f"InventoryProvider.load() must return a list of host dicts, got {type(loaded).__name__}"
        )
    entries: list[dict[str, Any]] = []
    for idx, item in enumerate(loaded):
        if not isinstance(item, Mapping):
            raise ConfigurationError(
                f"InventoryProvider.load() item #{idx} must be a mapping, got {type(item).__name__}"
            )
        entries.append(dict(item))
    return entries


class CachedInventoryProvider:
    """Универсальная TTL-обёртка над любым ``InventoryProvider`` с защитой от thundering herd."""

    def __init__(
        self,
        provider: InventoryProvider,
        *,
        ttl: float = 60.0,
        clock: Callable[[], float] | None = None,
    ) -> None:
        """Инициализировать кэширующую обёртку провайдера инвентаря.

        Args:
            provider: Целевой ``InventoryProvider``.
            ttl: Время жизни кэша в секундах (``0.0`` отключает кэширование).
            clock: Монотонные часы (по умолчанию ``time.monotonic``; удобно подменять в тестах).

        """
        if not isinstance(provider, InventoryProvider):
            raise ConfigurationError("provider must implement InventoryProvider protocol (async load())")
        if ttl < 0.0:
            raise ConfigurationError("ttl must be >= 0.0")
        self._provider = provider
        self._ttl = float(ttl)
        self._clock: Callable[[], float] = clock or time.monotonic
        self._locks_guard = threading.Lock()
        self._locks: WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock] = WeakKeyDictionary()
        self._state: tuple[list[dict[str, Any]], float] | None = None

    def _get_lock(self) -> asyncio.Lock:
        """Вернуть ``asyncio.Lock``, привязанный к текущему активному event loop."""
        loop = asyncio.get_running_loop()
        with self._locks_guard:
            lock = self._locks.get(loop)
            if lock is None:
                lock = asyncio.Lock()
                self._locks[loop] = lock
            return lock

    @property
    def provider(self) -> InventoryProvider:
        """Внутренний (оборачиваемый) ``InventoryProvider``."""
        return self._provider

    @property
    def ttl(self) -> float:
        """Время жизни кэша в секундах."""
        return self._ttl

    @property
    def expires_at(self) -> float | None:
        """Монотонная метка времени истечения текущего кэша (или ``None``, если кэш пуст)."""
        state = self._state
        return None if state is None else state[1]

    @property
    def is_stale(self) -> bool:
        """Проверить, пуст ли кэш или истёк ли его TTL."""
        state = self._state
        if state is None or self._ttl == 0.0:
            return True
        return self._clock() >= state[1]

    def invalidate(self) -> None:
        """Принудительно сбросить закэшированный снимок инвентаря."""
        self._state = None

    async def load(self, *, force_refresh: bool = False) -> list[dict[str, Any]]:
        """Вернуть закэшированный инвентарь или обновить его из источника при истечении TTL."""
        state = self._state
        if not force_refresh and state is not None and self._ttl > 0.0 and self._clock() < state[1]:
            return copy.deepcopy(state[0])

        async with self._get_lock():
            state = self._state
            if not force_refresh and state is not None and self._ttl > 0.0 and self._clock() < state[1]:
                return copy.deepcopy(state[0])
            validated = validate_inventory_entries(await self._provider.load())
            snapshot = copy.deepcopy(validated)
            if self._ttl > 0.0:
                self._state = (snapshot, self._clock() + self._ttl)
            else:
                self._state = None
            return copy.deepcopy(snapshot)


class FileInventoryProvider:
    """Встроенный zero-dependency провайдер инвентаря для локальных файлов YAML/JSON/TOML."""

    def __init__(
        self,
        path: str | Path,
        *,
        host: str | None = None,
        group: str | None = None,
        base_dir: str | Path | None = None,
    ) -> None:
        """Инициализировать файловый провайдер инвентаря."""
        self.path = Path(path)
        self.host = host
        self.group = group
        self.base_dir = base_dir

    async def load(self) -> list[dict[str, Any]]:
        """Асинхронно прочитать файл инвентаря через ``InventoryLoader.load_file``."""
        return await asyncio.to_thread(
            InventoryLoader.load_file,
            self.path,
            host=self.host,
            group=self.group,
            base_dir=self.base_dir,
        )


class StaticInventoryProvider:
    """Встроенный провайдер инвентаря из структуры данных в памяти (список или словарь)."""

    def __init__(
        self,
        data: Any,
        *,
        host: str | None = None,
        group: str | None = None,
        base_dir: str | Path | None = None,
    ) -> None:
        """Инициализировать статический провайдер инвентаря."""
        self.data = copy.deepcopy(data)
        self.host = host
        self.group = group
        self.base_dir = base_dir

    async def load(self) -> list[dict[str, Any]]:
        """Нормализовать и вернуть копию списка записей хостов из памяти."""
        return InventoryLoader.parse_data(
            copy.deepcopy(self.data),
            host=self.host,
            group=self.group,
            base_dir=self.base_dir,
        )


def provider_resolves_secrets(provider: InventoryProvider) -> bool:
    """Вернуть ``True``, если провайдер (или обёрнутый в ``CachedInventoryProvider``) уже разрешил секреты."""
    current: InventoryProvider = provider
    while isinstance(current, CachedInventoryProvider):
        current = current.provider
    return isinstance(current, (FileInventoryProvider, StaticInventoryProvider))


def resolve_inventory_provider(
    source: InventoryProvider | str | Path,
    *,
    host: str | None = None,
    group: str | None = None,
    base_dir: str | Path | None = None,
    provider_options: Mapping[str, Any] | None = None,
) -> InventoryProvider:
    """Преобразовать источник (``InventoryProvider``, путь к файлу или имя плагина) в ``InventoryProvider``."""
    if isinstance(source, InventoryProvider):
        if provider_options:
            raise ConfigurationError(
                "provider_options cannot be passed when source is already an InventoryProvider instance"
            )
        return source

    if isinstance(source, Path):
        if provider_options:
            raise ConfigurationError(
                "provider_options can only be used with inventory plugin names, not filesystem paths"
            )
        return FileInventoryProvider(source, host=host, group=group, base_dir=base_dir)

    if isinstance(source, str):
        raw = source.strip()
        if not raw:
            raise ConfigurationError("Inventory source must not be empty")
        from ..plugins._loader import PluginLoader

        plugin_key = raw.lower()
        available_plugins = set(PluginLoader.list_available("uniconn.inventory"))
        path_candidate = Path(raw)
        is_explicit_file = (
            path_candidate.suffix.lower() in _INVENTORY_FILE_SUFFIXES
            or path_candidate.is_file()
            or "/" in raw
            or "\\" in raw
        )
        if not is_explicit_file and (plugin_key in available_plugins or provider_options is not None):
            opts = dict(provider_options or {})
            return PluginLoader.instantiate(
                "uniconn.inventory",
                plugin_key,
                protocol=InventoryProvider,
                **opts,
            )

        if provider_options:
            raise ConfigurationError(
                f"provider_options can only be used with inventory plugin names, not file path {raw!r}"
            )
        return FileInventoryProvider(path_candidate, host=host, group=group, base_dir=base_dir)

    raise ConfigurationError(
        f"Unsupported inventory source {type(source).__name__!r}: expected InventoryProvider, str, or Path"
    )


__all__ = [
    "CachedInventoryProvider",
    "FileInventoryProvider",
    "InventoryProvider",
    "StaticInventoryProvider",
    "provider_resolves_secrets",
    "resolve_inventory_provider",
    "validate_inventory_entries",
]
