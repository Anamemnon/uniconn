# src/uniconn/config/__init__.py
"""Пакет конфигурации, URI-парсера, секретов и провайдеров инвентаря uniconn."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .._utils import make_lazy_package_loader

if TYPE_CHECKING:
    from .inventory import InventoryLoader
    from .inventory_providers import (
        CachedInventoryProvider,
        FileInventoryProvider,
        InventoryProvider,
        StaticInventoryProvider,
        resolve_inventory_provider,
    )
    from .models import ConnectionConfig
    from .secrets import EnvSecretBackend, FileSecretBackend, SecretBackend, SecretResolver
    from .uri import URIParser

_LAZY_MODULE_GROUPS: dict[str, tuple[str, ...]] = {
    ".inventory": ("InventoryLoader",),
    ".inventory_providers": (
        "CachedInventoryProvider",
        "FileInventoryProvider",
        "InventoryProvider",
        "StaticInventoryProvider",
        "resolve_inventory_provider",
    ),
    ".models": ("ConnectionConfig",),
    ".secrets": ("EnvSecretBackend", "FileSecretBackend", "SecretBackend", "SecretResolver"),
    ".uri": ("URIParser",),
}

__all__ = [
    "CachedInventoryProvider",
    "ConnectionConfig",
    "EnvSecretBackend",
    "FileInventoryProvider",
    "FileSecretBackend",
    "InventoryLoader",
    "InventoryProvider",
    "SecretBackend",
    "SecretResolver",
    "StaticInventoryProvider",
    "URIParser",
    "resolve_inventory_provider",
]

_LAZY_EXPORTS, __getattr__, __dir__ = make_lazy_package_loader(
    __name__, globals(), _LAZY_MODULE_GROUPS, all_names=__all__
)
