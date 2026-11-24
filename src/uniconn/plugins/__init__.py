# src/uniconn/plugins/__init__.py
"""Плагинная система ``uniconn``.

Унифицированная динамическая загрузка расширений через ``importlib.metadata.entry_points``
для транспортов, хранилищ состояния, провайдеров инвентаря, бэкендов секретов и HITL-каналов.
"""

from ._loader import PLUGIN_GROUPS, PluginInfo, PluginLoader, TransportLoader

__all__ = [
    "PLUGIN_GROUPS",
    "PluginInfo",
    "PluginLoader",
    "TransportLoader",
]
