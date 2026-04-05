# src/uniconn/plugins/__init__.py
"""
Плагинная система uniconn.

Модуль для динамической загрузки транспортов через entry-points.
"""

from ._loader import TransportLoader

__all__ = ["TransportLoader"]
