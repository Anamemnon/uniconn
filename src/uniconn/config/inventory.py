# src/uniconn/config/inventory.py
"""Загрузчик и парсер инвентарных файлов (YAML/JSON) с поддержкой хостов, групп и defaults."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class InventoryLoader:
    """Сервис чтения и нормализации инвентарных конфигураций (YAML/JSON)."""

    @staticmethod
    def parse_data(
        raw_data: Any,
        host: str | None = None,
        group: str | None = None,
    ) -> list[dict[str, Any]]:
        """Нормализовать данные инвентаря (список или словарь с hosts/groups/defaults).

        Args:
            raw_data: Распарсенная структура из YAML или JSON.
            host: Опциональное имя/алиас хоста для фильтрации.
            group: Опциональное имя группы для фильтрации.

        Returns:
            Список словарей с параметрами подключений.

        Raises:
            KeyError: Если запрошенный ``host`` или ``group`` не найден.

        """
        entries: list[dict[str, Any]] = []
        group_map: dict[str, list[str]] = {}

        if isinstance(raw_data, list):
            for item in raw_data:
                if isinstance(item, str):
                    entries.append({"uri": item})
                elif isinstance(item, dict):
                    entries.append(dict(item))
        elif isinstance(raw_data, dict):
            if "hosts" in raw_data and isinstance(raw_data["hosts"], (dict, list)):
                defaults = (
                    dict(raw_data.get("defaults", {}))
                    if isinstance(raw_data.get("defaults"), dict)
                    else {}
                )
                raw_groups = raw_data.get("groups")
                if isinstance(raw_groups, dict):
                    for g_name, g_members in raw_groups.items():
                        if isinstance(g_members, list):
                            group_map[str(g_name)] = [str(m) for m in g_members]

                hosts_sec = raw_data["hosts"]
                if isinstance(hosts_sec, dict):
                    for alias, h_val in hosts_sec.items():
                        if isinstance(h_val, str):
                            merged = {**defaults, "name": str(alias), "uri": h_val}
                        elif isinstance(h_val, dict):
                            merged = {**defaults, **h_val}
                            merged.setdefault("name", str(alias))
                            merged.setdefault("host", str(alias))
                        else:
                            continue
                        entries.append(merged)
                elif isinstance(hosts_sec, list):
                    for item in hosts_sec:
                        if isinstance(item, str):
                            entries.append({**defaults, "uri": item})
                        elif isinstance(item, dict):
                            entries.append({**defaults, **item})
            elif "transport" in raw_data or "uri" in raw_data:
                entries.append(dict(raw_data))
            else:
                for alias, h_val in raw_data.items():
                    if isinstance(h_val, str):
                        entries.append({"name": str(alias), "uri": h_val})
                    elif isinstance(h_val, dict):
                        merged = dict(h_val)
                        merged.setdefault("name", str(alias))
                        merged.setdefault("host", str(alias))
                        entries.append(merged)

        if group is not None:
            explicit_members = set(group_map.get(group, []))
            filtered_by_group: list[dict[str, Any]] = []
            for entry in entries:
                entry_groups = entry.get("groups") or []
                if isinstance(entry_groups, str):
                    entry_groups = [entry_groups]
                entry_name = entry.get("name") or entry.get("host")
                if group in entry_groups or (entry_name and str(entry_name) in explicit_members):
                    filtered_by_group.append(entry)
            if not filtered_by_group:
                raise KeyError(f"Group {group!r} not found in inventory")
            entries = filtered_by_group

        if host is not None:
            filtered_by_host = [
                entry
                for entry in entries
                if entry.get("name") == host or entry.get("host") == host
            ]
            if not filtered_by_host:
                raise KeyError(f"Host {host!r} not found in inventory")
            entries = filtered_by_host

        return entries

    @classmethod
    def load_file(
        cls,
        path: str | Path,
        *,
        host: str | None = None,
        group: str | None = None,
    ) -> list[dict[str, Any]]:
        """Прочитать файл ``.yaml``/``.yml``/``.json`` и вернуть список конфигураций хостов."""
        from ..exceptions import ConfigurationError

        filepath = Path(path)
        content = filepath.read_text(encoding="utf-8")

        if filepath.suffix in (".yaml", ".yml"):
            try:
                import yaml

                loader_cls = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
                raw_data = yaml.load(content, Loader=loader_cls)
            except ImportError:
                raise ImportError("PyYAML not installed. Run: pip install pyyaml") from None
        elif filepath.suffix == ".json":
            raw_data = json.loads(content)
        else:
            raise ConfigurationError(
                f"Unsupported file format: {filepath.suffix}. Use .json, .yaml or .yml"
            )

        return cls.parse_data(raw_data, host=host, group=group)
