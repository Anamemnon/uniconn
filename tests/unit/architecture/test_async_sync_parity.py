# tests/unit/architecture/test_async_sync_parity.py
"""Архитектурный тест 100% паритета методов между Async и Sync фасадами (v0.11.0)."""

from __future__ import annotations

import inspect
from pathlib import Path

from uniconn import (
    Connection,
    ConnectionPool,
    FileOperationsService,
    ShellSession,
    StateManagementService,
    SyncConnection,
    SyncConnectionPool,
    SyncFileOperationsService,
    SyncShellSession,
    SyncStateManagementService,
    SyncTunnelService,
    TunnelService,
)

# Фабричные методы класса и конвертеры, специфичные только для async-фасада
_ASYNC_ONLY_METHODS: frozenset[str] = frozenset(
    {
        "from_uri",
        "from_config",
        "from_dict",
        "from_inventory",
        "from_file",
        "copy",
        "with_overrides",
        "to_sync",
        "initialize",
    }
)


def _public_methods(cls: type) -> set[str]:
    names: set[str] = set()
    for name, member in inspect.getmembers(cls):
        if name.startswith("_"):
            continue
        if callable(member) or isinstance(member, property):
            names.add(name)
    return names


def test_connection_and_sync_connection_parity() -> None:
    """Все публичные методы и свойства Connection (кроме фабрик) должны быть в SyncConnection."""
    async_methods = _public_methods(Connection) - _ASYNC_ONLY_METHODS
    sync_methods = _public_methods(SyncConnection)
    missing = async_methods - sync_methods
    assert not missing, f"SyncConnection is missing methods from Connection: {missing}"


def test_domain_services_async_sync_parity() -> None:
    """Все публичные методы доменных сервисов должны присутствовать в Sync-аналогах."""
    pairs = [
        (FileOperationsService, SyncFileOperationsService),
        (StateManagementService, SyncStateManagementService),
        (TunnelService, SyncTunnelService),
        (ShellSession, SyncShellSession),
        (ConnectionPool, SyncConnectionPool),
    ]
    for async_cls, sync_cls in pairs:
        async_m = _public_methods(async_cls) - _ASYNC_ONLY_METHODS
        sync_m = _public_methods(sync_cls)
        missing = async_m - sync_m
        assert not missing, f"{sync_cls.__name__} is missing {missing} from {async_cls.__name__}"


def test_file_methods_accept_pathlib_path(tmp_path: Path) -> None:
    """Все файловые методы SyncConnection принимают объекты pathlib.Path."""
    target_file = tmp_path / "sample.txt"
    with Connection.from_uri("local://").to_sync() as conn:
        conn.write_file(target_file, "hello path")
        assert conn.exists(target_file)
        assert conn.read_file(target_file) == "hello path"
        stat_info = conn.stat(target_file)
        assert stat_info["size"] == 10
        assert "sample.txt" in conn.listdir(tmp_path)
        conn.chmod(target_file, 0o644)
        conn.remove_file(target_file)
        assert not conn.exists(target_file)
