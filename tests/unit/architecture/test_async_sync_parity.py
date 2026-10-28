# tests/unit/architecture/test_async_sync_parity.py
"""Архитектурные тесты паритета Async/Sync фасадов и отсутствия ручного дублирования."""

from __future__ import annotations

import inspect
from pathlib import Path

import uniconn.sync as sync_pkg
from uniconn import (
    Connection,
    ConnectionPool,
    FileOperationsService,
    PoolFileOperationsService,
    PoolStateManagementService,
    ShellSession,
    StateManagementService,
    SyncConnection,
    SyncConnectionPool,
    SyncFileOperationsService,
    SyncPoolFileOperationsService,
    SyncPoolStateManagementService,
    SyncShellSession,
    SyncStateManagementService,
    SyncTunnelService,
    TunnelService,
)
from uniconn.core.bridge import (
    _PoolFanOutDictDescriptor,
    _SyncContextDescriptor,
    _SyncIterDescriptor,
    _SyncMethodDescriptor,
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

# Низкоуровневые async-примитивы, которые по архитектурной политике не дублируются в Sync-слое
_ASYNC_ONLY_PRIMITIVES: tuple[str, ...] = (
    "SyncCommandPipeline",
    "SyncOperationObserver",
    "SyncBackgroundPool",
    "SyncLogPipeline",
    "SyncPoolStreamMultiplexer",
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
    """Все пользовательские методы и свойства Connection доступны в SyncConnection."""
    async_methods = _public_methods(Connection) - {"to_sync"}
    sync_methods = _public_methods(SyncConnection)
    missing = async_methods - sync_methods
    assert not missing, f"SyncConnection is missing methods from Connection: {missing}"


def test_domain_services_async_sync_parity() -> None:
    """Все публичные методы доменных сервисов присутствуют в Sync-аналогах."""
    pairs = [
        (FileOperationsService, SyncFileOperationsService),
        (StateManagementService, SyncStateManagementService),
        (TunnelService, SyncTunnelService),
        (PoolFileOperationsService, SyncPoolFileOperationsService),
        (PoolStateManagementService, SyncPoolStateManagementService),
        (ShellSession, SyncShellSession),
        (ConnectionPool, SyncConnectionPool),
    ]
    for async_cls, sync_cls in pairs:
        async_m = _public_methods(async_cls) - _ASYNC_ONLY_METHODS
        sync_m = _public_methods(sync_cls)
        missing = async_m - sync_m
        assert not missing, f"{sync_cls.__name__} is missing {missing} from {async_cls.__name__}"


def test_async_only_primitives_are_not_duplicated_in_sync_layer() -> None:
    """Низкоуровневые async-примитивы (конвейер, мультиплексор, фоновые пулы) не дублируются в sync."""
    for forbidden_name in _ASYNC_ONLY_PRIMITIVES:
        assert not hasattr(sync_pkg, forbidden_name), (
            f"{forbidden_name} should remain async-only and not be duplicated in uniconn.sync"
        )


def test_sync_and_facade_methods_use_descriptors_without_boilerplate() -> None:
    """Методы сервисов в Pool* и Sync* используют типизированные дескрипторы вместо копипасты."""
    assert isinstance(PoolFileOperationsService.__dict__["checksum"], _PoolFanOutDictDescriptor)
    assert isinstance(PoolStateManagementService.__dict__["ensure_package"], _PoolFanOutDictDescriptor)
    assert isinstance(ConnectionPool.__dict__["gather_facts"], _PoolFanOutDictDescriptor)

    assert isinstance(SyncConnection.__dict__["run"], _SyncMethodDescriptor)
    assert isinstance(SyncConnection.__dict__["stream"], _SyncIterDescriptor)
    assert isinstance(SyncConnection.__dict__["temp_dir"], _SyncContextDescriptor)
    assert isinstance(SyncFileOperationsService.__dict__["upload"], _SyncMethodDescriptor)
    assert isinstance(SyncStateManagementService.__dict__["ensure_user"], _SyncMethodDescriptor)
    assert isinstance(SyncTunnelService.__dict__["forward_local_port"], _SyncContextDescriptor)
    assert isinstance(SyncPoolFileOperationsService.__dict__["checksum"], _SyncMethodDescriptor)
    assert isinstance(SyncPoolStateManagementService.__dict__["ensure_package"], _SyncMethodDescriptor)
    assert isinstance(SyncConnectionPool.__dict__["map"], _SyncMethodDescriptor)


def test_file_methods_accept_pathlib_path(tmp_path: Path) -> None:
    """Все файловые методы SyncConnection.files принимают объекты pathlib.Path."""
    target_file = tmp_path / "sample.txt"
    with Connection.from_uri("local://").to_sync() as conn:
        conn.files.write_file(target_file, "hello path")
        assert conn.files.exists(target_file)
        assert conn.files.read_file(target_file) == "hello path"
        stat_info = conn.files.stat(target_file)
        assert stat_info["size"] == 10
        assert "sample.txt" in conn.files.listdir(tmp_path)
        conn.files.chmod(target_file, 0o644)
        conn.files.remove_file(target_file)
        assert not conn.files.exists(target_file)
