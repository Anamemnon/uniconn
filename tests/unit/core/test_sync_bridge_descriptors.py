# tests/unit/core/test_sync_bridge_descriptors.py
"""Unit-тесты типизированных ParamSpec-дескрипторов Sync-слоя, SyncProxyMixin и SyncConnectionPool.apply."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from uniconn import (
    Connection,
    ConnectionPool,
    PoolFileOperationsService,
    PoolStateManagementService,
    SyncConnection,
    SyncFileOperationsService,
    SyncPoolFileOperationsService,
    SyncStateManagementService,
)
from uniconn.core.bridge import (
    EventLoopPortal,
    SyncProxyMixin,
    async_delegate,
    context_delegate,
    pool_fan_out_dict,
    sync_context,
    sync_iter,
    sync_method,
)


def test_descriptors_preserve_docstrings_and_names() -> None:
    """Дескрипторы сохраняют __name__ и __doc__ исходных методов и не протекают на верхний уровень фасадов."""
    assert SyncFileOperationsService.upload.__name__ == "upload"
    assert SyncFileOperationsService.upload.__doc__ is not None
    assert "SHA-256" in SyncFileOperationsService.upload.__doc__

    assert PoolFileOperationsService.checksum.__name__ == "checksum"
    assert PoolFileOperationsService.checksum.__doc__ is not None

    assert PoolStateManagementService.ensure_package.__name__ == "ensure_package"
    assert PoolStateManagementService.ensure_package.__doc__ is not None

    assert SyncConnection.run.__name__ == "run"
    assert SyncConnection.run.__doc__ is not None
    assert "CommandPipeline" in SyncConnection.run.__doc__

    assert SyncStateManagementService.ensure_package.__name__ == "ensure_package"
    assert SyncStateManagementService.ensure_package.__doc__ is not None

    assert SyncPoolFileOperationsService.upload.__name__ == "upload"
    assert SyncPoolFileOperationsService.upload.__doc__ is not None

    # Проверка отсутствия дублирующих доменных алиасов на верхнем уровне Connection и ConnectionPool
    for removed_attr in ("upload", "download", "write_file", "ensure_package", "forward_local_port"):
        assert not hasattr(Connection, removed_attr)
        assert not hasattr(SyncConnection, removed_attr)
        assert not hasattr(ConnectionPool, removed_attr)


@pytest.mark.asyncio
async def test_class_level_descriptor_invocation(tmp_path: Path) -> None:
    """Вызов дескрипторов через класс (PoolFileOperationsService.write_file(pool.files, ...)) работает корректно."""
    target = tmp_path / "cls_call.txt"
    async with ConnectionPool(["local://"]) as pool:
        await PoolFileOperationsService.write_file(pool.files, target, "from_class")
        content_map = await PoolFileOperationsService.read_file(pool.files, target)
        assert content_map["local://"] == "from_class"
        _ = pool_fan_out_dict


def test_sync_class_level_descriptor_invocation(tmp_path: Path) -> None:
    """Вызов sync-дескрипторов через класс (SyncConnection.run, SyncFileOperationsService.write_file) работает."""
    target = tmp_path / "sync_cls.txt"
    with SyncConnection.from_uri("local://") as sync_conn:
        res = SyncConnection.run(sync_conn, "echo class_sync")
        assert res.text == "class_sync"
        SyncFileOperationsService.write_file(sync_conn.files, target, "sync_payload")
        assert SyncFileOperationsService.read_file(sync_conn.files, target) == "sync_payload"
        lines = list(SyncConnection.stream(sync_conn, "echo streamed_line"))
        assert any("streamed_line" in line for line in lines)
        with SyncConnection.temp_dir(sync_conn, prefix="desc_") as tmp_d:
            assert Path(tmp_d).is_dir()


def test_sync_proxy_mixin_dynamic_getattr_fallback() -> None:
    """SyncProxyMixin.__getattr__ автоматически оборачивает корутины, генераторы и свойства."""

    class _CustomAsyncBackend:
        custom_prop = "hello_prop"

        async def compute(self, x: int, y: int = 2) -> int:
            return x * y

        async def gen_items(self, count: int) -> AsyncIterator[int]:
            for i in range(count):
                yield i * 10

    class _CustomSyncWrapper(SyncProxyMixin):
        def __init__(self) -> None:
            self._async_target = _CustomAsyncBackend()
            self._portal = EventLoopPortal(owner_name="CustomSyncWrapper")

        def close(self) -> None:
            self._portal.close()

    wrapper: Any = _CustomSyncWrapper()
    try:
        assert wrapper.custom_prop == "hello_prop"
        assert wrapper.compute(7, y=3) == 21
        assert list(wrapper.gen_items(3)) == [0, 10, 20]
        with pytest.raises(AttributeError):
            _ = wrapper.non_existent_method
        with pytest.raises(AttributeError):
            _ = wrapper.__non_existent_dunder__
    finally:
        wrapper.close()


def test_custom_descriptors_direct_binding() -> None:
    """Проверка прямого использования async_delegate, context_delegate, sync_method, sync_context, sync_iter."""
    from contextlib import asynccontextmanager

    class _InnerService:
        async def ping_val(self, val: str) -> str:
            return f"pong:{val}"

        @asynccontextmanager
        async def scoped(self, token: int) -> AsyncIterator[int]:
            yield token + 1

        async def ticker(self) -> AsyncIterator[str]:
            yield "tick1"
            yield "tick2"

    class _AsyncFacade:
        def __init__(self) -> None:
            self.svc = _InnerService()

        ping_val = async_delegate("svc", _InnerService.ping_val)
        scoped = context_delegate("svc", _InnerService.scoped)

    class _SyncFacade(SyncProxyMixin):
        def __init__(self) -> None:
            self._async_target = _InnerService()
            self._portal = EventLoopPortal(owner_name="TestSyncFacade")

        ping_val = sync_method(_InnerService.ping_val)
        scoped = sync_context(_InnerService.scoped, cast_fn=int, reopen_portal=True)
        ticker = sync_iter(_InnerService.ticker)

    sf = _SyncFacade()
    try:
        assert sf.ping_val("ok") == "pong:ok"
        with _SyncFacade.scoped(sf, 41) as v:
            assert v == 42
        assert list(sf.ticker()) == ["tick1", "tick2"]
    finally:
        sf._portal.close()


def test_sync_connection_pool_apply_supports_both_sync_and_async_callables() -> None:
    """SyncConnectionPool.apply поддерживает как синхронные функции SyncConnection, так и async Connection."""
    pool = ConnectionPool(["local://", "local://"]).to_sync()
    with pool:
        # 1. Обычная синхронная функция, принимающая SyncConnection
        def sync_worker(conn: SyncConnection) -> str:
            res = conn.run("echo sync_worker_ok")
            return res.text

        sync_results = pool.apply(sync_worker)
        assert sync_results == ["sync_worker_ok", "sync_worker_ok"]

        # 2. Асинхронная функция, принимающая async Connection
        async def async_worker(conn: Connection) -> str:
            res = await conn.run("echo async_worker_ok")
            return res.text

        async_results = pool.apply(async_worker)
        assert async_results == ["async_worker_ok", "async_worker_ok"]
