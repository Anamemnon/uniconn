# tests/unit/pools/test_inventory_providers.py
"""Юнит-тесты InventoryProvider, CachedInventoryProvider, ConnectionPool.from_inventory и MCPHostRegistry."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from uniconn import (
    CachedInventoryProvider,
    ConfigurationError,
    ConnectionPool,
    InventoryProvider,
    PluginLoader,
    SyncConnectionPool,
)
from uniconn.config.inventory_providers import (
    FileInventoryProvider,
    StaticInventoryProvider,
    resolve_inventory_provider,
)
from uniconn.mcp.models import MCPSecurityPolicy
from uniconn.mcp.registry import MCPHostRegistry


class _CountingDynamicProvider:
    """Тестовый асинхронный провайдер инвентаря со счётчиком вызовов и задержкой."""

    def __init__(
        self,
        batches: list[list[dict[str, Any]]],
        *,
        delay: float = 0.0,
        fail_on_call: int | None = None,
    ) -> None:
        self._batches = batches
        self._delay = delay
        self._fail_on_call = fail_on_call
        self.calls = 0

    async def load(self) -> list[dict[str, Any]]:
        self.calls += 1
        if self._delay > 0:
            await asyncio.sleep(self._delay)
        if self._fail_on_call is not None and self.calls == self._fail_on_call:
            raise RuntimeError("Upstream inventory API unavailable")
        idx = min(self.calls - 1, len(self._batches) - 1)
        return self._batches[idx]


@pytest.fixture(autouse=True)
def _clean_inventory_plugins():
    PluginLoader.clear_cache(include_registered=True)
    yield
    PluginLoader.clear_cache(include_registered=True)


class TestCachedInventoryProvider:
    """Тесты TTL-кэширования, защиты от thundering herd и изоляции копий в CachedInventoryProvider."""

    @pytest.mark.asyncio
    async def test_ttl_caching_invalidate_and_force_refresh(self) -> None:
        """Кэш переиспользуется в пределах TTL, обновляется после истечения, invalidate() и force_refresh=True."""
        now = [100.0]
        inner = _CountingDynamicProvider(
            [
                [{"name": "web-1", "uri": "local://", "groups": ["web"], "options": {"tag": "v1"}}],
                [{"name": "web-2", "uri": "local://", "groups": ["web"], "options": {"tag": "v2"}}],
                [{"name": "web-3", "uri": "local://", "groups": ["web"], "options": {"tag": "v3"}}],
            ]
        )
        cached = CachedInventoryProvider(inner, ttl=30.0, clock=lambda: now[0])
        assert isinstance(cached, InventoryProvider)
        assert cached.is_stale is True

        # Первый вызов заполняет кэш
        r1 = await cached.load()
        assert inner.calls == 1
        assert r1[0]["name"] == "web-1"
        assert cached.is_stale is False
        assert cached.expires_at == 130.0

        # Мутация результата потребителем не портит внутренний кэш
        r1[0]["name"] = "mutated"
        r1[0]["options"]["tag"] = "mutated"

        # В пределах TTL кэш возвращает чистую копию без повторного обращения к inner
        now[0] = 120.0
        r2 = await cached.load()
        assert inner.calls == 1
        assert r2[0]["name"] == "web-1"
        assert r2[0]["options"]["tag"] == "v1"

        # После истечения TTL происходит обновление
        now[0] = 130.0
        assert cached.is_stale is True
        r3 = await cached.load()
        assert inner.calls == 2
        assert r3[0]["name"] == "web-2"

        # force_refresh=True игнорирует актуальный TTL
        now[0] = 135.0
        r4 = await cached.load(force_refresh=True)
        assert inner.calls == 3
        assert r4[0]["name"] == "web-3"

        # invalidate() сбрасывает кэш
        cached.invalidate()
        assert cached.is_stale is True
        assert cached.expires_at is None

    @pytest.mark.asyncio
    async def test_thundering_herd_single_upstream_call(self) -> None:
        """Конкурентные вызовы load() при холодном/просроченном кэше делают ровно один запрос к источнику."""
        inner = _CountingDynamicProvider(
            [[{"name": "n1", "uri": "local://"}]],
            delay=0.03,
        )
        cached = CachedInventoryProvider(inner, ttl=60.0)

        results = await asyncio.gather(*(cached.load() for _ in range(8)))
        assert inner.calls == 1
        assert len(results) == 8
        assert all(r[0]["name"] == "n1" for r in results)

    @pytest.mark.asyncio
    async def test_zero_ttl_disables_caching_and_negative_raises(self) -> None:
        """ttl=0.0 всегда перечитывает источник, а отрицательный ttl выбрасывает ConfigurationError."""
        inner = _CountingDynamicProvider([[{"name": "a", "uri": "local://"}]])
        with pytest.raises(ConfigurationError, match=r"ttl must be >= 0\.0"):
            CachedInventoryProvider(inner, ttl=-1.0)

        no_cache = CachedInventoryProvider(inner, ttl=0.0)
        await no_cache.load()
        await no_cache.load()
        assert inner.calls == 2
        assert no_cache.is_stale is True


class TestBuiltinAndPluginInventoryProviders:
    """Тесты FileInventoryProvider, StaticInventoryProvider и ConnectionPool / SyncConnectionPool.from_inventory."""

    @pytest.mark.asyncio
    async def test_file_and_static_providers(self, tmp_path: Path) -> None:
        """FileInventoryProvider читает YAML/JSON, StaticInventoryProvider нормализует словарь в памяти."""
        inv_file = tmp_path / "fleet.yaml"
        inv_file.write_text(
            "hosts:\n"
            "  app-1:\n"
            "    uri: local://\n"
            "    groups: [web]\n"
            "  db-1:\n"
            "    uri: local://\n"
            "    groups: [db]\n",
            encoding="utf-8",
        )

        file_provider = FileInventoryProvider(inv_file, group="web")
        assert isinstance(file_provider, InventoryProvider)
        entries = await file_provider.load()
        assert len(entries) == 1
        assert entries[0]["name"] == "app-1"

        static_provider = StaticInventoryProvider(
            {"hosts": {"edge-1": {"uri": "local://", "groups": ["edge"]}}}
        )
        assert isinstance(static_provider, InventoryProvider)
        static_entries = await static_provider.load()
        assert len(static_entries) == 1
        assert static_entries[0]["name"] == "edge-1"

        resolved = resolve_inventory_provider(inv_file)
        assert isinstance(resolved, FileInventoryProvider)

    @pytest.mark.asyncio
    async def test_connection_pool_from_inventory_async_and_plugin(self, tmp_path: Path) -> None:
        """ConnectionPool.from_inventory работает с InventoryProvider, файлом и зарегистрированным плагином."""

        class NetBoxMockProvider:
            def __init__(self, *, tag: str = "prod") -> None:
                self.tag = tag

            async def load(self) -> list[dict[str, Any]]:
                return [
                    {"name": f"{self.tag}-web-1", "transport": "local", "host": f"{self.tag}-web-1", "groups": ["web"]},
                    {"name": f"{self.tag}-db-1", "transport": "local", "host": f"{self.tag}-db-1", "groups": ["db"]},
                ]

        PluginLoader.register("inventory", "netbox", NetBoxMockProvider)

        # 1. Загрузка по имени плагина с provider_options и фильтрацией по группе
        pool = await ConnectionPool.from_inventory(
            "netbox",
            provider_options={"tag": "stage"},
            group="web",
            max_concurrent=4,
            dry_run=True,
        )
        assert len(pool.targets) == 1
        assert pool.dry_run is True
        async with pool:
            results = await pool.map("echo hello")
            assert len(results) == 1
            assert results[0].ok

        # 2. Загрузка через CachedInventoryProvider
        cached = CachedInventoryProvider(NetBoxMockProvider(tag="prod"), ttl=60.0)
        pool2 = await ConnectionPool.from_inventory(cached, host="prod-db-1")
        assert len(pool2.targets) == 1
        assert pool2.target_key(pool2.targets[0]) == "prod-db-1"

        # 3. Загрузка по пути к файлу
        inv_json = tmp_path / "hosts.json"
        inv_json.write_text('[{"name": "loc-1", "transport": "local", "host": "loc-1"}]', encoding="utf-8")
        pool3 = await ConnectionPool.from_inventory(inv_json)
        assert len(pool3.targets) == 1

    def test_sync_connection_pool_from_inventory_parity(self) -> None:
        """SyncConnectionPool.from_inventory синхронно строит рабочий пул поверх async InventoryProvider."""
        provider = StaticInventoryProvider(
            [
                {"name": "sync-1", "transport": "local", "host": "sync-1", "groups": ["workers"]},
                {"name": "sync-2", "transport": "local", "host": "sync-2", "groups": ["workers"]},
            ]
        )
        cached = CachedInventoryProvider(provider, ttl=30.0)
        sync_pool = SyncConnectionPool.from_inventory(cached, group="workers", dry_run=True)
        assert len(sync_pool.targets) == 2
        with sync_pool:
            results = sync_pool.map("echo sync-ok")
            assert len(results) == 2
            assert all(r.ok for r in results)


class TestMCPHostRegistryDynamicProvider:
    """Тесты интеграции InventoryProvider + CachedInventoryProvider + refresh() в MCPHostRegistry."""

    @pytest.mark.asyncio
    async def test_from_provider_refresh_and_atomic_rollback_on_failure(self) -> None:
        """MCPHostRegistry.from_provider и refresh() поддерживают TTL, force=True и сохраняют снимок при сбое."""
        now = [0.0]
        raw_provider = _CountingDynamicProvider(
            batches=[
                [
                    {"name": "api-1", "uri": "ssh://deploy@10.0.1.1", "groups": ["api"], "tenant": "acme"},
                ],
                [
                    {"name": "api-1", "uri": "ssh://deploy@10.0.1.1", "groups": ["api"], "tenant": "acme"},
                    {"name": "api-2", "uri": "ssh://deploy@10.0.1.2", "groups": ["api"], "tenant": "acme"},
                ],
            ],
            fail_on_call=3,
        )
        cached = CachedInventoryProvider(raw_provider, ttl=60.0, clock=lambda: now[0])

        registry = await MCPHostRegistry.from_provider(
            cached,
            policy=MCPSecurityPolicy(allow_dynamic_uri=False),
            default_to_local=False,
        )
        assert registry.provider is cached
        assert [e.name for e in registry.list_entries()] == ["api-1"]
        assert raw_provider.calls == 1

        # В пределах TTL refresh(force=False) берёт данные из кэша без повторного вызова источника
        now[0] = 10.0
        count_cached = await registry.refresh(force=False)
        assert count_cached == 1
        assert raw_provider.calls == 1

        # refresh(force=True) принудительно обновляет кэш и добавляет api-2
        count_forced = await registry.refresh(force=True)
        assert count_forced == 2
        assert raw_provider.calls == 2
        assert {e.name for e in registry.list_entries()} == {"api-1", "api-2"}

        # Совместимость с for_tenant()
        acme_reg = registry.for_tenant("acme")
        assert {e.name for e in acme_reg.list_entries()} == {"api-1", "api-2"}
        other_reg = registry.for_tenant("other")
        assert other_reg.list_entries() == []

        # При сбое провайдера (вызов №3) исключение пробрасывается, а старый снимок остаётся нетронутым
        with pytest.raises(RuntimeError, match="Upstream inventory API unavailable"):
            await registry.refresh(force=True)
        assert {e.name for e in registry.list_entries()} == {"api-1", "api-2"}

    @pytest.mark.asyncio
    async def test_no_double_secret_resolution_in_pool_and_registry(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Секрет, значение которого выглядит как file://..., не разыменовывается повторно."""
        monkeypatch.setenv("OUTER_LITERAL_TAG", "file:///nonexistent/should_not_be_read")
        inv_file = tmp_path / "sec_hosts.yaml"
        inv_file.write_text(
            "hosts:\n"
            "  node-1:\n"
            "    transport: local\n"
            "    host: node-1\n"
            "    options:\n"
            "      note: env://OUTER_LITERAL_TAG\n",
            encoding="utf-8",
        )

        pool = await ConnectionPool.from_inventory(inv_file)
        assert len(pool.targets) == 1
        conn = pool.targets[0]
        assert conn.config.options["note"] == "file:///nonexistent/should_not_be_read"  # type: ignore[union-attr]

        registry = await MCPHostRegistry.from_provider(inv_file)
        entry = registry.get_entry("node-1")
        assert entry.raw_config["options"]["note"] == "file:///nonexistent/should_not_be_read"

    @pytest.mark.asyncio
    async def test_inventory_factory_plugin_and_missing_plugin_error(self) -> None:
        """Фабричная функция в uniconn.inventory работает, а неизвестный плагин с provider_options даёт PluginNotFoundError."""
        from uniconn import PluginNotFoundError

        def build_factory_provider(*, env: str = "dev") -> InventoryProvider:
            return StaticInventoryProvider(
                [{"name": f"{env}-host", "transport": "local", "host": f"{env}-host"}]
            )

        PluginLoader.register("inventory", "FactoryInv", build_factory_provider)
        pool = await ConnectionPool.from_inventory("factoryinv", provider_options={"env": "prod"})
        assert len(pool.targets) == 1
        assert pool.target_key(pool.targets[0]) == "prod-host"

        with pytest.raises(PluginNotFoundError, match="nonexistent_inv"):
            await ConnectionPool.from_inventory("nonexistent_inv", provider_options={"token": "x"})

    def test_cached_provider_shared_across_sync_and_async_loops_and_validation(self) -> None:
        """Один CachedInventoryProvider безопасно работает между SyncConnectionPool и asyncio.run(), и валидирует записи."""
        provider = StaticInventoryProvider(
            [{"name": "shared-1", "transport": "local", "host": "shared-1"}]
        )
        cached = CachedInventoryProvider(provider, ttl=60.0)

        sync_pool = SyncConnectionPool.from_inventory(cached)
        assert len(sync_pool.targets) == 1

        async_pool = asyncio.run(ConnectionPool.from_inventory(cached))
        assert len(async_pool.targets) == 1

        class BadListProvider:
            async def load(self) -> list[dict[str, Any]]:
                return ["not-a-dict"]  # type: ignore[list-item]

        bad_cached = CachedInventoryProvider(BadListProvider(), ttl=10.0)
        with pytest.raises(ConfigurationError, match="must be a mapping"):
            asyncio.run(bad_cached.load())

    @pytest.mark.asyncio
    async def test_no_double_secret_resolution_on_password_sudo_copy_and_lazy_uri(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Поля password и sudo_password не переразрешаются повторно в ConnectionConfig, copy() и MCPHostRegistry."""
        monkeypatch.setenv("REAL_PW", "file:///nonexistent/must_stay_literal")
        monkeypatch.setenv("REAL_SUDO", "env://NONEXISTENT_INNER_VAR")
        inv_file = tmp_path / "creds.yaml"
        inv_file.write_text(
            "hosts:\n"
            "  app-1:\n"
            "    transport: ssh\n"
            "    host: 10.0.0.10\n"
            "    username: deploy\n"
            "    password: env://REAL_PW\n"
            "    options:\n"
            "      sudo_password: env://REAL_SUDO\n"
            "  app-2:\n"
            "    uri: ssh://deploy:env://LAZY_URI_PW@10.0.0.11\n"
            "    options:\n"
            "      sudo_password: env://REAL_SUDO\n",
            encoding="utf-8",
        )

        # 1. MCPHostRegistry.from_provider не падает на невыставленной LAZY_URI_PW при индексации
        registry = await MCPHostRegistry.from_provider(inv_file)
        conn1 = registry.create_connection("app-1")
        assert conn1.config.password is not None
        assert conn1.config.password.get_secret_value() == "file:///nonexistent/must_stay_literal"
        assert conn1.config.options["sudo_password"] == "env://NONEXISTENT_INNER_VAR"

        # 2. Connection.copy() сохраняет уже разрешённые секреты без повторной подстановки
        copied = conn1.copy(timeout=45.0)
        assert copied.config.password is not None
        assert copied.config.password.get_secret_value() == "file:///nonexistent/must_stay_literal"
        assert copied.config.options["sudo_password"] == "env://NONEXISTENT_INNER_VAR"

        # 3. ConnectionPool.from_inventory разрешает inline URI секрет ровно один раз и не трогает sudo_password
        monkeypatch.setenv("LAZY_URI_PW", "file:///nonexistent/inline_literal")
        pool = await ConnectionPool.from_inventory(inv_file)
        by_host = {c.config.host: c for c in pool.targets}  # type: ignore[union-attr]
        assert by_host["10.0.0.10"].config.password.get_secret_value() == "file:///nonexistent/must_stay_literal"  # type: ignore[union-attr]
        assert by_host["10.0.0.11"].config.password.get_secret_value() == "file:///nonexistent/inline_literal"  # type: ignore[union-attr]
        assert by_host["10.0.0.11"].config.options["sudo_password"] == "env://NONEXISTENT_INNER_VAR"  # type: ignore[union-attr]

    @pytest.mark.asyncio
    async def test_unwrapped_provider_validation_and_provider_options_guard(
        self,
        tmp_path: Path,
    ) -> None:
        """Сырой InventoryProvider валидируется так же строго, как Cached, а лишние provider_options отклоняются."""

        class InvalidReturnProvider:
            async def load(self) -> list[dict[str, Any]]:
                return "not-a-list"  # type: ignore[return-value]

        with pytest.raises(ConfigurationError, match="must return a list"):
            await ConnectionPool.from_inventory(InvalidReturnProvider())

        with pytest.raises(ConfigurationError, match="must return a list"):
            await MCPHostRegistry.from_provider(InvalidReturnProvider())

        inv_file = tmp_path / "ok.json"
        inv_file.write_text('[{"name": "n1", "transport": "local"}]', encoding="utf-8")

        with pytest.raises(ConfigurationError, match="provider_options"):
            resolve_inventory_provider(inv_file, provider_options={"tag": "prod"})

        with pytest.raises(ConfigurationError, match="provider_options"):
            resolve_inventory_provider(StaticInventoryProvider([]), provider_options={"tag": "prod"})

    @pytest.mark.asyncio
    async def test_base_dir_confinement_enforced_for_inline_file_uri_secrets(
        self,
        tmp_path: Path,
    ) -> None:
        """Ограничение base_dir действует и для встроенных file:// секретов внутри uri в пуле и MCPHostRegistry."""
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        (secrets_dir / "allowed.pw").write_text("ok_secret\n", encoding="utf-8")
        (tmp_path / "outside.pw").write_text("forbidden_secret\n", encoding="utf-8")

        allowed_inv = tmp_path / "allowed.yaml"
        allowed_inv.write_text(
            "hosts:\n"
            "  ok-node:\n"
            "    uri: ssh://deploy:file://allowed.pw@10.0.0.1\n"
            "    tenant: acme\n",
            encoding="utf-8",
        )
        escape_inv = tmp_path / "escape.yaml"
        escape_inv.write_text(
            "hosts:\n"
            "  bad-node:\n"
            "    uri: ssh://deploy:file://../outside.pw@10.0.0.2\n"
            "    tenant: acme\n",
            encoding="utf-8",
        )

        # Разрешённый относительный путь внутри base_dir работает в ConnectionPool и MCPHostRegistry
        pool = await ConnectionPool.from_inventory(allowed_inv, base_dir=secrets_dir)
        assert pool.targets[0].config.password.get_secret_value() == "ok_secret"  # type: ignore[union-attr]

        reg = await MCPHostRegistry.from_provider(allowed_inv, base_dir=secrets_dir)
        tenant_reg = reg.for_tenant("acme")
        conn = tenant_reg.create_connection("ok-node")
        assert conn.config.password is not None
        assert conn.config.password.get_secret_value() == "ok_secret"

        # Выход за пределы base_dir через ../ блокируется и в пуле, и в MCPHostRegistry (включая for_tenant)
        with pytest.raises(ConfigurationError, match="escapes allowed base_dir"):
            await ConnectionPool.from_inventory(escape_inv, base_dir=secrets_dir)

        escape_reg = await MCPHostRegistry.from_provider(escape_inv, base_dir=secrets_dir)
        with pytest.raises(ConfigurationError, match="escapes allowed base_dir"):
            escape_reg.for_tenant("acme").create_connection("bad-node")
