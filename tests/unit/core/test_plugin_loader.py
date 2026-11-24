# tests/unit/core/test_plugin_loader.py
"""Юнит-тесты единого слоя расширений (PluginLoader, entry_points, SecretBackend, storage и HITL-каналы)."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

import uniconn
from uniconn import (
    ConfigurationError,
    ConnectionConfig,
    InMemoryStateStore,
    InventoryProvider,
    PluginLoader,
    PluginNotFoundError,
    SecretBackend,
    SecretResolver,
    TransportNotFoundError,
    URIParser,
)
from uniconn.config.inventory_providers import FileInventoryProvider, StaticInventoryProvider
from uniconn.mcp.hitl import ApprovalChannel, ApprovalManager, TerminalApprovalChannel
from uniconn.mcp.models import ActionRiskTier, ApprovalRequest, HITLPolicy, MCPSecurityPolicy
from uniconn.mcp.registry import MCPHostRegistry
from uniconn.mcp.storage import StateStore, resolve_state_store
from uniconn.plugins import PLUGIN_GROUPS, PluginInfo, TransportLoader


class _FakeEntryPoint:
    """Минимальный двойник ``importlib.metadata.EntryPoint`` для тестов."""

    def __init__(self, name: str, value: str, obj: Any | None = None, *, error: Exception | None = None) -> None:
        self.name = name
        self.value = value
        self._obj = obj
        self._error = error

    def load(self) -> Any:
        if self._error is not None:
            raise self._error
        return self._obj


@pytest.fixture(autouse=True)
def _clean_plugin_state():
    """Сбрасывать кэш и программные регистрации плагинов до и после каждого теста."""
    PluginLoader.clear_cache(include_registered=True)
    yield
    PluginLoader.clear_cache(include_registered=True)


class TestPluginLoaderCore:
    """Базовые операции PluginLoader по всем 5 группам расширения."""

    def test_canonical_groups_and_builtins_discoverable(self) -> None:
        """Все 5 канонических групп содержат встроенные реализации и отдают PluginInfo."""
        assert set(PLUGIN_GROUPS.keys()) == {"transports", "storage", "inventory", "secrets", "hitl_channels"}

        assert "local" in PluginLoader.list_available("transports")
        assert {"memory", "sqlite"}.issubset(PluginLoader.list_available("storage"))
        assert {"file", "static"}.issubset(PluginLoader.list_available("inventory"))
        assert {"env", "file"}.issubset(PluginLoader.list_available("secrets"))
        assert {"terminal", "webhook"}.issubset(PluginLoader.list_available("hitl_channels"))

        all_infos = PluginLoader.discover()
        assert all(isinstance(info, PluginInfo) for info in all_infos)
        groups_found = {info.group for info in all_infos}
        assert groups_found == set(PLUGIN_GROUPS.values())

    def test_load_builtins_with_protocol_validation(self) -> None:
        """Загрузка встроенных плагинов проходит проверку соответствующих протоколов."""
        assert PluginLoader.load("storage", "memory", protocol=StateStore) is InMemoryStateStore
        assert PluginLoader.load("inventory", "file", protocol=InventoryProvider) is FileInventoryProvider
        assert PluginLoader.load("inventory", "static", protocol=InventoryProvider) is StaticInventoryProvider
        assert PluginLoader.load("hitl_channels", "terminal", protocol=ApprovalChannel) is TerminalApprovalChannel
        env_backend_cls = PluginLoader.load("secrets", "env", protocol=SecretBackend)
        assert isinstance(env_backend_cls(), SecretBackend)

    def test_register_unregister_and_priority(self) -> None:
        """Программная регистрация перекрывает встроенный/entry_point плагин и корректно удаляется."""

        class CustomProvider:
            async def load(self) -> list[dict[str, Any]]:
                return [{"uri": "local://"}]

        PluginLoader.register("inventory", "custom_cmdb", CustomProvider)
        assert "custom_cmdb" in PluginLoader.list_available("inventory")
        loaded = PluginLoader.load("inventory", "custom_cmdb", protocol=InventoryProvider)
        assert loaded is CustomProvider

        infos = {i.name: i for i in PluginLoader.discover("inventory")}
        assert infos["custom_cmdb"].source == "registered"

        assert PluginLoader.unregister("inventory", "custom_cmdb") is True
        assert PluginLoader.unregister("inventory", "custom_cmdb") is False
        assert "custom_cmdb" not in PluginLoader.list_available("inventory")

    def test_protocol_mismatch_raises_configuration_error(self) -> None:
        """Плагин, не удовлетворяющий контракту Protocol, отклоняется с ConfigurationError."""

        class BrokenPlugin:
            pass

        PluginLoader.register("inventory", "broken", BrokenPlugin)
        with pytest.raises(ConfigurationError, match="does not satisfy required contract InventoryProvider"):
            PluginLoader.load("inventory", "broken", protocol=InventoryProvider)

    def test_missing_plugin_and_exception_hierarchy(self) -> None:
        """Отсутствующий плагин бросает PluginNotFoundError (наследник UniconnError и LookupError)."""
        with pytest.raises(PluginNotFoundError) as exc_info:
            PluginLoader.load("storage", "nonexistent_backend")

        err = exc_info.value
        assert isinstance(err, LookupError)
        assert err.group == "uniconn.storage"
        assert err.plugin_name == "nonexistent_backend"
        assert "memory" in err.available

        with pytest.raises(TransportNotFoundError) as t_exc:
            TransportLoader.get("nonexistent_transport_abc")
        assert isinstance(t_exc.value, PluginNotFoundError)

    def test_entry_points_discovery_and_broken_entry_point(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Плагин из importlib.metadata.entry_points загружается, а сломанный оборачивается в PluginNotFoundError."""

        class ExternalStore(InMemoryStateStore):
            pass

        fake_eps = {
            "uniconn.storage": [
                _FakeEntryPoint("redis", "ext_pkg:ExternalStore", ExternalStore),
                _FakeEntryPoint("broken", "ext_pkg:Broken", error=ImportError("missing redis lib")),
            ]
        }
        monkeypatch.setattr(
            "uniconn.plugins._loader.entry_points",
            lambda *, group: fake_eps.get(group, []),
        )

        assert "redis" in PluginLoader.list_available("storage")
        assert PluginLoader.load("storage", "redis", protocol=StateStore) is ExternalStore
        infos = {i.name: i for i in PluginLoader.discover("storage")}
        assert infos["redis"].source == "entry_point"
        assert infos["redis"].target == "ext_pkg:ExternalStore"

        with pytest.raises(PluginNotFoundError, match="missing redis lib"):
            PluginLoader.load("storage", "broken")


class TestPluggableSecretBackend:
    """Тесты SecretBackend, SecretResolver, URIParser и защиты MCPHostRegistry."""

    def test_register_custom_secret_backend_and_resolve(self) -> None:
        """Пользовательский SecretBackend работает в SecretResolver, ConnectionConfig и URIParser."""

        class VaultSecretBackend:
            def __init__(self) -> None:
                self.data = {
                    "prod/ssh": "vault_s3cr3t!",
                    "prod/sudo": "sudo_pw_42",
                }

            def resolve(
                self,
                uri: str,
                *,
                env: Mapping[str, str] | None = None,
                base_dir: str | Path | None = None,
            ) -> str:
                _ = (env, base_dir)
                key = uri[len("vault://") :]
                if key not in self.data:
                    raise ConfigurationError(f"Vault key not found: {key}")
                return self.data[key]

        SecretResolver.register_backend("vault", VaultSecretBackend())
        assert "vault" in SecretResolver.list_schemes()
        assert SecretResolver.is_secret_ref("vault://prod/ssh") is True
        assert SecretResolver.is_secret_ref("ssh://user@host") is False
        assert SecretResolver.resolve("vault://prod/ssh") == "vault_s3cr3t!"
        assert SecretResolver.resolve("https://example.com/path") == "https://example.com/path"

        cfg = ConnectionConfig(
            transport="ssh",
            host="app-01",
            username="deploy",
            password="vault://prod/ssh",  # type: ignore[arg-type]
            options={"sudo_password": "vault://prod/sudo"},
        )
        assert cfg.password is not None
        assert cfg.password.get_secret_value() == "vault_s3cr3t!"
        assert cfg.options["sudo_password"] == "sudo_pw_42"

        parsed = URIParser.parse("ssh://deploy:vault://prod/ssh@app-01:2222")
        assert parsed.host == "app-01"
        assert parsed.port == 2222
        assert parsed.password is not None
        assert parsed.password.get_secret_value() == "vault_s3cr3t!"

    def test_secret_backend_autoloaded_from_entry_points(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SecretResolver автоматически находит и загружает схему из entry_points('uniconn.secrets')."""

        class MockSmBackend:
            def resolve(
                self,
                uri: str,
                *,
                env: Mapping[str, str] | None = None,
                base_dir: str | Path | None = None,
            ) -> str:
                _ = (env, base_dir)
                return f"resolved:{uri.removeprefix('aws-sm://')}"

        monkeypatch.setattr(
            "uniconn.plugins._loader.entry_points",
            lambda *, group: (
                [_FakeEntryPoint("aws-sm", "mock_pkg:MockSmBackend", MockSmBackend)]
                if group == "uniconn.secrets"
                else []
            ),
        )

        assert "aws-sm" in SecretResolver.list_schemes()
        assert SecretResolver.is_secret_ref("aws-sm://prod/db") is True
        assert SecretResolver.resolve("aws-sm://prod/db") == "resolved:prod/db"

    def test_mcp_dynamic_uri_blocks_custom_secret_scheme(self) -> None:
        """MCPHostRegistry (fail-closed) блокирует ссылки на кастомные схемы секретов в динамических URI."""

        class CustomVault:
            def resolve(
                self,
                uri: str,
                *,
                env: Mapping[str, str] | None = None,
                base_dir: str | Path | None = None,
            ) -> str:
                _ = (uri, env, base_dir)
                return "leaked"

        SecretResolver.register_backend("vault", CustomVault())
        registry = MCPHostRegistry(policy=MCPSecurityPolicy(allow_dynamic_uri=True))

        with pytest.raises(PermissionError, match="cannot reference controller secrets"):
            registry.get_entry("ssh://admin:vault://prod/ssh@10.0.0.5")

        with pytest.raises(PermissionError, match="cannot reference controller secrets"):
            registry.get_entry("ssh://admin@10.0.0.5?password=vault%3A%2F%2Fprod%2Fssh")


class TestStorageAndHITLChannelPlugins:
    """Тесты подключения плагинов StateStore (uniconn.storage) и ApprovalChannel (uniconn.hitl_channels)."""

    def test_resolve_state_store_custom_plugin(self) -> None:
        """resolve_state_store загружает кастомный StateStore по имени бэкенда и по URI-схеме."""

        class CustomMemoryStore(InMemoryStateStore):
            def __init__(self, uri: str = "") -> None:
                super().__init__()
                self.uri = uri

        PluginLoader.register("storage", "customkv", CustomMemoryStore)

        store1, path1 = resolve_state_store("customkv://cluster-1:6379/0")
        assert isinstance(store1, CustomMemoryStore)
        assert store1.uri == "customkv://cluster-1:6379/0"
        assert path1 is None

        store2, _ = resolve_state_store(backend="customkv", backend_options={"uri": "customkv://node2"})
        assert isinstance(store2, CustomMemoryStore)
        assert store2.uri == "customkv://node2"

    @pytest.mark.asyncio
    async def test_hitl_approval_manager_loads_custom_channel_plugin(self) -> None:
        """ApprovalManager автоматически подключает кастомный канал из uniconn.hitl_channels."""
        notified: list[str] = []

        class SlackApprovalChannel:
            async def notify(self, request: ApprovalRequest) -> dict[str, Any] | None:
                notified.append(request.approval_id)
                return None

        PluginLoader.register("hitl_channels", "slack", SlackApprovalChannel)
        policy = HITLPolicy(enabled=True, channels=("cli", "slack"))
        manager = ApprovalManager(policy=policy)
        try:
            assert any(isinstance(ch, SlackApprovalChannel) for ch in manager._channels)
            req = await manager.create_request(
                target_host="prod-db-01",
                tool_name="uniconn_run",
                risk_tier=ActionRiskTier.TIER_2_DESTRUCTIVE,
                command="systemctl restart postgresql",
            )
            assert req.approval_id in notified
        finally:
            await manager.close()

    def test_public_exports_from_root_package(self) -> None:
        """Ключевые символы плагинного слоя доступны на верхнем уровне пакета uniconn."""
        for name in (
            "PluginLoader",
            "PluginNotFoundError",
            "InventoryProvider",
            "CachedInventoryProvider",
            "SecretBackend",
            "PluginInfo",
            "PLUGIN_GROUPS",
            "FileInventoryProvider",
            "StaticInventoryProvider",
            "EnvSecretBackend",
            "FileSecretBackend",
        ):
            assert hasattr(uniconn, name), f"Missing export: {name}"

    def test_case_insensitive_plugin_lookup_and_factory_secret_backend(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Имена плагинов регистронезависимы, а SecretBackend инстанцируется один раз и поддерживает фабрики."""
        init_count = 0

        class CountingVaultBackend:
            def __init__(self) -> None:
                nonlocal init_count
                init_count += 1

            def resolve(
                self,
                uri: str,
                *,
                env: Mapping[str, str] | None = None,
                base_dir: str | Path | None = None,
            ) -> str:
                _ = (env, base_dir)
                return f"secret:{uri.split('://', 1)[1]}"

        def make_op_backend() -> SecretBackend:
            return CountingVaultBackend()

        monkeypatch.setattr(
            "uniconn.plugins._loader.entry_points",
            lambda *, group: (
                [
                    _FakeEntryPoint("Vault", "ext:CountingVaultBackend", CountingVaultBackend),
                    _FakeEntryPoint("OP", "ext:make_op_backend", make_op_backend),
                ]
                if group == "uniconn.secrets"
                else []
            ),
        )

        assert SecretResolver.resolve("vault://a") == "secret:a"
        assert SecretResolver.resolve("VAULT://b") == "secret:b"
        assert init_count == 1  # один инстанс на все вызовы!

        assert SecretResolver.resolve("op://item/pw") == "secret:item/pw"
        assert SecretResolver.resolve("op://item/pw2") == "secret:item/pw2"
        assert init_count == 2  # фабрика тоже вызвана ровно один раз

    def test_storage_plugin_factory_override_and_unmasked_type_error(self) -> None:
        """resolve_state_store поддерживает фабрики с URI, перекрытие memory и не скрывает TypeError внутри плагина."""

        class CustomStore(InMemoryStateStore):
            def __init__(self, uri: str) -> None:
                super().__init__()
                self.uri = uri

        def create_store(uri: str, *, prefix: str = "app") -> StateStore:
            store = CustomStore(uri)
            store.prefix = prefix  # type: ignore[attr-defined]
            return store

        PluginLoader.register("storage", "Redis", create_store)
        store, _ = resolve_state_store("redis://127.0.0.1:6379/1", backend_options={"prefix": "mcp"})
        assert isinstance(store, CustomStore)
        assert store.uri == "redis://127.0.0.1:6379/1"
        assert getattr(store, "prefix", None) == "mcp"

        # Перекрытие встроенного memory через PluginLoader
        custom_mem = InMemoryStateStore()
        PluginLoader.register("storage", "memory", custom_mem)
        resolved_mem, _ = resolve_state_store(backend="memory")
        assert resolved_mem is custom_mem

        # Внутренний TypeError внутри конструктора НЕ должен маскироваться
        def broken_factory(uri: str) -> StateStore:
            _ = uri
            raise TypeError("internal storage bug")

        PluginLoader.register("storage", "buggy", broken_factory)
        with pytest.raises(TypeError, match="internal storage bug"):
            resolve_state_store("buggy://host", backend="buggy")

        # Некорректный возвращаемый тип отклоняется с ConfigurationError
        PluginLoader.register("storage", "badret", lambda: object())
        with pytest.raises(ConfigurationError, match="StateStore"):
            resolve_state_store(backend="badret")

    @pytest.mark.asyncio
    async def test_hitl_channel_factory_dedup_and_unmasked_type_error(self) -> None:
        """ApprovalManager дедуплицирует каналы, поддерживает фабрики с policy и не маскирует внутренний TypeError."""
        created_with_policies: list[HITLPolicy] = []

        class PolicyAwareChannel:
            async def notify(self, request: ApprovalRequest) -> dict[str, Any] | None:
                _ = request
                return None

        def make_channel(*, policy: HITLPolicy) -> ApprovalChannel:
            created_with_policies.append(policy)
            return PolicyAwareChannel()

        PluginLoader.register("hitl_channels", "PagerDuty", make_channel)
        policy = HITLPolicy(enabled=True, channels=("pagerduty", "PAGERDUTY", "cli"))
        manager = ApprovalManager(policy=policy)
        try:
            assert len(created_with_policies) == 1
            assert created_with_policies[0] == policy
            assert len(manager._channels) == 1
        finally:
            await manager.close()

        # Внутренний TypeError в фабрике канала не маскируется
        def buggy_channel(*, policy: HITLPolicy) -> ApprovalChannel:
            _ = policy
            raise TypeError("internal channel bug")

        PluginLoader.register("hitl_channels", "buggychan", buggy_channel)
        with pytest.raises(TypeError, match="internal channel bug"):
            ApprovalManager(policy=HITLPolicy(enabled=True, channels=("buggychan",)))

        # Фабрика, возвращающая не-ApprovalChannel, бросает ConfigurationError
        PluginLoader.register("hitl_channels", "badchan", lambda: object())
        with pytest.raises(ConfigurationError, match="ApprovalChannel"):
            ApprovalManager(policy=HITLPolicy(enabled=True, channels=("badchan",)))

    def test_clear_cache_invalidates_secret_backend_instances_and_rejects_bad_schemes(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """PluginLoader.clear_cache сбрасывает кэш инстансов SecretResolver, а встроенные бэкенды проверяют схему."""
        from uniconn import EnvSecretBackend, FileSecretBackend

        init_count = 0

        class StatefulVault:
            def __init__(self) -> None:
                nonlocal init_count
                init_count += 1

            def resolve(
                self,
                uri: str,
                *,
                env: Mapping[str, str] | None = None,
                base_dir: str | Path | None = None,
            ) -> str:
                _ = (uri, env, base_dir)
                return f"v{init_count}"

        monkeypatch.setattr(
            "uniconn.plugins._loader.entry_points",
            lambda *, group: (
                [_FakeEntryPoint("vault", "ext:StatefulVault", StatefulVault)]
                if group == "uniconn.secrets"
                else []
            ),
        )
        assert SecretResolver.resolve("vault://k") == "v1"
        assert SecretResolver.resolve("vault://k") == "v1"
        assert init_count == 1

        PluginLoader.clear_cache("secrets")
        assert SecretResolver.resolve("vault://k") == "v2"
        assert init_count == 2

        with pytest.raises(ConfigurationError, match="env://"):
            EnvSecretBackend().resolve("file:///tmp/x")
        with pytest.raises(ConfigurationError, match="file://"):
            FileSecretBackend().resolve("env://FOO")

    def test_inline_secret_uri_with_at_in_query_and_masking(self) -> None:
        """URIParser и mask_uri_secrets корректно обрабатывают '@' в query-строке вместе со встроенным секретом."""
        from uniconn.mcp.registry import mask_uri_secrets

        class SimpleVault:
            def resolve(
                self,
                uri: str,
                *,
                env: Mapping[str, str] | None = None,
                base_dir: str | Path | None = None,
            ) -> str:
                _ = (env, base_dir)
                return f"pw:{uri.removeprefix('vault://')}"

        SecretResolver.register_backend("vault", SimpleVault())
        uri = "ssh://deploy:vault://prod/ssh@app-01:2222?proxy_jump=bastion@jump-01"
        cfg = URIParser.parse(uri)
        assert cfg.host == "app-01"
        assert cfg.port == 2222
        assert cfg.password is not None
        assert cfg.password.get_secret_value() == "pw:prod/ssh"
        assert cfg.options["proxy_jump"] == "bastion@jump-01"

        masked = mask_uri_secrets(uri)
        assert "***REDACTED***" in masked
        assert "prod/ssh" not in masked

    def test_resolve_state_store_sqlite_uri_kwonly_plugin_and_prebuilt_args_error(
        self,
        tmp_path: Path,
    ) -> None:
        """resolve_state_store корректно разбирает sqlite:// URI, kw-only плагины и отклоняет args у инстансов."""
        db_file = tmp_path / "state.db"
        store, resolved_path = resolve_state_store(f"sqlite://{db_file}")
        try:
            assert resolved_path == db_file.resolve()
        finally:
            if hasattr(store, "close_sync"):
                store.close_sync()  # type: ignore[union-attr]

        mem_store, mem_path = resolve_state_store("sqlite:///:memory:")
        assert isinstance(mem_store, InMemoryStateStore)
        assert mem_path is None

        class KwOnlyStore(InMemoryStateStore):
            def __init__(self, *, url: str) -> None:
                super().__init__()
                self.url = url

        PluginLoader.register("storage", "kwonly", KwOnlyStore)
        kw_store, _ = resolve_state_store("kwonly://node-1:6379")
        assert isinstance(kw_store, KwOnlyStore)
        assert kw_store.url == "kwonly://node-1:6379"

        # Передача аргументов конструктора готовому инстансу плагина вызывает ConfigurationError
        PluginLoader.register("storage", "prebuilt", InMemoryStateStore())
        with pytest.raises(ConfigurationError, match="already instantiated"):
            PluginLoader.instantiate("storage", "prebuilt", protocol=StateStore, timeout=5)

    def test_resolve_state_store_unknown_scheme_raises_and_file_uri_works(
        self,
        tmp_path: Path,
    ) -> None:
        """Неизвестная URI-схема в resolve_state_store бросает PluginNotFoundError, а file:// открывает SQLite."""
        with pytest.raises(PluginNotFoundError, match="unregistered_kv"):
            resolve_state_store("unregistered_kv://127.0.0.1:6379/0")

        db_file = tmp_path / "file_scheme.db"
        store, resolved_path = resolve_state_store(f"file://{db_file}")
        try:
            assert resolved_path == db_file.resolve()
        finally:
            if hasattr(store, "close_sync"):
                store.close_sync()  # type: ignore[union-attr]
