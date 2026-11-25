"""Регрессионные тесты Этапа 1 (v0.22.0): ленивый импорт, очистка корутин и удаление контейнерного стека."""

from __future__ import annotations

import json
import subprocess
import sys
import warnings
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

import uniconn
from uniconn.core.bridge import EventLoopPortal
from uniconn.exceptions import TransportNotFoundError
from uniconn.plugins import PluginLoader, TransportLoader

_FORBIDDEN_EAGER_MODULES = (
    "niquests",
    "urllib3",
    "asyncssh",
    "pydantic",
    "structlog",
    "uniconn.security",
    "uniconn.mcp",
    "uniconn.orchestration",
    "uniconn.services.provisioning",
)


class TestStartupImportHygiene:
    """Проверка скорости и чистоты импорта ``import uniconn`` в свежем процессе."""

    def test_import_uniconn_is_lazy_and_fast(self) -> None:
        probe = (
            "import json, sys, time; "
            "t0 = time.perf_counter(); "
            "import uniconn; "
            "dt_ms = (time.perf_counter() - t0) * 1000.0; "
            f"forbidden = {list(_FORBIDDEN_EAGER_MODULES)!r}; "
            "loaded = [m for m in forbidden if m in sys.modules]; "
            "print(json.dumps({'version': uniconn.__version__, 'ms': dt_ms, 'loaded': loaded}))"
        )
        proc = subprocess.run(
            [sys.executable, "-c", probe],
            capture_output=True,
            text=True,
            check=True,
            timeout=15,
        )
        data = json.loads(proc.stdout.strip())
        assert data["version"] == uniconn.__version__
        assert data["loaded"] == [], f"Тяжёлые модули загружены при import uniconn: {data['loaded']}"
        assert data["ms"] < 200.0, f"import uniconn слишком медленный: {data['ms']:.1f} ms"


class TestEventLoopPortalCoroutineCleanup:
    """Проверка закрытия корутин в EventLoopPortal.call() при сбоях до планирования в loop."""

    def test_call_closes_coroutine_when_get_loop_fails(self) -> None:
        portal = EventLoopPortal()

        async def _sample() -> int:
            return 42

        coro = _sample()
        with (
            warnings.catch_warnings(record=True) as caught,
            patch.object(portal, "get_loop", side_effect=RuntimeError("loop unavailable")),
        ):
            warnings.simplefilter("always", RuntimeWarning)
            with pytest.raises(RuntimeError, match="loop unavailable"):
                portal.call(coro)

        assert coro.cr_frame is None, "Корутина должна быть закрыта при ошибке get_loop()"
        runtime_warnings = [w for w in caught if issubclass(w.category, RuntimeWarning)]
        assert runtime_warnings == []

    def test_call_closes_coroutine_when_run_coroutine_threadsafe_fails(self) -> None:
        portal = EventLoopPortal()
        fake_loop = MagicMock()

        async def _sample() -> int:
            return 42

        coro = _sample()

        def _fail_schedule(wrapped: Any, loop: Any) -> Any:
            raise RuntimeError("loop is closed")

        with (
            warnings.catch_warnings(record=True) as caught,
            patch.object(portal, "get_loop", return_value=fake_loop),
            patch("uniconn.core.bridge.asyncio.run_coroutine_threadsafe", side_effect=_fail_schedule),
        ):
            warnings.simplefilter("always", RuntimeWarning)
            with pytest.raises(RuntimeError, match="loop is closed"):
                portal.call(coro)

        assert coro.cr_frame is None, "Корутина должна быть закрыта при ошибке run_coroutine_threadsafe()"
        runtime_warnings = [w for w in caught if issubclass(w.category, RuntimeWarning)]
        assert runtime_warnings == []

    def test_iter_async_closes_internal_coroutines_when_scheduling_fails(self) -> None:
        portal = EventLoopPortal()
        fake_loop = MagicMock()

        async def _sample_gen():
            yield 1

        def _fail_schedule(wrapped: Any, loop: Any) -> Any:
            raise RuntimeError("loop is closed")

        with (
            warnings.catch_warnings(record=True) as caught,
            patch.object(portal, "get_loop", return_value=fake_loop),
            patch("uniconn.core.bridge.asyncio.run_coroutine_threadsafe", side_effect=_fail_schedule),
        ):
            warnings.simplefilter("always", RuntimeWarning)
            with pytest.raises(RuntimeError, match="loop is closed"):
                list(portal.iter_async(_sample_gen()))

        runtime_warnings = [w for w in caught if issubclass(w.category, RuntimeWarning)]
        assert runtime_warnings == []


class TestContainerStackRemoved:
    """Проверка полного удаления контейнерного слоя из ядра и фабрик."""

    @pytest.mark.parametrize("scheme", ["docker", "podman", "kubectl"])
    def test_container_schemes_absent_from_loaders(self, scheme: str) -> None:
        assert scheme not in PluginLoader.list_available("transports")
        assert scheme not in TransportLoader.list_available()

    @pytest.mark.parametrize(
        "uri",
        [
            "docker://my-container",
            "podman://my-container",
            "kubectl://my-pod?namespace=default",
        ],
    )
    def test_from_uri_rejects_removed_container_schemes(self, uri: str) -> None:
        with pytest.raises(TransportNotFoundError):
            uniconn.Connection.from_uri(uri)

    @pytest.mark.parametrize(
        "symbol",
        [
            "DockerTransport",
            "PodmanTransport",
            "KubectlTransport",
            "ContainerDiagnosticStrategy",
        ],
    )
    def test_removed_symbols_not_exported(self, symbol: str) -> None:
        assert symbol not in uniconn.__all__
        assert not hasattr(uniconn, symbol)


class TestLazyDomainServices:
    """Проверка ленивой инициализации доменных сервисов Connection и поддержки явного присваивания."""

    def test_services_are_lazily_initialized_replaceable_and_deletable(self) -> None:
        conn = uniconn.Connection.local()

        for cache_key in ("_files_service", "_state_service", "_tunnels_service", "_net_service", "_python_worker_inst"):
            assert cache_key not in conn.__dict__

        files_svc = conn.files
        assert conn.__dict__["_files_service"] is files_svc
        assert conn.files is files_svc

        state_svc = conn.state
        assert conn.__dict__["_state_service"] is state_svc
        assert conn.state is state_svc

        tunnels_svc = conn.tunnels
        assert conn.__dict__["_tunnels_service"] is tunnels_svc

        net_svc = conn.net
        assert conn.__dict__["_net_service"] is net_svc

        custom_files = MagicMock()
        conn.files = custom_files
        assert conn.files is custom_files

        # Удаление через del сбрасывает кэш и позволяет пересоздать сервис
        del conn.files
        assert "_files_service" not in conn.__dict__
        assert conn.files is not custom_files

        # Явное отключение воркера через None не должно пересоздавать RemotePythonWorker
        conn._python_worker = None  # type: ignore[assignment]
        assert conn._python_worker is None

    def test_core_lazy_export_includes_operation_observer(self) -> None:
        import uniconn.core as core_pkg

        assert "OperationObserver" in core_pkg.__all__
        assert core_pkg.OperationObserver is uniconn.OperationObserver

    def test_cached_facts_access_does_not_instantiate_facts_collector(self) -> None:
        from uniconn.core.auto_diagnostics import resolve_diagnostic_strategy

        conn = uniconn.Connection.local()
        assert conn._cached_facts is None
        conn._cached_facts = None
        _ = resolve_diagnostic_strategy(conn)
        assert "_facts_collector_inst" not in conn.__dict__

    @pytest.mark.parametrize(
        "pkg_name",
        [
            "uniconn",
            "uniconn.config",
            "uniconn.core",
            "uniconn.transports",
            "uniconn.services",
            "uniconn.sync",
            "uniconn.pool",
        ],
    )
    def test_all_lazy_packages_export_sorted_resolvable_symbols(self, pkg_name: str) -> None:
        import importlib

        mod = importlib.import_module(pkg_name)
        all_names = list(mod.__all__)
        assert len(all_names) == len(set(all_names)), f"{pkg_name}.__all__ содержит дубликаты"
        for sym in all_names:
            assert hasattr(mod, sym), f"{pkg_name}.{sym} из __all__ не разрешается"
