# src/uniconn/pytest_plugin.py
"""Pytest плагин для uniconn: фикстуры, маркеры и автоматическая запись/воспроизведение кассет.

Позволяет бесшовно изолировать сетевые тесты и переводить интеграции на кассеты Replay:
- Маркер ``@pytest.mark.uniconn_cassette``: автоматическая запись сессий в YAML/JSON и повтор без сети.
- Фикстура ``uniconn_cassette``: контекстный менеджер и фабрика для явного управления кассетами.
- Фикстуры ``uniconn_replay_conn`` и ``uniconn_sync_replay_conn``: готовые подключения к кассетам.
- CLI-флаги pytest: ``--uniconn-record-mode`` и ``--uniconn-cassette-dir``.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import pytest
else:
    try:
        import pytest
    except ImportError:
        pytest = None

from .core.connection import Connection
from .sync.connection import SyncConnection
from .transports.base import FileCapableTransport, ShellCapableTransport, supports_capability
from .transports.replay.context import CassetteContext, SyncCassetteContext
from .transports.replay.models import CapabilityKind, Cassette, MatchField, RecordMode
from .transports.replay.proxy import CassetteTransportProxy


class UniconnCassetteFixture:
    """Вспомогательный объект pytest-фикстуры для работы с кассетами в тестах."""

    def __init__(
        self,
        request: Any,
        record_mode_override: str | None = None,
        cassette_dir_override: str | None = None,
    ) -> None:
        self._request = request
        self._override_mode = record_mode_override
        self._custom_dir = cassette_dir_override
        self._marker = request.node.get_closest_marker("uniconn_cassette") if request else None
        self._active_contexts: list[CassetteContext | SyncCassetteContext] = []

    @property
    def default_path(self) -> Path:
        """Вычислить путь к файлу кассеты по умолчанию для текущего теста."""
        if self._marker and self._marker.args:
            first_arg = self._marker.args[0]
            if isinstance(first_arg, str | Path):
                p = Path(first_arg)
                if p.is_absolute():
                    return p
                base_dir = (
                    Path(self._custom_dir)
                    if self._custom_dir
                    else self._request.path.parent / "cassettes"
                )
                return base_dir / p

        if self._marker and "name" in self._marker.kwargs:
            p = Path(str(self._marker.kwargs["name"]))
            if p.is_absolute():
                return p
            base_dir = (
                Path(self._custom_dir)
                if self._custom_dir
                else self._request.path.parent / "cassettes"
            )
            return base_dir / p

        base_dir = (
            Path(self._custom_dir)
            if self._custom_dir
            else self._request.path.parent / "cassettes"
        )
        safe_name = self._request.node.name.replace("[", "_").replace("]", "").replace("/", "_")
        return base_dir / self._request.path.stem / f"{safe_name}.yaml"

    @property
    def path(self) -> Path:
        """Путь к кассете текущего теста."""
        return self.default_path

    @property
    def mode(self) -> RecordMode:
        """Текущий эффективный режим записи (с учётом CLI-флага и маркера)."""
        if self._override_mode:
            return RecordMode(self._override_mode)
        if self._marker and "mode" in self._marker.kwargs:
            return RecordMode(self._marker.kwargs["mode"])
        if self._marker and len(self._marker.args) >= 2:
            return RecordMode(self._marker.args[1])
        return RecordMode.ONCE

    def use(
        self,
        conn: Connection | SyncConnection,
        path: str | Path | None = None,
        *,
        mode: RecordMode | str | None = None,
        match_on: Sequence[MatchField] = ("command", "cwd", "sudo"),
        normalize_temp: bool = True,
        allow_playback_repeats: bool = True,
        mask_secrets: bool = True,
    ) -> Any:
        """Использовать кассету с указанным подключением (поддерживает Async и Sync)."""
        target_path = Path(path) if path is not None else self.default_path
        target_mode = RecordMode(mode) if mode is not None else self.mode

        ctx = conn.use_cassette(
            target_path,
            mode=target_mode,
            match_on=match_on,
            normalize_temp=normalize_temp,
            allow_playback_repeats=allow_playback_repeats,
            mask_secrets=mask_secrets,
        )
        self._active_contexts.append(ctx)
        return ctx

    def __call__(
        self,
        conn: Connection | SyncConnection,
        path: str | Path | None = None,
        **kwargs: Any,
    ) -> Any:
        """Синтаксический сахар: ``async with uniconn_cassette(conn): ...``."""
        return self.use(conn, path, **kwargs)

    def load(self, path: str | Path | None = None) -> Cassette:
        """Загрузить существующую кассету."""
        target_path = Path(path) if path is not None else self.default_path
        return Cassette.load(target_path)

    def connection(
        self,
        path: str | Path | None = None,
        *,
        host: str | None = None,
        mode: str = "none",
        **kwargs: Any,
    ) -> Connection:
        """Создать асинхронное ``Connection`` поверх кассеты (транспорт ``replay://``)."""
        target_path = Path(path) if path is not None else self.default_path
        cassette_obj = self.load(target_path)
        eff_host = host or cassette_obj.host or "replayed-host"
        uri = f"replay://{eff_host}?cassette={target_path}&mode={mode}"
        return Connection.from_uri(uri, **kwargs)

    def sync_connection(
        self,
        path: str | Path | None = None,
        *,
        host: str | None = None,
        mode: str = "none",
        **kwargs: Any,
    ) -> SyncConnection:
        """Создать синхронное ``SyncConnection`` поверх кассеты (транспорт ``replay://``)."""
        target_path = Path(path) if path is not None else self.default_path
        cassette_obj = self.load(target_path)
        eff_host = host or cassette_obj.host or "replayed-host"
        uri = f"replay://{eff_host}?cassette={target_path}&mode={mode}"
        return SyncConnection.from_uri(uri, **kwargs)


if pytest is not None:

    def pytest_addoption(parser: pytest.Parser) -> None:
        """Зарегистрировать CLI-флаги uniconn для pytest."""
        group = parser.getgroup("uniconn", "Uniconn testing & cassette replay")
        group.addoption(
            "--uniconn-record-mode",
            action="store",
            choices=["once", "new_episodes", "none", "all"],
            default=None,
            help="Global record mode override for uniconn cassettes (once, new_episodes, none, all).",
        )
        group.addoption(
            "--uniconn-cassette-dir",
            action="store",
            default=None,
            help="Directory for uniconn cassettes (default: next to test file).",
        )

    def pytest_configure(config: pytest.Config) -> None:
        """Зарегистрировать маркеры uniconn в pytest."""
        config.addinivalue_line(
            "markers",
            "uniconn_cassette(name=None, mode=None, auto_wrap=True, mask_secrets=True, sanitize_ips=False): "
            "mark test to record/replay uniconn interactions using a cassette.",
        )

    @pytest.fixture
    def uniconn_record_mode(request: pytest.FixtureRequest) -> RecordMode:
        """Фикстура эффективного режима записи кассет."""
        cli_opt = request.config.getoption("--uniconn-record-mode", default=None)
        if cli_opt:
            return RecordMode(cli_opt)
        marker = request.node.get_closest_marker("uniconn_cassette")
        if marker and "mode" in marker.kwargs:
            return RecordMode(marker.kwargs["mode"])
        if marker and len(marker.args) >= 2:
            return RecordMode(marker.args[1])
        return RecordMode.ONCE

    @pytest.fixture
    def uniconn_cassette(request: pytest.FixtureRequest) -> UniconnCassetteFixture:
        """Основная фикстура для управления кассетами в тестах."""
        cli_mode = request.config.getoption("--uniconn-record-mode", default=None)
        cli_dir = request.config.getoption("--uniconn-cassette-dir", default=None)
        return UniconnCassetteFixture(
            request,
            record_mode_override=cli_mode,
            cassette_dir_override=cli_dir,
        )

    @pytest.fixture
    def uniconn_replay_conn(uniconn_cassette: UniconnCassetteFixture) -> Connection:
        """Фикстура асинхронного подключения, автоматически привязанного к кассете текущего теста."""
        return uniconn_cassette.connection()

    @pytest.fixture
    def uniconn_sync_replay_conn(uniconn_cassette: UniconnCassetteFixture) -> SyncConnection:
        """Фикстура синхронного подключения, автоматически привязанного к кассете текущего теста."""
        return uniconn_cassette.sync_connection()

    @pytest.fixture(autouse=True)
    def _uniconn_marker_auto_cassette(
        request: pytest.FixtureRequest,
        monkeypatch: pytest.MonkeyPatch,
    ) -> Iterator[None]:
        """Автоматический перехват и оборачивание подключений при наличии маркера @pytest.mark.uniconn_cassette."""
        marker = request.node.get_closest_marker("uniconn_cassette")
        if not marker:
            yield
            return

        auto_wrap = marker.kwargs.get("auto_wrap", True)
        if not auto_wrap:
            yield
            return

        cli_mode = request.config.getoption("--uniconn-record-mode", default=None)
        cli_dir = request.config.getoption("--uniconn-cassette-dir", default=None)
        fixture = UniconnCassetteFixture(
            request,
            record_mode_override=cli_mode,
            cassette_dir_override=cli_dir,
        )

        cassette_path = fixture.path
        cassette_mode = fixture.mode
        mask_secrets = marker.kwargs.get("mask_secrets", True)
        sanitize_ips = marker.kwargs.get("sanitize_ips", False)

        active_proxies: list[CassetteTransportProxy] = []
        bound_conns: list[Connection] = []

        orig_from_uri = Connection.from_uri
        orig_sync_from_uri = SyncConnection.from_uri

        def _wrap_connection(conn: Connection) -> Connection:
            if (
                isinstance(conn.transport, CassetteTransportProxy)
                or conn.config.transport == "replay"
            ):
                return conn
            exists = cassette_path.is_file()
            if exists and cassette_mode != RecordMode.ALL:
                loaded_cassette = Cassette.load(cassette_path)
            else:
                caps: list[CapabilityKind] = ["exec", "stream"]
                if supports_capability(conn.transport, FileCapableTransport):
                    caps.append("file")
                if supports_capability(conn.transport, ShellCapableTransport):
                    caps.append("shell")
                loaded_cassette = Cassette(
                    transport=conn.transport.name,
                    host=conn.config.host,
                    capabilities=caps,
                )

            proxy = CassetteTransportProxy(
                config=conn.config,
                cassette=loaded_cassette,
                wrapped=conn.transport,
                mode=cassette_mode,
                cassette_exists=exists,
                mask_secrets=mask_secrets,
            )
            conn.swap_transport(proxy)
            active_proxies.append(proxy)
            bound_conns.append(conn)
            return conn

        def patched_from_uri(*args: Any, **kwargs: Any) -> Connection:
            conn = orig_from_uri(*args, **kwargs)
            uri_str = args[0] if args else str(kwargs.get("uri", ""))
            if uri_str.startswith("replay://"):
                return conn
            return _wrap_connection(conn)

        def patched_sync_from_uri(*args: Any, **kwargs: Any) -> SyncConnection:
            sync_conn = orig_sync_from_uri(*args, **kwargs)
            uri_str = args[0] if args else str(kwargs.get("uri", ""))
            if uri_str.startswith("replay://"):
                return sync_conn
            _wrap_connection(sync_conn._async_conn)
            return sync_conn

        monkeypatch.setattr(Connection, "from_uri", staticmethod(patched_from_uri))
        monkeypatch.setattr(SyncConnection, "from_uri", staticmethod(patched_sync_from_uri))

        yield

        # Teardown: сохранить изменённые кассеты и восстановить исходные транспорты
        for proxy in active_proxies:
            if proxy.is_dirty:
                if sanitize_ips:
                    proxy.cassette.sanitize(redact_ips=True)
                proxy.cassette.save(cassette_path)

        for conn in bound_conns:
            if (
                isinstance(conn.transport, CassetteTransportProxy)
                and conn.transport._wrapped is not None
            ):
                conn.swap_transport(conn.transport._wrapped)


__all__ = [
    "UniconnCassetteFixture",
]
