# src/uniconn/mock/facade.py
"""Фасады MockSSHServer и SyncMockSSHServer для запуска сокетного SSH/SFTP сервера из кассет."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, Self

import asyncssh

from ..core.bridge import EventLoopPortal, SyncProxyMixin, sync_method
from ..transports.replay.models import Cassette
from .config import CassetteInteractionMatcher, MockRequestEvent, MockServerConfig
from .ssh_server import MockSSHServerInterface

_CACHED_HOST_KEY: asyncssh.SSHKey | None = None


def _get_ephemeral_host_key() -> asyncssh.SSHKey:
    """Получить или сгенерировать эфемерный ключ хоста ``ssh-ed25519`` в памяти."""
    global _CACHED_HOST_KEY
    if _CACHED_HOST_KEY is None:
        _CACHED_HOST_KEY = asyncssh.generate_private_key("ssh-ed25519")
    return _CACHED_HOST_KEY


class MockSSHServer:
    """Асинхронный контекстный менеджер и фасад сокетного Mock SSH / SFTP сервера."""

    def __init__(
        self,
        config: MockServerConfig | Cassette | Path | str,
        **kwargs: Any,
    ) -> None:
        """Инициализировать Mock SSH-сервер из ``MockServerConfig`` или пути к кассете."""
        if isinstance(config, MockServerConfig):
            self.config = config
        else:
            self.config = MockServerConfig(cassette=config, **kwargs)
        self._cassette: Cassette | None = None
        self._matcher: CassetteInteractionMatcher | None = None
        self._server: asyncssh.SSHAcceptor | None = None
        self._active_connections: set[asyncssh.SSHServerConnection] = set()
        self._port: int = self.config.port

    @classmethod
    def from_cassette(
        cls,
        cassette: Cassette | Path | str,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        allow_any_auth: bool = True,
        username: str | None = None,
        password: str | None = None,
        strict_mode: bool = False,
        normalize_temp: bool = True,
        allow_repeats: bool = True,
        default_exit_code: int = 127,
        on_request: Callable[[MockRequestEvent], Any] | None = None,
    ) -> Self:
        """Создать ``MockSSHServer`` из файла или экземпляра ``Cassette``."""
        cfg = MockServerConfig(
            cassette=cassette,
            host=host,
            port=port,
            server_type="ssh",
            allow_any_auth=allow_any_auth,
            username=username,
            password=password,
            strict_mode=strict_mode,
            normalize_temp=normalize_temp,
            allow_repeats=allow_repeats,
            default_exit_code=default_exit_code,
            on_request=on_request,
        )
        return cls(cfg)

    @property
    def host(self) -> str:
        """IP-адрес или хост, на котором слушает сервер."""
        return self.config.host

    @property
    def port(self) -> int:
        """Реально выделенный порт ОС (даже если был передан ``port=0``)."""
        return self._port

    @property
    def uri(self) -> str:
        """Строка подключения URI для ``uniconn.Connection.from_uri``."""
        if self.config.username and self.config.password:
            return f"ssh://{self.config.username}:{self.config.password}@{self.config.host}:{self._port}"
        if self.config.username:
            return f"ssh://{self.config.username}@{self.config.host}:{self._port}"
        return f"ssh://{self.config.host}:{self._port}"

    @property
    def is_running(self) -> bool:
        """Признак того, что сервер запущен и принимает подключения."""
        return self._server is not None

    @property
    def cassette(self) -> Cassette:
        """Загруженная кассета сервера."""
        if self._cassette is None:
            self._cassette = self.config.load_cassette()
        return self._cassette

    @property
    def matcher(self) -> CassetteInteractionMatcher:
        """Активный сопоставитель взаимодействий и SFTP-оверлей."""
        if self._matcher is None:
            self._matcher = CassetteInteractionMatcher(self.config, self.cassette)
        return self._matcher

    @property
    def history(self) -> list[MockRequestEvent]:
        """Список зафиксированных запросов к серверу."""
        return self.matcher.history

    async def start(self) -> Self:
        """Сгенерировать ключ хоста и запустить TCP-сервер ``asyncssh``."""
        if self._server is not None:
            return self

        host_key = _get_ephemeral_host_key()
        cassette = self.cassette
        matcher = self.matcher

        self._server = await asyncssh.create_server(
            lambda: MockSSHServerInterface(
                self.config,
                cassette,
                matcher=matcher,
                active_connections=self._active_connections,
            ),
            host=self.config.host,
            port=self.config.port,
            server_host_keys=[host_key],
            line_editor=False,
        )
        sockets = self._server.sockets
        if sockets:
            self._port = int(sockets[0].getsockname()[1])
        return self

    async def stop(self) -> None:
        """Остановить сервер, закрыть активные клиентские сессии и дождаться закрытия сокета."""
        if self._server is not None:
            self._server.close()
            for conn in list(self._active_connections):
                conn.close()
            self._active_connections.clear()
            await self._server.wait_closed()
            self._server = None

    async def __aenter__(self) -> Self:
        """Запустить сервер при входе в блок ``async with``."""
        return await self.start()

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Остановить сервер при выходе из блока ``async with``."""
        await self.stop()

    def to_sync(self) -> SyncMockSSHServer:
        """Вернуть синхронный фасад ``SyncMockSSHServer`` через ``EventLoopPortal``."""
        return SyncMockSSHServer(self)


class SyncMockSSHServer(SyncProxyMixin):
    """Синхронный контекстный менеджер и фасад ``MockSSHServer`` на базе ``EventLoopPortal``."""

    def __init__(
        self,
        server_or_config: MockSSHServer | MockServerConfig | Cassette | Path | str,
        portal: EventLoopPortal | None = None,
        **kwargs: Any,
    ) -> None:
        """Инициализировать синхронный фасад Mock SSH-сервера."""
        if isinstance(server_or_config, MockSSHServer):
            self._async_target = server_or_config
        else:
            self._async_target = MockSSHServer(server_or_config, **kwargs)
        self._portal = portal or EventLoopPortal(owner_name="SyncMockSSHServer")

    @classmethod
    def from_cassette(
        cls,
        cassette: Cassette | Path | str,
        **kwargs: Any,
    ) -> Self:
        """Создать ``SyncMockSSHServer`` напрямую из пути к кассете или объекта ``Cassette``."""
        return cls(MockSSHServer.from_cassette(cassette, **kwargs))

    start = sync_method(MockSSHServer.start)
    stop = sync_method(MockSSHServer.stop)

    @property
    def config(self) -> MockServerConfig:
        """Конфигурация сервера."""
        return self._async_target.config

    @property
    def host(self) -> str:
        """Хост сервера."""
        return self._async_target.host

    @property
    def port(self) -> int:
        """Выделенный TCP-порт."""
        return self._async_target.port

    @property
    def uri(self) -> str:
        """URI для подключения к серверу."""
        return self._async_target.uri

    @property
    def is_running(self) -> bool:
        """Признак активного состояния сервера."""
        return self._async_target.is_running

    @property
    def cassette(self) -> Cassette:
        """Загруженная кассета."""
        return self._async_target.cassette

    @property
    def matcher(self) -> CassetteInteractionMatcher:
        """Активный сопоставитель взаимодействий."""
        return self._async_target.matcher

    @property
    def history(self) -> list[MockRequestEvent]:
        """Журнал обработанных запросов."""
        return self._async_target.history

    def __enter__(self) -> Self:
        """Синхронно запустить сервер при входе в блок ``with``."""
        self._portal.reopen()
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Синхронно остановить сервер при выходе из блока ``with``."""
        self.stop()


__all__ = [
    "MockSSHServer",
    "SyncMockSSHServer",
]
