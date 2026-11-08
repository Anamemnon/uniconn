# src/uniconn/mock/telnet_server.py
"""Сокетный Mock Telnet-сервер на базе telnetlib3 и кассет Replay."""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import Any, Self

from ..core.bridge import EventLoopPortal, SyncProxyMixin, sync_method
from ..exceptions import ConfigurationError
from ..transports.replay.models import (
    _POSIX_MARKER_CMD_RE,
    Cassette,
    RecordedShellInteraction,
)
from .config import CassetteInteractionMatcher, MockRequestEvent, MockServerConfig

try:
    import telnetlib3
except ImportError:
    telnetlib3 = None  # type: ignore[assignment]


class MockTelnetServer:
    """Асинхронный Mock Telnet-сервер, воспроизводящий кассету по TCP-сокету."""

    def __init__(self, config: MockServerConfig) -> None:
        """Инициализировать Mock Telnet-сервер."""
        if telnetlib3 is None:
            raise ConfigurationError(
                "telnetlib3 is required for MockTelnetServer. Install with: pip install uniconn[telnet]"
            )
        self.config = config
        self._cassette = config.load_cassette()
        self.matcher = CassetteInteractionMatcher(config, self._cassette)
        self._server: Any = None
        self._port: int = config.port

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
    ) -> Self:
        """Создать ``MockTelnetServer`` напрямую из пути к кассете или объекта ``Cassette``."""
        cfg = MockServerConfig(
            cassette=cassette,
            host=host,
            port=port,
            server_type="telnet",
            allow_any_auth=allow_any_auth,
            username=username,
            password=password,
            strict_mode=strict_mode,
            normalize_temp=normalize_temp,
            allow_repeats=allow_repeats,
            default_exit_code=default_exit_code,
        )
        return cls(cfg)

    @property
    def host(self) -> str:
        """Хост, на котором запущен сервер."""
        return self.config.host

    @property
    def port(self) -> int:
        """Реально выделенный TCP-порт."""
        return self._port

    @property
    def uri(self) -> str:
        """URI для подключения к Mock Telnet-серверу."""
        return f"telnet://{self.config.host}:{self._port}"

    @property
    def is_running(self) -> bool:
        """Признак активного прослушивания сокета."""
        return self._server is not None

    @property
    def history(self) -> list[MockRequestEvent]:
        """Журнал обработанных запросов."""
        return self.matcher.history

    @staticmethod
    def _write_text(writer: Any, text: str) -> None:
        """Записать текст в Telnet writer с поддержкой строкового и байтового режимов."""
        try:
            writer.write(text)
        except TypeError:
            writer.write(text.encode("utf-8"))

    @staticmethod
    async def _read_line(reader: Any) -> str:
        """Прочитать одну строку из Telnet reader."""
        raw = await reader.readline()
        if isinstance(raw, bytes):
            return raw.decode("utf-8", errors="replace")
        return str(raw or "")

    async def _shell_handler(self, reader: Any, writer: Any) -> None:
        """Обработчик клиентской Telnet-сессии."""
        shell_interaction: RecordedShellInteraction | None = self.matcher.match_shell_session()
        consumed_steps: set[int] = set()

        try:
            if not self.config.allow_any_auth or self.config.username or self.config.password:
                self._write_text(writer, "login: ")
                await writer.drain()
                user_line = (await self._read_line(reader)).strip()
                self._write_text(writer, "Password: ")
                await writer.drain()
                pass_line = (await self._read_line(reader)).strip()
                user_ok = self.config.username is None or user_line == self.config.username
                pass_ok = self.config.password is None or pass_line == self.config.password
                if not (self.config.allow_any_auth or (user_ok and pass_ok)):
                    self.matcher.record_event("auth", f"telnet:{user_line}", matched=False, exit_code=1)
                    self._write_text(writer, "Login incorrect\r\n")
                    await writer.drain()
                    writer.close()
                    return
                self.matcher.record_event("auth", f"telnet:{user_line}", matched=True, exit_code=0)
                self._write_text(writer, "Welcome\r\n$ ")
                await writer.drain()

            while True:
                line = await self._read_line(reader)
                if not line:
                    break
                stripped = line.strip()
                if not stripped:
                    continue
                if stripped in ("exit", "logout", "quit"):
                    break

                is_marker = _POSIX_MARKER_CMD_RE.match(stripped) is not None
                out_text, code, matched = self.matcher.resolve_shell_input(
                    stripped,
                    shell_interaction,
                    consumed_steps,
                )
                self.matcher.record_event(
                    "telnet",
                    stripped,
                    matched=matched,
                    exit_code=code,
                )
                if out_text is None:
                    continue

                if is_marker:
                    self._write_text(writer, out_text)
                else:
                    clean_out = out_text.rstrip("\r\n")
                    if clean_out:
                        self._write_text(writer, f"{stripped}\r\n{clean_out}\r\n$ \r\n")
                    else:
                        self._write_text(writer, f"{stripped}\r\n$ \r\n")
                await writer.drain()
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    async def start(self) -> Self:
        """Запустить Telnet-сервер на сконфигурированном хосте и порту."""
        assert telnetlib3 is not None
        self._server = await telnetlib3.create_server(
            host=self.config.host,
            port=self.config.port,
            shell=self._shell_handler,
        )
        sockets = getattr(self._server, "sockets", None)
        if sockets:
            self._port = int(sockets[0].getsockname()[1])
        return self

    async def stop(self) -> None:
        """Остановить Telnet-сервер и освободить сокет."""
        if self._server is not None:
            self._server.close()
            if hasattr(self._server, "wait_closed"):
                with contextlib.suppress(Exception):
                    await self._server.wait_closed()
            self._server = None

    async def __aenter__(self) -> Self:
        """Войти в асинхронный контекстный менеджер и запустить сервер."""
        return await self.start()

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Остановить сервер при выходе из контекстного менеджера."""
        await self.stop()

    def to_sync(self) -> SyncMockTelnetServer:
        """Вернуть синхронную обёртку ``SyncMockTelnetServer``."""
        return SyncMockTelnetServer(self)


class SyncMockTelnetServer(SyncProxyMixin):
    """Синхронный фасад ``MockTelnetServer`` на базе ``EventLoopPortal``."""

    def __init__(
        self,
        server_or_config: MockTelnetServer | MockServerConfig,
        portal: EventLoopPortal | None = None,
    ) -> None:
        """Инициализировать синхронную обёртку над ``MockTelnetServer``."""
        self._async_target: MockTelnetServer = (
            server_or_config
            if isinstance(server_or_config, MockTelnetServer)
            else MockTelnetServer(server_or_config)
        )
        self._portal = portal or EventLoopPortal(owner_name="SyncMockTelnetServer")

    @classmethod
    def from_cassette(
        cls,
        cassette: Cassette | Path | str,
        **kwargs: Any,
    ) -> Self:
        """Создать ``SyncMockTelnetServer`` из пути к кассете или объекта ``Cassette``."""
        return cls(MockTelnetServer.from_cassette(cassette, **kwargs))

    start = sync_method(MockTelnetServer.start)
    stop = sync_method(MockTelnetServer.stop)

    @property
    def host(self) -> str:
        """Хост, на котором запущен сервер."""
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
    def history(self) -> list[MockRequestEvent]:
        """Журнал обработанных запросов."""
        return self._async_target.history

    def __enter__(self) -> Self:
        """Запустить сервер синхронно при входе в блок ``with``."""
        self._portal.reopen()
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Остановить сервер при выходе из блока ``with``."""
        self.stop()


__all__ = [
    "MockTelnetServer",
    "SyncMockTelnetServer",
]
