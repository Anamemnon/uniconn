# src/uniconn/transports/replay/context.py
"""Контекстные менеджеры ``conn.use_cassette()`` (асинхронный и синхронный)."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ...exceptions import CassetteError
from ..base import (
    BaseTransport,
    FileCapableTransport,
    ShellCapableTransport,
    supports_capability,
)
from .models import CapabilityKind, Cassette, MatchField, RecordMode
from .proxy import CassetteTransportProxy

if TYPE_CHECKING:
    from ...core.connection import Connection
    from ...sync.connection import SyncConnection


class CassetteContext:
    """Асинхронный контекстный менеджер ``conn.use_cassette()``."""

    def __init__(
        self,
        conn: Connection,
        path: str | Path,
        *,
        mode: RecordMode | str = RecordMode.ONCE,
        match_on: Sequence[MatchField] = ("command", "cwd", "sudo"),
        normalize_temp: bool = True,
        allow_playback_repeats: bool = True,
        mask_secrets: bool = True,
    ) -> None:
        """Инициализировать контекстный менеджер кассеты."""
        self._conn = conn
        self._path = Path(path)
        self._mode = RecordMode(mode)
        self._match_on = match_on
        self._normalize_temp = normalize_temp
        self._allow_playback_repeats = allow_playback_repeats
        self._mask_secrets = mask_secrets
        self._orig_transport: BaseTransport | None = None
        self._proxy: CassetteTransportProxy | None = None

    async def __aenter__(self) -> Cassette:
        """Подключить прокси кассеты к ``Connection``."""
        self._orig_transport = self._conn.transport
        exists = self._path.is_file()

        if exists and self._mode != RecordMode.ALL:
            cassette = Cassette.load(self._path)
        else:
            if self._mode == RecordMode.NONE and not exists:
                raise CassetteError(
                    f"Cassette file does not exist in RecordMode.NONE: {self._path}",
                    host=self._conn.config.host,
                )
            caps: list[CapabilityKind] = ["exec", "stream"]
            if supports_capability(self._orig_transport, FileCapableTransport):
                caps.append("file")
            if supports_capability(self._orig_transport, ShellCapableTransport):
                caps.append("shell")
            cassette = Cassette(
                transport=self._orig_transport.name,
                host=self._conn.config.host,
                capabilities=caps,
            )

        self._proxy = CassetteTransportProxy(
            config=self._conn.config,
            cassette=cassette,
            wrapped=self._orig_transport,
            mode=self._mode,
            cassette_exists=exists,
            match_on=self._match_on,
            normalize_temp=self._normalize_temp,
            allow_playback_repeats=self._allow_playback_repeats,
            mask_secrets=self._mask_secrets,
        )
        self._conn.swap_transport(self._proxy)
        return cassette

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Сохранить кассету (если были записи) и восстановить исходный транспорт."""
        try:
            if self._proxy is not None and self._proxy.is_dirty:
                self._proxy.cassette.save(self._path)
        finally:
            if self._orig_transport is not None:
                self._conn.swap_transport(self._orig_transport)


class SyncCassetteContext:
    """Синхронный контекстный менеджер ``sync_conn.use_cassette()``."""

    def __init__(self, async_ctx: CassetteContext, sync_conn: SyncConnection) -> None:
        """Инициализировать синхронную обёртку над ``CassetteContext``."""
        self._async_ctx = async_ctx
        self._sync_conn = sync_conn

    def __enter__(self) -> Cassette:
        """Открыть контекст кассеты синхронно."""
        return self._sync_conn._run_coro(self._async_ctx.__aenter__())

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Закрыть контекст кассеты и сохранить файл синхронно."""
        self._sync_conn._run_coro(self._async_ctx.__aexit__(exc_type, exc_val, exc_tb))


__all__ = [
    "CassetteContext",
    "SyncCassetteContext",
]
