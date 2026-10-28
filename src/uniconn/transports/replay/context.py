# src/uniconn/transports/replay/context.py
"""Контекстные менеджеры ``conn.use_cassette()`` и ``pool.use_cassette()``."""

from __future__ import annotations

import contextlib
import re
from collections.abc import AsyncIterator, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

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
    from ...pool.connection_pool import ConnectionPool
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


@contextlib.asynccontextmanager
async def pool_use_cassette(
    pool: ConnectionPool,
    path: str | Path,
    *,
    mode: Any = "once",
    match_on: Sequence[Literal["command", "cwd", "sudo"]] = (
        "command",
        "cwd",
        "sudo",
    ),
    normalize_temp: bool = True,
    allow_playback_repeats: bool = True,
    mask_secrets: bool = True,
) -> AsyncIterator[dict[str, Any]]:
    """Асинхронный контекстный менеджер записи/воспроизведения кассет для пула хостов."""
    target_path = Path(path)
    rec_mode = RecordMode(mode)
    is_single_file = target_path.suffix.lower() in (".yaml", ".yml", ".json")

    conns_by_idx: dict[int, Connection] = {}
    keys_by_idx: dict[int, str] = {}
    for idx, target in enumerate(pool._uris):
        key = pool._target_key(target)
        keys_by_idx[idx] = key
        if pool._is_entered and idx in pool._active_conns:
            conns_by_idx[idx] = pool._active_conns[idx]
        else:
            conn = pool._build_conn(target, with_defaults=True)
            conns_by_idx[idx] = conn
            pool._cassette_conns[idx] = conn

    try:
        if not is_single_file:
            used_names: set[str] = set()
            async with contextlib.AsyncExitStack() as stack:
                cassettes: dict[str, Cassette] = {}
                for idx, conn in conns_by_idx.items():
                    key = keys_by_idx[idx]
                    raw_host = key.split("://", 1)[-1]
                    safe_name = (
                        re.sub(r"[^a-zA-Z0-9._-]+", "_", raw_host).strip("_")
                        or f"host_{idx}"
                    )
                    if safe_name in used_names:
                        safe_name = f"{safe_name}_{idx}"
                    used_names.add(safe_name)
                    host_file = target_path / f"{safe_name}.yaml"
                    cass = await stack.enter_async_context(
                        conn.use_cassette(
                            host_file,
                            mode=rec_mode,
                            match_on=match_on,
                            normalize_temp=normalize_temp,
                            allow_playback_repeats=allow_playback_repeats,
                            mask_secrets=mask_secrets,
                        )
                    )
                    cassettes[key] = cass
                yield cassettes
        else:
            exists = target_path.is_file()
            if exists and rec_mode != RecordMode.ALL:
                shared_cass = Cassette.load(target_path)
            else:
                if rec_mode == RecordMode.NONE and not exists:
                    raise CassetteError(
                        f"Cassette file does not exist in RecordMode.NONE: {target_path}"
                    )
                shared_cass = Cassette(
                    transport="pool",
                    host="pool",
                    capabilities=["exec", "stream", "file", "shell"],
                )

            base_interactions = [
                it.model_copy(deep=True) for it in shared_cass.interactions
            ]
            base_len = len(base_interactions)
            orig_transports: dict[int, Any] = {}
            proxies: dict[int, CassetteTransportProxy] = {}
            cassettes = {}

            for idx, conn in conns_by_idx.items():
                key = keys_by_idx[idx]
                orig = conn.transport
                orig_transports[idx] = orig
                host_cass = Cassette(
                    transport=orig.name,
                    host=conn.config.host or key,
                    capabilities=list(shared_cass.capabilities),
                    interactions=[
                        it.model_copy(deep=True) for it in base_interactions
                    ],
                )
                proxy = CassetteTransportProxy(
                    config=conn.config,
                    cassette=host_cass,
                    wrapped=orig,
                    mode=rec_mode,
                    cassette_exists=exists,
                    match_on=match_on,
                    normalize_temp=normalize_temp,
                    allow_playback_repeats=allow_playback_repeats,
                    mask_secrets=mask_secrets,
                )
                conn.swap_transport(proxy)
                proxies[idx] = proxy
                cassettes[key] = host_cass

            try:
                yield cassettes
            finally:
                any_dirty = False
                new_items: list[Any] = []
                for idx, conn in conns_by_idx.items():
                    proxy = proxies[idx]
                    if proxy.is_dirty:
                        any_dirty = True
                        new_items.extend(proxy.cassette.interactions[base_len:])
                    conn.swap_transport(orig_transports[idx])
                if any_dirty:
                    shared_cass.interactions = [*base_interactions, *new_items]
                    shared_cass.save(target_path)
    finally:
        pool._cassette_conns.clear()


__all__ = [
    "CassetteContext",
    "SyncCassetteContext",
    "pool_use_cassette",
]
