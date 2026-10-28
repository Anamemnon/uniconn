# src/uniconn/sync/shell.py
"""Синхронная обёртка над async ShellSession на базе ``EventLoopPortal`` и ``ParamSpec``-дескрипторов."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Self

from ..core.bridge import EventLoopPortal, SyncProxyMixin, sync_method
from ..shell.session import ShellSession

if TYPE_CHECKING:
    from .connection import SyncConnection


class SyncShellSession(SyncProxyMixin):
    """Синхронная обёртка над async ShellSession на базе ``EventLoopPortal``."""

    def __init__(self, async_session: ShellSession, sync_conn: SyncConnection) -> None:
        self._async_session = async_session
        self._async_target = async_session
        self._sync_conn = sync_conn

    @property
    def _portal(self) -> EventLoopPortal:
        return self._sync_conn._portal

    @property
    def is_alive(self) -> bool:
        """Проверить, что процесс оболочки активен."""
        return self._async_session.is_alive

    execute = sync_method(ShellSession.execute)
    send = sync_method(ShellSession.send)
    receive = sync_method(ShellSession.receive)
    resize = sync_method(ShellSession.resize)
    expect = sync_method(ShellSession.expect)

    def close(self) -> None:
        """Закрыть shell-сессию (синхронно)."""
        if self._sync_conn._closed:
            return
        self._sync_conn._run_coro(self._async_session.close())

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
