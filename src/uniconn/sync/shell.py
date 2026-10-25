# src/uniconn/sync/shell.py
"""Синхронная обёртка над async ShellSession на базе ``EventLoopPortal``."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any, Self

from pydantic import SecretStr

from ..result import Result
from ..shell.session import ShellSession

if TYPE_CHECKING:
    from .connection import SyncConnection


class SyncShellSession:
    """Синхронная обёртка над async ShellSession на базе ``EventLoopPortal``."""

    def __init__(self, async_session: ShellSession, sync_conn: SyncConnection) -> None:
        self._async_session = async_session
        self._sync_conn = sync_conn

    @property
    def is_alive(self) -> bool:
        """Проверить, что процесс оболочки активен."""
        return self._async_session.is_alive

    def execute(
        self,
        command: str | Sequence[str],
        timeout: float | None = None,
    ) -> Result:
        """Выполнить команду в stateful shell-сессии (синхронно)."""
        return self._sync_conn._run_coro(
            self._async_session.execute(command, timeout=timeout)
        )

    def send(self, text: str) -> None:
        """Отправить текст в stdin оболочки (синхронно)."""
        self._sync_conn._run_coro(self._async_session.send(text))

    def receive(self, timeout: float | None = None) -> str:
        """Прочитать доступный вывод из stdout оболочки (синхронно)."""
        return self._sync_conn._run_coro(
            self._async_session.receive(timeout=timeout)
        )

    def resize(self, cols: int, rows: int) -> None:
        """Изменить размер окна терминала PTY (синхронно)."""
        self._sync_conn._run_coro(self._async_session.resize(cols, rows))

    def expect(
        self,
        command: str | Sequence[str] | None = None,
        patterns: Mapping[str, str | SecretStr] | None = None,
        final_prompt: str | None = None,
        timeout: float | None = None,
        line_ending: str = "\n",
        sensitive: bool = False,
        allow_eof: bool = True,
    ) -> Result:
        """Выполнить интерактивный диалог по regex-паттернам в shell-сессии (синхронно)."""
        return self._sync_conn._run_coro(
            self._async_session.expect(
                command=command,
                patterns=patterns,
                final_prompt=final_prompt,
                timeout=timeout,
                line_ending=line_ending,
                sensitive=sensitive,
                allow_eof=allow_eof,
            )
        )

    def close(self) -> None:
        """Закрыть shell-сессию (синхронно)."""
        if self._sync_conn._closed:
            return
        self._sync_conn._run_coro(self._async_session.close())

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
