# src/uniconn/core/shell_facade.py
"""Фасад интерактивных сессий Shell/Expect и протокол наблюдателей сквозных операций."""

from __future__ import annotations

import sys
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from pydantic import SecretStr

from ..result import Result, SyncResult
from ..shell.session import ShellSession
from .pipeline import format_command

if TYPE_CHECKING:
    from .connection import Connection


@runtime_checkable
class OperationObserver(Protocol):
    """Протокол наблюдателя сквозных операций (files, shell, stream)."""

    def observe_stream(
        self,
        conn: Any,
        command: Any,
        raw_gen: AsyncIterator[str],
        /,
    ) -> AsyncIterator[str]: ...

    async def observe_open_shell(
        self,
        conn: Any,
        raw_fn: Callable[..., Awaitable[ShellSession]],
        /,
        term_type: str = "xterm",
        term_size: tuple[int, int] = (80, 24),
        init_posix: bool | None = None,
        **kwargs: Any,
    ) -> ShellSession: ...

    async def observe_upload(
        self,
        conn: Any,
        raw_fn: Callable[..., Awaitable[None]],
        local_path: str | Path,
        remote_path: str | Path,
        /,
        recurse: bool = False,
        **kwargs: Any,
    ) -> None: ...

    async def observe_download(
        self,
        conn: Any,
        raw_fn: Callable[..., Awaitable[None]],
        remote_path: str | Path,
        local_path: str | Path,
        /,
        recurse: bool = False,
        **kwargs: Any,
    ) -> None: ...

    async def observe_read_file(
        self,
        conn: Any,
        raw_fn: Callable[..., Awaitable[str | bytes]],
        remote_path: str | Path,
        /,
        encoding: str | None = "utf-8",
    ) -> str | bytes: ...

    async def observe_write_file(
        self,
        conn: Any,
        raw_fn: Callable[..., Awaitable[None]],
        remote_path: str | Path,
        content: str | bytes,
        /,
        mode: int | None = None,
        encoding: str = "utf-8",
    ) -> None: ...

    async def observe_sync_dir(
        self,
        conn: Any,
        raw_fn: Callable[..., Awaitable[SyncResult]],
        /,
        local_dir: str | Path,
        remote_dir: str | Path,
        delete: bool = False,
        exclude: Any = None,
        mtime_tolerance: float = 1.0,
        dry_run: bool | None = None,
    ) -> SyncResult: ...

    async def observe_shell_execute(
        self,
        conn: Any,
        raw_fn: Callable[..., Awaitable[Result]],
        command: Any,
        /,
        timeout: float | None = None,
    ) -> Result: ...

    async def observe_shell_expect(
        self,
        conn: Any,
        raw_fn: Callable[..., Awaitable[Result]],
        /,
        command: Any = None,
        patterns: Any = None,
        final_prompt: str | None = None,
        timeout: float | None = None,
        line_ending: str = "\n",
        sensitive: bool = False,
        allow_eof: bool = True,
    ) -> Result: ...


class ObserverContext:
    """Универсальный (sync + async) контекстный менеджер временной подписки ``OperationObserver``."""

    def __init__(self, conn: Any, observer: OperationObserver) -> None:
        """Инициализировать контекст временного наблюдателя."""
        self._conn = conn
        self._observer = observer

    def __enter__(self) -> OperationObserver:
        """Зарегистрировать наблюдателя в соединении."""
        self._conn.add_operation_observer(self._observer)
        return self._observer

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Гарантированно удалить наблюдателя из соединения при выходе."""
        self._conn.remove_operation_observer(self._observer)

    async def __aenter__(self) -> OperationObserver:
        """Асинхронный вход в контекст наблюдателя."""
        return self.__enter__()

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Асинхронный выход из контекста наблюдателя."""
        self.__exit__(exc_type, exc_val, exc_tb)


async def raw_open_shell(
    conn: Connection,
    term_type: str = "xterm",
    term_size: tuple[int, int] = (80, 24),
    init_posix: bool | None = None,
    **kwargs: Any,
) -> ShellSession:
    """Низкоуровневое открытие интерактивной сессии ``ShellSession`` на транспорте."""
    if not conn.transport.is_connected:
        await conn.transport.connect()

    proc = await conn.transport.open_shell(
        term_type=term_type,
        term_size=term_size,
        **kwargs,
    )
    session = ShellSession(
        proc=proc,
        host=conn.config.host,
        default_timeout=conn.config.timeout,
        observers=list(conn.operation_observers),
        conn=conn,
    )
    should_init_posix = (
        (conn.transport_name not in ("serial", "uart"))
        if init_posix is None
        else init_posix
    )
    if should_init_posix:
        await session.initialize()
    else:
        session._initialized = True
    return session


async def open_shell_session(
    conn: Connection,
    term_type: str = "xterm",
    term_size: tuple[int, int] = (80, 24),
    init_posix: bool | None = None,
    **kwargs: Any,
) -> ShellSession:
    """Открыть интерактивную stateful PTY shell-сессию с цепочкой ``OperationObserver``."""
    handler: Callable[..., Awaitable[ShellSession]] = conn._raw_open_shell
    for obs in reversed(conn.operation_observers):
        prev_handler = handler

        async def _step(
            *a: Any,
            _obs: Any = obs,
            _nxt: Callable[..., Awaitable[ShellSession]] = prev_handler,
            **kw: Any,
        ) -> ShellSession:
            return await _obs.observe_open_shell(conn, _nxt, *a, **kw)

        handler = _step

    return await handler(
        term_type=term_type,
        term_size=term_size,
        init_posix=init_posix,
        **kwargs,
    )


async def expect_command(
    conn: Connection,
    command: str | Sequence[str],
    patterns: Mapping[str, str | SecretStr] | None = None,
    final_prompt: str | None = None,
    timeout: float | None = None,
    line_ending: str = "\n",
    sensitive: bool = False,
    term_type: str = "xterm",
    term_size: tuple[int, int] = (80, 24),
    **kwargs: Any,
) -> Result:
    """Выполнить интерактивную команду с декларативным сопоставлением regex-паттернов."""
    cmd_str = format_command(command)
    if (
        sys.platform == "win32"
        and conn.transport_name == "local"
        and cmd_str.startswith("python3 ")
    ):
        cmd_str = f'"{sys.executable}" {cmd_str[len("python3 "):]}'
    if conn.dry_run:
        conn.logger.info(
            f"[DRY-RUN] Skipping expect {cmd_str!r} on {conn.config.uri_safe}"
        )
        return Result(
            exit_code=0,
            stdout="",
            stderr="",
            duration=0.0,
            command=cmd_str,
            host=conn.config.host,
            sensitive=sensitive,
        )

    session = await conn.open_shell(
        term_type=term_type,
        term_size=term_size,
        init_posix=False,
        **kwargs,
    )
    try:
        return await session.expect(
            command=cmd_str,
            patterns=patterns,
            final_prompt=final_prompt,
            timeout=timeout,
            line_ending=line_ending,
            sensitive=sensitive,
        )
    finally:
        await session.close()


raw_open_shell.__name__ = "_raw_open_shell"
open_shell_session.__name__ = "open_shell"
expect_command.__name__ = "expect"

__all__ = [
    "ObserverContext",
    "OperationObserver",
    "expect_command",
    "open_shell_session",
    "raw_open_shell",
]
