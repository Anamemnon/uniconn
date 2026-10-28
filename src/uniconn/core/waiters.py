# src/uniconn/core/waiters.py
"""Проверка доступности хоста и поллинг условий (ping, wait_for_connection, wait_for_port, wait_for_path)."""

from __future__ import annotations

import asyncio
import contextlib
import re
import shlex
import time
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from ..exceptions import TimeoutError as UniconnTimeoutError
from ..result import PingResult

if TYPE_CHECKING:
    from .connection import Connection


async def ping_connection(
    conn: Connection,
    timeout: float | None = None,
) -> PingResult:
    """Проверить доступность хоста с измерением задержки (``latency_ms``)."""
    host = conn.config.host or conn.config.uri_safe or "localhost"
    transport = conn.transport_name
    if conn.is_dry_run:
        return PingResult(
            host=host,
            alive=True,
            latency_ms=0.0,
            transport=transport,
        )

    start = time.monotonic()
    try:
        if not conn.transport.is_connected:
            await conn.transport.connect()
        alive = await conn.transport.ping(timeout=timeout)
        elapsed_ms = (time.monotonic() - start) * 1000.0
        return PingResult(
            host=host,
            alive=alive,
            latency_ms=elapsed_ms,
            transport=transport,
            error=None if alive else "Ping check returned False",
        )
    except Exception as exc:
        elapsed_ms = (time.monotonic() - start) * 1000.0
        return PingResult(
            host=host,
            alive=False,
            latency_ms=elapsed_ms,
            transport=transport,
            error=str(exc),
        )


async def wait_for_connection(
    conn: Connection,
    timeout: float = 120.0,
    interval: float = 2.0,
    delay: float = 0.0,
) -> PingResult:
    """Ожидать восстановления доступности хоста (например, после ``reboot``)."""
    if conn.is_dry_run:
        return await conn.ping(timeout=timeout)

    start = time.monotonic()
    deadline = start + timeout
    if delay > 0:
        await asyncio.sleep(delay)

    last_res: PingResult | None = None
    while True:
        remaining = deadline - time.monotonic()
        probe_timeout = max(0.5, min(interval * 2.0, max(0.5, remaining)))
        try:
            if not conn.transport.is_connected:
                with contextlib.suppress(Exception):
                    await conn.transport.disconnect()
            last_res = await conn.ping(timeout=probe_timeout)
            if last_res.alive:
                return last_res
        except Exception as exc:
            last_res = PingResult(
                host=conn.config.host or "localhost",
                alive=False,
                latency_ms=0.0,
                transport=conn.transport_name,
                error=str(exc),
            )

        now = time.monotonic()
        if now >= deadline:
            break
        await asyncio.sleep(min(interval, deadline - now))

    err_detail = last_res.error if last_res and last_res.error else "host unreachable"
    raise UniconnTimeoutError(
        f"Timed out in wait_for_connection after {timeout:.2f}s ({err_detail})",
        host=conn.config.host,
    )


async def wait_for_port(
    conn: Connection,
    port: int,
    *,
    host: str | None = None,
    state: Literal["open", "closed"] = "open",
    check_from: Literal["remote", "local"] = "remote",
    timeout: float = 60.0,
    interval: float = 1.0,
    delay: float = 0.0,
) -> float:
    """Ожидать открытия (``open``) или закрытия (``closed``) TCP-порта."""
    if conn.is_dry_run:
        return 0.0

    start = time.monotonic()
    deadline = start + timeout
    if delay > 0:
        await asyncio.sleep(delay)

    if host is not None:
        target_host = host
    elif check_from == "local":
        target_host = conn.config.host or "127.0.0.1"
    else:
        target_host = "127.0.0.1"

    port_num = int(port)

    while True:
        is_open = False
        if check_from == "local":
            probe_timeout = max(0.2, min(2.0, interval))
            try:
                _reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target_host, port_num),
                    timeout=probe_timeout,
                )
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
                is_open = True
            except Exception:
                is_open = False
        else:
            q_host = shlex.quote(target_host)
            probe_cmd = (
                f"python3 -c 'import socket,sys; s=socket.socket(); s.settimeout(1.5); "
                f"sys.exit(0 if s.connect_ex(({target_host!r},{port_num}))==0 else 1)' 2>/dev/null "
                f"|| nc -z -w 2 {q_host} {port_num} 2>/dev/null "
                f"|| (echo >/dev/tcp/{q_host}/{port_num}) >/dev/null 2>&1"
            )
            with contextlib.suppress(Exception):
                res = await conn.run(probe_cmd, raise_on_error=False, dry_run=False)
                is_open = res.ok

        if (state == "open" and is_open) or (state == "closed" and not is_open):
            return time.monotonic() - start

        now = time.monotonic()
        if now >= deadline:
            break
        await asyncio.sleep(min(interval, deadline - now))

    raise UniconnTimeoutError(
        f"Timed out in wait_for_port({target_host}:{port_num}, state={state!r}, "
        f"check_from={check_from!r}) after {timeout:.2f}s",
        host=conn.config.host,
    )


async def wait_for_path(
    conn: Connection,
    remote_path: str | Path,
    *,
    state: Literal["present", "absent"] = "present",
    content_regex: str | None = None,
    timeout: float = 60.0,
    interval: float = 1.0,
    delay: float = 0.0,
    sudo: bool = False,
) -> float:
    """Ожидать появления (``present``) или удаления (``absent``) файла/директории/сокета."""
    if conn.is_dry_run:
        return 0.0

    start = time.monotonic()
    deadline = start + timeout
    if delay > 0:
        await asyncio.sleep(delay)

    path_str = str(remote_path)
    q_path = shlex.quote(path_str)
    compiled_re = re.compile(content_regex) if content_regex is not None else None

    while True:
        exists = False
        with contextlib.suppress(Exception):
            if sudo:
                chk = await conn.run(
                    f"test -e {q_path}",
                    sudo=True,
                    raise_on_error=False,
                    dry_run=False,
                )
                exists = chk.ok
            else:
                try:
                    exists = await conn.files.exists(path_str)
                except Exception:
                    chk = await conn.run(
                        f"test -e {q_path}",
                        raise_on_error=False,
                        dry_run=False,
                    )
                    exists = chk.ok

        if state == "absent" and not exists:
            return time.monotonic() - start

        if state == "present" and exists:
            if compiled_re is None:
                return time.monotonic() - start
            text_content: str | None = None
            with contextlib.suppress(Exception):
                if sudo:
                    cat_res = await conn.run(
                        f"cat {q_path}",
                        sudo=True,
                        raise_on_error=False,
                        dry_run=False,
                    )
                    if cat_res.ok:
                        text_content = cat_res.stdout
                else:
                    raw = await conn.files.read_file(path_str, encoding="utf-8")
                    text_content = (
                        raw if isinstance(raw, str) else raw.decode("utf-8", errors="replace")
                    )
            if text_content is not None and compiled_re.search(text_content):
                return time.monotonic() - start

        now = time.monotonic()
        if now >= deadline:
            break
        await asyncio.sleep(min(interval, deadline - now))

    raise UniconnTimeoutError(
        f"Timed out in wait_for_path({path_str!r}, state={state!r}) after {timeout:.2f}s",
        host=conn.config.host,
    )


__all__ = [
    "ping_connection",
    "wait_for_connection",
    "wait_for_path",
    "wait_for_port",
]
