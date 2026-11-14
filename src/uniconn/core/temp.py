# src/uniconn/core/temp.py
"""Управление временными директориями на целевом хосте (HostTempManager)."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from .context import TempDirContext

if TYPE_CHECKING:
    from .connection import Connection


def temp_dir(
    conn: Connection,
    prefix: str = "uniconn_",
    suffix: str = "",
    dir: str | Path | None = None,
) -> TempDirContext:
    """Асинхронный контекстный менеджер временной директории на хосте."""
    return TempDirContext(conn, prefix=prefix, suffix=suffix, dir=dir)


async def create_temp_dir(
    conn: Connection,
    prefix: str = "uniconn_",
    suffix: str = "",
    dir: str | None = None,
) -> str:
    """Создать временную директорию на хосте и вернуть путь к ней."""
    from ..services.provisioning.windows import is_windows_connection, ps_quote

    is_win = is_windows_connection(conn)
    base_dir = dir or ("C:\\Windows\\Temp" if is_win else "/tmp")
    if conn.dry_run:
        sep = "\\" if is_win else "/"
        trimmed = base_dir.rstrip("\\" if is_win else "/")
        return f"{trimmed}{sep}{prefix}dryrun{suffix}"

    if conn.transport_name == "local":
        return tempfile.mkdtemp(suffix=suffix, prefix=prefix, dir=dir)

    if is_win:
        q_dir = ps_quote(dir or "")
        q_prefix = ps_quote(prefix)
        q_suffix = ps_quote(suffix)
        ps_cmd = (
            f"$base = if ({q_dir} -ne '') {{ {q_dir} }} else {{ $env:TEMP }}; "
            f"$name = {q_prefix} + [guid]::NewGuid().ToString('N').Substring(0, 8) + {q_suffix}; "
            "$p = Join-Path $base $name; "
            "New-Item -ItemType Directory -Path $p -Force -ErrorAction Stop | Out-Null; "
            "Write-Output $p"
        )
        res = await conn.run(ps_cmd, raise_on_error=True)
        return res.text

    template = f"{base_dir.rstrip('/')}/{prefix}XXXXXX{suffix}"
    res = await conn.run(["mktemp", "-d", template], raise_on_error=True)
    return res.text


async def remove_temp_dir(conn: Connection, path: str) -> None:
    """Удалить временную директорию на хосте."""
    from ..services.provisioning.windows import is_windows_connection, ps_quote

    if conn.dry_run or not path:
        return
    if conn.transport_name == "local":
        shutil.rmtree(path, ignore_errors=True)
        return
    if is_windows_connection(conn):
        q_path = ps_quote(path)
        await conn.run(
            f"Remove-Item -LiteralPath {q_path} -Recurse -Force -ErrorAction SilentlyContinue"
        )
        return
    await conn.run(["rm", "-rf", path])


create_temp_dir.__name__ = "_create_temp_dir"
remove_temp_dir.__name__ = "_remove_temp_dir"


class HostTempManager:
    """Менеджер создания и гарантированной очистки временных директорий на хосте."""

    temp_dir = staticmethod(temp_dir)
    create_temp_dir = staticmethod(create_temp_dir)
    remove_temp_dir = staticmethod(remove_temp_dir)


__all__ = [
    "HostTempManager",
    "create_temp_dir",
    "remove_temp_dir",
    "temp_dir",
]
