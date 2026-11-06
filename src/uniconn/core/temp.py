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


def _ps_quote(value: str) -> str:
    """Экранировать строку для одинарных кавычек PowerShell."""
    return "'" + value.replace("'", "''") + "'"


async def create_temp_dir(
    conn: Connection,
    prefix: str = "uniconn_",
    suffix: str = "",
    dir: str | None = None,
) -> str:
    """Создать временную директорию на хосте и вернуть путь к ней."""
    base_dir = dir or "/tmp"
    if conn.dry_run:
        return f"{base_dir.rstrip('/')}/{prefix}dryrun{suffix}"

    if conn.transport_name == "local":
        return tempfile.mkdtemp(suffix=suffix, prefix=prefix, dir=dir)

    if conn.transport_name in ("winrm", "wsman"):
        q_dir = _ps_quote(dir or "")
        q_prefix = _ps_quote(prefix)
        q_suffix = _ps_quote(suffix)
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
    if conn.dry_run or not path:
        return
    if conn.transport_name == "local":
        shutil.rmtree(path, ignore_errors=True)
        return
    if conn.transport_name in ("winrm", "wsman"):
        q_path = _ps_quote(path)
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
