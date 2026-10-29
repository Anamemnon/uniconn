# src/uniconn/core/scripts.py
"""Исполнение локальных скриптов на удалённом или локальном хосте (ScriptExecutionManager)."""

from __future__ import annotations

import shlex
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import SecretStr

from ..result import Result

if TYPE_CHECKING:
    from .connection import Connection


async def run_script(
    conn: Connection,
    local_path: str | Path,
    args: Sequence[str] | None = None,
    *,
    interpreter: str | None = None,
    sudo: bool = False,
    sudo_user: str | None = None,
    sudo_password: str | SecretStr | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float | None = None,
    raise_on_error: bool = False,
    sensitive: bool = False,
    dry_run: bool | None = None,
) -> Result:
    """Загрузить локальный скрипт во временную директорию, выполнить и гарантированно удалить."""
    script_path = Path(local_path)
    if not script_path.is_file():
        raise FileNotFoundError(f"Local script not found: {local_path}")

    effective_dry_run = conn.dry_run if dry_run is None else dry_run
    async with conn.temp_dir() as remote_dir:
        remote_script = f"{remote_dir.rstrip('/')}/{script_path.name}"
        if not effective_dry_run:
            await conn.files.upload(str(script_path), remote_script)
            await conn.files.chmod(remote_script, 0o700)

        if interpreter:
            cmd_parts: list[str] = [*shlex.split(interpreter), remote_script]
        else:
            cmd_parts = [remote_script]

        if args:
            cmd_parts.extend(str(a) for a in args)

        if env:
            with conn.env(dict(env)):
                return await conn.run(
                    cmd_parts,
                    timeout=timeout,
                    raise_on_error=raise_on_error,
                    sudo=sudo,
                    sudo_user=sudo_user,
                    sudo_password=sudo_password,
                    sensitive=sensitive,
                    dry_run=dry_run,
                )
        return await conn.run(
            cmd_parts,
            timeout=timeout,
            raise_on_error=raise_on_error,
            sudo=sudo,
            sudo_user=sudo_user,
            sudo_password=sudo_password,
            sensitive=sensitive,
            dry_run=dry_run,
        )


class ScriptExecutionManager:
    """Менеджер загрузки, подготовки и запуска локальных скриптов во временной директории хоста."""

    run_script = staticmethod(run_script)


__all__ = [
    "ScriptExecutionManager",
    "run_script",
]
