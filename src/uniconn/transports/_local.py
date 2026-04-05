# src/uniconn/transports/_local.py
import asyncio
import os
import sys
import time
from collections.abc import AsyncIterator

from ..result import Result
from ._base import BaseTransport


class LocalTransport(BaseTransport):
    """Выполнение команд локально через subprocess."""

    @property
    def name(self) -> str:
        return "local"

    async def connect(self) -> None:
        self._connected = True

    async def disconnect(self) -> None:
        self._connected = False

    async def ping(self, timeout: float | None = None) -> bool:
        """Для локального транспорта всегда True (нет сетевого подключения)."""
        return self._connected

    async def run(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs
    ) -> Result:
        start_time = time.monotonic()

        # Подготовка окружения
        env = kwargs.get("env")
        final_env: dict[str, str] | None = None
        if env:
            final_env = {**os.environ, **env}

        # На Windows env передаётся только через subprocess с shell=True
        creation_flags = 0
        if sys.platform == "win32":
            import subprocess
            creation_flags = subprocess.CREATE_NO_WINDOW

        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=final_env,
            cwd=kwargs.get("cwd"),
            creationflags=creation_flags if sys.platform == "win32" else 0,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout
            )
        except TimeoutError:
            proc.kill()
            await proc.wait()
            raise

        duration = time.monotonic() - start_time

        return Result(
            exit_code=proc.returncode or 0,
            stdout=stdout.decode("utf-8", errors="replace") if stdout else "",
            stderr=stderr.decode("utf-8", errors="replace") if stderr else "",
            duration=duration,
            command=command,
            host="localhost"
        )

    async def stream(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs
    ) -> AsyncIterator[str]:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            **kwargs
        )

        async for line in proc.stdout:
            yield line.decode().rstrip()

        await proc.wait()
