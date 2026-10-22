# src/uniconn/transports/_local.py
import asyncio
import os
import sys
import time
from collections.abc import AsyncIterator
from pathlib import Path

from ..exceptions import ConnectionError, ExecutionError
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

    async def _exec_raw(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs,
    ) -> tuple[int, bytes, bytes, float]:
        """Запустить процесс и вернуть сырые байты (exit_code, stdout, stderr, duration)."""
        start_time = time.monotonic()

        env = kwargs.get("env")
        final_env: dict[str, str] | None = None
        if env:
            final_env = {**os.environ, **env}

        input_data = kwargs.get("input")
        stdin_bytes: bytes | None = None
        if isinstance(input_data, str):
            stdin_bytes = input_data.encode("utf-8")
        elif isinstance(input_data, bytes):
            stdin_bytes = input_data

        creation_flags = 0
        if sys.platform == "win32":
            import subprocess
            creation_flags = subprocess.CREATE_NO_WINDOW

        proc_kwargs: dict = {
            "stdout": asyncio.subprocess.PIPE,
            "stderr": asyncio.subprocess.PIPE,
            "env": final_env,
            "cwd": kwargs.get("cwd"),
            "creationflags": creation_flags if sys.platform == "win32" else 0,
        }
        if stdin_bytes is not None:
            proc_kwargs["stdin"] = asyncio.subprocess.PIPE

        proc = await asyncio.create_subprocess_shell(command, **proc_kwargs)

        try:
            comm_coro = (
                proc.communicate(stdin_bytes)
                if stdin_bytes is not None
                else proc.communicate()
            )
            stdout, stderr = await asyncio.wait_for(
                comm_coro,
                timeout=timeout,
            )
        except TimeoutError:
            proc.kill()
            await proc.wait()
            raise

        duration = time.monotonic() - start_time
        return (proc.returncode or 0, stdout or b"", stderr or b"", duration)

    async def run(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs
    ) -> Result:
        exit_code, stdout, stderr, duration = await self._exec_raw(
            command, timeout=timeout, **kwargs
        )
        return Result(
            exit_code=exit_code,
            stdout=stdout.decode("utf-8", errors="replace") if stdout else "",
            stderr=stderr.decode("utf-8", errors="replace") if stderr else "",
            duration=duration,
            command=command,
            host="localhost"
        )

    async def run_bytes(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs,
    ) -> bytes:
        """Выполнить команду локально и вернуть сырой байтовый stdout."""
        raise_on_error = kwargs.pop("raise_on_error", False)
        exit_code, stdout, stderr, _ = await self._exec_raw(
            command, timeout=timeout, **kwargs
        )
        if raise_on_error and exit_code != 0:
            raise ExecutionError(
                f"Command failed with exit code {exit_code}",
                command=command,
                exit_code=exit_code,
                stdout=stdout.decode("utf-8", errors="replace"),
                stderr=stderr.decode("utf-8", errors="replace"),
            )
        return stdout

    async def read_file(self, remote_path: str) -> bytes:
        """Прочитать локальный файл в память (bytes)."""
        try:
            return Path(remote_path).read_bytes()
        except OSError as e:
            raise ConnectionError(
                f"Local read_file failed for {remote_path}: {e}",
                host="localhost",
            ) from e

    async def write_file(
        self,
        remote_path: str,
        data: bytes,
        mode: int | None = None,
    ) -> None:
        """Записать байты в локальный файл и опционально применить chmod."""
        try:
            path = Path(remote_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            if mode is not None and sys.platform != "win32":
                os.chmod(path, mode)
        except OSError as e:
            raise ConnectionError(
                f"Local write_file failed for {remote_path}: {e}",
                host="localhost",
            ) from e

    async def exists(self, remote_path: str) -> bool:
        """Проверить существование локального файла или директории."""
        return Path(remote_path).exists()

    async def mkdir(
        self,
        remote_path: str,
        parents: bool = True,
        exist_ok: bool = True,
        mode: int | None = None,
    ) -> None:
        """Создать локальную директорию и опционально применить chmod."""
        try:
            path = Path(remote_path)
            path.mkdir(parents=parents, exist_ok=exist_ok)
            if mode is not None and sys.platform != "win32":
                os.chmod(path, mode)
        except OSError as e:
            raise ConnectionError(
                f"Local mkdir failed for {remote_path}: {e}",
                host="localhost",
            ) from e

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

        if proc.stdout is not None:
            async for line in proc.stdout:
                yield line.decode().rstrip()

        await proc.wait()

