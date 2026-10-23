# src/uniconn/transports/_local.py
from __future__ import annotations

import asyncio
import contextlib
import os
import sys
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from ..exceptions import ConnectionError, ExecutionError
from ..result import Result
from ._base import BaseTransport


class _LocalShellStdin:
    """Адаптер текстовой записи поверх байтового StreamWriter для LocalTransport."""

    def __init__(self, writer: asyncio.StreamWriter) -> None:
        self._writer = writer

    def write(self, text: str | bytes) -> None:
        data = text.encode("utf-8") if isinstance(text, str) else bytes(text)
        self._writer.write(data)

    async def drain(self) -> None:
        await self._writer.drain()


class _LocalShellStdout:
    """Адаптер текстового чтения поверх байтового StreamReader для LocalTransport."""

    def __init__(self, reader: asyncio.StreamReader) -> None:
        self._reader = reader

    async def read(self, n: int = 4096) -> str:
        chunk = await self._reader.read(n)
        return chunk.decode("utf-8", errors="replace") if chunk else ""


class _LocalShellProcess:
    """Адаптер локального shell-процесса для совместимости с ``ShellSession``."""

    def __init__(
        self,
        proc: asyncio.subprocess.Process,
        term_size: tuple[int, int] = (80, 24),
    ) -> None:
        assert proc.stdin is not None
        assert proc.stdout is not None
        self._proc = proc
        self.stdin = _LocalShellStdin(proc.stdin)
        self.stdout = _LocalShellStdout(proc.stdout)
        self.term_size = term_size
        self.terminated = False
        self.closed = False

    @property
    def returncode(self) -> int | None:
        return self._proc.returncode

    def change_terminal_size(self, cols: int, rows: int) -> None:
        self.term_size = (cols, rows)

    def terminate(self) -> None:
        self.terminated = True
        with contextlib.suppress(ProcessLookupError, OSError):
            self._proc.terminate()

    def close(self) -> None:
        self.closed = True
        if self._proc.stdin is not None:
            with contextlib.suppress(Exception):
                self._proc.stdin.close()
        transport = getattr(self._proc, "_transport", None)
        if transport is not None:
            with contextlib.suppress(Exception):
                transport.close()

    async def wait_closed(self) -> None:
        with contextlib.suppress(Exception):
            await asyncio.wait_for(self._proc.wait(), timeout=1.0)
        self.close()


class LocalTransport(BaseTransport):
    """Выполнение команд локально через subprocess."""

    def __init__(self, config: Any) -> None:
        super().__init__(config)
        self._shell_procs: list[_LocalShellProcess] = []

    @property
    def name(self) -> str:
        return "local"

    async def connect(self) -> None:
        self._connected = True

    async def disconnect(self) -> None:
        while self._shell_procs:
            proc = self._shell_procs.pop()
            with contextlib.suppress(Exception):
                proc.terminate()
            with contextlib.suppress(Exception):
                await proc.wait_closed()
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

    async def chmod(self, remote_path: str, mode: int) -> None:
        """Изменить права доступа к локальному файлу."""
        try:
            if sys.platform != "win32":
                os.chmod(remote_path, mode)
        except OSError as e:
            raise ConnectionError(
                f"Local chmod failed for {remote_path}: {e}",
                host="localhost",
            ) from e

    async def stat(self, remote_path: str) -> dict[str, Any]:
        """Получить метаданные локального файла."""
        import stat as stat_module

        try:
            st = os.stat(remote_path, follow_symlinks=False)
            mode = st.st_mode
            return {
                "size": st.st_size,
                "uid": st.st_uid,
                "gid": st.st_gid,
                "permissions": oct(mode),
                "atime": st.st_atime,
                "mtime": st.st_mtime,
                "is_file": stat_module.S_ISREG(mode),
                "is_dir": stat_module.S_ISDIR(mode),
                "is_symlink": stat_module.S_ISLNK(mode),
            }
        except OSError as e:
            raise ConnectionError(
                f"Local stat failed for {remote_path}: {e}",
                host="localhost",
            ) from e

    async def listdir(self, remote_path: str = ".") -> list[str]:
        """Список файлов в локальной директории."""
        try:
            return os.listdir(remote_path)
        except OSError as e:
            raise ConnectionError(
                f"Local listdir failed for {remote_path}: {e}",
                host="localhost",
            ) from e

    async def remove_file(self, remote_path: str) -> None:
        """Удалить локальный файл."""
        try:
            Path(remote_path).unlink()
        except OSError as e:
            raise ConnectionError(
                f"Local remove_file failed for {remote_path}: {e}",
                host="localhost",
            ) from e

    async def upload(
        self,
        local_path: str,
        remote_path: str,
        **kwargs: Any,
    ) -> None:
        """Скопировать локальный файл или директорию."""
        import shutil

        try:
            src = Path(local_path)
            dst = Path(remote_path)
            if src.is_dir():
                shutil.copytree(src, dst, dirs_exist_ok=True)
            else:
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
        except OSError as e:
            raise ConnectionError(
                f"Local upload failed from {local_path} to {remote_path}: {e}",
                host="localhost",
            ) from e

    async def download(
        self,
        remote_path: str,
        local_path: str,
        **kwargs: Any,
    ) -> None:
        """Скопировать локальный файл или директорию в назначение."""
        await self.upload(remote_path, local_path, **kwargs)

    async def open_shell(
        self,
        term_type: str = "xterm",
        term_size: tuple[int, int] = (80, 24),
        **kwargs: Any,
    ) -> _LocalShellProcess:
        """Открыть интерактивную stateful shell-сессию локально (``/bin/sh``)."""
        if not self._connected:
            raise ConnectionError(
                "Local transport is not connected. Call connect() first",
                host="localhost",
            )

        shell_bin = kwargs.pop("shell", "/bin/sh")
        env = {
            **os.environ,
            "TERM": term_type,
            "COLUMNS": str(term_size[0]),
            "LINES": str(term_size[1]),
        }
        proc = await asyncio.create_subprocess_exec(
            shell_bin,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env,
        )
        wrapped = _LocalShellProcess(proc, term_size=term_size)
        self._shell_procs.append(wrapped)
        return wrapped

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

