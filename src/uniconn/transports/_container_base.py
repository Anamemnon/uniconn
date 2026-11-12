# src/uniconn/transports/_container_base.py
"""Базовый класс и общие утилиты для контейнерных и оркестрационных транспортов (Docker, Podman, Kubernetes)."""

from __future__ import annotations

import abc
import asyncio
import builtins
import contextlib
import shlex
import stat as stat_module
import time
from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from typing import Any

from ..config.models import ConnectionConfig
from ..exceptions import ConnectionError, ExecutionError, TimeoutError
from ..result import Result
from ._local import _LocalShellProcess
from .base import BaseTransport, FileStat

_FILETYPE_MAP: dict[str, int] = {
    "-": stat_module.S_IFREG,
    "d": stat_module.S_IFDIR,
    "l": stat_module.S_IFLNK,
    "c": stat_module.S_IFCHR,
    "b": stat_module.S_IFBLK,
    "p": stat_module.S_IFIFO,
    "s": stat_module.S_IFSOCK,
}


def _symbolic_mode_to_int(perm_str: str) -> int:
    """Преобразовать символическую строку прав ``ls -ldn`` (например, ``drwxr-xr-x``) в целочисленный mode."""
    if len(perm_str) < 10 or perm_str[0] not in _FILETYPE_MAP:
        raise ValueError(f"Invalid symbolic permission string: {perm_str!r}")
    mode = _FILETYPE_MAP[perm_str[0]]
    if perm_str[1] == "r":
        mode |= stat_module.S_IRUSR
    if perm_str[2] == "w":
        mode |= stat_module.S_IWUSR
    if perm_str[3] in ("x", "s"):
        mode |= stat_module.S_IXUSR
    if perm_str[3] in ("s", "S"):
        mode |= stat_module.S_ISUID
    if perm_str[4] == "r":
        mode |= stat_module.S_IRGRP
    if perm_str[5] == "w":
        mode |= stat_module.S_IWGRP
    if perm_str[6] in ("x", "s"):
        mode |= stat_module.S_IXGRP
    if perm_str[6] in ("s", "S"):
        mode |= stat_module.S_ISGID
    if perm_str[7] == "r":
        mode |= stat_module.S_IROTH
    if perm_str[8] == "w":
        mode |= stat_module.S_IWOTH
    if perm_str[9] in ("x", "t"):
        mode |= stat_module.S_IXOTH
    if perm_str[9] in ("t", "T"):
        mode |= stat_module.S_ISVTX
    return mode


def _parse_ls_stat_output(raw: str) -> FileStat:
    """Разобрать строку вывода ``ls -ldn`` в ``FileStat``."""
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    if not lines:
        raise ValueError(f"Empty ls -ldn output: {raw!r}")
    parts = lines[0].split()
    if len(parts) < 5:
        raise ValueError(f"Unexpected ls -ldn output format: {raw!r}")
    mode = _symbolic_mode_to_int(parts[0])
    uid = int(parts[2]) if parts[2].isdigit() else 0
    gid = int(parts[3]) if parts[3].isdigit() else 0
    size = int(parts[4]) if parts[4].isdigit() else 0
    return {
        "size": size,
        "uid": uid,
        "gid": gid,
        "permissions": oct(mode),
        "mode": mode,
        "atime": 0.0,
        "mtime": 0.0,
        "is_file": stat_module.S_ISREG(mode),
        "is_dir": stat_module.S_ISDIR(mode),
        "is_symlink": stat_module.S_ISLNK(mode),
    }


def _parse_stat_output(raw: str) -> FileStat:
    """Разобрать строку вывода ``stat -c '%s|%u|%g|%f|%X|%Y'`` или ``ls -ldn`` в ``FileStat``."""
    stripped = raw.strip()
    if "|" not in stripped:
        return _parse_ls_stat_output(stripped)
    first_line = stripped.splitlines()[0].strip()
    parts = first_line.split("|")
    if len(parts) < 6:
        raise ValueError(f"Unexpected stat output format: {raw!r}")
    size = int(parts[0])
    uid = int(parts[1])
    gid = int(parts[2])
    mode = int(parts[3], 16)
    atime = float(parts[4])
    mtime = float(parts[5])
    return {
        "size": size,
        "uid": uid,
        "gid": gid,
        "permissions": oct(mode),
        "mode": mode,
        "atime": atime,
        "mtime": mtime,
        "is_file": stat_module.S_ISREG(mode),
        "is_dir": stat_module.S_ISDIR(mode),
        "is_symlink": stat_module.S_ISLNK(mode),
    }


def _build_stat_fallback_command(remote_path: str) -> str:
    """Сформировать резервную команду получения метаданных файла через Python или ``ls -ldn``."""
    q_path = shlex.quote(remote_path)
    py_expr = (
        "import os,sys; s=os.lstat(sys.argv[1]); "
        "print(f'{s.st_size}|{s.st_uid}|{s.st_gid}|{s.st_mode:x}|{int(s.st_atime)}|{int(s.st_mtime)}')"
    )
    q_py = shlex.quote(py_expr)
    return (
        f"python3 -c {q_py} {q_path} 2>/dev/null "
        f"|| python -c {q_py} {q_path} 2>/dev/null "
        f"|| ls -ldn -- {q_path} 2>/dev/null || ls -ldn {q_path}"
    )


class ContainerExecTransportBase(BaseTransport):
    """Абстрактный базовый транспорт CLI-исполнения внутри контейнеров или подов."""

    _cli_label: str = "Container runtime CLI"
    _target_noun: str = "container"

    def __init__(self, config: ConnectionConfig) -> None:
        super().__init__(config)
        self._shell_procs: list[_LocalShellProcess] = []

    @property
    @abc.abstractmethod
    def _target_host(self) -> str:
        """Имя целевого контейнера или пода для формирования ошибок и ``Result.host``."""

    @abc.abstractmethod
    def _build_exec_args(
        self,
        command: str,
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        interactive: bool = True,
        tty: bool = False,
    ) -> list[str]:
        """Сформировать список аргументов CLI для выполнения команды внутри контейнера/пода."""

    async def _close_shell_procs(self) -> None:
        """Закрыть все активные интерактивные shell-процессы."""
        while self._shell_procs:
            proc = self._shell_procs.pop()
            with contextlib.suppress(Exception):
                proc.terminate()
            with contextlib.suppress(Exception):
                await proc.wait_closed()

    async def _run_host_cli(
        self,
        args: list[str],
        *,
        stdin_bytes: bytes | None = None,
        timeout: float | None = None,
    ) -> tuple[int, bytes, bytes, float]:
        """Выполнить команду CLI рантайма на хосте и вернуть ``(exit_code, stdout, stderr, duration)``."""
        start_time = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdin=asyncio.subprocess.PIPE if stdin_bytes is not None else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise ConnectionError(
                f"{self._cli_label} {args[0]!r} not found in PATH",
                host=self.config.host,
            ) from exc
        except OSError as exc:
            raise ConnectionError(
                f"Failed to invoke {args[0]!r}: {exc}",
                host=self.config.host,
            ) from exc

        try:
            comm_coro = (
                proc.communicate(stdin_bytes)
                if stdin_bytes is not None
                else proc.communicate()
            )
            stdout, stderr = await asyncio.wait_for(comm_coro, timeout=timeout)
        except builtins.TimeoutError as exc:
            with contextlib.suppress(ProcessLookupError, OSError):
                proc.kill()
            with contextlib.suppress(Exception):
                await proc.wait()
            raise TimeoutError(
                f"{self.name} command timed out after {timeout}s",
                command=" ".join(args),
                host=self.config.host,
            ) from exc
        finally:
            transport = getattr(proc, "_transport", None)
            if transport is not None:
                with contextlib.suppress(Exception):
                    transport.close()

        duration = time.monotonic() - start_time
        return (proc.returncode or 0, stdout or b"", stderr or b"", duration)

    async def _exec_raw(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> tuple[int, bytes, bytes, float]:
        """Выполнить команду внутри контейнера/пода и вернуть сырые байты."""
        input_data = kwargs.get("input")
        stdin_bytes: bytes | None = None
        if isinstance(input_data, str):
            stdin_bytes = input_data.encode("utf-8")
        elif isinstance(input_data, bytes):
            stdin_bytes = input_data

        exec_args = self._build_exec_args(
            command,
            cwd=kwargs.get("cwd"),
            env=kwargs.get("env"),
            interactive=stdin_bytes is not None,
        )
        eff_timeout = timeout if timeout is not None else self.config.timeout
        try:
            return await self._run_host_cli(
                exec_args,
                stdin_bytes=stdin_bytes,
                timeout=eff_timeout,
            )
        except TimeoutError as exc:
            raise TimeoutError(
                f"{self.name} command timed out after {eff_timeout}s",
                command=command,
                host=self._target_host,
            ) from exc

    async def run(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> Result:
        """Выполнить команду в контейнере/поде и вернуть ``Result``."""
        raise_on_error = bool(kwargs.pop("raise_on_error", False))
        exit_code, stdout_b, stderr_b, duration = await self._exec_raw(
            command,
            timeout=timeout,
            **kwargs,
        )
        stdout_str = stdout_b.decode("utf-8", errors="replace") if stdout_b else ""
        stderr_str = stderr_b.decode("utf-8", errors="replace") if stderr_b else ""
        target = self._target_host
        if raise_on_error and exit_code != 0:
            raise ExecutionError(
                f"Command failed in {self._target_noun} {target!r} with exit code {exit_code}",
                command=command,
                exit_code=exit_code,
                stdout=stdout_str,
                stderr=stderr_str,
                host=target,
            )
        return Result(
            exit_code=exit_code,
            stdout=stdout_str,
            stderr=stderr_str,
            duration=duration,
            command=command,
            host=target,
        )

    async def run_bytes(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> bytes:
        """Выполнить команду в контейнере/поде и вернуть сырой байтовый ``stdout``."""
        raise_on_error = bool(kwargs.pop("raise_on_error", False))
        exit_code, stdout_b, stderr_b, _ = await self._exec_raw(
            command,
            timeout=timeout,
            **kwargs,
        )
        if raise_on_error and exit_code != 0:
            target = self._target_host
            raise ExecutionError(
                f"Command failed in {self._target_noun} {target!r} with exit code {exit_code}",
                command=command,
                exit_code=exit_code,
                stdout=stdout_b.decode("utf-8", errors="replace"),
                stderr=stderr_b.decode("utf-8", errors="replace"),
                host=target,
            )
        return stdout_b

    async def stream(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Построчное потоковое чтение вывода команды из контейнера/пода."""
        _ = timeout
        exec_args = self._build_exec_args(
            command,
            cwd=kwargs.get("cwd"),
            env=kwargs.get("env"),
            interactive=False,
        )
        proc = await asyncio.create_subprocess_exec(
            *exec_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            if proc.stdout is not None:
                async for line in proc.stdout:
                    yield line.decode("utf-8", errors="replace").rstrip("\r\n")
            await proc.wait()
        finally:
            if proc.returncode is None:
                with contextlib.suppress(ProcessLookupError, OSError):
                    proc.terminate()
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(proc.wait(), timeout=1.0)
            transport = getattr(proc, "_transport", None)
            if transport is not None:
                with contextlib.suppress(Exception):
                    transport.close()

    async def read_file(self, remote_path: str) -> bytes:
        """Прочитать файл из контейнера/пода в память (``bytes``)."""
        q_path = shlex.quote(remote_path)
        exit_code, stdout_b, stderr_b, _ = await self._exec_raw(f"cat -- {q_path}")
        if exit_code != 0:
            err = stderr_b.decode("utf-8", errors="replace").strip()
            raise ConnectionError(
                f"{self.name} read_file failed for {remote_path}: {err}",
                host=self._target_host,
            )
        return stdout_b

    async def write_file(
        self,
        remote_path: str,
        data: bytes,
        mode: int | None = None,
    ) -> None:
        """Записать байты в файл внутри контейнера/пода и опционально применить ``chmod``."""
        q_path = shlex.quote(remote_path)
        parent = str(Path(remote_path).parent)
        mkdir_part = f"mkdir -p -- {shlex.quote(parent)} && " if parent and parent != "." else ""
        chmod_part = f" && chmod {oct(mode)[2:]} -- {q_path}" if mode is not None else ""
        cmd = f"{mkdir_part}cat > {q_path}{chmod_part}"
        exit_code, _, stderr_b, _ = await self._exec_raw(cmd, input=data)
        if exit_code != 0:
            err = stderr_b.decode("utf-8", errors="replace").strip()
            raise ConnectionError(
                f"{self.name} write_file failed for {remote_path}: {err}",
                host=self._target_host,
            )

    @staticmethod
    def _compute_local_size(path_str: str) -> int:
        """Вычислить размер локального файла или директории для progress_callback."""
        p = Path(path_str)
        if not p.exists():
            return 0
        if p.is_file():
            return p.stat().st_size
        return sum(f.stat().st_size for f in p.rglob("*") if f.is_file())

    async def chmod(self, remote_path: str, mode: int) -> None:
        """Изменить права доступа к файлу внутри контейнера/пода."""
        res = await self.run(f"chmod {oct(mode)[2:]} -- {shlex.quote(remote_path)}")
        if not res.ok:
            raise ConnectionError(
                f"{self.name} chmod failed for {remote_path}: {res.stderr.strip()}",
                host=self._target_host,
            )

    async def stat(self, remote_path: str) -> FileStat:
        """Получить метаданные файла или директории внутри контейнера/пода (с fallback на Python и ls -ldn)."""
        q_path = shlex.quote(remote_path)
        res = await self.run(f"stat -c '%s|%u|%g|%f|%X|%Y' -- {q_path}")
        if res.ok and res.stdout.strip():
            try:
                return _parse_stat_output(res.stdout)
            except ValueError:
                pass

        fb_res = await self.run(_build_stat_fallback_command(remote_path))
        if fb_res.ok and fb_res.stdout.strip():
            try:
                return _parse_stat_output(fb_res.stdout)
            except ValueError as exc:
                raise ConnectionError(
                    f"{self.name} stat parse failed for {remote_path}: {exc}",
                    host=self._target_host,
                ) from exc

        err_msg = (res.stderr or fb_res.stderr).strip()
        if res.ok and res.stdout.strip():
            raise ConnectionError(
                f"{self.name} stat parse failed for {remote_path}: Unexpected stat output format: {res.stdout!r}",
                host=self._target_host,
            )
        raise ConnectionError(
            f"{self.name} stat failed for {remote_path}: {err_msg}",
            host=self._target_host,
        )

    async def listdir(self, remote_path: str = ".") -> list[str]:
        """Список имён файлов в директории внутри контейнера/пода."""
        q_path = shlex.quote(remote_path)
        res = await self.run(f"ls -1A -- {q_path}")
        if not res.ok:
            raise ConnectionError(
                f"{self.name} listdir failed for {remote_path}: {res.stderr.strip()}",
                host=self._target_host,
            )
        return [line for line in res.stdout.splitlines() if line]

    async def remove_file(self, remote_path: str) -> None:
        """Удалить файл внутри контейнера/пода."""
        q_path = shlex.quote(remote_path)
        res = await self.run(f"rm -f -- {q_path}")
        if not res.ok:
            raise ConnectionError(
                f"{self.name} remove_file failed for {remote_path}: {res.stderr.strip()}",
                host=self._target_host,
            )


__all__ = [
    "ContainerExecTransportBase",
    "_build_stat_fallback_command",
    "_parse_ls_stat_output",
    "_parse_stat_output",
    "_symbolic_mode_to_int",
]
