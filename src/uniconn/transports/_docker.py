# src/uniconn/transports/_docker.py
"""Контейнерные транспорты Docker и Podman (``docker://``, ``podman://``).

Реализуют полный набор протоколов возможностей ISP:
- ``CommandTransport`` (``run``, ``run_bytes``, ``stream``, ``ping``)
- ``FileCapableTransport`` (``read_file``, ``write_file``, ``upload``, ``download``,
  ``exists``, ``mkdir``, ``chmod``, ``stat``, ``listdir``, ``remove_file``)
- ``ShellCapableTransport`` (интерактивный shell через ``open_shell``)
- ``TunnelCapableTransport`` (локальный TCP-туннель ``forward_local_port``)
"""

from __future__ import annotations

import asyncio
import builtins
import contextlib
import os
import shlex
import shutil
import stat as stat_module
import time
from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from typing import Any

from ..config.models import ConnectionConfig
from ..exceptions import ConfigurationError, ConnectionError, ExecutionError, TimeoutError
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
    # Owner
    if perm_str[1] == "r":
        mode |= stat_module.S_IRUSR
    if perm_str[2] == "w":
        mode |= stat_module.S_IWUSR
    if perm_str[3] in ("x", "s"):
        mode |= stat_module.S_IXUSR
    if perm_str[3] in ("s", "S"):
        mode |= stat_module.S_ISUID
    # Group
    if perm_str[4] == "r":
        mode |= stat_module.S_IRGRP
    if perm_str[5] == "w":
        mode |= stat_module.S_IWGRP
    if perm_str[6] in ("x", "s"):
        mode |= stat_module.S_IXGRP
    if perm_str[6] in ("s", "S"):
        mode |= stat_module.S_ISGID
    # Other
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


class DockerTransport(BaseTransport):
    """Транспорт выполнения команд, файловых операций и PTY внутри контейнеров Docker/Podman."""

    DEFAULT_RUNTIME: str = "docker"

    def __init__(self, config: ConnectionConfig) -> None:
        super().__init__(config)
        self._shell_procs: list[_LocalShellProcess] = []
        self._tunnel_servers: list[asyncio.AbstractServer] = []

    @property
    def name(self) -> str:
        """Название транспорта."""
        return "docker"

    @property
    def runtime(self) -> str:
        """Имя исполняемого файла контейнерного рантайма (``docker`` или ``podman``)."""
        return str(self.config.options.get("runtime", self.DEFAULT_RUNTIME))

    @property
    def container(self) -> str:
        """Имя или ID целевого контейнера."""
        if not self.config.host:
            raise ConfigurationError(f"{self.name}:// URI requires a container name or ID")
        return self.config.host

    def _base_cli_args(self) -> list[str]:
        """Базовые аргументы вызова CLI (с учётом ``context`` и ``docker_host``)."""
        args = [self.runtime]
        ctx = self.config.options.get("context")
        if ctx:
            args.extend(["--context", str(ctx)])
        docker_host = self.config.options.get("docker_host")
        if docker_host:
            args.extend(["-H", str(docker_host)])
        return args

    def _build_exec_args(
        self,
        command: str,
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        interactive: bool = True,
        tty: bool = False,
    ) -> list[str]:
        """Сформировать аргументы команды ``docker/podman exec``."""
        args = [*self._base_cli_args(), "exec"]
        if interactive:
            args.append("-i")
        if tty:
            args.append("-t")

        user = self.config.username or self.config.options.get("user")
        if user:
            args.extend(["-u", str(user)])

        workdir = cwd or self.config.options.get("workdir")
        if workdir:
            args.extend(["-w", str(workdir)])

        if env:
            for k, v in env.items():
                args.extend(["-e", f"{k}={v}"])

        shell = str(self.config.options.get("shell", "/bin/sh"))
        args.extend([self.container, shell, "-c", command])
        return args

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
                f"Container runtime CLI {args[0]!r} not found in PATH",
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

    async def connect(self) -> None:
        """Проверить доступность CLI рантайма и статус ``Running`` у контейнера."""
        container = self.container
        if shutil.which(self.runtime) is None:
            raise ConnectionError(
                f"Container runtime CLI {self.runtime!r} not found in PATH",
                host=container,
            )

        inspect_args = [
            *self._base_cli_args(),
            "inspect",
            "--format",
            "{{.State.Running}}",
            container,
        ]
        exit_code, stdout, stderr, _ = await self._run_host_cli(
            inspect_args,
            timeout=self.config.timeout,
        )
        state_str = stdout.decode("utf-8", errors="replace").strip().lower()
        if exit_code != 0 or state_str != "true":
            err_msg = stderr.decode("utf-8", errors="replace").strip() or f"running={state_str!r}"
            raise ConnectionError(
                f"Container {container!r} is not running or inaccessible via {self.runtime}: {err_msg}",
                host=container,
            )
        self._connected = True

    async def disconnect(self) -> None:
        """Закрыть активные интерактивные сессии и туннели."""
        while self._shell_procs:
            proc = self._shell_procs.pop()
            with contextlib.suppress(Exception):
                proc.terminate()
            with contextlib.suppress(Exception):
                await proc.wait_closed()
        while self._tunnel_servers:
            srv = self._tunnel_servers.pop()
            with contextlib.suppress(Exception):
                srv.close()
                await srv.wait_closed()
        self._connected = False

    async def _exec_raw(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> tuple[int, bytes, bytes, float]:
        """Выполнить команду внутри контейнера и вернуть сырые байты."""
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
                host=self.container,
            ) from exc

    async def run(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> Result:
        """Выполнить команду в контейнере и вернуть ``Result``."""
        raise_on_error = bool(kwargs.pop("raise_on_error", False))
        exit_code, stdout_b, stderr_b, duration = await self._exec_raw(
            command,
            timeout=timeout,
            **kwargs,
        )
        stdout_str = stdout_b.decode("utf-8", errors="replace") if stdout_b else ""
        stderr_str = stderr_b.decode("utf-8", errors="replace") if stderr_b else ""
        if raise_on_error and exit_code != 0:
            raise ExecutionError(
                f"Command failed in container {self.container!r} with exit code {exit_code}",
                command=command,
                exit_code=exit_code,
                stdout=stdout_str,
                stderr=stderr_str,
                host=self.container,
            )
        return Result(
            exit_code=exit_code,
            stdout=stdout_str,
            stderr=stderr_str,
            duration=duration,
            command=command,
            host=self.container,
        )

    async def run_bytes(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> bytes:
        """Выполнить команду в контейнере и вернуть сырой байтовый ``stdout``."""
        raise_on_error = bool(kwargs.pop("raise_on_error", False))
        exit_code, stdout_b, stderr_b, _ = await self._exec_raw(
            command,
            timeout=timeout,
            **kwargs,
        )
        if raise_on_error and exit_code != 0:
            raise ExecutionError(
                f"Command failed in container {self.container!r} with exit code {exit_code}",
                command=command,
                exit_code=exit_code,
                stdout=stdout_b.decode("utf-8", errors="replace"),
                stderr=stderr_b.decode("utf-8", errors="replace"),
                host=self.container,
            )
        return stdout_b

    async def stream(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Построчное потоковое чтение вывода команды из контейнера."""
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
        """Прочитать файл из контейнера в память (``bytes``)."""
        q_path = shlex.quote(remote_path)
        exit_code, stdout_b, stderr_b, _ = await self._exec_raw(f"cat -- {q_path}")
        if exit_code != 0:
            err = stderr_b.decode("utf-8", errors="replace").strip()
            raise ConnectionError(
                f"{self.name} read_file failed for {remote_path}: {err}",
                host=self.container,
            )
        return stdout_b

    async def write_file(
        self,
        remote_path: str,
        data: bytes,
        mode: int | None = None,
    ) -> None:
        """Записать байты в файл внутри контейнера и опционально применить ``chmod``."""
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
                host=self.container,
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

    async def upload(
        self,
        local_path: str,
        remote_path: str,
        **kwargs: Any,
    ) -> None:
        """Скопировать локальный файл или директорию в контейнер через ``docker/podman cp``."""
        progress_cb = kwargs.get("progress_callback")
        total_bytes = self._compute_local_size(local_path) if callable(progress_cb) else 0
        if callable(progress_cb):
            progress_cb(0, total_bytes)
        parent = str(Path(remote_path).parent)
        if parent and parent not in (".", "/"):
            await self.mkdir(parent, parents=True, exist_ok=True)
        cp_args = [
            *self._base_cli_args(),
            "cp",
            str(local_path),
            f"{self.container}:{remote_path}",
        ]
        exit_code, _, stderr_b, _ = await self._run_host_cli(
            cp_args,
            timeout=self.config.timeout,
        )
        if exit_code != 0:
            err = stderr_b.decode("utf-8", errors="replace").strip()
            raise ConnectionError(
                f"{self.name} upload failed from {local_path} to {remote_path}: {err}",
                host=self.container,
            )
        if callable(progress_cb):
            progress_cb(total_bytes, total_bytes)

    async def download(
        self,
        remote_path: str,
        local_path: str,
        **kwargs: Any,
    ) -> None:
        """Скопировать файл или директорию из контейнера на локальный хост через ``cp``."""
        progress_cb = kwargs.get("progress_callback")
        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        cp_args = [
            *self._base_cli_args(),
            "cp",
            f"{self.container}:{remote_path}",
            str(local_path),
        ]
        exit_code, _, stderr_b, _ = await self._run_host_cli(
            cp_args,
            timeout=self.config.timeout,
        )
        if exit_code != 0:
            err = stderr_b.decode("utf-8", errors="replace").strip()
            raise ConnectionError(
                f"{self.name} download failed from {remote_path} to {local_path}: {err}",
                host=self.container,
            )
        if callable(progress_cb):
            total_bytes = self._compute_local_size(local_path)
            progress_cb(total_bytes, total_bytes)

    async def chmod(self, remote_path: str, mode: int) -> None:
        """Изменить права доступа к файлу внутри контейнера."""
        res = await self.run(f"chmod {oct(mode)[2:]} -- {shlex.quote(remote_path)}")
        if not res.ok:
            raise ConnectionError(
                f"{self.name} chmod failed for {remote_path}: {res.stderr.strip()}",
                host=self.container,
            )

    async def stat(self, remote_path: str) -> FileStat:
        """Получить метаданные файла или директории внутри контейнера (с fallback на Python и ls -ldn)."""
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
                    host=self.container,
                ) from exc

        err_msg = (res.stderr or fb_res.stderr).strip()
        if res.ok and res.stdout.strip():
            raise ConnectionError(
                f"{self.name} stat parse failed for {remote_path}: Unexpected stat output format: {res.stdout!r}",
                host=self.container,
            )
        raise ConnectionError(
            f"{self.name} stat failed for {remote_path}: {err_msg}",
            host=self.container,
        )

    async def listdir(self, remote_path: str = ".") -> list[str]:
        """Список имён файлов в директории внутри контейнера."""
        q_path = shlex.quote(remote_path)
        res = await self.run(f"ls -1A -- {q_path}")
        if not res.ok:
            raise ConnectionError(
                f"{self.name} listdir failed for {remote_path}: {res.stderr.strip()}",
                host=self.container,
            )
        return [line for line in res.stdout.splitlines() if line]

    async def remove_file(self, remote_path: str) -> None:
        """Удалить файл внутри контейнера."""
        q_path = shlex.quote(remote_path)
        res = await self.run(f"rm -f -- {q_path}")
        if not res.ok:
            raise ConnectionError(
                f"{self.name} remove_file failed for {remote_path}: {res.stderr.strip()}",
                host=self.container,
            )

    async def open_shell(
        self,
        term_type: str = "xterm",
        term_size: tuple[int, int] = (80, 24),
        **kwargs: Any,
    ) -> _LocalShellProcess:
        """Открыть интерактивную stateful shell-сессию внутри контейнера."""
        if not self._connected:
            raise ConnectionError(
                f"{self.name} transport is not connected. Call connect() first",
                host=self.config.host,
            )

        shell_bin = str(kwargs.pop("shell", self.config.options.get("shell", "/bin/sh")))
        args = [*self._base_cli_args(), "exec", "-i"]
        user = self.config.username or self.config.options.get("user")
        if user:
            args.extend(["-u", str(user)])
        workdir = self.config.options.get("workdir")
        if workdir:
            args.extend(["-w", str(workdir)])
        args.extend(
            [
                "-e",
                f"TERM={term_type}",
                "-e",
                f"COLUMNS={term_size[0]}",
                "-e",
                f"LINES={term_size[1]}",
                self.container,
                shell_bin,
            ]
        )
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env={**os.environ, "TERM": term_type},
        )
        wrapped = _LocalShellProcess(proc, term_size=term_size)
        self._shell_procs.append(wrapped)
        return wrapped

    @contextlib.asynccontextmanager
    async def forward_local_port(
        self,
        remote_host: str = "127.0.0.1",
        remote_port: int = 80,
        local_host: str = "127.0.0.1",
        local_port: int = 0,
    ) -> AsyncIterator[int]:
        """Пробросить локальный TCP-порт внутрь контейнера через stdio-мост."""
        if not self._connected:
            await self.connect()

        bridge_cmd = (
            f"socat STDIO TCP:{shlex.quote(remote_host)}:{int(remote_port)} "
            f"|| nc {shlex.quote(remote_host)} {int(remote_port)}"
        )
        exec_args = self._build_exec_args(bridge_cmd, interactive=True)

        async def _handle_client(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            proc = await asyncio.create_subprocess_exec(
                *exec_args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )

            async def _c2p() -> None:
                try:
                    while True:
                        data = await reader.read(4096)
                        if not data or proc.stdin is None:
                            break
                        proc.stdin.write(data)
                        await proc.stdin.drain()
                finally:
                    if proc.stdin is not None:
                        with contextlib.suppress(Exception):
                            proc.stdin.close()

            async def _p2c() -> None:
                try:
                    while proc.stdout is not None:
                        data = await proc.stdout.read(4096)
                        if not data:
                            break
                        writer.write(data)
                        await writer.drain()
                finally:
                    with contextlib.suppress(Exception):
                        writer.close()

            await asyncio.gather(_c2p(), _p2c(), return_exceptions=True)
            with contextlib.suppress(ProcessLookupError, OSError):
                proc.terminate()

        server = await asyncio.start_server(_handle_client, host=local_host, port=local_port)
        self._tunnel_servers.append(server)
        try:
            sockets = server.sockets or []
            bound_port = int(sockets[0].getsockname()[1]) if sockets else local_port
            yield bound_port
        finally:
            if server in self._tunnel_servers:
                self._tunnel_servers.remove(server)
            server.close()
            await server.wait_closed()


class PodmanTransport(DockerTransport):
    """Алиас-транспорт ``podman://`` с использованием CLI ``podman`` по умолчанию."""

    DEFAULT_RUNTIME: str = "podman"

    @property
    def name(self) -> str:
        """Название транспорта."""
        return "podman"


__all__ = ["DockerTransport", "PodmanTransport"]
