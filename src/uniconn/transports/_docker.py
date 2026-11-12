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
import contextlib
import os
import shlex
import shutil
from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from typing import Any

from ..config.models import ConnectionConfig
from ..exceptions import ConfigurationError, ConnectionError
from ._container_base import (
    ContainerExecTransportBase,
    _build_stat_fallback_command,
    _parse_ls_stat_output,
    _parse_stat_output,
    _symbolic_mode_to_int,
)
from ._local import _LocalShellProcess


class DockerTransport(ContainerExecTransportBase):
    """Транспорт выполнения команд, файловых операций и PTY внутри контейнеров Docker/Podman."""

    DEFAULT_RUNTIME: str = "docker"
    _cli_label: str = "Container runtime CLI"
    _target_noun: str = "container"

    def __init__(self, config: ConnectionConfig) -> None:
        super().__init__(config)
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

    @property
    def _target_host(self) -> str:
        return self.container

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
        await self._close_shell_procs()
        while self._tunnel_servers:
            srv = self._tunnel_servers.pop()
            with contextlib.suppress(Exception):
                srv.close()
                await srv.wait_closed()
        self._connected = False

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


__all__ = [
    "DockerTransport",
    "PodmanTransport",
    "_build_stat_fallback_command",
    "_parse_ls_stat_output",
    "_parse_stat_output",
    "_symbolic_mode_to_int",
]
