# src/uniconn/transports/_kubectl.py
"""Оркестрационный транспорт Kubernetes (``kubectl://``).

Реализует полный набор протоколов возможностей ISP:
- ``CommandTransport`` (``run``, ``run_bytes``, ``stream``, ``ping``)
- ``FileCapableTransport`` (``read_file``, ``write_file``, ``upload``, ``download``,
  ``exists``, ``mkdir``, ``chmod``, ``stat``, ``listdir``, ``remove_file``)
- ``ShellCapableTransport`` (интерактивный shell через ``open_shell``)
- ``TunnelCapableTransport`` (проброс портов через ``kubectl port-forward``)
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import shlex
import shutil
from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from typing import Any

from ..config.models import ConnectionConfig
from ..exceptions import ConfigurationError, ConnectionError
from ._container_base import ContainerExecTransportBase
from ._local import _LocalShellProcess

_PORT_FORWARD_RE = re.compile(
    r"(?:Forwarding from\s+.+:|127\.0\.0\.1:|\[::1\]:)(\d+)\s*->\s*\d+",
    re.IGNORECASE,
)


async def _wait_for_local_port_ready(
    local_host: str,
    port: int,
    proc: asyncio.subprocess.Process,
) -> None:
    """Дождаться готовности локального TCP-порта port-forward (неблокирующая проверка)."""
    if port <= 0:
        return
    probe_host = "127.0.0.1" if local_host in ("0.0.0.0", "") else local_host
    for _ in range(3):
        if proc.returncode is not None and proc.returncode != 0:
            raise ConnectionError(
                f"kubectl port-forward exited prematurely with code {proc.returncode}"
            )
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(probe_host, port),
                timeout=0.05,
            )
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            return
        except Exception:
            await asyncio.sleep(0.01)


class KubectlTransport(ContainerExecTransportBase):
    """Транспорт выполнения команд, работы с файлами, PTY и port-forward для подов Kubernetes."""

    _cli_label: str = "Kubernetes CLI"
    _target_noun: str = "pod"

    def __init__(self, config: ConnectionConfig) -> None:
        super().__init__(config)
        self._port_forward_procs: list[asyncio.subprocess.Process] = []

    @property
    def name(self) -> str:
        """Название транспорта."""
        return "kubectl"

    @property
    def kubectl_bin(self) -> str:
        """Имя или путь к исполняемому файлу ``kubectl``."""
        return str(self.config.options.get("kubectl_bin", "kubectl"))

    @property
    def pod(self) -> str:
        """Имя целевого пода Kubernetes."""
        if not self.config.host:
            raise ConfigurationError("kubectl:// URI requires a pod name")
        return self.config.host

    @property
    def _target_host(self) -> str:
        return self.pod

    @property
    def namespace(self) -> str | None:
        """Целевой namespace пода (если указан в URI или опциях)."""
        ns = self.config.options.get("namespace")
        return str(ns) if ns else None

    @property
    def container(self) -> str | None:
        """Целевой контейнер внутри пода (если указан ``?container=...``)."""
        ctr = self.config.options.get("container")
        return str(ctr) if ctr else None

    def _base_cli_args(self) -> list[str]:
        """Сформировать базовые глобальные флаги ``kubectl`` (``--kubeconfig``, ``--context``, ``-n``)."""
        args = [self.kubectl_bin]
        kubeconfig = self.config.options.get("kubeconfig")
        if kubeconfig:
            args.extend(["--kubeconfig", str(kubeconfig)])
        context = self.config.options.get("context")
        if context:
            args.extend(["--context", str(context)])
        if self.namespace:
            args.extend(["-n", self.namespace])
        return args

    def _wrap_command_with_context(
        self,
        command: str,
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
    ) -> str:
        """Обернуть команду в ``export ...`` и ``cd ...``, так как ``kubectl exec`` не имеет флага ``-w``."""
        prefixes: list[str] = []
        workdir = cwd or self.config.options.get("workdir")
        if workdir:
            prefixes.append(f"cd {shlex.quote(str(workdir))}")
        if env:
            exports = " ".join(f"{k}={shlex.quote(str(v))}" for k, v in env.items())
            prefixes.append(f"export {exports}")
        if not prefixes:
            return command
        return " && ".join([*prefixes, command])

    def _build_exec_args(
        self,
        command: str,
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        interactive: bool = True,
        tty: bool = False,
    ) -> list[str]:
        """Сформировать аргументы команды ``kubectl exec``."""
        args = [*self._base_cli_args(), "exec"]
        if interactive:
            args.append("-i")
        if tty:
            args.append("-t")
        if self.container:
            args.extend(["-c", self.container])

        shell = str(self.config.options.get("shell", "/bin/sh"))
        wrapped_cmd = self._wrap_command_with_context(command, cwd=cwd, env=env)
        args.extend([self.pod, "--", shell, "-c", wrapped_cmd])
        return args

    async def connect(self) -> None:
        """Проверить наличие ``kubectl`` и статус ``Running`` у целевого пода."""
        pod = self.pod
        if shutil.which(self.kubectl_bin) is None:
            raise ConnectionError(
                f"Kubernetes CLI {self.kubectl_bin!r} not found in PATH",
                host=pod,
            )

        get_args = [
            *self._base_cli_args(),
            "get",
            "pod",
            pod,
            "-o",
            "jsonpath={.status.phase}",
        ]
        exit_code, stdout, stderr, _ = await self._run_host_cli(
            get_args,
            timeout=self.config.timeout,
        )
        phase = stdout.decode("utf-8", errors="replace").strip().strip("'\"")
        if exit_code != 0 or phase.lower() != "running":
            err_msg = stderr.decode("utf-8", errors="replace").strip() or f"phase={phase!r}"
            raise ConnectionError(
                f"Pod {pod!r} is not Running or inaccessible via kubectl: {err_msg}",
                host=pod,
            )
        self._connected = True

    async def disconnect(self) -> None:
        """Закрыть активные shell-сессии и процессы ``kubectl port-forward``."""
        await self._close_shell_procs()
        while self._port_forward_procs:
            pf_proc = self._port_forward_procs.pop()
            if pf_proc.returncode is None:
                with contextlib.suppress(ProcessLookupError, OSError):
                    pf_proc.terminate()
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(pf_proc.wait(), timeout=1.0)
        self._connected = False

    def _cp_pod_target(self, remote_path: str) -> str:
        """Сформировать спецификатор ``[namespace/]pod:path`` для ``kubectl cp``."""
        clean_path = remote_path.lstrip("/") if remote_path.startswith("./") else remote_path
        if self.namespace:
            return f"{self.namespace}/{self.pod}:{clean_path}"
        return f"{self.pod}:{clean_path}"

    async def upload(
        self,
        local_path: str,
        remote_path: str,
        **kwargs: Any,
    ) -> None:
        """Скопировать локальный файл или директорию в под через ``kubectl cp``."""
        progress_cb = kwargs.get("progress_callback")
        total_bytes = self._compute_local_size(local_path) if callable(progress_cb) else 0
        if callable(progress_cb):
            progress_cb(0, total_bytes)
        parent = str(Path(remote_path).parent)
        if parent and parent not in (".", "/"):
            await self.mkdir(parent, parents=True, exist_ok=True)
        cp_args = [*self._base_cli_args(), "cp"]
        if self.container:
            cp_args.extend(["-c", self.container])
        cp_args.extend([str(local_path), self._cp_pod_target(remote_path)])
        exit_code, _, stderr_b, _ = await self._run_host_cli(
            cp_args,
            timeout=self.config.timeout,
        )
        if exit_code != 0:
            err = stderr_b.decode("utf-8", errors="replace").strip()
            raise ConnectionError(
                f"kubectl upload failed from {local_path} to {remote_path}: {err}",
                host=self.pod,
            )
        if callable(progress_cb):
            progress_cb(total_bytes, total_bytes)

    async def download(
        self,
        remote_path: str,
        local_path: str,
        **kwargs: Any,
    ) -> None:
        """Скопировать файл или директорию из пода на локальный хост через ``kubectl cp``."""
        progress_cb = kwargs.get("progress_callback")
        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        cp_args = [*self._base_cli_args(), "cp"]
        if self.container:
            cp_args.extend(["-c", self.container])
        cp_args.extend([self._cp_pod_target(remote_path), str(local_path)])
        exit_code, _, stderr_b, _ = await self._run_host_cli(
            cp_args,
            timeout=self.config.timeout,
        )
        if exit_code != 0:
            err = stderr_b.decode("utf-8", errors="replace").strip()
            raise ConnectionError(
                f"kubectl download failed from {remote_path} to {local_path}: {err}",
                host=self.pod,
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
        """Открыть интерактивную stateful shell-сессию внутри пода."""
        if not self._connected:
            raise ConnectionError(
                "kubectl transport is not connected. Call connect() first",
                host=self.config.host,
            )

        shell_bin = str(kwargs.pop("shell", self.config.options.get("shell", "/bin/sh")))
        args = [*self._base_cli_args(), "exec", "-i"]
        if self.container:
            args.extend(["-c", self.container])
        args.extend(
            [
                self.pod,
                "--",
                "env",
                f"TERM={term_type}",
                f"COLUMNS={term_size[0]}",
                f"LINES={term_size[1]}",
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
        """Открыть локальный проброс порта к поду через ``kubectl port-forward``."""
        _ = remote_host
        if not self._connected:
            await self.connect()

        port_spec = f"{local_port}:{remote_port}" if local_port > 0 else f":{remote_port}"
        pf_args = [
            *self._base_cli_args(),
            "port-forward",
            "--address",
            local_host,
            f"pod/{self.pod}",
            port_spec,
        ]
        proc = await asyncio.create_subprocess_exec(
            *pf_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        self._port_forward_procs.append(proc)
        bound_port = local_port
        try:
            if proc.stdout is not None:
                line_bytes = await asyncio.wait_for(
                    proc.stdout.readline(),
                    timeout=self.config.timeout,
                )
                line_str = line_bytes.decode("utf-8", errors="replace").strip()
                m = _PORT_FORWARD_RE.search(line_str)
                if m:
                    bound_port = int(m.group(1))
                elif proc.returncode is not None and proc.returncode != 0:
                    raise ConnectionError(
                        f"kubectl port-forward failed for pod {self.pod!r}: {line_str}",
                        host=self.pod,
                    )
            await _wait_for_local_port_ready(local_host, bound_port, proc)
            yield bound_port
        finally:
            if proc in self._port_forward_procs:
                self._port_forward_procs.remove(proc)
            if proc.returncode is None:
                with contextlib.suppress(ProcessLookupError, OSError):
                    proc.terminate()
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(proc.wait(), timeout=1.0)
            transport = getattr(proc, "_transport", None)
            if transport is not None:
                with contextlib.suppress(Exception):
                    transport.close()


__all__ = ["KubectlTransport"]
