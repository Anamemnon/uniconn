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
import builtins
import contextlib
import os
import re
import shlex
import shutil
import time
from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from typing import Any

from ..config.models import ConnectionConfig
from ..exceptions import ConfigurationError, ConnectionError, ExecutionError, TimeoutError
from ..result import Result
from ._docker import _build_stat_fallback_command, _parse_stat_output
from ._local import _LocalShellProcess
from .base import BaseTransport, FileStat

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


class KubectlTransport(BaseTransport):
    """Транспорт выполнения команд, работы с файлами, PTY и port-forward для подов Kubernetes."""

    def __init__(self, config: ConnectionConfig) -> None:
        super().__init__(config)
        self._shell_procs: list[_LocalShellProcess] = []
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

    async def _run_host_cli(
        self,
        args: list[str],
        *,
        stdin_bytes: bytes | None = None,
        timeout: float | None = None,
    ) -> tuple[int, bytes, bytes, float]:
        """Запустить процесс ``kubectl`` и вернуть ``(exit_code, stdout, stderr, duration)``."""
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
                f"Kubernetes CLI {args[0]!r} not found in PATH",
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
                f"kubectl command timed out after {timeout}s",
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
        while self._shell_procs:
            proc = self._shell_procs.pop()
            with contextlib.suppress(Exception):
                proc.terminate()
            with contextlib.suppress(Exception):
                await proc.wait_closed()
        while self._port_forward_procs:
            pf_proc = self._port_forward_procs.pop()
            if pf_proc.returncode is None:
                with contextlib.suppress(ProcessLookupError, OSError):
                    pf_proc.terminate()
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(pf_proc.wait(), timeout=1.0)
        self._connected = False

    async def _exec_raw(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> tuple[int, bytes, bytes, float]:
        """Выполнить команду внутри пода и вернуть сырые байты."""
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
                f"kubectl command timed out after {eff_timeout}s",
                command=command,
                host=self.pod,
            ) from exc

    async def run(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> Result:
        """Выполнить команду в поде и вернуть ``Result``."""
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
                f"Command failed in pod {self.pod!r} with exit code {exit_code}",
                command=command,
                exit_code=exit_code,
                stdout=stdout_str,
                stderr=stderr_str,
                host=self.pod,
            )
        return Result(
            exit_code=exit_code,
            stdout=stdout_str,
            stderr=stderr_str,
            duration=duration,
            command=command,
            host=self.pod,
        )

    async def run_bytes(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> bytes:
        """Выполнить команду в поде и вернуть сырой байтовый ``stdout``."""
        raise_on_error = bool(kwargs.pop("raise_on_error", False))
        exit_code, stdout_b, stderr_b, _ = await self._exec_raw(
            command,
            timeout=timeout,
            **kwargs,
        )
        if raise_on_error and exit_code != 0:
            raise ExecutionError(
                f"Command failed in pod {self.pod!r} with exit code {exit_code}",
                command=command,
                exit_code=exit_code,
                stdout=stdout_b.decode("utf-8", errors="replace"),
                stderr=stderr_b.decode("utf-8", errors="replace"),
                host=self.pod,
            )
        return stdout_b

    async def stream(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Построчное потоковое чтение вывода команды из пода."""
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
        """Прочитать файл из пода в память (``bytes``)."""
        q_path = shlex.quote(remote_path)
        exit_code, stdout_b, stderr_b, _ = await self._exec_raw(f"cat -- {q_path}")
        if exit_code != 0:
            err = stderr_b.decode("utf-8", errors="replace").strip()
            raise ConnectionError(
                f"kubectl read_file failed for {remote_path}: {err}",
                host=self.pod,
            )
        return stdout_b

    async def write_file(
        self,
        remote_path: str,
        data: bytes,
        mode: int | None = None,
    ) -> None:
        """Записать байты в файл внутри пода и опционально применить ``chmod``."""
        q_path = shlex.quote(remote_path)
        parent = str(Path(remote_path).parent)
        mkdir_part = f"mkdir -p -- {shlex.quote(parent)} && " if parent and parent != "." else ""
        chmod_part = f" && chmod {oct(mode)[2:]} -- {q_path}" if mode is not None else ""
        cmd = f"{mkdir_part}cat > {q_path}{chmod_part}"
        exit_code, _, stderr_b, _ = await self._exec_raw(cmd, input=data)
        if exit_code != 0:
            err = stderr_b.decode("utf-8", errors="replace").strip()
            raise ConnectionError(
                f"kubectl write_file failed for {remote_path}: {err}",
                host=self.pod,
            )

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
        _ = kwargs
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

    async def download(
        self,
        remote_path: str,
        local_path: str,
        **kwargs: Any,
    ) -> None:
        """Скопировать файл или директорию из пода на локальный хост через ``kubectl cp``."""
        _ = kwargs
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

    async def chmod(self, remote_path: str, mode: int) -> None:
        """Изменить права доступа к файлу внутри пода."""
        res = await self.run(f"chmod {oct(mode)[2:]} -- {shlex.quote(remote_path)}")
        if not res.ok:
            raise ConnectionError(
                f"kubectl chmod failed for {remote_path}: {res.stderr.strip()}",
                host=self.pod,
            )

    async def stat(self, remote_path: str) -> FileStat:
        """Получить метаданные файла или директории внутри пода (с fallback на Python и ls -ldn)."""
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
                    f"kubectl stat parse failed for {remote_path}: {exc}",
                    host=self.pod,
                ) from exc

        err_msg = (res.stderr or fb_res.stderr).strip()
        if res.ok and res.stdout.strip():
            raise ConnectionError(
                f"kubectl stat parse failed for {remote_path}: Unexpected stat output format: {res.stdout!r}",
                host=self.pod,
            )
        raise ConnectionError(
            f"kubectl stat failed for {remote_path}: {err_msg}",
            host=self.pod,
        )

    async def listdir(self, remote_path: str = ".") -> list[str]:
        """Список имён файлов в директории внутри пода."""
        q_path = shlex.quote(remote_path)
        res = await self.run(f"ls -1A -- {q_path}")
        if not res.ok:
            raise ConnectionError(
                f"kubectl listdir failed for {remote_path}: {res.stderr.strip()}",
                host=self.pod,
            )
        return [line for line in res.stdout.splitlines() if line]

    async def remove_file(self, remote_path: str) -> None:
        """Удалить файл внутри пода."""
        q_path = shlex.quote(remote_path)
        res = await self.run(f"rm -f -- {q_path}")
        if not res.ok:
            raise ConnectionError(
                f"kubectl remove_file failed for {remote_path}: {res.stderr.strip()}",
                host=self.pod,
            )

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
