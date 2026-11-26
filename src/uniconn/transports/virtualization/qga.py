# src/uniconn/transports/virtualization/qga.py
"""Транспорт QEMU Guest Agent (qga://, qemu-ga://) поверх virtio-serial и libvirt."""

from __future__ import annotations

import contextlib
import time
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

from ...config.models import ConnectionConfig
from ...exceptions import ConfigurationError, ConnectionError, FileTransferError
from ...result import Result
from ..base import _iter_local_file_chunks, _save_chunk_stream_to_file
from ..ssh.config_parser import OpenSSHConfigParser
from .guest_base import GuestAgentTransportBase, parse_qga_network_interfaces
from .qga_protocol import (
    LocalUnixSocketChannel,
    NamedPipeQgaChannel,
    QgaChannelProtocol,
    QgaProtocolClient,
    SshUnixSocketChannel,
    TcpQgaChannel,
    VirshCommandChannel,
    is_windows_pipe_path,
)


class QgaTransport(GuestAgentTransportBase):
    r"""Out-of-band транспорт QEMU Guest Agent (``qga://``, ``qemu-ga://``).

    Поддерживает пять бэкендов канала:
    - локальный UNIX-сокет (``qga:///var/lib/libvirt/qemu/.../org.qemu.guest_agent.0``);
    - удалённый UNIX-сокет через SSH-туннель (``qga://root@kvm-host/vm-name?socket=...``);
    - обёртка поверх CLI ``virsh qemu-agent-command`` (``qga://root@kvm-host/vm-name?backend=virsh``);
    - прямой TCP-сокет локального/сетевого QEMU (``qga://127.0.0.1:4444?backend=tcp``);
    - Windows Named Pipe (``qga://?backend=pipe&pipe=\\.\pipe\qga-vm1``).
    """

    def __init__(
        self,
        config: ConnectionConfig,
        *,
        channel: QgaChannelProtocol | None = None,
    ) -> None:
        super().__init__(config)
        opts = config.options
        self._transport_scheme = config.transport if config.transport in ("qga", "qemu-ga") else "qga"
        raw_socket = str(opts["socket"]) if "socket" in opts else (
            config.host if (config.host and config.host.startswith("/")) else None
        )
        raw_pipe = str(opts["pipe"]) if "pipe" in opts else (
            raw_socket if is_windows_pipe_path(raw_socket) else (
                config.host if is_windows_pipe_path(config.host) else None
            )
        )
        self.socket_path: str | None = None if is_windows_pipe_path(raw_socket) else raw_socket
        self.pipe_path: str | None = raw_pipe
        self.vm_name: str | None = str(opts.get("vm") or opts.get("domain") or "") or None
        self.libvirt_uri = str(opts.get("libvirt_uri", "qemu:///system"))
        self.poll_interval = float(opts.get("poll_interval", 0.05))
        self._custom_channel = channel
        self.client: QgaProtocolClient | None = None

        _supported_backends = ("socket", "ssh", "virsh", "tcp", "pipe")
        _local_hosts = ("localhost", "127.0.0.1", "::1")

        if "backend" in opts:
            self.backend = str(opts["backend"]).strip().lower()
            if self.backend not in _supported_backends:
                raise ConfigurationError(
                    f"Unsupported QGA backend {self.backend!r}. "
                    f"Supported: {', '.join(_supported_backends)}"
                )
        elif self.pipe_path:
            self.backend = "pipe"
        elif (
            config.host in _local_hosts
            and config.port is not None
            and not self.socket_path
            and not self.vm_name
        ):
            self.backend = "tcp"
        else:
            self.backend = "socket"

    @property
    def name(self) -> str:
        """Название транспорта (``qga`` или ``qemu-ga``)."""
        return self._transport_scheme

    def _build_channel(self) -> QgaChannelProtocol:
        """Создать подходящий канал связи на основе конфигурации."""
        if self._custom_channel is not None:
            return self._custom_channel

        if self.backend == "tcp":
            host = self.config.host or "127.0.0.1"
            if self.config.port is None:
                raise ConnectionError(
                    "TCP port is required for QGA tcp backend. "
                    "Provide qga://127.0.0.1:4444?backend=tcp"
                )
            return TcpQgaChannel(host=host, port=self.config.port)

        if self.backend == "pipe":
            pipe = self.pipe_path or self.socket_path
            if not pipe:
                raise ConnectionError(
                    "Windows Named Pipe path is required for QGA pipe backend. "
                    r"Provide qga://?backend=pipe&pipe=\\.\pipe\qga-vm1"
                )
            opener = self.config.options.get("_pipe_opener")
            return NamedPipeQgaChannel(pipe, opener=opener)

        password_str = self.config.password.get_secret_value() if self.config.password else None
        passphrase_str = self.config.passphrase.get_secret_value() if self.config.passphrase else None
        known_hosts = OpenSSHConfigParser.resolve_known_hosts(
            self.config.options.get("known_hosts", "strict"),
            host=self.config.host,
        )
        local_hosts = ("localhost", "127.0.0.1", "::1")

        if self.backend == "virsh":
            domain = self.vm_name or (self.config.host if self.config.host not in local_hosts else "")
            ssh_host = (
                self.config.host
                if (self.config.host and self.config.host not in local_hosts and self.vm_name)
                else None
            )
            return VirshCommandChannel(
                domain=domain or "",
                libvirt_uri=self.libvirt_uri,
                ssh_host=ssh_host,
                ssh_port=self.config.port or 22,
                ssh_user=self.config.username,
                ssh_password=password_str,
                ssh_key_file=self.config.key_file,
                known_hosts=known_hosts,
            )

        is_remote_ssh = self.backend == "ssh" or bool(
            self.config.host
            and not self.config.host.startswith("/")
            and self.config.host not in local_hosts
        )
        if is_remote_ssh:
            return SshUnixSocketChannel(
                host=self.config.host or "localhost",
                port=self.config.port or 22,
                username=self.config.username,
                password=password_str,
                key_file=self.config.key_file,
                passphrase=passphrase_str,
                socket_path=self.socket_path,
                vm_name=self.vm_name,
                known_hosts=known_hosts,
            )

        if not self.socket_path:
            raise ConnectionError(
                "QGA local socket path is not specified. "
                "Provide qga:///path/to/socket or ?socket=/path/to/socket"
            )
        return LocalUnixSocketChannel(self.socket_path)

    async def connect(self) -> None:
        """Установить подключение к QEMU Guest Agent и определить тип гостевой ОС."""
        if self._connected and self.client is not None:
            return
        channel = self._build_channel()
        self.client = QgaProtocolClient(channel, poll_interval=self.poll_interval)
        await self.client.connect(timeout=self.config.timeout)
        self._connected = True

        if self.os_type == "auto":
            with contextlib.suppress(Exception):
                osinfo = await self.client.get_osinfo(timeout=5.0)
                if isinstance(osinfo, dict):
                    self._apply_osinfo(osinfo)

    async def disconnect(self) -> None:
        """Закрыть подключение к QEMU Guest Agent."""
        self._connected = False
        client = self.client
        self.client = None
        if client is not None:
            await client.disconnect()

    async def ping(self, timeout: float | None = None) -> bool:
        """Проверить доступность гостевого агента через нативный ``guest-ping``."""
        if not self._connected or self.client is None:
            return False
        return await self.client.ping(
            timeout=timeout if timeout is not None else 5.0
        )

    def _resolve_shell_invocation(self, command: str) -> tuple[str, list[str]]:
        """Обернуть строковую команду в вызов командного интерпретатора гостевой ОС."""
        if self._is_windows:
            return "cmd.exe", ["/d", "/s", "/c", command]
        return "/bin/sh", ["-c", command]

    async def run(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> Result:
        """Выполнить команду внутри гостевой ВМ через ``guest-exec``."""
        if not self._connected or self.client is None:
            raise ConnectionError("QGA transport is not connected", host=self.config.host)

        eff_timeout = timeout if timeout is not None else self.exec_timeout
        input_data = self._extract_input_bytes(kwargs)
        cwd: str | None = kwargs.get("cwd")
        env_dict: dict[str, str] | None = kwargs.get("env")
        env_list = [f"{k}={v}" for k, v in env_dict.items()] if env_dict else None

        effective_cmd = self._prepare_guest_command(
            command,
            cwd=cwd,
            env=env_dict,
            inject_env_in_shell=False,
        )
        bin_path, args = self._resolve_shell_invocation(effective_cmd)
        started = time.perf_counter()
        exit_code, stdout, stderr = await self.client.exec_command(
            bin_path,
            args,
            env=env_list,
            input_data=input_data,
            timeout=eff_timeout,
            is_windows=self._is_windows,
        )
        duration = time.perf_counter() - started
        return Result(
            command=command,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            duration=duration,
            host=self.config.host or "qga",
        )

    async def iter_file_chunks(
        self,
        remote_path: str,
        chunk_size: int = 65536,
    ) -> AsyncIterator[bytes]:
        """Потоково читать файл из гостевой ВМ чанками через ``guest-file-read``."""
        if chunk_size <= 0:
            raise ValueError(f"chunk_size must be positive, got {chunk_size}")
        if not self._connected or self.client is None:
            raise ConnectionError("QGA transport is not connected", host=self.config.host)
        async for chunk in self.client.iter_file_chunks(
            remote_path,
            chunk_size=chunk_size,
            timeout=self.exec_timeout,
        ):
            yield chunk

    async def read_file(self, remote_path: str) -> bytes:
        """Прочитать файл из гостевой ВМ через ``guest-file-read``."""
        if not self._connected or self.client is None:
            raise ConnectionError("QGA transport is not connected", host=self.config.host)
        return await self.client.read_file(remote_path, timeout=self.exec_timeout)

    async def write_file(
        self,
        remote_path: str,
        data: bytes,
        mode: int | None = None,
    ) -> None:
        """Записать файл в гостевую ВМ через ``guest-file-write`` с опциональным ``chmod``."""
        if not self._connected or self.client is None:
            raise ConnectionError("QGA transport is not connected", host=self.config.host)
        await self.client.write_file(remote_path, data, timeout=self.exec_timeout)
        if mode is not None and not self._is_windows:
            await self.chmod(remote_path, mode)

    async def upload(
        self,
        local_path: str,
        remote_path: str,
        **kwargs: Any,
    ) -> None:
        """Потоково загрузить локальный файл в гостевую ВМ без полной буферизации в памяти."""
        if not self._connected or self.client is None:
            raise ConnectionError("QGA transport is not connected", host=self.config.host)
        src = Path(local_path)
        if not src.is_file():
            raise FileTransferError(f"Local file not found: {local_path}", host=self.config.host)

        progress_cb: Callable[[int, int], None] | None = kwargs.get("progress_callback")
        total_size = int(src.stat().st_size)

        await self.client.write_file_chunks(
            remote_path,
            _iter_local_file_chunks(src, self.client.chunk_size),
            timeout=self.exec_timeout,
            total_size=total_size,
            progress_callback=progress_cb,
        )

    async def download(
        self,
        remote_path: str,
        local_path: str,
        **kwargs: Any,
    ) -> None:
        """Потоково скачать файл из гостевой ВМ на локальный диск без полной буферизации."""
        if not self._connected or self.client is None:
            raise ConnectionError("QGA transport is not connected", host=self.config.host)
        progress_cb: Callable[[int, int], None] | None = kwargs.get("progress_callback")
        total_size: int | None = None
        if callable(progress_cb):
            with contextlib.suppress(Exception):
                st = await self.stat(remote_path)
                total_size = int(st.get("size", 0))

        chunk_size = self.client.chunk_size

        async def _qga_chunks_with_total() -> AsyncIterator[tuple[bytes, int | None]]:
            async for chunk in self.iter_file_chunks(remote_path, chunk_size=chunk_size):
                yield chunk, total_size

        await _save_chunk_stream_to_file(
            Path(local_path),
            _qga_chunks_with_total(),
            progress_callback=progress_cb,
            empty_total=total_size if total_size is not None else 0,
        )

    async def gather_qga_native_facts(self, timeout: float = 5.0) -> dict[str, Any]:
        """Собрать нативные факты напрямую через RPC-методы QEMU Guest Agent."""
        if not self._connected or self.client is None:
            return {}
        payload: dict[str, Any] = {}
        with contextlib.suppress(Exception):
            payload["osinfo"] = await self.client.get_osinfo(timeout=timeout)
        with contextlib.suppress(Exception):
            payload["hostname"] = await self.client.get_host_name(timeout=timeout)
        with contextlib.suppress(Exception):
            raw_ifaces = await self.client.get_network_interfaces(timeout=timeout)
            payload["interfaces"] = parse_qga_network_interfaces(raw_ifaces)
            payload["raw_interfaces"] = raw_ifaces
        with contextlib.suppress(Exception):
            payload["fsinfo"] = await self.client.get_fsinfo(timeout=timeout)
        with contextlib.suppress(Exception):
            payload["vcpus"] = await self.client.get_vcpus(timeout=timeout)
        return payload


__all__ = ["QgaTransport", "parse_qga_network_interfaces"]
