# src/uniconn/transports/virtualization/qga.py
"""Транспорт QEMU Guest Agent (qga://, qemu-ga://) поверх virtio-serial и libvirt."""

from __future__ import annotations

import contextlib
import time
from typing import Any

from ...config.models import ConnectionConfig
from ...exceptions import ConnectionError
from ...result import Result
from .guest_base import GuestAgentTransportBase, parse_qga_network_interfaces
from .qga_protocol import (
    LocalUnixSocketChannel,
    QgaChannelProtocol,
    QgaProtocolClient,
    SshUnixSocketChannel,
    VirshCommandChannel,
)


class QgaTransport(GuestAgentTransportBase):
    """Out-of-band транспорт QEMU Guest Agent (``qga://``, ``qemu-ga://``).

    Поддерживает три бэкенда канала:
    - локальный UNIX-сокет (``qga:///var/lib/libvirt/qemu/.../org.qemu.guest_agent.0``);
    - удалённый UNIX-сокет через SSH-туннель (``qga://root@kvm-host/vm-name?socket=...``);
    - обёртка поверх CLI ``virsh qemu-agent-command`` (``qga://root@kvm-host/vm-name?backend=virsh``).
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
        self.backend = str(opts.get("backend", "socket")).lower()
        self.socket_path: str | None = str(opts["socket"]) if "socket" in opts else (
            config.host if (config.host and config.host.startswith("/")) else None
        )
        self.vm_name: str | None = str(opts.get("vm") or opts.get("domain") or "") or None
        self.libvirt_uri = str(opts.get("libvirt_uri", "qemu:///system"))
        self.poll_interval = float(opts.get("poll_interval", 0.05))
        self._custom_channel = channel
        self.client: QgaProtocolClient | None = None

    @property
    def name(self) -> str:
        """Название транспорта (``qga`` или ``qemu-ga``)."""
        return self._transport_scheme

    def _build_channel(self) -> QgaChannelProtocol:
        """Создать подходящий канал связи на основе конфигурации."""
        if self._custom_channel is not None:
            return self._custom_channel

        password_str = self.config.password.get_secret_value() if self.config.password else None
        passphrase_str = self.config.passphrase.get_secret_value() if self.config.passphrase else None
        known_hosts = self.config.options.get("known_hosts")

        if self.backend == "virsh":
            domain = self.vm_name or (self.config.host if self.config.host not in ("localhost", "127.0.0.1") else "")
            ssh_host = (
                self.config.host
                if (self.config.host and self.config.host not in ("localhost", "127.0.0.1") and self.vm_name)
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

        is_remote_ssh = bool(
            self.config.host
            and not self.config.host.startswith("/")
            and self.config.host not in ("localhost", "127.0.0.1")
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
        return await self.client.ping(timeout=timeout or 5.0)

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
