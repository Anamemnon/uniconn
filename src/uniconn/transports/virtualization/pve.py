# src/uniconn/transports/virtualization/pve.py
"""Транспорт Proxmox VE REST API (pve://) для out-of-band выполнения команд и управления ВМ."""

from __future__ import annotations

import base64
import contextlib
import shlex
import time
from typing import Any

from ...config.models import ConnectionConfig
from ...exceptions import ConfigurationError, ConnectionError, ExecutionError, FileTransferError
from ...result import Result
from .guest_base import GuestAgentTransportBase, parse_qga_network_interfaces
from .pve_client import PveHttpClient, get_pve_niquests_module, niquests


class PveTransport(GuestAgentTransportBase):
    """Out-of-band транспорт гипервизора Proxmox VE (``pve://``).

    Обеспечивает:
    - выполнение команд и работу с файлами внутри гостевой ВМ через ``/agent/exec``,
      ``/agent/file-read`` (GET) и ``/agent/file-write`` (POST с ``encode=1``);
    - нативное управление питанием ВМ (``pve power status|start|stop|shutdown|reboot|reset|suspend|resume``);
    - управление снапшотами ВМ (``pve snapshot list|create|rollback|delete``);
    - сбор нативных фактов через QGA RPC и статус ВМ Proxmox.
    """

    def __init__(
        self,
        config: ConnectionConfig,
        *,
        http_client: PveHttpClient | None = None,
    ) -> None:
        super().__init__(config)
        if http_client is None and get_pve_niquests_module() is None:
            raise ImportError(
                "niquests is required for PveTransport. Install with: pip install uniconn[bmc]"
            )

        opts = config.options
        vmid = opts.get("vmid")
        if vmid is None:
            raise ConfigurationError(
                "Proxmox VE URI must include VMID in path (pve://host:8006/105) or ?vmid=105"
            )
        self.vmid: int | str = vmid
        self.node: str | None = str(opts["node"]) if opts.get("node") else None
        self.realm = str(opts.get("realm", "pam"))
        self.token_id: str | None = str(opts["token_id"]) if "token_id" in opts else None
        raw_secret = opts.get("secret") or opts.get("token_secret")
        if raw_secret is not None and hasattr(raw_secret, "get_secret_value"):
            raw_secret = raw_secret.get_secret_value()
        password_str = config.password.get_secret_value() if config.password else None
        self.token_secret: str | None = str(raw_secret) if raw_secret is not None else (
            password_str if self.token_id else None
        )
        self.password: str | None = None if self.token_id else password_str

        scheme = str(opts.get("scheme", "https")).lower()
        port = config.port or 8006
        host = config.host or "localhost"
        self.base_url = f"{scheme}://{host}:{port}"

        verify_opt = opts.get("verify_ssl", opts.get("verify", True))
        self.verify_ssl: bool | str = verify_opt if isinstance(verify_opt, (bool, str)) else True
        self.poll_interval = float(opts.get("poll_interval", 0.2))
        self._custom_http_client = http_client
        self.client: PveHttpClient | None = None

    @property
    def name(self) -> str:
        """Название транспорта (``pve``)."""
        return "pve"

    def _build_http_client(self) -> PveHttpClient:
        """Создать экземпляр ``PveHttpClient``."""
        if self._custom_http_client is not None:
            return self._custom_http_client
        return PveHttpClient(
            base_url=self.base_url,
            vmid=self.vmid,
            node=self.node,
            username=self.config.username or "root",
            realm=self.realm,
            password=self.password,
            token_id=self.token_id,
            token_secret=self.token_secret,
            verify=self.verify_ssl,
            default_timeout=self.config.timeout,
            poll_interval=self.poll_interval,
        )

    async def connect(self) -> None:
        """Установить сессию с Proxmox VE API, разрешить имя ноды и определить ОС гостя."""
        if self._connected and self.client is not None:
            return
        self.client = self._build_http_client()
        await self.client.connect(timeout=self.config.timeout)
        self.node = self.client.node
        self._connected = True

        if self.os_type == "auto":
            with contextlib.suppress(Exception):
                osinfo = await self.client.agent_get("get-osinfo", timeout=5.0)
                if isinstance(osinfo, dict):
                    self._apply_osinfo(osinfo)

    async def disconnect(self) -> None:
        """Закрыть HTTP-сессию Proxmox VE."""
        self._connected = False
        client = self.client
        self.client = None
        if client is not None:
            await client.close()

    async def ping(self, timeout: float | None = None) -> bool:
        """Проверить доступность QEMU Guest Agent через ``POST /agent/ping``."""
        if not self._connected or self.client is None:
            return False
        return await self.client.agent_ping(timeout=timeout or 5.0)

    def _resolve_shell_args(self, command: str) -> list[str]:
        """Сформировать массив аргументов командной оболочки для ``POST /agent/exec``."""
        if self._is_windows:
            return ["cmd.exe", "/d", "/s", "/c", command]
        return ["/bin/sh", "-c", command]

    async def _handle_hypervisor_command(
        self,
        tokens: list[str],
        raw_command: str,
        timeout: float,
    ) -> Result:
        """Обработать управляющие команды гипервизора ``pve power ...``, ``pve snapshot ...``, ``pve status``."""
        assert self.client is not None
        started = time.perf_counter()
        host_label = self.config.host or "pve"
        sub = tokens[1].lower() if len(tokens) > 1 else "status"

        if sub == "status" or (sub == "power" and (len(tokens) < 3 or tokens[2].lower() == "status")):
            st_data = await self.client.vm_status(timeout=timeout)
            return self._json_result(raw_command, st_data, time.perf_counter() - started, host_label)

        if sub == "power" and len(tokens) >= 3:
            action = tokens[2].lower()
            res_data = await self.client.vm_power(action, timeout=timeout)
            return self._json_result(raw_command, res_data, time.perf_counter() - started, host_label)

        if sub == "snapshot":
            snap_action = tokens[2].lower() if len(tokens) >= 3 else "list"
            if snap_action == "list":
                snaps = await self.client.list_snapshots(timeout=timeout)
                return self._json_result(raw_command, snaps, time.perf_counter() - started, host_label)
            if len(tokens) < 4:
                raise ExecutionError(
                    f"Snapshot name is required for 'pve snapshot {snap_action}'",
                    command=raw_command,
                )
            snap_name = tokens[3]
            if snap_action == "create":
                desc = ""
                vmstate = "--vmstate" in tokens
                if "--description" in tokens:
                    idx = tokens.index("--description")
                    if idx + 1 < len(tokens):
                        desc = tokens[idx + 1]
                snap_res = await self.client.create_snapshot(
                    snap_name,
                    description=desc,
                    vmstate=vmstate,
                    timeout=timeout,
                )
            elif snap_action == "rollback":
                snap_res = await self.client.rollback_snapshot(snap_name, timeout=timeout)
            elif snap_action in ("delete", "remove", "rm"):
                snap_res = await self.client.delete_snapshot(snap_name, timeout=timeout)
            else:
                raise ExecutionError(f"Unsupported snapshot action: {snap_action!r}", command=raw_command)

            return self._json_result(raw_command, snap_res, time.perf_counter() - started, host_label)

        raise ExecutionError(
            f"Unknown PVE hypervisor command: {raw_command!r}. "
            "Supported: 'pve status', 'pve power <status|start|stop|shutdown|reboot|reset|suspend|resume>', "
            "'pve snapshot <list|create|rollback|delete>'",
            command=raw_command,
        )

    async def run(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> Result:
        """Выполнить команду внутри гостевой ВМ через QGA либо команду гипервизора ``pve ...``."""
        if not self._connected or self.client is None:
            raise ConnectionError("PVE transport is not connected", host=self.config.host)

        eff_timeout = timeout if timeout is not None else self.exec_timeout
        stripped = command.strip()
        if stripped == "pve" or stripped.startswith("pve "):
            tokens = shlex.split(stripped)
            if tokens and tokens[0] == "pve":
                return await self._handle_hypervisor_command(tokens, command, eff_timeout)

        input_data = self._extract_input_bytes(kwargs)
        cwd: str | None = kwargs.get("cwd")
        env_dict: dict[str, str] | None = kwargs.get("env")
        effective_cmd = self._prepare_guest_command(
            command,
            cwd=cwd,
            env=env_dict,
            inject_env_in_shell=True,
        )
        cmd_args = self._resolve_shell_args(effective_cmd)
        started = time.perf_counter()
        exit_code, stdout, stderr = await self.client.agent_exec(
            cmd_args,
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
            host=self.config.host or "pve",
        )

    async def _read_file_via_exec_fallback(self, remote_path: str) -> bytes:
        """Прочитать большой или усечённый файл через ``agent_exec`` (base64)."""
        if self._is_windows:
            ps_path = "'" + remote_path.replace("'", "''") + "'"
            cmd = (
                f'powershell -NoProfile -NonInteractive -Command "'
                f'[Convert]::ToBase64String([IO.File]::ReadAllBytes({ps_path}))"'
            )
        else:
            cmd = f"base64 {shlex.quote(remote_path)}"
        res = await self.run(cmd, timeout=self.exec_timeout)
        if not res.ok:
            raise FileTransferError(
                f"Fallback base64 file read failed for {remote_path!r}: {res.stderr or res.stdout}",
                host=self.config.host,
            )
        compact = "".join(res.stdout.split())
        try:
            return base64.b64decode(compact)
        except Exception as exc:
            raise FileTransferError(f"Invalid base64 output reading {remote_path!r}: {exc}") from exc

    async def read_file(self, remote_path: str) -> bytes:
        """Прочитать файл из гостевой ВМ через ``GET /agent/file-read`` (с fallback при ``truncated=1``)."""
        if not self._connected or self.client is None:
            raise ConnectionError("PVE transport is not connected", host=self.config.host)
        try:
            return await self.client.agent_file_read(remote_path, timeout=self.exec_timeout)
        except FileTransferError as exc:
            if "truncated" in str(exc).lower():
                return await self._read_file_via_exec_fallback(remote_path)
            raise

    async def write_file(
        self,
        remote_path: str,
        data: bytes,
        mode: int | None = None,
    ) -> None:
        """Записать файл в гостевую ВМ через ``POST /agent/file-write`` с ``encode=1``."""
        if not self._connected or self.client is None:
            raise ConnectionError("PVE transport is not connected", host=self.config.host)
        await self.client.agent_file_write(remote_path, data, timeout=self.exec_timeout)
        if mode is not None and not self._is_windows:
            await self.chmod(remote_path, mode)

    async def vm_power(self, action: str, *, wait: bool = True, timeout: float = 60.0) -> dict[str, Any]:
        """Управление питанием ВМ на уровне гипервизора Proxmox VE."""
        if not self._connected or self.client is None:
            raise ConnectionError("PVE transport is not connected", host=self.config.host)
        return await self.client.vm_power(action, wait=wait, timeout=timeout)

    async def gather_qga_native_facts(self, timeout: float = 5.0) -> dict[str, Any]:
        """Собрать нативные факты через REST-прокси агента Proxmox VE и статус ВМ."""
        if not self._connected or self.client is None:
            return {}
        payload: dict[str, Any] = {"vmid": self.vmid, "node": self.node}
        with contextlib.suppress(Exception):
            osinfo = await self.client.agent_get("get-osinfo", timeout=timeout)
            if isinstance(osinfo, dict):
                payload["osinfo"] = osinfo
        with contextlib.suppress(Exception):
            hn = await self.client.agent_get("get-host-name", timeout=timeout)
            if isinstance(hn, dict) and hn.get("host-name"):
                payload["hostname"] = str(hn["host-name"])
        with contextlib.suppress(Exception):
            raw_ifaces = await self.client.agent_get("network-get-interfaces", timeout=timeout)
            if isinstance(raw_ifaces, list):
                payload["interfaces"] = parse_qga_network_interfaces(raw_ifaces)
                payload["raw_interfaces"] = raw_ifaces
        with contextlib.suppress(Exception):
            fsinfo = await self.client.agent_get("get-fsinfo", timeout=timeout)
            if isinstance(fsinfo, list):
                payload["fsinfo"] = fsinfo
        with contextlib.suppress(Exception):
            vcpus = await self.client.agent_get("get-vcpus", timeout=timeout)
            if isinstance(vcpus, list):
                payload["vcpus"] = vcpus
        with contextlib.suppress(Exception):
            payload["vm_status"] = await self.client.vm_status(timeout=timeout)
        return payload


__all__ = ["PveTransport", "niquests"]
