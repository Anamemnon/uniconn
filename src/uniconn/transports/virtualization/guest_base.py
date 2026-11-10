# src/uniconn/transports/virtualization/_base.py
"""Общая база для гостевых транспортов виртуализации (QEMU Guest Agent и Proxmox VE)."""

from __future__ import annotations

import json
import shlex
from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from typing import Any

from ...config.models import ConnectionConfig
from ...exceptions import FileTransferError
from ..base import BaseTransport, FileStat


def parse_qga_network_interfaces(raw_interfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Преобразовать ответ ``guest-network-get-interfaces`` в нормализованные словари интерфейсов."""
    normalized: list[dict[str, Any]] = []
    for item in raw_interfaces:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        mac = str(item.get("hardware-address") or "00:00:00:00:00:00").strip()
        ipv4: list[str] = []
        ipv6: list[str] = []
        for ip_entry in item.get("ip-addresses") or []:
            if not isinstance(ip_entry, dict):
                continue
            addr = str(ip_entry.get("ip-address") or "").strip()
            ip_type = str(ip_entry.get("ip-address-type") or "").lower()
            if not addr:
                continue
            if ip_type == "ipv4" or ("." in addr and ":" not in addr):
                if addr not in ipv4:
                    ipv4.append(addr)
            elif (ip_type == "ipv6" or ":" in addr) and addr not in ipv6:
                ipv6.append(addr)
        state = "UP" if (ipv4 or ipv6 or name == "lo") else "UNKNOWN"
        normalized.append(
            {
                "name": name,
                "mac": mac,
                "ipv4": ipv4,
                "ipv6": ipv6,
                "state": state,
                "mtu": 1500,
            }
        )
    return normalized


class GuestAgentTransportBase(BaseTransport):
    """Базовый класс для транспортов, выполняющих команды и файловые операции через гостевой агент."""

    def __init__(self, config: ConnectionConfig) -> None:
        super().__init__(config)
        opts = config.options
        self.exec_timeout = float(opts.get("exec_timeout", config.timeout or 60.0))
        self.os_type = str(opts.get("os_type", "auto")).lower()
        self._is_windows = self.os_type == "windows"
        self.guest_osinfo: dict[str, Any] = {}

    def _apply_osinfo(self, osinfo: dict[str, Any]) -> None:
        """Обновить кэш ``guest_osinfo`` и выставить флаг ``_is_windows`` при автоопределении."""
        self.guest_osinfo = osinfo
        if self.os_type == "auto":
            os_id = str(osinfo.get("id") or "").lower()
            os_name = str(osinfo.get("name") or "").lower()
            if "mswindows" in os_id or "windows" in os_name:
                self._is_windows = True

    @staticmethod
    def _extract_input_bytes(kwargs: dict[str, Any]) -> bytes | None:
        """Извлечь входные данные ``stdin`` из ``kwargs['input_data']`` или ``kwargs['input']``."""
        raw = kwargs.get("input_data")
        if raw is None:
            raw = kwargs.get("input")
        if raw is None:
            return None
        if isinstance(raw, bytes):
            return raw
        return str(raw).encode("utf-8")

    def _prepare_guest_command(
        self,
        command: str,
        *,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        inject_env_in_shell: bool = False,
    ) -> str:
        """Обернуть команду в переходы ``cd`` и экспорт переменных окружения (для ``conn.cd`` / ``conn.env``)."""
        effective = command
        if self._is_windows:
            prefixes: list[str] = []
            if inject_env_in_shell and env:
                for k, v in env.items():
                    safe_v = str(v).replace('"', '\\"')
                    prefixes.append(f'set "{k}={safe_v}"')
            if cwd:
                safe_cwd = str(cwd).replace('"', '\\"')
                prefixes.append(f'cd /d "{safe_cwd}"')
            if prefixes:
                effective = " && ".join([*prefixes, effective])
            return effective

        posix_prefixes: list[str] = []
        if inject_env_in_shell and env:
            exports = " ".join(f"{k}={shlex.quote(str(v))}" for k, v in env.items())
            posix_prefixes.append(f"export {exports};")
        if cwd:
            posix_prefixes.append(f"cd {shlex.quote(str(cwd))} &&")
        if posix_prefixes:
            effective = f"{' '.join(posix_prefixes)} {effective}"
        return effective

    async def stream(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Потоковое чтение вывода команды поверх гостевого агента."""
        res = await self.run(command, timeout=timeout, **kwargs)
        for line in res.stdout.splitlines(keepends=True):
            yield line

    async def upload(
        self,
        local_path: str,
        remote_path: str,
        **kwargs: Any,
    ) -> None:
        """Загрузить локальный файл в гостевую ВМ."""
        _ = kwargs
        src = Path(local_path)
        if not src.is_file():
            raise FileTransferError(f"Local file not found: {local_path}", host=self.config.host)
        await self.write_file(remote_path, src.read_bytes())

    async def download(
        self,
        remote_path: str,
        local_path: str,
        **kwargs: Any,
    ) -> None:
        """Скачать файл из гостевой ВМ на локальный диск."""
        _ = kwargs
        data = await self.read_file(remote_path)
        dst = Path(local_path)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(data)

    async def chmod(self, remote_path: str, mode: int) -> None:
        """Изменить права доступа к файлу в гостевой ВМ."""
        if self._is_windows:
            return
        oct_mode = oct(mode)[2:]
        res = await self.run(f"chmod {oct_mode} {shlex.quote(remote_path)}")
        if not res.ok:
            raise FileTransferError(
                f"chmod failed on {remote_path!r}: {res.stderr or res.stdout}",
                host=self.config.host,
            )

    async def stat(self, remote_path: str) -> FileStat:
        """Получить метаданные файла или директории в гостевой ВМ (POSIX и Windows)."""
        if self._is_windows:
            ps_path = "'" + remote_path.replace("'", "''") + "'"
            ps_cmd = (
                f'powershell -NoProfile -NonInteractive -Command "'
                f"$i = Get-Item -LiteralPath {ps_path} -Force -ErrorAction Stop; "
                f"$isDir = [bool]$i.PSIsContainer; "
                f"$sz = if ($isDir) {{ 0 }} else {{ [int64]$i.Length }}; "
                f"$mt = [int64]([DateTimeOffset]$i.LastWriteTimeUtc).ToUnixTimeSeconds(); "
                f'Write-Output \\"$sz|$mt|$isDir\\""'
            )
            res = await self.run(ps_cmd)
            if not res.ok or not res.stdout.strip():
                raise FileNotFoundError(f"Remote path does not exist: {remote_path}")
            parts = res.stdout.strip().splitlines()[0].split("|")
            if len(parts) < 3:
                raise FileTransferError(f"Unexpected Windows stat output for {remote_path!r}: {res.stdout!r}")
            size = int(parts[0]) if parts[0].strip().isdigit() else 0
            mtime = float(parts[1]) if parts[1].strip().lstrip("-").isdigit() else None
            is_dir = parts[2].strip().lower() == "true"
            return FileStat(
                size=size,
                uid=None,
                gid=None,
                permissions="0755" if is_dir else "0644",
                mode=0o755 if is_dir else 0o644,
                mtime=mtime,
                is_file=not is_dir,
                is_dir=is_dir,
                is_symlink=False,
            )

        q_path = shlex.quote(remote_path)
        res = await self.run(f"stat -c '%s|%u|%g|%a|%Y|%F' {q_path} 2>/dev/null")
        if not res.ok or not res.stdout.strip():
            raise FileNotFoundError(f"Remote path does not exist: {remote_path}")
        parts = res.stdout.strip().splitlines()[0].split("|")
        if len(parts) < 6:
            raise FileTransferError(f"Unexpected stat output for {remote_path!r}: {res.stdout!r}")
        size = int(parts[0]) if parts[0].isdigit() else 0
        uid = int(parts[1]) if parts[1].isdigit() else None
        gid = int(parts[2]) if parts[2].isdigit() else None
        mode_oct = int(parts[3], 8) if parts[3] else None
        mtime = float(parts[4]) if parts[4].isdigit() else None
        ftype = parts[5].lower()
        return FileStat(
            size=size,
            uid=uid,
            gid=gid,
            permissions=parts[3],
            mode=mode_oct,
            mtime=mtime,
            is_file="regular" in ftype,
            is_dir="directory" in ftype,
            is_symlink="symbolic link" in ftype,
        )

    async def listdir(self, remote_path: str = ".") -> list[str]:
        """Получить список элементов директории в гостевой ВМ (POSIX и Windows)."""
        if self._is_windows:
            ps_path = "'" + remote_path.replace("'", "''") + "'"
            ps_cmd = (
                f'powershell -NoProfile -NonInteractive -Command "'
                f'Get-ChildItem -LiteralPath {ps_path} -Force -Name -ErrorAction Stop"'
            )
            res = await self.run(ps_cmd)
            if not res.ok:
                raise FileTransferError(
                    f"listdir failed on {remote_path!r}: {res.stderr or res.stdout}",
                    host=self.config.host,
                )
            return [line.strip() for line in res.stdout.splitlines() if line.strip()]

        res = await self.run(f"ls -1A {shlex.quote(remote_path)}")
        if not res.ok:
            raise FileTransferError(
                f"listdir failed on {remote_path!r}: {res.stderr or res.stdout}",
                host=self.config.host,
            )
        return [line.strip() for line in res.stdout.splitlines() if line.strip()]

    async def remove_file(self, remote_path: str) -> None:
        """Удалить файл в гостевой ВМ (POSIX и Windows)."""
        if self._is_windows:
            ps_path = "'" + remote_path.replace("'", "''") + "'"
            ps_cmd = (
                f'powershell -NoProfile -NonInteractive -Command "'
                f'Remove-Item -LiteralPath {ps_path} -Force -ErrorAction SilentlyContinue"'
            )
            res = await self.run(ps_cmd)
        else:
            res = await self.run(f"rm -f {shlex.quote(remote_path)}")
        if not res.ok:
            raise FileTransferError(
                f"remove_file failed on {remote_path!r}: {res.stderr or res.stdout}",
                host=self.config.host,
            )

    async def exists(self, remote_path: str) -> bool:
        """Проверить существование файла или директории в гостевой ВМ (POSIX и Windows)."""
        if self._is_windows:
            ps_path = "'" + remote_path.replace("'", "''") + "'"
            ps_cmd = (
                f'powershell -NoProfile -NonInteractive -Command "'
                f'if (Test-Path -LiteralPath {ps_path}) {{ exit 0 }} else {{ exit 1 }}"'
            )
            res = await self.run(ps_cmd)
            return res.ok
        return await super().exists(remote_path)

    async def mkdir(
        self,
        remote_path: str,
        parents: bool = True,
        exist_ok: bool = True,
        mode: int | None = None,
    ) -> None:
        """Создать директорию в гостевой ВМ (POSIX и Windows)."""
        if self._is_windows:
            _ = (parents, exist_ok, mode)
            ps_path = "'" + remote_path.replace("'", "''") + "'"
            ps_cmd = (
                f'powershell -NoProfile -NonInteractive -Command "'
                f'New-Item -ItemType Directory -Path {ps_path} -Force | Out-Null"'
            )
            res = await self.run(ps_cmd)
            res.raise_for_status()
            return
        await super().mkdir(remote_path, parents=parents, exist_ok=exist_ok, mode=mode)

    @staticmethod
    def _json_result(command: str, payload: Any, duration: float, host: str) -> Any:
        """Сформировать ``Result`` с JSON-сериализованным ``stdout``."""
        from ...result import Result

        return Result(
            command=command,
            stdout=json.dumps(payload, ensure_ascii=False),
            stderr="",
            exit_code=0,
            duration=duration,
            host=host,
        )


__all__ = ["GuestAgentTransportBase", "parse_qga_network_interfaces"]
