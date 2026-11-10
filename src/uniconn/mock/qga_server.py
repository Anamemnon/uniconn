# src/uniconn/mock/qga_server.py
"""Mock-сервер протокола QEMU Guest Agent (UNIX-сокет и in-memory канал) для тестирования."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import shlex
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any, Self

from ..exceptions import ConnectionError, ExecutionError


class MockQgaServer:
    """Легковесный тестовый сервер протокола QEMU Guest Agent (QGA JSON-RPC).

    Поддерживает:
    - запуск реального UNIX domain socket сервера (``asyncio.start_unix_server``);
    - прямое использование в качестве ``QgaChannelProtocol`` без файлового сокета;
    - виртуальную файловую систему в памяти (``files``) для ``guest-file-*``, ``stat``, ``chmod``, ``ls``, ``rm``;
    - настраиваемые ответы команд, сетевые интерфейсы и информацию об ОС.
    """

    def __init__(
        self,
        *,
        socket_path: str | Path | None = None,
        hostname: str = "vm-guest-01",
        osinfo: dict[str, Any] | None = None,
        interfaces: list[dict[str, Any]] | None = None,
        files: dict[str, bytes] | None = None,
        command_handlers: dict[str, tuple[int, str, str] | Callable[[str], tuple[int, str, str]]] | None = None,
        polls_before_exit: int = 1,
    ) -> None:
        self._tmp_dir: tempfile.TemporaryDirectory[str] | None = None
        if socket_path is not None:
            self.socket_path = str(socket_path)
        else:
            self._tmp_dir = tempfile.TemporaryDirectory(prefix="uniconn_qga_")
            self.socket_path = str(Path(self._tmp_dir.name) / "qga.sock")

        self.hostname = hostname
        self.osinfo: dict[str, Any] = osinfo or {
            "id": "ubuntu",
            "name": "Ubuntu",
            "pretty-name": "Ubuntu 24.04 LTS",
            "version-id": "24.04",
            "kernel-release": "6.8.0-45-generic",
            "kernel-version": "#45-Ubuntu SMP PREEMPT_DYNAMIC",
            "machine": "x86_64",
        }
        self.interfaces: list[dict[str, Any]] = interfaces or [
            {
                "name": "lo",
                "hardware-address": "00:00:00:00:00:00",
                "ip-addresses": [
                    {"ip-address-type": "ipv4", "ip-address": "127.0.0.1", "prefix": 8},
                ],
            },
            {
                "name": "eth0",
                "hardware-address": "52:54:00:12:34:56",
                "ip-addresses": [
                    {"ip-address-type": "ipv4", "ip-address": "10.20.30.40", "prefix": 24},
                    {"ip-address-type": "ipv6", "ip-address": "fe80::5054:ff:fe12:3456", "prefix": 64},
                ],
            },
        ]
        self.fsinfo: list[dict[str, Any]] = [
            {
                "name": "vda1",
                "mountpoint": "/",
                "type": "ext4",
                "total-bytes": 21474836480,
                "used-bytes": 5368709120,
            }
        ]
        self.vcpus: list[dict[str, Any]] = [
            {"logical-id": 0, "online": True},
            {"logical-id": 1, "online": True},
        ]
        self.files: dict[str, bytes] = dict(files or {})
        self.file_modes: dict[str, int] = dict.fromkeys(self.files, 0o644)
        self.command_handlers = dict(command_handlers or {})
        self.polls_before_exit = max(1, polls_before_exit)

        self._server: asyncio.AbstractServer | None = None
        self._next_pid = 1000
        self._next_handle = 100
        self._processes: dict[int, dict[str, Any]] = {}
        self._open_files: dict[int, dict[str, Any]] = {}
        self._channel_open = False
        self.executed_commands: list[str] = []
        self.last_input_data: bytes | None = None
        self.last_env: list[str] | None = None

    @property
    def is_open(self) -> bool:
        """Совместимость с ``QgaChannelProtocol``."""
        return self._channel_open

    async def open(self, timeout: float = 10.0) -> None:
        """Открыть in-memory канал."""
        _ = timeout
        self._channel_open = True

    async def close(self) -> None:
        """Закрыть in-memory канал."""
        self._channel_open = False

    async def start(self) -> None:
        """Запустить UNIX-сокет сервер ``asyncio.start_unix_server``."""
        start_unix = getattr(asyncio, "start_unix_server", None)
        if start_unix is not None:
            sock_file = Path(self.socket_path)
            sock_file.parent.mkdir(parents=True, exist_ok=True)
            if sock_file.exists():
                sock_file.unlink()
            self._server = await start_unix(
                self._handle_client,
                path=self.socket_path,
                limit=1024 * 1024,
            )
        self._channel_open = True

    async def stop(self) -> None:
        """Остановить UNIX-сокет сервер и удалить временную директорию."""
        self._channel_open = False
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        if self._tmp_dir is not None:
            with contextlib.suppress(Exception):
                self._tmp_dir.cleanup()
            self._tmp_dir = None

    async def __aenter__(self) -> Self:
        await self.start()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.stop()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Обработчик входящего соединения по UNIX-сокету."""
        try:
            while not reader.at_eof():
                raw_line = await reader.readline()
                if not raw_line:
                    break
                has_sentinel = b"\xff" in raw_line
                clean = raw_line.replace(b"\xff", b"").strip()
                if not clean:
                    continue
                try:
                    req = json.loads(clean.decode("utf-8", errors="replace"))
                except ValueError:
                    continue
                cmd = str(req.get("execute") or "")
                args = req.get("arguments") or {}
                if cmd == "guest-sync-delimited":
                    sync_id = args.get("id", 0)
                    resp_bytes = b"\xff" + json.dumps({"return": sync_id}).encode("utf-8") + b"\n"
                    writer.write(resp_bytes)
                    await writer.drain()
                    continue
                try:
                    result = self._dispatch_rpc(cmd, args)
                    resp_obj: dict[str, Any] = {"return": result}
                except Exception as exc:
                    resp_obj = {"error": {"class": "GenericError", "desc": str(exc)}}
                prefix = b"\xff" if has_sentinel else b""
                writer.write(prefix + json.dumps(resp_obj).encode("utf-8") + b"\n")
                await writer.drain()
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    async def execute(
        self,
        command: str,
        arguments: dict[str, Any] | None = None,
        timeout: float = 30.0,
    ) -> Any:
        """Прямое выполнение RPC-команды (реализация ``QgaChannelProtocol``)."""
        _ = timeout
        if not self._channel_open:
            raise ConnectionError("MockQgaServer channel is not open")
        try:
            return self._dispatch_rpc(command, arguments or {})
        except ExecutionError:
            raise
        except Exception as exc:
            raise ExecutionError(f"QGA command {command!r} failed: {exc}", command=command) from exc

    def _dispatch_rpc(self, command: str, args: dict[str, Any]) -> Any:
        """Маршрутизация QGA JSON-RPC вызова внутри мок-сервера."""
        if command in ("guest-sync", "guest-sync-delimited"):
            return args.get("id", 0)
        if command == "guest-ping":
            return {}
        if command == "guest-get-osinfo":
            return dict(self.osinfo)
        if command == "guest-get-host-name":
            return {"host-name": self.hostname}
        if command == "guest-network-get-interfaces":
            return list(self.interfaces)
        if command == "guest-get-fsinfo":
            return list(self.fsinfo)
        if command == "guest-get-vcpus":
            return list(self.vcpus)

        if command == "guest-exec":
            return self._rpc_guest_exec(args)
        if command == "guest-exec-status":
            return self._rpc_guest_exec_status(args)
        if command == "guest-file-open":
            return self._rpc_file_open(args)
        if command == "guest-file-read":
            return self._rpc_file_read(args)
        if command == "guest-file-write":
            return self._rpc_file_write(args)
        if command == "guest-file-flush":
            return {}
        if command == "guest-file-close":
            handle = int(args.get("handle", -1))
            self._open_files.pop(handle, None)
            return {}

        raise ExecutionError(f"Unsupported QGA RPC command: {command}")

    def _evaluate_shell_command(self, shell_cmd: str) -> tuple[int, str, str]:
        """Вычислить результат shell-команды в виртуальном окружении гостя."""
        self.executed_commands.append(shell_cmd)

        for pattern, handler in self.command_handlers.items():
            if shell_cmd == pattern or pattern in shell_cmd:
                if callable(handler):
                    return handler(shell_cmd)
                return handler

        # Поддержка base64 fallback чтения
        if shell_cmd.startswith("base64 "):
            tokens = shlex.split(shell_cmd)
            target = tokens[-1]
            if target in self.files:
                return 0, base64.b64encode(self.files[target]).decode("ascii") + "\n", ""
            return 1, "", "No such file"

        # Поддержка Windows PowerShell файловых операций (stat, listdir, remove_file, exists, mkdir, base64)
        if "Get-Item -LiteralPath" in shell_cmd:
            target = shell_cmd.split("Get-Item -LiteralPath '", 1)[-1].split("'", 1)[0]
            if target in self.files:
                return 0, f"{len(self.files[target])}|1700000000|False\n", ""
            if any(k.startswith(target.rstrip("\\/") + "\\") for k in self.files):
                return 0, "0|1700000000|True\n", ""
            return 1, "", "Cannot find path"

        if "Get-ChildItem -LiteralPath" in shell_cmd:
            target = shell_cmd.split("Get-ChildItem -LiteralPath '", 1)[-1].split("'", 1)[0]
            prefix = target.rstrip("\\/")
            items: set[str] = set()
            for k in self.files:
                if k.startswith((prefix + "\\", prefix + "/")):
                    rel = k[len(prefix) + 1 :].replace("\\", "/")
                    if rel:
                        items.add(rel.split("/", 1)[0])
            return 0, ("\n".join(sorted(items)) + "\n") if items else "", ""

        if "Remove-Item -LiteralPath" in shell_cmd:
            target = shell_cmd.split("Remove-Item -LiteralPath '", 1)[-1].split("'", 1)[0]
            self.files.pop(target, None)
            self.file_modes.pop(target, None)
            return 0, "", ""

        if "Test-Path -LiteralPath" in shell_cmd:
            target = shell_cmd.split("Test-Path -LiteralPath '", 1)[-1].split("'", 1)[0]
            clean_t = target.rstrip("\\/")
            exists = target in self.files or any(
                k.startswith((clean_t + "\\", clean_t + "/"))
                for k in self.files
            )
            return (0 if exists else 1), "", ""

        if "New-Item -ItemType Directory" in shell_cmd:
            return 0, "", ""

        if "[Convert]::ToBase64String([IO.File]::ReadAllBytes(" in shell_cmd:
            target = shell_cmd.split("ReadAllBytes('", 1)[-1].split("'", 1)[0]
            if target in self.files:
                return 0, base64.b64encode(self.files[target]).decode("ascii") + "\n", ""
            return 1, "", "File not found"

        # Поддержка встроенных файловых команд uniconn (stat, chmod, test -e, mkdir, rm, ls, sha256sum)
        if shell_cmd.startswith("stat -c"):
            tokens = shlex.split(shell_cmd.split("2>/dev/null")[0])
            target = tokens[-1]
            if target in self.files:
                size = len(self.files[target])
                mode_oct = oct(self.file_modes.get(target, 0o644))[2:]
                return 0, f"{size}|0|0|{mode_oct}|1700000000|regular file\n", ""
            return 1, "", "No such file"

        if shell_cmd.startswith("chmod "):
            tokens = shlex.split(shell_cmd)
            if len(tokens) >= 3:
                mode_val = int(tokens[1], 8)
                target = tokens[2]
                self.file_modes[target] = mode_val
                return 0, "", ""

        if shell_cmd.startswith("test -e "):
            tokens = shlex.split(shell_cmd)
            target = tokens[-1]
            if target in self.files or any(k.startswith(target.rstrip("/") + "/") for k in self.files):
                return 0, "", ""
            return 1, "", ""

        if shell_cmd.startswith("rm -f "):
            tokens = shlex.split(shell_cmd)
            target = tokens[-1]
            self.files.pop(target, None)
            self.file_modes.pop(target, None)
            return 0, "", ""

        if shell_cmd.startswith("ls -1A "):
            tokens = shlex.split(shell_cmd)
            prefix = tokens[-1].rstrip("/") + "/"
            items_list = sorted(
                {
                    k[len(prefix) :].split("/", 1)[0]
                    for k in self.files
                    if k.startswith(prefix) and k[len(prefix) :]
                }
            )
            return 0, ("\n".join(items_list) + "\n") if items_list else "", ""

        if shell_cmd.startswith("mkdir "):
            return 0, "", ""

        if shell_cmd.startswith("mv -f "):
            tokens = shlex.split(shell_cmd)
            if len(tokens) >= 4:
                src, dst = tokens[2], tokens[3]
                if src in self.files:
                    self.files[dst] = self.files.pop(src)
                    self.file_modes[dst] = self.file_modes.pop(src, 0o644)
                    return 0, "", ""
            return 1, "", "mv failed"

        if "===UNICONN_SECTION:UNAME===" in shell_cmd:
            out = (
                "===UNICONN_SECTION:UNAME===\n"
                f"Linux {self.osinfo.get('kernel-release', '6.8.0')} "
                f"{self.osinfo.get('machine', 'x86_64')} {self.hostname}\n"
                "===UNICONN_SECTION:HOSTNAME===\n"
                f"{self.hostname}\n"
                "===UNICONN_SECTION:OS_RELEASE===\n"
                f'NAME="{self.osinfo.get("name", "Ubuntu")}"\n'
                f'PRETTY_NAME="{self.osinfo.get("pretty-name", "Ubuntu 24.04 LTS")}"\n'
                f'ID={self.osinfo.get("id", "ubuntu")}\n'
                "===UNICONN_SECTION:UPTIME===\n"
                "3600.5 7200.0\n"
                "===UNICONN_SECTION:CPU===\n"
                f"{len(self.vcpus)}\n"
                "===UNICONN_SECTION:MEMINFO===\n"
                "MemTotal:        4194304 kB\n"
                "MemAvailable:    3145728 kB\n"
                "===UNICONN_SECTION:DISKS===\n"
                "Filesystem Type 1024-blocks Used Available Capacity Mounted on\n"
                "/dev/vda1 ext4 20971520 5242880 15728640 25% /\n"
                "===UNICONN_SECTION:NET_JSON===\n"
                "===UNICONN_SECTION:NET_TEXT===\n"
                "===UNICONN_SECTION:END===\n"
            )
            return 0, out, ""

        if shell_cmd == "cat" and self.last_input_data is not None:
            return 0, self.last_input_data.decode("utf-8", errors="replace"), ""

        if shell_cmd.startswith("echo "):
            return 0, shell_cmd[5:].strip("'\"") + "\n", ""

        return 0, f"executed: {shell_cmd}\n", ""

    def _rpc_guest_exec(self, args: dict[str, Any]) -> dict[str, Any]:
        path = str(args.get("path") or "")
        cmd_args = [str(a) for a in (args.get("arg") or [])]
        raw_env = args.get("env")
        self.last_env = [str(x) for x in raw_env] if isinstance(raw_env, list) else None
        in_b64 = args.get("input-data")
        self.last_input_data = base64.b64decode(str(in_b64)) if in_b64 else None

        if path in ("/bin/sh", "sh") and len(cmd_args) >= 2 and cmd_args[0] == "-c":
            shell_cmd = cmd_args[1]
        elif path.lower().endswith("cmd.exe") and len(cmd_args) >= 1:
            shell_cmd = cmd_args[-1]
        elif path in ("/bin/kill", "taskkill.exe"):
            target_pid = int(cmd_args[-1]) if cmd_args and cmd_args[-1].isdigit() else -1
            if target_pid in self._processes:
                self._processes[target_pid]["exited"] = True
                self._processes[target_pid]["exitcode"] = 137
            pid = self._next_pid
            self._next_pid += 1
            self._processes[pid] = {"polls": 0, "exited": True, "exitcode": 0, "stdout": "", "stderr": ""}
            return {"pid": pid}
        else:
            shell_cmd = " ".join([path, *cmd_args]).strip()

        exit_code, stdout, stderr = self._evaluate_shell_command(shell_cmd)
        pid = self._next_pid
        self._next_pid += 1
        self._processes[pid] = {
            "polls": 0,
            "exited": False,
            "exitcode": exit_code,
            "stdout": stdout,
            "stderr": stderr,
        }
        return {"pid": pid}

    def _rpc_guest_exec_status(self, args: dict[str, Any]) -> dict[str, Any]:
        pid = int(args.get("pid", -1))
        proc = self._processes.get(pid)
        if proc is None:
            raise ExecutionError(f"PID {pid} not found")
        proc["polls"] += 1
        if not proc["exited"] and proc["polls"] < self.polls_before_exit:
            return {"exited": False}
        proc["exited"] = True
        out_b64 = base64.b64encode(proc["stdout"].encode("utf-8")).decode("ascii")
        err_b64 = base64.b64encode(proc["stderr"].encode("utf-8")).decode("ascii")
        return {
            "exited": True,
            "exitcode": proc["exitcode"],
            "out-data": out_b64,
            "err-data": err_b64,
        }

    def _rpc_file_open(self, args: dict[str, Any]) -> int:
        path = str(args.get("path") or "")
        mode = str(args.get("mode") or "r")
        if "r" in mode and path not in self.files:
            raise ExecutionError(f"File not found: {path}")
        if "w" in mode:
            self.files[path] = b""
            self.file_modes.setdefault(path, 0o644)
        elif "a" in mode:
            self.files.setdefault(path, b"")
            self.file_modes.setdefault(path, 0o644)
        handle = self._next_handle
        self._next_handle += 1
        self._open_files[handle] = {"path": path, "mode": mode, "offset": 0}
        return handle

    def _rpc_file_read(self, args: dict[str, Any]) -> dict[str, Any]:
        handle = int(args.get("handle", -1))
        count = int(args.get("count", 49152))
        fobj = self._open_files.get(handle)
        if fobj is None:
            raise ExecutionError(f"Invalid file handle: {handle}")
        data = self.files.get(fobj["path"], b"")
        offset = int(fobj["offset"])
        chunk = data[offset : offset + count]
        fobj["offset"] = offset + len(chunk)
        eof = fobj["offset"] >= len(data)
        return {
            "count": len(chunk),
            "buf-b64": base64.b64encode(chunk).decode("ascii"),
            "eof": eof,
        }

    def _rpc_file_write(self, args: dict[str, Any]) -> dict[str, Any]:
        handle = int(args.get("handle", -1))
        buf_b64 = str(args.get("buf-b64") or "")
        fobj = self._open_files.get(handle)
        if fobj is None:
            raise ExecutionError(f"Invalid file handle: {handle}")
        chunk = base64.b64decode(buf_b64) if buf_b64 else b""
        path = fobj["path"]
        self.files[path] = self.files.get(path, b"") + chunk
        return {"count": len(chunk), "eof": False}


__all__ = ["MockQgaServer"]
