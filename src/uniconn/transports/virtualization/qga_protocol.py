# src/uniconn/transports/virtualization/qga_protocol.py
"""Низкоуровневый клиент протокола QEMU Guest Agent (QGA JSON-RPC) и каналы ввода-вывода."""

from __future__ import annotations

import asyncio
import base64
import builtins
import contextlib
import json
import random
import shlex
import time
from typing import Any, Protocol, runtime_checkable

from ...exceptions import ConnectionError, ExecutionError, FileTransferError, TimeoutError

_SYNC_SENTINEL = b"\xff"
_DEFAULT_CHUNK_SIZE = 32768  # 32 KB (~43.6 KB in base64, fits safely within 64 KB buffers)
_STREAM_LIMIT = 1024 * 1024  # 1 MiB StreamReader buffer limit


@runtime_checkable
class QgaChannelProtocol(Protocol):
    """Протокол двунаправленного канала обмена JSON-RPC сообщениями с QEMU Guest Agent."""

    @property
    def is_open(self) -> bool:
        """Открыт ли канал связи."""
        ...

    async def open(self, timeout: float = 10.0) -> None:
        """Открыть канал связи и выполнить инициализацию/синхронизацию."""
        ...

    async def close(self) -> None:
        """Закрыть канал связи."""
        ...

    async def execute(
        self,
        command: str,
        arguments: dict[str, Any] | None = None,
        timeout: float = 30.0,
    ) -> Any:
        """Выполнить QGA JSON-RPC команду и вернуть содержимое поля ``return``."""
        ...


class StreamQgaChannelBase:
    """Базовый потоковый QGA-канал поверх пары ``(StreamReader, StreamWriter)`` с ``guest-sync-delimited``."""

    def __init__(self) -> None:
        self._reader: asyncio.StreamReader | None = None
        self._writer: Any = None
        self._lock = asyncio.Lock()
        self._open = False

    @property
    def is_open(self) -> bool:
        """Открыт ли потоковый канал."""
        return self._open and self._reader is not None and self._writer is not None

    async def _sync_stream(self, timeout: float = 10.0) -> None:
        """Выполнить рукопожатие ``guest-sync-delimited`` с отсечением мусора по байту ``0xff``."""
        if self._reader is None or self._writer is None:
            raise ConnectionError("QGA stream is not initialized")

        sync_id = random.randint(100_000, 999_999_999)
        req = json.dumps(
            {"execute": "guest-sync-delimited", "arguments": {"id": sync_id}},
            separators=(",", ":"),
        ).encode("utf-8")
        payload = _SYNC_SENTINEL + req + b"\n"

        try:
            self._writer.write(payload)
            drain_fn = getattr(self._writer, "drain", None)
            if callable(drain_fn):
                res = drain_fn()
                if asyncio.iscoroutine(res):
                    await asyncio.wait_for(res, timeout=timeout)

            deadline = time.monotonic() + timeout
            found_sentinel = False
            while True:
                remaining = max(0.05, deadline - time.monotonic())
                line = await asyncio.wait_for(self._reader.readline(), timeout=remaining)
                if not line:
                    raise ConnectionError("EOF received from QGA socket during guest-sync-delimited")
                if _SYNC_SENTINEL in line:
                    idx = line.rfind(_SYNC_SENTINEL)
                    line = line[idx + 1 :]
                    found_sentinel = True
                clean = line.strip()
                if not clean:
                    continue
                if found_sentinel or clean.startswith(b"{"):
                    try:
                        parsed = json.loads(clean.decode("utf-8", errors="replace"))
                    except ValueError:
                        continue
                    if isinstance(parsed, dict) and parsed.get("return") == sync_id:
                        return
        except builtins.TimeoutError as exc:
            raise TimeoutError(
                f"QEMU Guest Agent sync timed out after {timeout}s. "
                "Ensure qemu-guest-agent service is running in guest."
            ) from exc
        except (ConnectionError, TimeoutError):
            raise
        except Exception as exc:
            raise ConnectionError(f"QEMU Guest Agent sync failed: {exc}") from exc

    async def execute(
        self,
        command: str,
        arguments: dict[str, Any] | None = None,
        timeout: float = 30.0,
    ) -> Any:
        """Отправить JSON-RPC запрос в поток и прочитать JSON-ответ."""
        if not self.is_open or self._reader is None or self._writer is None:
            raise ConnectionError("QGA channel is not connected")

        req_obj: dict[str, Any] = {"execute": command}
        if arguments is not None:
            req_obj["arguments"] = arguments
        raw_req = json.dumps(req_obj, separators=(",", ":")).encode("utf-8") + b"\n"

        async with self._lock:
            try:
                self._writer.write(raw_req)
                drain_fn = getattr(self._writer, "drain", None)
                if callable(drain_fn):
                    res = drain_fn()
                    if asyncio.iscoroutine(res):
                        await asyncio.wait_for(res, timeout=timeout)

                deadline = time.monotonic() + timeout
                while True:
                    remaining = max(0.05, deadline - time.monotonic())
                    raw_line = await asyncio.wait_for(self._reader.readline(), timeout=remaining)
                    if not raw_line:
                        raise ConnectionError(f"QGA socket closed while waiting for {command}")
                    clean_line = raw_line.replace(_SYNC_SENTINEL, b"").strip()
                    if not clean_line:
                        continue
                    resp = json.loads(clean_line.decode("utf-8", errors="replace"))
                    if not isinstance(resp, dict):
                        continue
                    if "error" in resp:
                        err = resp["error"]
                        desc = err.get("desc", str(err)) if isinstance(err, dict) else str(err)
                        raise ExecutionError(f"QGA command {command!r} failed: {desc}", command=command)
                    if "return" in resp:
                        return resp["return"]
            except builtins.TimeoutError as exc:
                raise TimeoutError(f"QGA command {command!r} timed out after {timeout}s", command=command) from exc
            except (ConnectionError, ExecutionError, TimeoutError):
                raise
            except Exception as exc:
                raise ConnectionError(f"QGA command {command!r} transport error: {exc}", command=command) from exc

    async def close(self) -> None:
        """Закрыть потоковый канал связи."""
        self._open = False
        writer = self._writer
        self._writer = None
        self._reader = None
        if writer is not None:
            with contextlib.suppress(Exception):
                writer.close()
                wait_closed = getattr(writer, "wait_closed", None)
                if callable(wait_closed):
                    res = wait_closed()
                    if asyncio.iscoroutine(res):
                        await res


class LocalUnixSocketChannel(StreamQgaChannelBase):
    """Канал прямого подключения к локальному UNIX-сокету QEMU Guest Agent."""

    def __init__(self, socket_path: str) -> None:
        super().__init__()
        self.socket_path = socket_path

    async def open(self, timeout: float = 10.0) -> None:
        """Открыть локальный UNIX-сокет и синхронизировать поток QGA."""
        open_unix = getattr(asyncio, "open_unix_connection", None)
        if open_unix is None:
            raise ConnectionError("UNIX domain sockets are not supported on this platform")
        try:
            self._reader, self._writer = await asyncio.wait_for(
                open_unix(self.socket_path, limit=_STREAM_LIMIT),
                timeout=timeout,
            )
            self._open = True
            await self._sync_stream(timeout=timeout)
        except (ConnectionError, TimeoutError):
            await self.close()
            raise
        except builtins.TimeoutError as exc:
            await self.close()
            raise TimeoutError(f"Timed out connecting to QGA socket {self.socket_path!r}") from exc
        except Exception as exc:
            await self.close()
            raise ConnectionError(f"Cannot open QGA UNIX socket {self.socket_path!r}: {exc}") from exc


class SshUnixSocketChannel(StreamQgaChannelBase):
    """Канал подключения к UNIX-сокету QGA на удалённом гипервизоре через SSH-туннель."""

    def __init__(
        self,
        *,
        host: str,
        port: int = 22,
        username: str | None = None,
        password: str | None = None,
        key_file: str | None = None,
        passphrase: str | None = None,
        socket_path: str | None = None,
        vm_name: str | None = None,
        known_hosts: Any = None,
    ) -> None:
        super().__init__()
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_file = key_file
        self.passphrase = passphrase
        self.socket_path = socket_path
        self.vm_name = vm_name
        self.known_hosts = known_hosts
        self._ssh_conn: Any = None

    async def _resolve_remote_socket_path(self, timeout: float) -> str:
        """Определить путь к UNIX-сокету QGA на удалённом гипервизоре, если он не задан явно."""
        if self.socket_path:
            return self.socket_path
        if not self.vm_name:
            raise ConnectionError("Either 'socket' path or VM name must be provided for remote QGA connection")

        q_vm = shlex.quote(self.vm_name)
        probe_cmd = (
            f"for p in /run/qemu-server/{q_vm}.qga "
            f"/var/run/qemu-server/{q_vm}.qga "
            f"/var/lib/libvirt/qemu/channel/target/domain-*-{q_vm}/org.qemu.guest_agent.0 "
            f"/var/lib/libvirt/qemu/channel/target/{q_vm}/org.qemu.guest_agent.0 "
            f"/var/run/qemu/{q_vm}.sock; do "
            'if [ -S "$p" ]; then echo "$p"; break; fi; done'
        )
        res = await asyncio.wait_for(self._ssh_conn.run(probe_cmd), timeout=timeout)
        detected = (res.stdout or "").strip().splitlines()
        if detected and detected[0].strip():
            self.socket_path = detected[0].strip()
            return self.socket_path
        raise ConnectionError(
            f"Could not auto-discover QGA UNIX socket for VM {self.vm_name!r} on {self.host}"
        )

    async def open(self, timeout: float = 10.0) -> None:
        """Установить SSH-соединение с гипервизором и открыть поток к его UNIX-сокету QGA."""
        import asyncssh

        connect_kwargs: dict[str, Any] = {
            "host": self.host,
            "port": self.port,
            "known_hosts": self.known_hosts,
        }
        if self.username:
            connect_kwargs["username"] = self.username
        if self.password:
            connect_kwargs["password"] = self.password
        if self.key_file:
            connect_kwargs["client_keys"] = [self.key_file]
        if self.passphrase:
            connect_kwargs["passphrase"] = self.passphrase

        try:
            self._ssh_conn = await asyncio.wait_for(
                asyncssh.connect(**connect_kwargs),
                timeout=timeout,
            )
            sock_path = await self._resolve_remote_socket_path(timeout=timeout)
            open_unix: Any = getattr(self._ssh_conn, "open_unix_connection", None)
            if open_unix is not None:
                self._reader, self._writer = await asyncio.wait_for(
                    open_unix(sock_path),
                    timeout=timeout,
                )
            else:
                proc = await asyncio.wait_for(
                    self._ssh_conn.create_process(f"socat - UNIX-CONNECT:{shlex.quote(sock_path)}"),
                    timeout=timeout,
                )
                self._reader = proc.stdout
                self._writer = proc.stdin
            self._open = True
            await self._sync_stream(timeout=timeout)
        except (ConnectionError, TimeoutError):
            await self.close()
            raise
        except builtins.TimeoutError as exc:
            await self.close()
            raise TimeoutError(f"SSH QGA tunnel to {self.host}:{self.port} timed out") from exc
        except Exception as exc:
            await self.close()
            raise ConnectionError(f"Failed to open remote QGA socket on {self.host}: {exc}") from exc

    async def close(self) -> None:
        """Закрыть туннелированный поток и SSH-соединение."""
        await super().close()
        ssh_conn: Any = self._ssh_conn
        self._ssh_conn = None
        if ssh_conn is not None:
            with contextlib.suppress(Exception):
                ssh_conn.close()
                wait_closed: Any = getattr(ssh_conn, "wait_closed", None)
                if wait_closed is not None:
                    res = wait_closed()
                    if asyncio.iscoroutine(res):
                        await res


class VirshCommandChannel:
    """Канал обмена с QGA через CLI ``virsh qemu-agent-command`` (локально или по SSH)."""

    def __init__(
        self,
        *,
        domain: str,
        libvirt_uri: str = "qemu:///system",
        ssh_host: str | None = None,
        ssh_port: int = 22,
        ssh_user: str | None = None,
        ssh_password: str | None = None,
        ssh_key_file: str | None = None,
        known_hosts: Any = None,
    ) -> None:
        self.domain = domain
        self.libvirt_uri = libvirt_uri
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.ssh_user = ssh_user
        self.ssh_password = ssh_password
        self.ssh_key_file = ssh_key_file
        self.known_hosts = known_hosts
        self._ssh_conn: Any = None
        self._open = False

    @property
    def is_open(self) -> bool:
        """Открыт ли канал ``virsh``."""
        return self._open

    async def open(self, timeout: float = 10.0) -> None:
        """Открыть соединение (при удалённом хосте — установить SSH) и проверить ``guest-ping``."""
        if not self.domain:
            raise ConnectionError("VM domain name or UUID is required for virsh QGA backend")
        if self.ssh_host and self.ssh_host not in ("localhost", "127.0.0.1"):
            import asyncssh

            kwargs: dict[str, Any] = {
                "host": self.ssh_host,
                "port": self.ssh_port,
                "known_hosts": self.known_hosts,
            }
            if self.ssh_user:
                kwargs["username"] = self.ssh_user
            if self.ssh_password:
                kwargs["password"] = self.ssh_password
            if self.ssh_key_file:
                kwargs["client_keys"] = [self.ssh_key_file]
            try:
                self._ssh_conn = await asyncio.wait_for(asyncssh.connect(**kwargs), timeout=timeout)
            except Exception as exc:
                raise ConnectionError(f"Failed to connect to libvirt host {self.ssh_host}: {exc}") from exc

        self._open = True
        try:
            await self.execute("guest-ping", timeout=timeout)
        except Exception as exc:
            await self.close()
            if isinstance(exc, (ConnectionError, TimeoutError)):
                raise
            raise ConnectionError(
                f"QEMU Guest Agent is not responding on domain {self.domain!r}: {exc}"
            ) from exc

    async def close(self) -> None:
        """Закрыть канал ``virsh``."""
        self._open = False
        ssh_conn: Any = self._ssh_conn
        self._ssh_conn = None
        if ssh_conn is not None:
            with contextlib.suppress(Exception):
                ssh_conn.close()
                wait_closed: Any = getattr(ssh_conn, "wait_closed", None)
                if wait_closed is not None:
                    res = wait_closed()
                    if asyncio.iscoroutine(res):
                        await res

    async def execute(
        self,
        command: str,
        arguments: dict[str, Any] | None = None,
        timeout: float = 30.0,
    ) -> Any:
        """Выполнить команду через ``virsh qemu-agent-command``."""
        if not self._open:
            raise ConnectionError("Virsh QGA channel is not connected")

        req_obj: dict[str, Any] = {"execute": command}
        if arguments is not None:
            req_obj["arguments"] = arguments
        json_str = json.dumps(req_obj, separators=(",", ":"))
        cmd = (
            f"virsh -c {shlex.quote(self.libvirt_uri)} "
            f"qemu-agent-command {shlex.quote(self.domain)} {shlex.quote(json_str)}"
        )

        try:
            if self._ssh_conn is not None:
                res = await asyncio.wait_for(self._ssh_conn.run(cmd), timeout=timeout)
                exit_code = int(res.exit_status or 0)
                stdout = str(res.stdout or "").strip()
                stderr = str(res.stderr or "").strip()
            else:
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                try:
                    out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                    exit_code = int(proc.returncode or 0)
                    stdout = out_b.decode("utf-8", errors="replace").strip()
                    stderr = err_b.decode("utf-8", errors="replace").strip()
                finally:
                    proc_tr = getattr(proc, "_transport", None)
                    if proc_tr is not None:
                        with contextlib.suppress(Exception):
                            proc_tr.close()
        except builtins.TimeoutError as exc:
            raise TimeoutError(f"virsh qemu-agent-command {command!r} timed out after {timeout}s") from exc
        except Exception as exc:
            raise ConnectionError(f"virsh qemu-agent-command {command!r} failed: {exc}") from exc

        if exit_code != 0:
            raise ExecutionError(
                f"virsh qemu-agent-command failed (exit {exit_code}): {stderr or stdout}",
                command=command,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
            )

        try:
            parsed = json.loads(stdout)
        except ValueError as exc:
            raise ConnectionError(f"Invalid JSON from virsh qemu-agent-command: {stdout!r}") from exc

        if isinstance(parsed, dict) and "error" in parsed:
            err = parsed["error"]
            desc = err.get("desc", str(err)) if isinstance(err, dict) else str(err)
            raise ExecutionError(f"QGA command {command!r} failed: {desc}", command=command)
        return parsed.get("return") if isinstance(parsed, dict) else parsed


class QgaProtocolClient:
    """Высокоуровневый клиент операций QEMU Guest Agent поверх ``QgaChannelProtocol``."""

    def __init__(
        self,
        channel: QgaChannelProtocol,
        *,
        poll_interval: float = 0.05,
        max_poll_interval: float = 0.5,
        chunk_size: int = _DEFAULT_CHUNK_SIZE,
    ) -> None:
        self.channel = channel
        self.poll_interval = max(0.01, poll_interval)
        self.max_poll_interval = max(self.poll_interval, max_poll_interval)
        self.chunk_size = max(1024, chunk_size)

    @property
    def is_connected(self) -> bool:
        """Открыт ли базовый канал связи."""
        return self.channel.is_open

    async def connect(self, timeout: float = 10.0) -> None:
        """Открыть канал и проверить отклик ``guest-ping``."""
        await self.channel.open(timeout=timeout)
        await self.ping(timeout=timeout)

    async def disconnect(self) -> None:
        """Закрыть канал связи."""
        await self.channel.close()

    async def ping(self, timeout: float = 5.0) -> bool:
        """Выполнить ``guest-ping``."""
        try:
            await self.channel.execute("guest-ping", timeout=timeout)
            return True
        except Exception:
            return False

    async def get_osinfo(self, timeout: float = 5.0) -> dict[str, Any]:
        """Получить информацию о гостевой ОС через ``guest-get-osinfo``."""
        res = await self.channel.execute("guest-get-osinfo", timeout=timeout)
        return res if isinstance(res, dict) else {}

    async def get_host_name(self, timeout: float = 5.0) -> str:
        """Получить имя хоста через ``guest-get-host-name``."""
        res = await self.channel.execute("guest-get-host-name", timeout=timeout)
        if isinstance(res, dict):
            return str(res.get("host-name") or "")
        return ""

    async def get_network_interfaces(self, timeout: float = 5.0) -> list[dict[str, Any]]:
        """Получить список сетевых интерфейсов через ``guest-network-get-interfaces``."""
        res = await self.channel.execute("guest-network-get-interfaces", timeout=timeout)
        return res if isinstance(res, list) else []

    async def get_fsinfo(self, timeout: float = 5.0) -> list[dict[str, Any]]:
        """Получить список примонтированных файловых систем через ``guest-get-fsinfo``."""
        res = await self.channel.execute("guest-get-fsinfo", timeout=timeout)
        return res if isinstance(res, list) else []

    async def get_vcpus(self, timeout: float = 5.0) -> list[dict[str, Any]]:
        """Получить информацию о виртуальных процессорах через ``guest-get-vcpus``."""
        res = await self.channel.execute("guest-get-vcpus", timeout=timeout)
        return res if isinstance(res, list) else []

    async def exec_command(
        self,
        path: str,
        args: list[str] | None = None,
        *,
        env: list[str] | None = None,
        input_data: bytes | None = None,
        timeout: float = 60.0,
        is_windows: bool = False,
    ) -> tuple[int, str, str]:
        """Запустить процесс через ``guest-exec`` и дождаться завершения в ``guest-exec-status``."""
        exec_args: dict[str, Any] = {
            "path": path,
            "capture-output": True,
        }
        if args:
            exec_args["arg"] = list(args)
        if env:
            exec_args["env"] = list(env)
        if input_data is not None:
            exec_args["input-data"] = base64.b64encode(input_data).decode("ascii")

        start_res = await self.channel.execute("guest-exec", exec_args, timeout=min(timeout, 15.0))
        if not isinstance(start_res, dict) or "pid" not in start_res:
            raise ExecutionError(f"Unexpected guest-exec response: {start_res!r}", command=path)

        pid = int(start_res["pid"])
        deadline = time.monotonic() + timeout
        delay = self.poll_interval

        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    await self._kill_guest_pid(pid, is_windows=is_windows)
                    raise TimeoutError(
                        f"QGA guest-exec (pid={pid}) timed out after {timeout}s",
                        command=f"{path} {' '.join(args or [])}".strip(),
                    )
                status = await self.channel.execute(
                    "guest-exec-status",
                    {"pid": pid},
                    timeout=min(remaining, 10.0),
                )
                if isinstance(status, dict) and status.get("exited"):
                    sig = status.get("signal")
                    default_exit = (128 + int(sig)) if isinstance(sig, int) else (137 if sig else 0)
                    exit_code = int(status.get("exitcode", default_exit))
                    out_b64 = str(status.get("out-data") or "")
                    err_b64 = str(status.get("err-data") or "")
                    stdout = base64.b64decode(out_b64).decode("utf-8", errors="replace") if out_b64 else ""
                    stderr = base64.b64decode(err_b64).decode("utf-8", errors="replace") if err_b64 else ""
                    return exit_code, stdout, stderr

                await asyncio.sleep(min(delay, max(0.01, deadline - time.monotonic())))
                delay = min(self.max_poll_interval, delay * 1.5)
        except asyncio.CancelledError:
            with contextlib.suppress(Exception):
                await self._kill_guest_pid(pid, is_windows=is_windows)
            raise

    async def _kill_guest_pid(self, pid: int, *, is_windows: bool = False) -> None:
        """Принудительно завершить зависший процесс в гостевой ОС."""
        with contextlib.suppress(Exception):
            if is_windows:
                await self.channel.execute(
                    "guest-exec",
                    {"path": "taskkill.exe", "arg": ["/F", "/PID", str(pid)], "capture-output": False},
                    timeout=3.0,
                )
            else:
                await self.channel.execute(
                    "guest-exec",
                    {"path": "/bin/kill", "arg": ["-9", str(pid)], "capture-output": False},
                    timeout=3.0,
                )

    async def read_file(self, remote_path: str, timeout: float = 60.0) -> bytes:
        """Прочитать файл из гостевой ОС через ``guest-file-open`` / ``guest-file-read`` / ``guest-file-close``."""
        try:
            handle_res = await self.channel.execute(
                "guest-file-open",
                {"path": remote_path, "mode": "r"},
                timeout=timeout,
            )
        except ExecutionError as exc:
            raise FileTransferError(f"Cannot open remote file {remote_path!r} via QGA: {exc}") from exc

        handle = int(handle_res["handle"] if isinstance(handle_res, dict) else handle_res)
        chunks: list[bytes] = []
        try:
            while True:
                read_res = await self.channel.execute(
                    "guest-file-read",
                    {"handle": handle, "count": self.chunk_size},
                    timeout=timeout,
                )
                if not isinstance(read_res, dict):
                    break
                buf_b64 = str(read_res.get("buf-b64") or "")
                if buf_b64:
                    chunks.append(base64.b64decode(buf_b64))
                if read_res.get("eof") or int(read_res.get("count", 0)) == 0:
                    break
        except Exception as exc:
            if isinstance(exc, TimeoutError):
                raise
            raise FileTransferError(f"Failed reading file {remote_path!r} via QGA: {exc}") from exc
        finally:
            with contextlib.suppress(Exception):
                await self.channel.execute("guest-file-close", {"handle": handle}, timeout=5.0)

        return b"".join(chunks)

    async def write_file(self, remote_path: str, data: bytes, timeout: float = 60.0) -> None:
        """Записать байты в файл гостевой ОС через ``guest-file-open`` / ``guest-file-write`` / ``guest-file-close``."""
        try:
            handle_res = await self.channel.execute(
                "guest-file-open",
                {"path": remote_path, "mode": "wb"},
                timeout=timeout,
            )
        except ExecutionError as exc:
            raise FileTransferError(f"Cannot open remote file {remote_path!r} for writing via QGA: {exc}") from exc

        handle = int(handle_res["handle"] if isinstance(handle_res, dict) else handle_res)
        try:
            offset = 0
            total = len(data)
            if total == 0:
                await self.channel.execute(
                    "guest-file-write",
                    {"handle": handle, "buf-b64": ""},
                    timeout=timeout,
                )
            while offset < total:
                chunk = data[offset : offset + self.chunk_size]
                b64_chunk = base64.b64encode(chunk).decode("ascii")
                write_res = await self.channel.execute(
                    "guest-file-write",
                    {"handle": handle, "buf-b64": b64_chunk},
                    timeout=timeout,
                )
                written = int(write_res.get("count", len(chunk))) if isinstance(write_res, dict) else len(chunk)
                if written <= 0:
                    raise FileTransferError(
                        f"QGA guest-file-write returned 0 bytes written for {remote_path!r}"
                    )
                offset += written
            with contextlib.suppress(Exception):
                await self.channel.execute("guest-file-flush", {"handle": handle}, timeout=timeout)
        except Exception as exc:
            if isinstance(exc, (TimeoutError, FileTransferError)):
                raise
            raise FileTransferError(f"Failed writing file {remote_path!r} via QGA: {exc}") from exc
        finally:
            with contextlib.suppress(Exception):
                await self.channel.execute("guest-file-close", {"handle": handle}, timeout=5.0)


__all__ = [
    "LocalUnixSocketChannel",
    "QgaChannelProtocol",
    "QgaProtocolClient",
    "SshUnixSocketChannel",
    "StreamQgaChannelBase",
    "VirshCommandChannel",
]
