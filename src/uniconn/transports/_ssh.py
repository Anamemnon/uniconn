# src/uniconn/transports/_ssh.py
"""SSH транспорт на базе asyncssh.

Декомпозирован на специализированные компоненты в пакете ``uniconn.transports.ssh``:
- ``OpenSSHConfigParser`` — разбор ``~/.ssh/config``, ``known_hosts`` и ``ProxyCommand``
- ``SSHJumpChainManager`` — цепочка Jump-хостов и процессов ``ProxyCommand``
- ``SFTPClientAdapter`` — файловые SFTP-операции
"""

from __future__ import annotations

import asyncio
import builtins
import contextlib
import inspect
import shlex
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from pydantic import SecretStr

from ..config.models import ConnectionConfig
from ..exceptions import (
    AuthenticationError,
    ConnectionError,
    ExecutionError,
    TimeoutError,
)
from ..result import Result
from .base import BaseTransport, FileStat
from .ssh.config_parser import OpenSSHConfigParser
from .ssh.sftp import SFTPClientAdapter
from .ssh.tunnel_chain import SSHJumpChainManager

try:
    import asyncssh
except ImportError:
    asyncssh = None  # type: ignore[assignment]


class SSHTransport(BaseTransport):
    """SSH транспорт на базе asyncssh."""

    def __init__(self, config: ConnectionConfig) -> None:
        if asyncssh is None:
            raise ImportError(
                "asyncssh not installed. Run: pip install uniconn[ssh]"
            )
        super().__init__(config)
        self._conn: Any = None
        self._jump_manager_inst: SSHJumpChainManager | None = SSHJumpChainManager(config)
        self._sftp_inst: SFTPClientAdapter | None = SFTPClientAdapter(self)
        self._ssh_config_proxy_command: str | None = None
        self._shell_procs: list[Any] = []
        self._known_hosts = self.config.options.get("known_hosts", "no")

    @property
    def _jump_manager(self) -> SSHJumpChainManager:
        """Ленивый доступ к менеджеру цепочки Jump-хостов (безопасно при ``__new__``)."""
        inst = self.__dict__.get("_jump_manager_inst")
        if inst is None:
            inst = SSHJumpChainManager(self.config)
            self._jump_manager_inst = inst
        return inst

    @property
    def _sftp(self) -> SFTPClientAdapter:
        """Ленивый доступ к SFTP-адаптеру (безопасно при ``__new__``)."""
        inst = self.__dict__.get("_sftp_inst")
        if inst is None:
            inst = SFTPClientAdapter(self)
            self._sftp_inst = inst
        return inst

    @property
    def _tunnel_conns(self) -> list[Any]:
        """Список промежуточных jump-соединений."""
        return self._jump_manager.tunnel_conns

    @_tunnel_conns.setter
    def _tunnel_conns(self, value: list[Any]) -> None:
        self._jump_manager.tunnel_conns = value

    @property
    def _proxy_procs(self) -> list[Any]:
        """Список процессов ProxyCommand."""
        return self._jump_manager.proxy_procs

    @_proxy_procs.setter
    def _proxy_procs(self, value: list[Any]) -> None:
        self._jump_manager.proxy_procs = value

    @property
    def _active_proxy_command(self) -> str | None:
        """Активная расширенная команда ProxyCommand."""
        return self._jump_manager.active_proxy_command

    @_active_proxy_command.setter
    def _active_proxy_command(self, value: str | None) -> None:
        self._jump_manager.active_proxy_command = value

    @property
    def name(self) -> str:
        """Название транспорта."""
        return "ssh"

    @staticmethod
    def expand_proxy_command(
        template: str,
        host: str | None,
        port: int | None,
        username: str | None,
    ) -> str:
        """Подставить токены OpenSSH (``%h``, ``%p``, ``%r``, ``%%``) в строку ProxyCommand."""
        return OpenSSHConfigParser.expand_proxy_command(template, host, port, username)

    def _resolve_known_hosts(self) -> str | None:
        """Определить политику проверки known_hosts."""
        return OpenSSHConfigParser.resolve_known_hosts(self._known_hosts, host=self.config.host)

    def _resolve_ssh_config(self) -> list[str] | None:
        """Определить список файлов конфигурации OpenSSH (``ssh_config``)."""
        return OpenSSHConfigParser.resolve_ssh_config_files(self.config)

    @staticmethod
    def parse_openssh_config(
        config_path: str | Path,
        host: str | None,
    ) -> dict[str, Any]:
        """Распарсить директивы OpenSSH config для заданного хоста/алиаса."""
        return OpenSSHConfigParser.parse_file(config_path, host)

    def _apply_extra_connect_options(self, connect_kwargs: dict[str, Any]) -> None:
        """Применить расширенные SSH-опции (keepalive, ssh_config, agent, client_cert)."""
        opts = self.config.options
        self._ssh_config_proxy_command = None

        keepalive = opts.get("keepalive_interval", opts.get("keepalive"))
        if keepalive is not None:
            connect_kwargs["keepalive_interval"] = float(keepalive)

        keepalive_max = opts.get("keepalive_count_max")
        if keepalive_max is not None:
            connect_kwargs["keepalive_count_max"] = int(keepalive_max)

        ssh_cfg = self._resolve_ssh_config()
        if ssh_cfg is not None:
            connect_kwargs["config"] = ssh_cfg
            for cfg_file in ssh_cfg:
                parsed_cfg = self.parse_openssh_config(cfg_file, self.config.host)
                if not parsed_cfg:
                    continue
                if "hostname" in parsed_cfg:
                    connect_kwargs["host"] = parsed_cfg["hostname"]
                if self.config.username is None and "user" in parsed_cfg:
                    connect_kwargs["username"] = parsed_cfg["user"]
                if self.config.key_file is None and "identityfile" in parsed_cfg:
                    connect_kwargs["client_keys"] = [parsed_cfg["identityfile"]]
                if self.config.port in (None, 22) and "port" in parsed_cfg:
                    connect_kwargs["port"] = parsed_cfg["port"]
                if "proxycommand" in parsed_cfg and self._ssh_config_proxy_command is None:
                    self._ssh_config_proxy_command = str(parsed_cfg["proxycommand"])

        if "agent_path" in opts and opts["agent_path"] is not None:
            connect_kwargs["agent_path"] = str(opts["agent_path"])
        elif "use_agent" in opts:
            use_agent = opts["use_agent"]
            if use_agent is False or str(use_agent).lower() in ("false", "no", "0"):
                connect_kwargs["agent_path"] = None

        client_cert = opts.get("client_cert")
        if client_cert:
            cert_path = Path(str(client_cert)).expanduser()
            if not cert_path.exists():
                raise ConnectionError(
                    f"client_cert file not found: {cert_path}",
                    host=self.config.host,
                )
            connect_kwargs["client_certs"] = [str(cert_path)]

        if "passphrase" in opts and opts["passphrase"] is not None:
            raw_pp = opts["passphrase"]
            connect_kwargs["passphrase"] = (
                raw_pp.get_secret_value()
                if isinstance(raw_pp, SecretStr)
                else str(raw_pp)
            )

    async def _start_proxy_command(self, expanded_command: str) -> Any:
        """Запустить процесс ProxyCommand."""
        return await self._jump_manager.start_proxy_command(expanded_command)

    async def _create_proxy_conn(
        self,
        proxy_host: str,
        tunnel: Any = None,
    ) -> Any:
        """Создать подключение к jump/proxy хосту."""
        return await self._jump_manager.create_proxy_conn(asyncssh, proxy_host, tunnel=tunnel)

    async def _close_tunnel_conns(self) -> None:
        """Закрыть промежуточные proxy-подключения и процессы ProxyCommand."""
        await self._jump_manager.close_all()

    async def connect(self) -> None:
        """Установить SSH подключение."""
        assert asyncssh is not None
        try:
            connect_kwargs: dict[str, Any] = {
                "host": self.config.host,
                "port": self.config.port or 22,
                "username": self.config.username,
                "known_hosts": self._resolve_known_hosts(),
                "connect_timeout": self.config.timeout,
            }

            if self.config.password:
                connect_kwargs["password"] = self.config.password.get_secret_value()

            if self.config.key_file:
                connect_kwargs["client_keys"] = [self.config.key_file]

            if self.config.passphrase:
                connect_kwargs["passphrase"] = self.config.passphrase.get_secret_value()

            self._apply_extra_connect_options(connect_kwargs)

            proxy_option = self.config.options.get("proxy")
            if proxy_option:
                proxy_hosts = [
                    h.strip() for h in str(proxy_option).split(",") if h.strip()
                ]
                for proxy_host in proxy_hosts:
                    tunnel = self._tunnel_conns[-1] if self._tunnel_conns else None
                    proxy_conn = await self._create_proxy_conn(proxy_host, tunnel)
                    self._tunnel_conns.append(proxy_conn)

                connect_kwargs["tunnel"] = self._tunnel_conns[-1]

            raw_proxy_cmd = (
                self.config.options.get("proxy_command")
                or self._ssh_config_proxy_command
            )
            if raw_proxy_cmd and str(raw_proxy_cmd).lower() != "none":
                expanded_cmd = self.expand_proxy_command(
                    str(raw_proxy_cmd),
                    host=connect_kwargs.get("host"),
                    port=connect_kwargs.get("port", 22),
                    username=connect_kwargs.get("username"),
                )
                self._active_proxy_command = expanded_cmd
                proxy_proc = await self._start_proxy_command(expanded_cmd)
                if "tunnel" not in connect_kwargs:
                    connect_kwargs["tunnel"] = proxy_proc

            self._conn = await asyncssh.connect(**connect_kwargs)
            self._connected = True

        except asyncssh.PermissionDenied as e:
            await self._close_tunnel_conns()
            raise AuthenticationError(
                f"SSH authentication failed: {e}",
                host=self.config.host,
            ) from e
        except asyncssh.DisconnectError as e:
            await self._close_tunnel_conns()
            raise ConnectionError(
                f"SSH connection failed: {e}",
                host=self.config.host,
            ) from e
        except ConnectionError:
            await self._close_tunnel_conns()
            raise
        except Exception as e:
            await self._close_tunnel_conns()
            raise ConnectionError(
                f"SSH connection error: {e}",
                host=self.config.host,
            ) from e

    async def disconnect(self) -> None:
        """Закрыть SSH подключение, активные shell-процессы и proxy-подключения."""
        while self._shell_procs:
            proc = self._shell_procs.pop()
            with contextlib.suppress(Exception):
                proc.terminate()
            with contextlib.suppress(Exception):
                close_fn = getattr(proc, "close", None)
                if callable(close_fn):
                    close_fn()
        if self._conn:
            self._conn.close()
            await self._conn.wait_closed()
            self._conn = None
        await self._close_tunnel_conns()
        self._connected = False

    async def ping(self, timeout: float | None = None) -> bool:
        """Проверить живость SSH подключения через лёгкую команду ``true``."""
        if not self._connected or not self._conn:
            return False
        try:
            result = await asyncio.wait_for(
                self._conn.run("true"),
                timeout=timeout or 5.0,
            )
            return result.exit_status == 0
        except Exception:
            return False

    @staticmethod
    def _wrap_cwd(command: str, cwd: str | Path | None) -> str:
        """Обернуть команду в ``cd <cwd> && <command>``, если указан ``cwd``."""
        if cwd is None:
            return command
        return f"cd {shlex.quote(str(cwd))} && {command}"

    async def run(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> Result:
        """Выполнить команду через SSH."""
        if not self._connected or not self._conn:
            raise ConnectionError(
                "SSH transport is not connected. Call connect() first",
                host=self.config.host,
            )
        start_time = time.monotonic()

        env = kwargs.get("env")
        cwd = kwargs.get("cwd")
        input_data = kwargs.get("input")
        effective_cmd = self._wrap_cwd(command, cwd)

        proc: Any = None
        try:
            async with self._conn.create_process(effective_cmd, env=env) as proc:
                if input_data is not None:
                    text_in = (
                        input_data.decode("utf-8", errors="replace")
                        if isinstance(input_data, bytes)
                        else str(input_data)
                    )
                    proc.stdin.write(text_in)
                    eof_fn = getattr(proc.stdin, "write_eof", None)
                    if callable(eof_fn):
                        eof_fn()

                stdout, stderr = await asyncio.wait_for(
                    asyncio.gather(proc.stdout.read(), proc.stderr.read()),
                    timeout=timeout,
                )
                await proc.wait()
        except builtins.TimeoutError as exc:
            if proc is not None and hasattr(proc, "terminate"):
                proc.terminate()
            raise TimeoutError(
                f"SSH command timed out after {timeout}s",
                command=command,
                host=self.config.host,
            ) from exc

        duration = time.monotonic() - start_time

        return Result(
            exit_code=proc.returncode or 0,
            stdout=stdout if isinstance(stdout, str) else stdout.decode(),
            stderr=stderr if isinstance(stderr, str) else stderr.decode(),
            duration=duration,
            command=command,
            host=self.config.host,
        )

    async def run_bytes(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> bytes:
        """Выполнить команду через SSH и вернуть сырой байтовый stdout."""
        if not self._connected or not self._conn:
            raise ConnectionError(
                "SSH transport is not connected. Call connect() first",
                host=self.config.host,
            )

        raise_on_error = kwargs.pop("raise_on_error", False)
        env = kwargs.get("env")
        cwd = kwargs.get("cwd")
        input_data = kwargs.get("input")
        effective_cmd = self._wrap_cwd(command, cwd)

        proc: Any = None
        try:
            async with self._conn.create_process(
                effective_cmd, env=env, encoding=None
            ) as proc:
                if input_data is not None:
                    bytes_in = (
                        input_data.encode("utf-8")
                        if isinstance(input_data, str)
                        else bytes(input_data)
                    )
                    proc.stdin.write(bytes_in)
                    eof_fn = getattr(proc.stdin, "write_eof", None)
                    if callable(eof_fn):
                        eof_fn()

                stdout, stderr = await asyncio.wait_for(
                    asyncio.gather(proc.stdout.read(), proc.stderr.read()),
                    timeout=timeout,
                )
                await proc.wait()
        except builtins.TimeoutError as exc:
            if proc is not None and hasattr(proc, "terminate"):
                proc.terminate()
            raise TimeoutError(
                f"SSH command timed out after {timeout}s",
                command=command,
                host=self.config.host,
            ) from exc

        raw_stdout = (
            stdout.encode("utf-8") if isinstance(stdout, str) else bytes(stdout or b"")
        )
        raw_stderr = (
            stderr.encode("utf-8") if isinstance(stderr, str) else bytes(stderr or b"")
        )
        exit_code = proc.returncode or 0
        if raise_on_error and exit_code != 0:
            raise ExecutionError(
                f"Command failed with exit code {exit_code}",
                command=command,
                exit_code=exit_code,
                stdout=raw_stdout.decode("utf-8", errors="replace"),
                stderr=raw_stderr.decode("utf-8", errors="replace"),
                host=self.config.host,
            )
        return raw_stdout

    async def stream(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        """Потоковое выполнение команды через SSH."""
        if not self._connected or not self._conn:
            raise ConnectionError(
                "SSH transport is not connected. Call connect() first",
                host=self.config.host,
            )
        env = kwargs.get("env")
        cwd = kwargs.get("cwd")
        effective_cmd = self._wrap_cwd(command, cwd)
        async with self._conn.create_process(effective_cmd, env=env) as proc:
            async for line in proc.stdout:
                yield line.rstrip()

    async def upload(
        self,
        local_path: str,
        remote_path: str,
        recurse: bool = False,
        **kwargs: Any,
    ) -> None:
        """Загрузить файл или директорию на удалённый хост через SFTP."""
        await self._sftp.upload(
            asyncssh, local_path, remote_path, recurse=recurse, **kwargs
        )

    async def download(
        self,
        remote_path: str,
        local_path: str,
        recurse: bool = False,
        **kwargs: Any,
    ) -> None:
        """Скачать файл или директорию с удалённого хоста через SFTP."""
        await self._sftp.download(
            asyncssh, remote_path, local_path, recurse=recurse, **kwargs
        )

    async def chmod(self, remote_path: str, mode: int) -> None:
        """Изменить права доступа к файлу через SFTP chmod."""
        await self._sftp.chmod(asyncssh, remote_path, mode)

    async def stat(self, remote_path: str) -> FileStat:
        """Получить информацию о файле через SFTP stat."""
        return await self._sftp.stat(asyncssh, remote_path)

    async def listdir(self, remote_path: str = ".") -> list[str]:
        """Список файлов и директорий через SFTP readdir."""
        return await self._sftp.listdir(asyncssh, remote_path)

    async def read_file(self, remote_path: str) -> bytes:
        """Прочитать содержимое удалённого файла в память через SFTP."""
        return await self._sftp.read_file(asyncssh, remote_path)

    async def write_file(
        self,
        remote_path: str,
        data: bytes,
        mode: int | None = None,
    ) -> None:
        """Записать байты в удалённый файл через SFTP."""
        await self._sftp.write_file(asyncssh, remote_path, data, mode=mode)

    async def exists(self, remote_path: str) -> bool:
        """Проверить существование файла или директории через SFTP stat."""
        return await self._sftp.exists(asyncssh, remote_path)

    async def mkdir(
        self,
        remote_path: str,
        parents: bool = True,
        exist_ok: bool = True,
        mode: int | None = None,
    ) -> None:
        """Создать директорию на удалённом хосте через SFTP."""
        await self._sftp.mkdir(
            asyncssh,
            remote_path,
            parents=parents,
            exist_ok=exist_ok,
            mode=mode,
        )

    async def remove_file(self, remote_path: str) -> None:
        """Удалить файл на удалённом хосте через SFTP."""
        await self._sftp.remove_file(asyncssh, remote_path)

    async def open_shell(
        self,
        term_type: str = "xterm",
        term_size: tuple[int, int] = (80, 24),
        **kwargs: Any,
    ) -> Any:
        """Открыть интерактивный login shell с PTY на текущем SSH-соединении."""
        if not self._connected or not self._conn:
            raise ConnectionError(
                "SSH transport is not connected. Call connect() first",
                host=self.config.host,
            )

        try:
            res = self._conn.create_process(
                term_type=term_type,
                term_size=term_size,
                encoding="utf-8",
                **kwargs,
            )
            if inspect.isawaitable(res):
                proc = await res
            elif hasattr(res, "__aenter__"):
                proc = await res.__aenter__()
            else:
                proc = res
        except Exception as e:
            raise ConnectionError(
                f"Failed to open SSH shell: {e}",
                host=self.config.host,
            ) from e

        self._shell_procs.append(proc)
        return proc

    @contextlib.asynccontextmanager
    async def forward_local_port(
        self,
        remote_host: str = "127.0.0.1",
        remote_port: int = 80,
        local_host: str = "127.0.0.1",
        local_port: int = 0,
    ) -> AsyncIterator[int]:
        """Открыть локальный SSH-туннель (Local Port Forwarding) через asyncssh."""
        if not self._connected or not self._conn:
            raise ConnectionError(
                "SSH transport is not connected. Call connect() first",
                host=self.config.host,
            )

        try:
            res = self._conn.forward_local_port(
                local_host, local_port, remote_host, remote_port
            )
            listener: Any = await res if inspect.isawaitable(res) else res
        except Exception as e:
            raise ConnectionError(
                f"Failed to forward local port {local_host}:{local_port} -> "
                f"{remote_host}:{remote_port}: {e}",
                host=self.config.host,
            ) from e

        get_port = getattr(listener, "get_port", None)
        port_val: Any = get_port() if callable(get_port) else local_port
        bound_port = int(port_val)
        try:
            yield bound_port
        finally:
            with contextlib.suppress(Exception):
                close_fn = getattr(listener, "close", None)
                if callable(close_fn):
                    close_fn()
                wait_closed = getattr(listener, "wait_closed", None)
                if callable(wait_closed):
                    wres = wait_closed()
                    if inspect.isawaitable(wres):
                        await wres

    @contextlib.asynccontextmanager
    async def forward_remote_port(
        self,
        remote_host: str = "127.0.0.1",
        remote_port: int = 0,
        local_host: str = "127.0.0.1",
        local_port: int = 80,
    ) -> AsyncIterator[int]:
        """Открыть обратный SSH-туннель (Remote Port Forwarding) через asyncssh."""
        if not self._connected or not self._conn:
            raise ConnectionError(
                "SSH transport is not connected. Call connect() first",
                host=self.config.host,
            )

        try:
            res = self._conn.forward_remote_port(
                remote_host, remote_port, local_host, local_port
            )
            listener: Any = await res if inspect.isawaitable(res) else res
        except Exception as e:
            raise ConnectionError(
                f"Failed to forward remote port {remote_host}:{remote_port} -> "
                f"{local_host}:{local_port}: {e}",
                host=self.config.host,
            ) from e

        get_port = getattr(listener, "get_port", None)
        port_val: Any = get_port() if callable(get_port) else remote_port
        bound_port = int(port_val)
        try:
            yield bound_port
        finally:
            with contextlib.suppress(Exception):
                close_fn = getattr(listener, "close", None)
                if callable(close_fn):
                    close_fn()
                wait_closed = getattr(listener, "wait_closed", None)
                if callable(wait_closed):
                    wres = wait_closed()
                    if inspect.isawaitable(wres):
                        await wres
