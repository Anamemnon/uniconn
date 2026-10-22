# src/uniconn/transports/_ssh.py
"""SSH транспорт на базе asyncssh.

Поддерживает:
    - Аутентификацию по паролю, ключу, SSH-агенту и сертификату OpenSSH
    - Проверку known_hosts (отключена по умолчанию для обратной совместимости)
    - Чтение ~/.ssh/config
    - Keepalive / heartbeat для долгоживущих соединений
    - Proxy/jump hosts через цепочку подключений
    - Таймауты подключения и выполнения, поддержку cwd и input (stdin)
    - Потоковый вывод команд, SFTP и интерактивный PTY shell

Пример URI:
    ssh://user:pass@host:22
    ssh://user@host?known_hosts=strict&keepalive=30
    ssh://user@host?ssh_config=true&use_agent=true
    ssh://user@host?proxy=jump1.example.com,jump2.example.com

Опции (query параметры):
    known_hosts: "strict" | "default" | путь к файлу | "no" (по умолчанию "no")
    proxy: comma-separated список jump хостов (user@host)
    keepalive / keepalive_interval: интервал отправки keepalive-пакетов (сек)
    keepalive_count_max: максимальное число неотвеченных keepalive
    ssh_config: true | "default" | путь к файлу OpenSSH config
    use_agent: bool — использовать ли системный SSH-агент
    agent_path: явный путь к сокету SSH-агента
    client_cert: путь к клиентскому сертификату OpenSSH

Зависимости:
    asyncssh >= 2.13
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import os
import shlex
import stat as stat_module
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from pydantic import SecretStr

from ..exceptions import AuthenticationError, ConnectionError, ExecutionError
from ..result import Result
from ._base import BaseTransport

# Импорт опциональный (extra dependency)
try:
    import asyncssh
except ImportError:
    asyncssh = None  # type: ignore


class SSHTransport(BaseTransport):
    """SSH транспорт на базе asyncssh."""

    def __init__(self, config):
        if asyncssh is None:
            raise ImportError(
                "asyncssh not installed. "
                "Run: pip install uniconn[ssh]"
            )
        super().__init__(config)
        self._conn: Any = None
        # Промежуточные proxy/jump подключения (в порядке построения цепочки)
        self._tunnel_conns: list[Any] = []
        # Дочерние процессы ProxyCommand для закрытия при disconnect()
        self._proxy_procs: list[Any] = []
        self._ssh_config_proxy_command: str | None = None
        self._active_proxy_command: str | None = None
        # Активные PTY shell-процессы для корректного закрытия при disconnect()
        self._shell_procs: list[Any] = []
        self._known_hosts = self.config.options.get("known_hosts", "no")

    @property
    def name(self) -> str:
        return "ssh"

    @staticmethod
    def expand_proxy_command(
        template: str,
        host: str | None,
        port: int | None,
        username: str | None,
    ) -> str:
        """Подставить токены OpenSSH (``%h``, ``%p``, ``%r``, ``%%``) в строку ProxyCommand."""
        sentinel = "\x00PERCENT\x00"
        expanded = template.replace("%%", sentinel)
        expanded = expanded.replace("%h", str(host or ""))
        expanded = expanded.replace("%p", str(port or 22))
        expanded = expanded.replace("%r", str(username or ""))
        return expanded.replace(sentinel, "%")

    def _resolve_known_hosts(self) -> Any:
        """Определить политику проверки known_hosts.

        Returns:
            None — проверка отключена
            str — путь к файлу known_hosts (asyncssh загрузит и проверит сам)

        """
        mode = str(self._known_hosts).lower()

        if mode in ("no", "false", "none", ""):
            return None

        if mode in ("strict", "default"):
            known_hosts_path = Path.home() / ".ssh" / "known_hosts"
            if known_hosts_path.exists():
                return str(known_hosts_path)
            return None

        path = Path(str(self._known_hosts)).expanduser()
        if path.exists():
            return str(path)

        raise ConnectionError(
            f"known_hosts file not found: {path}",
            host=self.config.host
        )

    def _resolve_ssh_config(self) -> list[str] | None:
        """Определить список файлов конфигурации OpenSSH (``ssh_config``)."""
        opt = (
            self.config.ssh_config
            if self.config.ssh_config is not None
            else self.config.options.get("ssh_config")
        )
        if opt is False or (
            opt is not None and str(opt).lower() in ("false", "no", "none", "0", "")
        ):
            return None

        if opt is None:
            default_cfg = Path.home() / ".ssh" / "config"
            return [str(default_cfg)] if default_cfg.exists() else None

        if opt is True or str(opt).lower() in ("true", "yes", "1", "default"):
            default_cfg = Path.home() / ".ssh" / "config"
            return [str(default_cfg)] if default_cfg.exists() else []

        cfg_path = Path(str(opt)).expanduser()
        if cfg_path.exists():
            return [str(cfg_path)]

        raise ConnectionError(
            f"ssh_config file not found: {cfg_path}",
            host=self.config.host,
        )

    @staticmethod
    def parse_openssh_config(
        config_path: str | Path,
        host: str | None,
    ) -> dict[str, Any]:
        """Распарсить директивы OpenSSH config для заданного хоста/алиаса.

        Поддерживает ``Host`` (с масками ``*`` и ``?``), ``HostName``, ``User``,
        ``Port``, ``IdentityFile``, ``ProxyJump`` и ``ProxyCommand`` (по правилу
        first-match-wins, принятому в OpenSSH).
        """
        import fnmatch

        if not host:
            return {}
        path = Path(config_path).expanduser()
        if not path.is_file():
            return {}

        matched_directives: dict[str, Any] = {}
        current_matches = False

        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return {}

        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line and (
                " " not in line or line.index("=") < line.index(" ")
            ):
                key, val = line.split("=", 1)
            else:
                parts = line.split(None, 1)
                if len(parts) < 2:
                    continue
                key, val = parts[0], parts[1]

            key_lower = key.strip().lower()
            val = val.strip().strip('"')

            if key_lower == "host":
                patterns = val.split()
                pos_match = False
                neg_match = False
                for pat in patterns:
                    if pat.startswith("!"):
                        if fnmatch.fnmatchcase(host, pat[1:]):
                            neg_match = True
                    elif fnmatch.fnmatchcase(host, pat):
                        pos_match = True
                current_matches = pos_match and not neg_match
                continue

            if not current_matches:
                continue

            if key_lower == "hostname" and "hostname" not in matched_directives:
                matched_directives["hostname"] = val
            elif key_lower == "user" and "user" not in matched_directives:
                matched_directives["user"] = val
            elif key_lower == "port" and "port" not in matched_directives:
                with contextlib.suppress(ValueError):
                    matched_directives["port"] = int(val)
            elif key_lower == "identityfile" and "identityfile" not in matched_directives:
                matched_directives["identityfile"] = str(Path(val).expanduser())
            elif key_lower == "proxyjump" and "proxyjump" not in matched_directives:
                matched_directives["proxyjump"] = val
            elif key_lower == "proxycommand" and "proxycommand" not in matched_directives:
                matched_directives["proxycommand"] = val

        return matched_directives

    def _apply_extra_connect_options(self, connect_kwargs: dict[str, Any]) -> None:
        """Применить расширенные SSH-опции (keepalive, ssh_config, agent, client_cert)."""
        opts = self.config.options
        self._ssh_config_proxy_command = None

        # Keepalive / Heartbeat (§22)
        keepalive = opts.get("keepalive_interval", opts.get("keepalive"))
        if keepalive is not None:
            connect_kwargs["keepalive_interval"] = float(keepalive)

        keepalive_max = opts.get("keepalive_count_max")
        if keepalive_max is not None:
            connect_kwargs["keepalive_count_max"] = int(keepalive_max)

        # ~/.ssh/config (§24 & v0.5.0–v0.6.0)
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
                if (
                    self.config.port in (None, 22)
                    and "port" in parsed_cfg
                ):
                    connect_kwargs["port"] = parsed_cfg["port"]
                if (
                    "proxycommand" in parsed_cfg
                    and self._ssh_config_proxy_command is None
                ):
                    self._ssh_config_proxy_command = str(parsed_cfg["proxycommand"])

        # SSH-агент (§23)
        if "agent_path" in opts and opts["agent_path"] is not None:
            connect_kwargs["agent_path"] = str(opts["agent_path"])
        elif "use_agent" in opts:
            use_agent = opts["use_agent"]
            if use_agent is False or str(use_agent).lower() in ("false", "no", "0"):
                connect_kwargs["agent_path"] = None

        # Сертификаты OpenSSH (§23)
        client_cert = opts.get("client_cert")
        if client_cert:
            cert_path = Path(str(client_cert)).expanduser()
            if not cert_path.exists():
                raise ConnectionError(
                    f"client_cert file not found: {cert_path}",
                    host=self.config.host,
                )
            connect_kwargs["client_certs"] = [str(cert_path)]

        # Парольная фраза для зашифрованного приватного ключа (v0.4.0)
        if "passphrase" in opts and opts["passphrase"] is not None:
            raw_pp = opts["passphrase"]
            connect_kwargs["passphrase"] = (
                raw_pp.get_secret_value()
                if isinstance(raw_pp, SecretStr)
                else str(raw_pp)
            )

    async def _start_proxy_command(self, expanded_command: str) -> Any:
        """Запустить процесс ProxyCommand (например, ``nc -X 5 -x proxy:1080 %h %p``)."""
        proc = await asyncio.create_subprocess_shell(
            expanded_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._proxy_procs.append(proc)
        return proc

    async def _create_proxy_conn(
        self,
        proxy_host: str,
        tunnel: Any = None,
    ) -> Any:
        """Создать подключение к jump/proxy хосту.

        Args:
            proxy_host: Хост в формате ``user@host`` или просто ``host``
            tunnel: Предыдущее подключение цепочки, через которое
                устанавливается это подключение (multi-hop)

        """
        assert asyncssh is not None
        user: str | None = None
        host = proxy_host
        if "@" in proxy_host:
            user, host = proxy_host.split("@", 1)

        proxy_kwargs: dict[str, Any] = {
            "host": host,
            "port": 22,
            "username": user or self.config.username,
            "known_hosts": None,  # Для jump хостов пока отключаем
            "connect_timeout": self.config.timeout,
        }

        if tunnel is not None:
            proxy_kwargs["tunnel"] = tunnel

        if self.config.password:
            proxy_kwargs["password"] = self.config.password.get_secret_value()

        if self.config.key_file:
            proxy_kwargs["client_keys"] = [self.config.key_file]

        if self.config.passphrase:
            proxy_kwargs["passphrase"] = self.config.passphrase.get_secret_value()

        return await asyncssh.connect(**proxy_kwargs)

    async def _close_tunnel_conns(self) -> None:
        """Закрыть промежуточные proxy-подключения и процессы ProxyCommand."""
        while self._tunnel_conns:
            conn = self._tunnel_conns.pop()
            conn.close()
            await conn.wait_closed()
        while self._proxy_procs:
            proc = self._proxy_procs.pop()
            with contextlib.suppress(Exception):
                proc.terminate()
            with contextlib.suppress(Exception):
                wait_fn = getattr(proc, "wait", None)
                if callable(wait_fn):
                    res = wait_fn()
                    if inspect.isawaitable(res):
                        await res
        self._active_proxy_command = None

    async def connect(self) -> None:
        """Установить SSH подключение.

        Поддерживает proxy/jump hosts, ``proxy_command`` (SOCKS5/HTTP прокси),
        keepalive, ssh_config, ssh-agent, client_cert и passphrase.
        """
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

            # Обработка proxy/jump hosts
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

            # Обработка ProxyCommand / SOCKS5 / HTTP прокси (§24)
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
                host=self.config.host
            ) from e
        except asyncssh.DisconnectError as e:
            await self._close_tunnel_conns()
            raise ConnectionError(
                f"SSH connection failed: {e}",
                host=self.config.host
            ) from e
        except ConnectionError:
            await self._close_tunnel_conns()
            raise
        except Exception as e:
            await self._close_tunnel_conns()
            raise ConnectionError(
                f"SSH connection error: {e}",
                host=self.config.host
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
        """Проверить живость SSH подключения через лёгкую команду.

        Использует ``asyncssh.run()`` для выполнения ``true``,
        что не создаёт PTY и минимально нагружает сервер.

        Args:
            timeout: Таймаут в секундах

        Returns:
            True если SSH сессия активна

        """
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
        **kwargs
    ) -> Result:
        """Выполнить команду через SSH.

        Args:
            command: Команда для выполнения
            timeout: Таймаут в секундах
            **kwargs: Дополнительные аргументы (``env``, ``cwd``, ``input``)

        Returns:
            Result объект с результатом

        Raises:
            ConnectionError: Если нет активного подключения

        """
        if not self._connected or not self._conn:
            raise ConnectionError(
                "SSH transport is not connected. Call connect() first",
                host=self.config.host
            )
        start_time = time.monotonic()

        env = kwargs.get("env")
        cwd = kwargs.get("cwd")
        input_data = kwargs.get("input")
        effective_cmd = self._wrap_cwd(command, cwd)

        async with self._conn.create_process(effective_cmd, env=env) as proc:
            try:
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
                    asyncio.gather(
                        proc.stdout.read(),
                        proc.stderr.read()
                    ),
                    timeout=timeout
                )
                await proc.wait()
            except TimeoutError:
                proc.terminate()
                raise

        duration = time.monotonic() - start_time

        return Result(
            exit_code=proc.returncode or 0,
            stdout=stdout if isinstance(stdout, str) else stdout.decode(),
            stderr=stderr if isinstance(stderr, str) else stderr.decode(),
            duration=duration,
            command=command,
            host=self.config.host
        )

    async def run_bytes(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs,
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

        async with self._conn.create_process(
            effective_cmd, env=env, encoding=None
        ) as proc:
            try:
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
                    asyncio.gather(
                        proc.stdout.read(),
                        proc.stderr.read(),
                    ),
                    timeout=timeout,
                )
                await proc.wait()
            except TimeoutError:
                proc.terminate()
                raise

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
        **kwargs
    ) -> AsyncIterator[str]:
        """Потоковое выполнение команды через SSH.

        Yields:
            Строки вывода команды

        Raises:
            ConnectionError: Если нет активного подключения

        """
        if not self._connected or not self._conn:
            raise ConnectionError(
                "SSH transport is not connected. Call connect() first",
                host=self.config.host
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
        **kwargs
    ) -> None:
        """Загрузить файл или директорию на удалённый хост через SFTP.

        Args:
            local_path: Путь к локальному файлу или директории
            remote_path: Путь на удалённом хосте
            recurse: Рекурсивная загрузка директории
            **kwargs: Дополнительные аргументы для asyncssh SFTP

        Raises:
            ConnectionError: Если нет подключения или ошибка SFTP

        """
        assert asyncssh is not None
        if not self._connected or not self._conn:
            raise ConnectionError("Not connected", host=self.config.host)

        if recurse is False and os.path.isdir(local_path):
            recurse = True

        try:
            async with self._conn.start_sftp_client() as sftp:
                if recurse:
                    await sftp.put(local_path, remote_path, recurse=True, **kwargs)
                else:
                    await sftp.put(local_path, remote_path, **kwargs)
        except asyncssh.Error as e:
            raise ConnectionError(
                f"SFTP upload failed: {local_path} -> {remote_path}: {e}",
                host=self.config.host
            ) from e

    async def download(
        self,
        remote_path: str,
        local_path: str,
        recurse: bool = False,
        **kwargs
    ) -> None:
        """Скачать файл или директорию с удалённого хоста через SFTP.

        Args:
            remote_path: Путь на удалённом хосте
            local_path: Путь для сохранения локально
            recurse: Рекурсивная загрузка директории
            **kwargs: Дополнительные аргументы для asyncssh

        Raises:
            ConnectionError: Если нет подключения или ошибка SFTP

        """
        assert asyncssh is not None
        if not self._connected or not self._conn:
            raise ConnectionError("Not connected", host=self.config.host)

        try:
            async with self._conn.start_sftp_client() as sftp:
                if recurse:
                    await sftp.get(remote_path, local_path, recurse=True, **kwargs)
                else:
                    await sftp.get(remote_path, local_path, **kwargs)
        except asyncssh.Error as e:
            raise ConnectionError(
                f"SFTP download failed: {remote_path} -> {local_path}: {e}",
                host=self.config.host
            ) from e

    async def chmod(
        self,
        remote_path: str,
        mode: int,
    ) -> None:
        """Изменить права доступа к файлу через SFTP chmod.

        Args:
            remote_path: Путь к файлу на удалённом хосте
            mode: Права доступа в восьмеричном формате
                (например, ``0o755``, ``0o644``)

        Raises:
            ConnectionError: Если нет подключения или ошибка SFTP

        """
        assert asyncssh is not None
        if not self._connected or not self._conn:
            raise ConnectionError("Not connected", host=self.config.host)

        try:
            async with self._conn.start_sftp_client() as sftp:
                await sftp.chmod(remote_path, mode)
        except asyncssh.Error as e:
            raise ConnectionError(
                f"SFTP chmod failed: {remote_path}: {e}",
                host=self.config.host
            ) from e

    async def stat(
        self,
        remote_path: str,
    ) -> dict:
        """Получить информацию о файле через SFTP stat.

        Args:
            remote_path: Путь к файлу на удалённом хосте

        Returns:
            Словарь с атрибутами файла

        Raises:
            ConnectionError: Если нет подключения или ошибка SFTP

        """
        assert asyncssh is not None
        if not self._connected or not self._conn:
            raise ConnectionError("Not connected", host=self.config.host)

        try:
            async with self._conn.start_sftp_client() as sftp:
                attrs = await sftp.stat(remote_path)

            perms = attrs.permissions
            return {
                "size": attrs.size,
                "uid": attrs.uid,
                "gid": attrs.gid,
                "permissions": oct(perms) if perms is not None else None,
                "atime": attrs.atime,
                "mtime": attrs.mtime,
                "is_file": stat_module.S_ISREG(perms) if perms else False,
                "is_dir": stat_module.S_ISDIR(perms) if perms else False,
                "is_symlink": stat_module.S_ISLNK(perms) if perms else False,
            }
        except asyncssh.Error as e:
            raise ConnectionError(
                f"SFTP stat failed: {remote_path}: {e}",
                host=self.config.host
            ) from e

    async def listdir(
        self,
        remote_path: str = ".",
    ) -> list[str]:
        """Список файлов и директорий через SFTP readdir.

        Args:
            remote_path: Путь к директории на удалённом хосте

        Returns:
            Список имён файлов и директорий

        Raises:
            ConnectionError: Если нет подключения или ошибка SFTP

        """
        assert asyncssh is not None
        if not self._connected or not self._conn:
            raise ConnectionError("Not connected", host=self.config.host)

        try:
            async with self._conn.start_sftp_client() as sftp:
                entries = await sftp.readdir(remote_path)
            return [entry.filename for entry in entries]
        except asyncssh.Error as e:
            raise ConnectionError(
                f"SFTP listdir failed: {remote_path}: {e}",
                host=self.config.host
            ) from e

    async def read_file(self, remote_path: str) -> bytes:
        """Прочитать содержимое удалённого файла в память через SFTP."""
        assert asyncssh is not None
        if not self._connected or not self._conn:
            raise ConnectionError("Not connected", host=self.config.host)

        try:
            async with (
                self._conn.start_sftp_client() as sftp,
                sftp.open(remote_path, "rb") as f,
            ):
                data = await f.read()
            return data.encode("utf-8") if isinstance(data, str) else bytes(data)
        except asyncssh.Error as e:
            raise ConnectionError(
                f"SFTP read_file failed: {remote_path}: {e}",
                host=self.config.host,
            ) from e

    async def write_file(
        self,
        remote_path: str,
        data: bytes,
        mode: int | None = None,
    ) -> None:
        """Записать байты в удалённый файл через SFTP (с опциональным ``chmod``)."""
        assert asyncssh is not None
        if not self._connected or not self._conn:
            raise ConnectionError("Not connected", host=self.config.host)

        try:
            async with self._conn.start_sftp_client() as sftp:
                async with sftp.open(remote_path, "wb") as f:
                    await f.write(data)
                if mode is not None:
                    await sftp.chmod(remote_path, mode)
        except asyncssh.Error as e:
            raise ConnectionError(
                f"SFTP write_file failed: {remote_path}: {e}",
                host=self.config.host,
            ) from e

    async def exists(self, remote_path: str) -> bool:
        """Проверить существование файла или директории через SFTP stat."""
        assert asyncssh is not None
        if not self._connected or not self._conn:
            raise ConnectionError("Not connected", host=self.config.host)

        try:
            await self.stat(remote_path)
            return True
        except ConnectionError:
            return False

    async def mkdir(
        self,
        remote_path: str,
        parents: bool = True,
        exist_ok: bool = True,
        mode: int | None = None,
    ) -> None:
        """Создать директорию на удалённом хосте через SFTP."""
        assert asyncssh is not None
        if not self._connected or not self._conn:
            raise ConnectionError("Not connected", host=self.config.host)

        try:
            async with self._conn.start_sftp_client() as sftp:
                if parents and hasattr(sftp, "makedirs"):
                    await sftp.makedirs(remote_path, exist_ok=exist_ok)
                else:
                    await sftp.mkdir(remote_path)
                if mode is not None:
                    await sftp.chmod(remote_path, mode)
        except asyncssh.Error as e:
            raise ConnectionError(
                f"SFTP mkdir failed: {remote_path}: {e}",
                host=self.config.host,
            ) from e

    async def open_shell(
        self,
        term_type: str = "xterm",
        term_size: tuple[int, int] = (80, 24),
        **kwargs,
    ) -> Any:
        """Открыть интерактивный login shell с PTY на текущем SSH-соединении.

        Args:
            term_type: Тип терминала (по умолчанию "xterm")
            term_size: Размер терминала (cols, rows), по умолчанию (80, 24)
            **kwargs: Дополнительные параметры для ``create_process``

        Returns:
            Живой объект ``asyncssh.SSHClientProcess``

        Raises:
            ConnectionError: Если нет активного подключения

        """
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
