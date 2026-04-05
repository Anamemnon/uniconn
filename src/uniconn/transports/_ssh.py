# src/uniconn/transports/_ssh.py
"""SSH транспорт на базе asyncssh.

Поддерживает:
    - Аутентификацию по паролю и ключу
    - Проверку known_hosts (отключена по умолчанию для обратной совместимости)
    - Proxy/jump hosts через цепочку подключений
    - Таймауты подключения и выполнения
    - Потоковый вывод команд

Пример URI:
    ssh://user:pass@host:22
    ssh://user@host?known_hosts=strict
    ssh://user@host?known_hosts=/path/to/file
    ssh://user@host?proxy=jump1.example.com,jump2.example.com

Опции (query параметры):
    known_hosts: "strict" | "default" | путь к файлу | "no" (по умолчанию "no")
        - "strict" — использовать ~/.ssh/known_hosts, ошибка если хост неизвестен
        - "default" — ~/.ssh/known_hosts, автодобавление новых хостов
        - "/path/to/file" — конкретный файл known_hosts
        - "no" — отключить проверку (небезопасно, но по умолчанию для совместимости)
    proxy: comma-separated список jump хостов (user@host)
"""

import asyncio
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import asyncssh

from ..exceptions import AuthenticationError, ConnectionError
from ..result import Result
from ._base import BaseTransport


class SSHTransport(BaseTransport):
    """SSH транспорт на базе asyncssh."""

    def __init__(self, config):
        super().__init__(config)
        self._conn: asyncssh.SSHClientConnection | None = None
        self._known_hosts = self.config.options.get("known_hosts", "no")

    @property
    def name(self) -> str:
        return "ssh"

    def _resolve_known_hosts(self) -> Any:
        """Определить политику проверки known_hosts.

        Returns:
            None — отключено
            asyncssh.SSHKnownHostPublicKey — загрузить из файла

        """
        mode = str(self._known_hosts).lower()

        if mode in ("no", "false", "none", ""):
            # Отключено (текущее поведение по умолчанию)
            return None

        if mode == "strict":
            # Строгая проверка: ~/.ssh/known_hosts
            known_hosts_path = Path.home() / ".ssh" / "known_hosts"
            if known_hosts_path.exists():
                return asyncssh.SSHKnownHostPublicKey(
                    str(known_hosts_path),
                    strict=True
                )
            # Если файла нет — разрешаем подключение (как в OpenSSH)
            return asyncssh.SSHKnownHostPublicKey(
                str(known_hosts_path),
                strict=False
            )

        if mode == "default":
            # Автодобавление: ~/.ssh/known_hosts
            known_hosts_path = Path.home() / ".ssh" / "known_hosts"
            return asyncssh.SSHKnownHostPublicKey(
                str(known_hosts_path),
                strict=False
            )

        # Считаем, что это путь к файлу
        path = Path(mode).expanduser()
        if path.exists():
            return asyncssh.SSHKnownHostPublicKey(str(path), strict=True)

        raise ConnectionError(
            f"known_hosts file not found: {path}",
            host=self.config.host
        )

    async def _create_proxy_conn(self, proxy_host: str) -> asyncssh.SSHClientConnection:
        """Создать подключение к jump/proxy хосту."""
        # Парсим user@host
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

        if self.config.password:
            proxy_kwargs["password"] = self.config.password.get_secret_value()

        if self.config.key_file:
            proxy_kwargs["client_keys"] = [self.config.key_file]

        return await asyncssh.connect(**proxy_kwargs)

    async def connect(self) -> None:
        """Установить SSH подключение.

        Поддерживает proxy/jump hosts через опцию 'proxy' в config.options.
        """
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

            # Обработка proxy/jump hosts
            proxy_option = self.config.options.get("proxy")
            if proxy_option:
                proxy_hosts = [h.strip() for h in str(proxy_option).split(",")]

                # Строим цепочку подключений
                last_conn = None
                for proxy_host in proxy_hosts:
                    last_conn = await self._create_proxy_conn(proxy_host)
                    # Последний proxy используем как tunnel
                    connect_kwargs["tunnel"] = last_conn

            self._conn = await asyncssh.connect(**connect_kwargs)
            self._connected = True

        except asyncssh.PermissionDenied as e:
            raise AuthenticationError(
                f"SSH authentication failed: {e}",
                host=self.config.host
            ) from e
        except asyncssh.DisconnectError as e:
            raise ConnectionError(
                f"SSH connection failed: {e}",
                host=self.config.host
            ) from e
        except Exception as e:
            raise ConnectionError(
                f"SSH connection error: {e}",
                host=self.config.host
            ) from e

    async def disconnect(self) -> None:
        """Закрыть SSH подключение."""
        if self._conn:
            self._conn.close()
            await self._conn.wait_closed()
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
            **kwargs: Дополнительные аргументы (env, cwd, etc.)

        Returns:
            Result объект с результатом

        """
        start_time = time.monotonic()

        env = kwargs.get("env")
        async with self._conn.create_process(command, env=env) as proc:
            try:
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

    async def stream(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs
    ) -> AsyncIterator[str]:
        """Потоковое выполнение команды через SSH.

        Yields:
            Строки вывода команды

        """
        env = kwargs.get("env")
        async with self._conn.create_process(command, env=env) as proc:
            async for line in proc.stdout:
                yield line.rstrip()
