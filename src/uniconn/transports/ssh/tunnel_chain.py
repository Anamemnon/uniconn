# src/uniconn/transports/ssh/tunnel_chain.py
"""Менеджер цепочки промежуточных SSH jump-хостов и процессов ProxyCommand."""

from __future__ import annotations

import asyncio
import contextlib
import inspect
from typing import Any

from ...config.models import ConnectionConfig
from ...exceptions import ConfigurationError
from .config_parser import OpenSSHConfigParser


class SSHJumpChainManager:
    """Управляет жизненным циклом multi-hop jump-соединений и subprocess-ов ProxyCommand."""

    def __init__(self, config: ConnectionConfig) -> None:
        """Инициализировать менеджер цепочки туннелей."""
        self.config = config
        self.tunnel_conns: list[Any] = []
        self.proxy_procs: list[Any] = []
        self.active_proxy_command: str | None = None

    @staticmethod
    def _parse_proxy_target(
        proxy_host: str,
        default_username: str | None,
    ) -> tuple[str, int, str | None]:
        user: str | None = None
        target = proxy_host.strip()
        if "@" in target:
            user, target = target.split("@", 1)

        port = 22
        host = target
        if target.startswith("["):
            end_bracket = target.find("]")
            if end_bracket == -1:
                raise ConfigurationError(f"Invalid IPv6 proxy host specification: {proxy_host!r}")
            host = target[1:end_bracket]
            rest = target[end_bracket + 1 :]
            if rest.startswith(":"):
                try:
                    port = int(rest[1:])
                except ValueError as exc:
                    raise ConfigurationError(f"Invalid proxy port in {proxy_host!r}") from exc
        elif target.count(":") == 1:
            host_part, port_part = target.split(":", 1)
            if port_part:
                try:
                    port = int(port_part)
                except ValueError as exc:
                    raise ConfigurationError(f"Invalid proxy port in {proxy_host!r}") from exc
                host = host_part

        if not host or not 1 <= port <= 65535:
            raise ConfigurationError(f"Invalid proxy target specification: {proxy_host!r}")
        return host, port, (user or default_username)

    async def start_proxy_command(self, expanded_command: str) -> Any:
        """Запустить дочерний процесс ProxyCommand."""
        proc = await asyncio.create_subprocess_shell(
            expanded_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self.proxy_procs.append(proc)
        self.active_proxy_command = expanded_command
        return proc

    async def create_proxy_conn(
        self,
        asyncssh_mod: Any,
        proxy_host: str,
        tunnel: Any = None,
    ) -> Any:
        """Создать подключение к одному jump/proxy хосту."""
        host, port, username = self._parse_proxy_target(proxy_host, self.config.username)
        known_hosts = OpenSSHConfigParser.resolve_known_hosts(
            self.config.options.get("known_hosts", "strict"),
            host=host,
        )

        proxy_kwargs: dict[str, Any] = {
            "host": host,
            "port": port,
            "username": username,
            "known_hosts": known_hosts,
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

        return await asyncssh_mod.connect(**proxy_kwargs)

    async def close_all(self) -> None:
        """Закрыть все промежуточные jump-соединения и процессы ProxyCommand в обратном порядке."""
        try:
            while self.tunnel_conns:
                conn = self.tunnel_conns.pop()
                with contextlib.suppress(Exception):
                    conn.close()
                with contextlib.suppress(Exception):
                    await conn.wait_closed()
            while self.proxy_procs:
                proc = self.proxy_procs.pop()
                with contextlib.suppress(Exception):
                    proc.terminate()
                with contextlib.suppress(Exception):
                    wait_fn = getattr(proc, "wait", None)
                    if callable(wait_fn):
                        res = wait_fn()
                        if inspect.isawaitable(res):
                            await res
        finally:
            self.active_proxy_command = None
