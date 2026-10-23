# src/uniconn/transports/ssh/tunnel_chain.py
"""Менеджер цепочки промежуточных SSH jump-хостов и процессов ProxyCommand."""

from __future__ import annotations

import asyncio
import contextlib
import inspect
from typing import Any

from ..._config import ConnectionConfig


class SSHJumpChainManager:
    """Управляет жизненным циклом multi-hop jump-соединений и subprocess-ов ProxyCommand."""

    def __init__(self, config: ConnectionConfig) -> None:
        """Инициализировать менеджер цепочки туннелей."""
        self.config = config
        self.tunnel_conns: list[Any] = []
        self.proxy_procs: list[Any] = []
        self.active_proxy_command: str | None = None

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
        user: str | None = None
        host = proxy_host
        if "@" in proxy_host:
            user, host = proxy_host.split("@", 1)

        proxy_kwargs: dict[str, Any] = {
            "host": host,
            "port": 22,
            "username": user or self.config.username,
            "known_hosts": None,
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
        while self.tunnel_conns:
            conn = self.tunnel_conns.pop()
            conn.close()
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
        self.active_proxy_command = None
