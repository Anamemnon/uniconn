# src/uniconn/transports/_ssh.py
import asyncio
import time
from typing import AsyncIterator, Optional, List
import asyncssh
from ._base import BaseTransport
from ..result import Result
from ..exceptions import AuthenticationError, ConnectionError

class SSHTransport(BaseTransport):
    """SSH транспорт на базе asyncssh"""
    
    def __init__(self, config):
        super().__init__(config)
        self._conn: Optional[asyncssh.SSHClientConnection] = None
    
    @property
    def name(self) -> str:
        return "ssh"
    
    async def connect(self) -> None:
        try:
            connect_kwargs = {
                'host': self.config.host,
                'port': self.config.port or 22,
                'username': self.config.username,
                'known_hosts': None,  # Или строгая проверка
                'connect_timeout': self.config.timeout,
            }
            
            if self.config.password:
                connect_kwargs['password'] = self.config.password.get_secret_value()
            
            if self.config.key_file:
                connect_kwargs['client_keys'] = [self.config.key_file]
            
            # Обработка proxy/jump hosts
            if 'proxy' in self.config.options:
                proxy_hosts = self.config.options['proxy'].split(',')
                # Реализация цепочки подключений
            
            self._conn = await asyncssh.connect(**connect_kwargs)
            self._connected = True
            
        except asyncssh.PermissionDenied as e:
            raise AuthenticationError(f"SSH authentication failed: {e}", host=self.config.host) from e
        except asyncssh.DisconnectError as e:
            raise ConnectionError(f"SSH connection failed: {e}", host=self.config.host) from e
        except Exception as e:
            raise ConnectionError(f"SSH connection error: {e}", host=self.config.host) from e
    
    async def disconnect(self) -> None:
        if self._conn:
            self._conn.close()
            await self._conn.wait_closed()
        self._connected = False
    
    async def run(
        self,
        command: str,
        timeout: Optional[float] = None,
        **kwargs
    ) -> Result:
        start_time = time.monotonic()
        
        async with self._conn.create_process(command) as proc:
            try:
                stdout, stderr = await asyncio.wait_for(
                    asyncio.gather(
                        proc.stdout.read(),
                        proc.stderr.read()
                    ),
                    timeout=timeout
                )
                await proc.wait()
            except asyncio.TimeoutError:
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
        timeout: Optional[float] = None,
        **kwargs
    ) -> AsyncIterator[str]:
        async with self._conn.create_process(command) as proc:
            async for line in proc.stdout:
                yield line.rstrip()