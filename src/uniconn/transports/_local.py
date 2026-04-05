# src/uniconn/transports/_local.py
import asyncio
import time
from typing import AsyncIterator, Optional
from ._base import BaseTransport
from ..result import Result

class LocalTransport(BaseTransport):
    """Выполнение команд локально через subprocess"""
    
    @property
    def name(self) -> str:
        return "local"
    
    async def connect(self) -> None:
        self._connected = True
    
    async def disconnect(self) -> None:
        self._connected = False
    
    async def run(
        self,
        command: str,
        timeout: Optional[float] = None,
        **kwargs
    ) -> Result:
        start_time = time.monotonic()
        
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=kwargs.get('env'),
            cwd=kwargs.get('cwd')
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise
        
        duration = time.monotonic() - start_time
        
        return Result(
            exit_code=proc.returncode or 0,
            stdout=stdout.decode() if stdout else "",
            stderr=stderr.decode() if stderr else "",
            duration=duration,
            command=command,
            host="localhost"
        )
    
    async def stream(
        self,
        command: str,
        timeout: Optional[float] = None,
        **kwargs
    ) -> AsyncIterator[str]:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            **kwargs
        )
        
        async for line in proc.stdout:
            yield line.decode().rstrip()
        
        await proc.wait()