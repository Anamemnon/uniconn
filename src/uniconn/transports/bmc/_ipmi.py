# src/uniconn/transports/bmc/_ipmi.py
import asyncio
import time
from typing import AsyncIterator, Optional, Callable, Dict
from .._base import BaseTransport
from ...result import Result
from ...exceptions import BMCCapabilityError

# Импорт опциональный (extra dependency)
try:
    from pyghmi.ipmi import command as ipmi_cmd
except ImportError:
    ipmi_cmd = None

class IPMITransport(BaseTransport):
    """IPMI транспорт для BMC управления"""
    
    # Маппинг псевдокоманд на IPMI вызовы
    _COMMAND_MAP: Dict[str, Callable] = {
        "power on": lambda c: c.set_power('on'),
        "power off": lambda c: c.set_power('off'),
        "power cycle": lambda c: c.set_power('cycle'),
        "power status": lambda c: c.get_power(),
        "status": lambda c: c.get_power(),
        "boot device": lambda c: c.get_bootdev(),
        "sensors": lambda c: c.get_health(),
    }
    
    def __init__(self, config):
        if ipmi_cmd is None:
            raise ImportError("pyghmi not installed. Run: pip install uniconn[bmc]")
        super().__init__(config)
        self._bmc = None
    
    @property
    def name(self) -> str:
        return "ipmi"
    
    async def connect(self) -> None:
        # IPMI не требует явного подключения (stateless)
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
        
        # pyghmi синхронный — запускаем в executor
        loop = asyncio.get_event_loop()
        
        def _execute():
            cmd = ipmi_cmd.Command(
                bmc=self.config.host,
                userid=self.config.username,
                password=self.config.password.get_secret_value() if self.config.password else None,
                port=self.config.port or 623
            )
            
            if command not in self._COMMAND_MAP:
                raise BMCCapabilityError(
                    f"Unknown IPMI command: {command}. "
                    f"Available: {list(self._COMMAND_MAP.keys())}"
                )
            
            result = self._COMMAND_MAP[command](cmd)
            return result
        
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, _execute),
                timeout=timeout or self.config.timeout
            )
        except asyncio.TimeoutError:
            raise
        
        duration = time.monotonic() - start_time
        
        return Result(
            exit_code=0,
            stdout=str(result),
            stderr="",
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
        # IPMI не поддерживает стриминг
        result = await self.run(command, timeout=timeout, **kwargs)
        for line in result.stdout.splitlines():
            yield line