# src/uniconn/_sync.py
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Self
from ._connection import Connection
from .result import Result

class SyncConnection:
    """
    Синхронная обертка над async Connection.
    
    Пример использования:
        with Connection.from_uri("ssh://user@host").to_sync() as conn:
            result = conn.run("uptime")
            print(result.stdout)
    """
    
    def __init__(self, async_conn: Connection):
        self._async_conn = async_conn
        self._executor = ThreadPoolExecutor(max_workers=1)
        self._own_loop = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
    
    def _get_loop(self) -> asyncio.AbstractEventLoop:
        """Получить или создать event loop"""
        try:
            loop = asyncio.get_running_loop()
            # Мы уже в async контексте — нужен новый loop в отдельном потоке
            return asyncio.new_event_loop()
        except RuntimeError:
            # Нет активного loop
            if self._loop is None or self._loop.is_closed():
                self._loop = asyncio.new_event_loop()
            return self._loop
    
    def _run_coro(self, coro):
        """Запустить корутину синхронно"""
        loop = self._get_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            if self._own_loop and self._loop:
                self._loop.close()
    
    def run(
        self,
        command: str,
        timeout: Optional[float] = None,
        raise_on_error: bool = False,
        **kwargs
    ) -> Result:
        """Синхронная версия Connection.run()"""
        return self._run_coro(
            self._async_conn.run(command, timeout=timeout, raise_on_error=raise_on_error, **kwargs)
        )
    
    def stream(self, command: str, timeout: Optional[float] = None, **kwargs):
        """Синхронная версия Connection.stream()"""
        async def _stream():
            async for line in self._async_conn.stream(command, timeout=timeout, **kwargs):
                yield line
        
        # Для синхронного стриминга нужен отдельный подход
        raise NotImplementedError("Sync streaming not yet implemented")
    
    def close(self) -> None:
        """Закрыть подключение"""
        self._run_coro(self._async_conn.close())
        self._executor.shutdown(wait=True)
        if self._loop:
            self._loop.close()
    
    def __enter__(self) -> Self:
        self._run_coro(self._async_conn._transport.connect())
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self._run_coro(self._async_conn._transport.disconnect())
        self.close()