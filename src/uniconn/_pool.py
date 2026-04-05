# src/uniconn/_pool.py
from typing import List, Callable, Optional, Dict
import asyncio
from ._connection import Connection
from .result import Result
import logging

logger = logging.getLogger(__name__)

class ConnectionPool:
    """
    Пул подключений для параллельного выполнения команд.
    
    Пример использования:
        hosts = ["ssh://node1", "ssh://node2", "ssh://node3"]
        pool = ConnectionPool(hosts, max_concurrent=5)
        results = await pool.map("uptime")
    """
    
    def __init__(
        self,
        uris: List[str],
        max_concurrent: int = 10,
        retry_attempts: int = 3,
        logger: Optional[logging.Logger] = None
    ):
        self._uris = uris
        self._max_concurrent = max_concurrent
        self._retry_attempts = retry_attempts
        self._logger = logger or logging.getLogger(__name__)
        self._semaphore = asyncio.Semaphore(max_concurrent)
    
    async def map(
        self,
        command: str,
        timeout: Optional[float] = None,
        raise_on_error: bool = False
    ) -> List[Result]:
        """
        Выполнить команду на всех хостах пула.
        
        Returns:
            Список Result в том же порядке, что и URI
        """
        async def _run_single(uri: str) -> Result:
            async with self._semaphore:
                try:
                    async with Connection.from_uri(
                        uri,
                        retry_attempts=self._retry_attempts,
                        logger=self._logger
                    ) as conn:
                        return await conn.run(
                            command,
                            timeout=timeout,
                            raise_on_error=raise_on_error
                        )
                except Exception as e:
                    self._logger.error(f"Failed to execute on {uri}: {e}")
                    raise
        
        # Python 3.11+ TaskGroup для структурированного параллелизма
        results: List[Result] = []
        try:
            async with asyncio.TaskGroup() as tg:
                tasks = [
                    tg.create_task(_run_single(uri))
                    for uri in self._uris
                ]
            results = [task.result() for task in tasks]
        except* Exception as eg:
            # Обработка группы исключений (Python 3.11+)
            self._logger.error(f"Multiple failures: {len(eg.exceptions)} errors")
            raise
        
        return results
    
    async def map_with_callback(
        self,
        command: str,
        callback: Callable[[str, Result], None],
        timeout: Optional[float] = None
    ) -> None:
        """
        Выполнить команду с callback по мере готовности результатов.
        
        Args:
            command: Команда для выполнения
            callback: Функция(uri, result) вызывается для каждого результата
            timeout: Таймаут для каждой команды
        """
        async def _run_and_notify(uri: str):
            async with self._semaphore:
                try:
                    async with Connection.from_uri(uri) as conn:
                        result = await conn.run(command, timeout=timeout)
                        callback(uri, result)
                except Exception as e:
                    self._logger.error(f"Failed on {uri}: {e}")
                    # Создаём фейковый результат с ошибкой
                    from .result import Result
                    from datetime import datetime
                    error_result = Result(
                        exit_code=-1,
                        stdout="",
                        stderr=str(e),
                        duration=0.0,
                        command=command,
                        timestamp=datetime.now(),
                        host=uri
                    )
                    callback(uri, error_result)
        
        async with asyncio.TaskGroup() as tg:
            for uri in self._uris:
                tg.create_task(_run_and_notify(uri))
    
    async def map_safe(
        self,
        command: str,
        timeout: Optional[float] = None
    ) -> Dict[str, Result | Exception]:
        """
        Выполнить команду, возвращая результаты или исключения без выброса.
        
        Returns:
            Dict[uri, Result | Exception]
        """
        results: Dict[str, Result | Exception] = {}
        
        async def _run_single(uri: str):
            async with self._semaphore:
                try:
                    async with Connection.from_uri(uri) as conn:
                        results[uri] = await conn.run(command, timeout=timeout)
                except Exception as e:
                    results[uri] = e
        
        try:
            async with asyncio.TaskGroup() as tg:
                for uri in self._uris:
                    tg.create_task(_run_single(uri))
        except* Exception:
            # Исключения уже сохранены в results dict
            pass
        
        return results