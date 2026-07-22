# src/uniconn/_sync.py
"""Синхронная обёртка над async Connection.

Использует выделенный event loop в отдельном потоке через ThreadPoolExecutor.
Корректно управляет жизненным циклом loop — создаёт один раз при первом
вызове и закрывает при close().
"""

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Self

from ._connection import Connection
from .result import Result


class SyncConnection:
    """Синхронная обёртка над async Connection.

    Все async операции запускаются в выделенном event loop через
    ThreadPoolExecutor. Loop создаётся один раз (лениво) и переиспользуется
    между вызовами.

    Пример использования:
        with Connection.from_uri("ssh://user@host").to_sync() as conn:
            result = conn.run("uptime")
            print(result.stdout)

    Потокобезопасность:
        Не является потокобезопасной. Один экземпляр — один поток.
    """

    def __init__(self, async_conn: Connection):
        self._async_conn = async_conn
        self._executor = ThreadPoolExecutor(max_workers=1)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._loop_lock = threading.Lock()
        self._closed = False

    def _get_loop(self) -> asyncio.AbstractEventLoop:
        """Получить или лениво создать event loop (однократно)."""
        with self._loop_lock:
            if self._loop is None or self._loop.is_closed():
                self._loop = asyncio.new_event_loop()
            return self._loop

    def _run_coro(self, coro) -> Any:
        """Запустить корутину синхронно в выделенном потоке."""
        if self._closed:
            raise RuntimeError("SyncConnection уже закрыт")

        loop = self._get_loop()

        def _runner() -> Any:
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(coro)
            finally:
                asyncio.set_event_loop(None)

        future = self._executor.submit(_runner)
        return future.result()

    def run(
        self,
        command: str,
        timeout: float | None = None,
        raise_on_error: bool = False,
        **kwargs
    ) -> Result:
        """Выполнить команду синхронно.

        Args:
            command: Команда для выполнения
            timeout: Таймаут в секундах
            raise_on_error: Выбросить исключение при ненулевом exit code
            **kwargs: Дополнительные аргументы для транспорта

        Returns:
            Result объект с результатом

        """
        return self._run_coro(
            self._async_conn.run(
                command,
                timeout=timeout,
                raise_on_error=raise_on_error,
                **kwargs
            )
        )

    def run_commands(
        self,
        commands: list[str],
        stop_on_error: bool = True,
        **kwargs
    ) -> list[Result]:
        """Последовательно выполнить список команд (синхронно).

        Args:
            commands: Список команд для выполнения
            stop_on_error: Прервать выполнение при первой ошибке
            **kwargs: Дополнительные аргументы для ``run()``

        Returns:
            Список Result в порядке выполнения команд

        """
        return self._run_coro(
            self._async_conn.run_commands(
                commands,
                stop_on_error=stop_on_error,
                **kwargs
            )
        )

    def stream(self, command: str, timeout: float | None = None, **kwargs):
        """Синхронный генератор для потокового выполнения команды.

        Yields:
            Строки вывода команды

        Пример:
            for line in conn.stream("tail -f /var/log/syslog"):
                print(line)

        """
        async def _collect_lines():
            lines = []
            async for line in self._async_conn.stream(
                command, timeout=timeout, **kwargs
            ):
                lines.append(line)
            return lines

        lines = self._run_coro(_collect_lines())
        yield from lines

    def is_alive(self, timeout: float | None = None) -> bool:
        """Проверить живость подключения (синхронно)."""
        return self._run_coro(self._async_conn.is_alive(timeout=timeout))

    def close(self) -> None:
        """Закрыть подключение и освободить ресурсы."""
        if self._closed:
            return

        # Закрываем async подключение
        if self._async_conn:
            try:
                self._run_coro(self._async_conn.close())
            except Exception:
                pass  # Игнорируем ошибки при закрытии

        self._closed = True
        self._executor.shutdown(wait=True)

        with self._loop_lock:
            if self._loop and not self._loop.is_closed():
                self._loop.close()
                self._loop = None

    def __enter__(self) -> Self:
        self._run_coro(self._async_conn._transport.connect())
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        try:
            self._run_coro(self._async_conn._transport.disconnect())
        except Exception:
            pass  # Игнорируем ошибки при выходе
        self.close()
