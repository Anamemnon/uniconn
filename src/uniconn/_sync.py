# src/uniconn/_sync.py
"""Синхронная обёртка над async Connection.

Использует выделенный event loop в отдельном daemon-потоке.
Корректно управляет жизненным циклом loop — создаёт один раз при первом
вызове и закрывает при close(). Daemon-поток не блокирует завершение
процесса, даже если close() не был вызван.
"""

import asyncio
import threading
from collections.abc import Iterator
from typing import Any, Self

from ._connection import Connection
from .result import Result

# Маркер завершения потока в очереди стриминга
_STREAM_DONE = object()


class SyncConnection:
    """Синхронная обёртка над async Connection.

    Event loop создаётся один раз (лениво) и крутится постоянно
    в daemon-потоке; все корутины запускаются через
    ``asyncio.run_coroutine_threadsafe``.

    Пример использования:
        with Connection.from_uri("ssh://user@host").to_sync() as conn:
            result = conn.run("uptime")
            print(result.stdout)

    Потокобезопасность:
        Не является потокобезопасной. Один экземпляр — один поток.
    """

    def __init__(self, async_conn: Connection):
        self._async_conn = async_conn
        self._loop: asyncio.AbstractEventLoop | None = None
        self._loop_thread: threading.Thread | None = None
        self._loop_lock = threading.Lock()
        self._closed = False

    def _get_loop(self) -> asyncio.AbstractEventLoop:
        """Получить или лениво создать и запустить event loop (однократно).

        Loop крутится постоянно (``run_forever``) в daemon-потоке,
        чтобы корутины можно было запускать через
        ``run_coroutine_threadsafe`` (в т.ч. потоковые генераторы).
        Daemon-поток не мешает завершению процесса при забытом close().
        """
        with self._loop_lock:
            if self._loop is None or self._loop.is_closed():
                self._loop = asyncio.new_event_loop()
                self._loop_thread = threading.Thread(
                    target=self._run_loop, args=(self._loop,), daemon=True
                )
                self._loop_thread.start()
            return self._loop

    @staticmethod
    def _run_loop(loop: asyncio.AbstractEventLoop) -> None:
        """Запустить loop навсегда (до ``loop.stop()`` из close())."""
        asyncio.set_event_loop(loop)
        try:
            loop.run_forever()
        finally:
            asyncio.set_event_loop(None)

    def _run_coro(self, coro) -> Any:
        """Запустить корутину синхронно в выделенном потоке."""
        if self._closed:
            raise RuntimeError("SyncConnection уже закрыт")

        loop = self._get_loop()
        future = asyncio.run_coroutine_threadsafe(coro, loop)
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

    def stream(
        self,
        command: str,
        timeout: float | None = None,
        **kwargs
    ) -> Iterator[str]:
        """Синхронный генератор для потокового выполнения команды.

        Строки отдаются инкрементально, по мере поступления из
        async-генератора, без буферизации всего вывода — подходит
        для долгоживущих команд вроде ``tail -f``.

        Yields:
            Строки вывода команды

        Пример:
            for line in conn.stream("tail -f /var/log/syslog"):
                print(line)

        """
        if self._closed:
            raise RuntimeError("SyncConnection уже закрыт")

        loop = self._get_loop()
        q: asyncio.Queue = asyncio.Queue()

        async def _pump() -> None:
            """Читать async-генератор и складывать элементы в очередь."""
            try:
                async for line in self._async_conn.stream(
                    command, timeout=timeout, **kwargs
                ):
                    await q.put(line)
            except Exception as e:
                # Пробрасываем исключение потребителю через очередь
                await q.put(e)
            else:
                await q.put(_STREAM_DONE)

        pump_future = asyncio.run_coroutine_threadsafe(_pump(), loop)

        try:
            while True:
                item = asyncio.run_coroutine_threadsafe(q.get(), loop).result()
                if item is _STREAM_DONE:
                    break
                if isinstance(item, Exception):
                    raise item
                yield item
        finally:
            # При досрочном закрытии генератора останавливаем pump-задачу
            if not pump_future.done():
                pump_future.cancel()

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

        # Останавливаем run_forever, иначе executor.shutdown(wait=True)
        # зависнет в ожидании рабочего потока
        with self._loop_lock:
            if self._loop and not self._loop.is_closed():
                self._loop.call_soon_threadsafe(self._loop.stop)

        self._executor.shutdown(wait=True)

        with self._loop_lock:
            if self._loop and not self._loop.is_closed():
                self._loop.close()
                self._loop = None

    def __enter__(self) -> Self:
        self._run_coro(self._async_conn._transport.connect())
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        # close() сам закрывает async-подключение (disconnect транспорта),
        # останавливает loop и executor — отдельный disconnect не нужен
        self.close()
