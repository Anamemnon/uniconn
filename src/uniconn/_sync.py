# src/uniconn/_sync.py
"""Синхронная обёртка над async Connection.

Использует выделенный event loop в отдельном daemon-потоке.
Корректно управляет жизненным циклом loop — создаёт один раз при первом
вызове и закрывает при close(). Daemon-поток не блокирует завершение
процесса, даже если close() не был вызван.
"""

import asyncio
import contextlib
import threading
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any, Self

from pydantic import SecretStr

from ._connection import Connection, HookCallback, HookEvent, _CwdContext, _EnvContext
from ._shell import ShellSession
from .result import Result

# Маркер завершения потока в очереди стриминга
_STREAM_DONE = object()


class SyncShellSession:
    """Синхронная обёртка над async ShellSession.

    Делегирует все операции в выделенный event loop родительского
    ``SyncConnection`` через ``run_coroutine_threadsafe``.

    Пример использования:
        with Connection.from_uri("ssh://user@host").to_sync() as conn:
            with conn.open_shell() as shell:
                shell.execute("cd /tmp")
                res = shell.execute("pwd")
                print(res.stdout)
    """

    def __init__(self, async_session: ShellSession, sync_conn: "SyncConnection"):
        self._async_session = async_session
        self._sync_conn = sync_conn

    @property
    def is_alive(self) -> bool:
        """Проверить, что процесс оболочки активен."""
        return self._async_session.is_alive

    def execute(
        self,
        command: str | Sequence[str],
        timeout: float | None = None,
    ) -> Result:
        """Выполнить команду в stateful shell-сессии (синхронно)."""
        return self._sync_conn._run_coro(
            self._async_session.execute(command, timeout=timeout)
        )

    def send(self, text: str) -> None:
        """Отправить текст в stdin оболочки (синхронно)."""
        self._sync_conn._run_coro(self._async_session.send(text))

    def receive(self, timeout: float | None = None) -> str:
        """Прочитать доступный вывод из stdout оболочки (синхронно)."""
        return self._sync_conn._run_coro(
            self._async_session.receive(timeout=timeout)
        )

    def resize(self, cols: int, rows: int) -> None:
        """Изменить размер окна терминала PTY (синхронно)."""
        self._sync_conn._run_coro(self._async_session.resize(cols, rows))

    def close(self) -> None:
        """Закрыть shell-сессию (синхронно)."""
        if self._sync_conn._closed:
            return
        self._sync_conn._run_coro(self._async_session.close())

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


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

    def cd(self, path: str | Path) -> _CwdContext:
        """Контекстный менеджер смены рабочей директории (синхронный)."""
        return self._async_conn.cd(path)

    def env(self, mapping: dict[str, str] | None = None, **env_vars: str) -> _EnvContext:
        """Контекстный менеджер переменных окружения (синхронный)."""
        return self._async_conn.env(mapping, **env_vars)

    def add_hook(self, event: HookEvent, callback: HookCallback) -> Self:
        """Зарегистрировать lifecycle-хук (``before_run``, ``after_run``, ``on_error``)."""
        self._async_conn.add_hook(event, callback)
        return self

    def run(
        self,
        command: str | Sequence[str],
        timeout: float | None = None,
        raise_on_error: bool = False,
        input: str | bytes | None = None,
        sudo: bool = False,
        sudo_user: str | None = None,
        sudo_password: str | SecretStr | None = None,
        sensitive: bool = False,
        dry_run: bool | None = None,
        **kwargs
    ) -> Result:
        """Выполнить команду синхронно.

        Args:
            command: Команда (строка или последовательность аргументов)
            timeout: Таймаут в секундах
            raise_on_error: Выбросить исключение при ненулевом exit code
            input: Данные для передачи в stdin процесса (``str`` или ``bytes``)
            sudo: Выполнить команду через ``sudo``
            sudo_user: Пользователь для ``sudo -u``
            sudo_password: Пароль для ``sudo``
            sensitive: Скрыть вывод в логах, ``repr(Result)`` и ``ExecutionError``
            dry_run: Режим без реального выполнения команды
            **kwargs: Дополнительные аргументы для транспорта

        Returns:
            Result объект с результатом

        """
        return self._run_coro(
            self._async_conn.run(
                command,
                timeout=timeout,
                raise_on_error=raise_on_error,
                input=input,
                sudo=sudo,
                sudo_user=sudo_user,
                sudo_password=sudo_password,
                sensitive=sensitive,
                dry_run=dry_run,
                **kwargs
            )
        )

    def run_bytes(
        self,
        command: str | Sequence[str],
        timeout: float | None = None,
        raise_on_error: bool = False,
        input: str | bytes | None = None,
        sudo: bool = False,
        sudo_user: str | None = None,
        sudo_password: str | SecretStr | None = None,
        **kwargs,
    ) -> bytes:
        """Выполнить команду синхронно и вернуть сырой байтовый вывод."""
        return self._run_coro(
            self._async_conn.run_bytes(
                command,
                timeout=timeout,
                raise_on_error=raise_on_error,
                input=input,
                sudo=sudo,
                sudo_user=sudo_user,
                sudo_password=sudo_password,
                **kwargs,
            )
        )

    def read_file(
        self,
        remote_path: str,
        encoding: str | None = "utf-8",
    ) -> str | bytes:
        """Прочитать содержимое файла в память (синхронно)."""
        return self._run_coro(
            self._async_conn.read_file(remote_path, encoding=encoding)
        )

    def write_file(
        self,
        remote_path: str,
        content: str | bytes,
        mode: int | None = None,
        encoding: str = "utf-8",
    ) -> None:
        """Записать строку или байты из памяти в файл (синхронно)."""
        self._run_coro(
            self._async_conn.write_file(
                remote_path,
                content,
                mode=mode,
                encoding=encoding,
            )
        )

    def run_commands(
        self,
        commands: Sequence[str | Sequence[str]],
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
        command: str | Sequence[str],
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

    def open_shell(
        self,
        term_type: str = "xterm",
        term_size: tuple[int, int] = (80, 24),
        **kwargs,
    ) -> SyncShellSession:
        """Открыть интерактивную stateful PTY shell-сессию (синхронно).

        Args:
            term_type: Тип терминала (по умолчанию "xterm")
            term_size: Размер терминала (cols, rows), по умолчанию (80, 24)
            **kwargs: Дополнительные параметры для транспорта

        Returns:
            Экземпляр ``SyncShellSession``

        """
        async_session = self._run_coro(
            self._async_conn.open_shell(
                term_type=term_type,
                term_size=term_size,
                **kwargs,
            )
        )
        return SyncShellSession(async_session, self)

    def close(self) -> None:
        """Закрыть подключение и освободить ресурсы."""
        if self._closed:
            return

        # Закрываем async подключение
        if self._async_conn:
            with contextlib.suppress(Exception):
                self._run_coro(self._async_conn.close())

        self._closed = True

        # Останавливаем run_forever и ждём завершения потока loop'а,
        # иначе loop останется крутиться в фоне
        with self._loop_lock:
            if self._loop and not self._loop.is_closed():
                self._loop.call_soon_threadsafe(self._loop.stop)
            thread = self._loop_thread

        if thread is not None:
            thread.join(timeout=5.0)

        with self._loop_lock:
            if self._loop and not self._loop.is_closed():
                self._loop.close()
            self._loop = None
            self._loop_thread = None

    def __enter__(self) -> Self:
        self._run_coro(self._async_conn._transport.connect())
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        # close() сам закрывает async-подключение (disconnect транспорта),
        # останавливает loop и его поток — отдельный disconnect не нужен
        self.close()

