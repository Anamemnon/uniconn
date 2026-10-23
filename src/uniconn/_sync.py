# src/uniconn/_sync.py
"""Синхронная обёртка над async Connection.

Использует выделенный event loop в отдельном daemon-потоке.
Корректно управляет жизненным циклом loop — создаёт один раз при первом
вызове и закрывает при close(). Daemon-поток не блокирует завершение
процесса, даже если close() не был вызван.
"""

import asyncio
import contextlib
import logging
import threading
from collections.abc import Callable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Self

from pydantic import SecretStr

from ._connection import Connection, HookCallback, HookEvent, _CwdContext, _EnvContext
from ._facts import HostFacts
from ._shell import ShellSession
from .result import EnsureResult, Result, SyncResult

if TYPE_CHECKING:
    from ._pool import ConnectionPool

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

    def expect(
        self,
        command: str | Sequence[str] | None = None,
        patterns: Mapping[str, str | SecretStr] | None = None,
        final_prompt: str | None = None,
        timeout: float | None = None,
        line_ending: str = "\n",
        sensitive: bool = False,
        allow_eof: bool = True,
    ) -> Result:
        """Выполнить интерактивный диалог по regex-паттернам в shell-сессии (синхронно)."""
        return self._sync_conn._run_coro(
            self._async_session.expect(
                command=command,
                patterns=patterns,
                final_prompt=final_prompt,
                timeout=timeout,
                line_ending=line_ending,
                sensitive=sensitive,
                allow_eof=allow_eof,
            )
        )

    def close(self) -> None:
        """Закрыть shell-сессию (синхронно)."""
        if self._sync_conn._closed:
            return
        self._sync_conn._run_coro(self._async_session.close())

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


class _SyncTempDirContext:
    """Синхронный контекстный менеджер временной директории поверх ``SyncConnection``."""

    def __init__(
        self,
        sync_conn: "SyncConnection",
        prefix: str = "uniconn_",
        suffix: str = "",
        dir: str | Path | None = None,
    ) -> None:
        self._sync_conn = sync_conn
        self._async_ctx = sync_conn._async_conn.temp_dir(
            prefix=prefix,
            suffix=suffix,
            dir=dir,
        )

    def __enter__(self) -> str:
        return self._sync_conn._run_coro(self._async_ctx.__aenter__())

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self._sync_conn._run_coro(
            self._async_ctx.__aexit__(exc_type, exc_val, exc_tb)
        )


class _SyncPortForwardContext:
    """Синхронный контекстный менеджер проброса портов поверх ``SyncConnection``."""

    def __init__(self, sync_conn: "SyncConnection", async_cm: Any) -> None:
        self._sync_conn = sync_conn
        self._async_cm = async_cm

    def __enter__(self) -> int:
        return int(self._sync_conn._run_coro(self._async_cm.__aenter__()))

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self._sync_conn._run_coro(
            self._async_cm.__aexit__(exc_type, exc_val, exc_tb)
        )


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
            with contextlib.suppress(Exception):
                coro.close()
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

    def exists(self, remote_path: str | Path) -> bool:
        """Проверить существование файла или директории на хосте (синхронно)."""
        return self._run_coro(self._async_conn.exists(remote_path))

    def mkdir(
        self,
        remote_path: str | Path,
        parents: bool = True,
        exist_ok: bool = True,
        mode: int | None = None,
    ) -> None:
        """Создать директорию на хосте (синхронно)."""
        self._run_coro(
            self._async_conn.mkdir(
                remote_path,
                parents=parents,
                exist_ok=exist_ok,
                mode=mode,
            )
        )

    def temp_dir(
        self,
        prefix: str = "uniconn_",
        suffix: str = "",
        dir: str | Path | None = None,
    ) -> _SyncTempDirContext:
        """Синхронный контекстный менеджер временной директории на хосте."""
        return _SyncTempDirContext(
            self,
            prefix=prefix,
            suffix=suffix,
            dir=dir,
        )

    def remove_file(self, remote_path: str | Path) -> None:
        """Удалить файл на хосте (синхронно)."""
        self._run_coro(self._async_conn.remove_file(remote_path))

    def upload(
        self,
        local_path: str,
        remote_path: str,
        recurse: bool = False,
        **kwargs: Any,
    ) -> None:
        """Загрузить файл или директорию на хост (синхронно)."""
        self._run_coro(
            self._async_conn.upload(local_path, remote_path, recurse=recurse, **kwargs)
        )

    def download(
        self,
        remote_path: str,
        local_path: str,
        recurse: bool = False,
        **kwargs: Any,
    ) -> None:
        """Скачать файл или директорию с хоста (синхронно)."""
        self._run_coro(
            self._async_conn.download(remote_path, local_path, recurse=recurse, **kwargs)
        )

    def chmod(self, remote_path: str, mode: int) -> None:
        """Изменить права доступа к файлу на хосте (синхронно)."""
        self._run_coro(self._async_conn.chmod(remote_path, mode))

    def stat(self, remote_path: str) -> dict[str, Any]:
        """Получить метаданные файла на хосте (синхронно)."""
        return self._run_coro(self._async_conn.stat(remote_path))

    def listdir(self, remote_path: str = ".") -> list[str]:
        """Получить список файлов в директории на хосте (синхронно)."""
        return self._run_coro(self._async_conn.listdir(remote_path))

    def write_template(
        self,
        remote_path: str | Path,
        template_str_or_path: str | Path,
        context: Mapping[str, Any] | None = None,
        mode: int | None = 0o644,
        encoding: str = "utf-8",
        engine: Literal["auto", "string", "jinja2"] = "auto",
    ) -> str:
        """Отрендерить шаблон и записать его на хост (синхронно)."""
        return self._run_coro(
            self._async_conn.write_template(
                remote_path=remote_path,
                template_str_or_path=template_str_or_path,
                context=context,
                mode=mode,
                encoding=encoding,
                engine=engine,
            )
        )

    def sync_dir(
        self,
        local_dir: str | Path,
        remote_dir: str | Path,
        delete: bool = False,
        exclude: Sequence[str] | None = None,
        mtime_tolerance: float = 1.0,
        dry_run: bool | None = None,
    ) -> SyncResult:
        """Инкрементально синхронизировать директорию с хостом (синхронно)."""
        return self._run_coro(
            self._async_conn.sync_dir(
                local_dir=local_dir,
                remote_dir=remote_dir,
                delete=delete,
                exclude=exclude,
                mtime_tolerance=mtime_tolerance,
                dry_run=dry_run,
            )
        )

    def forward_local_port(
        self,
        remote_host: str = "127.0.0.1",
        remote_port: int = 80,
        local_host: str = "127.0.0.1",
        local_port: int = 0,
    ) -> _SyncPortForwardContext:
        """Синхронный контекстный менеджер прямого проброса порта (Local Port Forwarding)."""
        return _SyncPortForwardContext(
            self,
            self._async_conn.forward_local_port(
                remote_host=remote_host,
                remote_port=remote_port,
                local_host=local_host,
                local_port=local_port,
            ),
        )

    def forward_remote_port(
        self,
        remote_host: str = "127.0.0.1",
        remote_port: int = 0,
        local_host: str = "127.0.0.1",
        local_port: int = 80,
    ) -> _SyncPortForwardContext:
        """Синхронный контекстный менеджер обратного проброса порта (Remote Port Forwarding)."""
        return _SyncPortForwardContext(
            self,
            self._async_conn.forward_remote_port(
                remote_host=remote_host,
                remote_port=remote_port,
                local_host=local_host,
                local_port=local_port,
            ),
        )

    def expect(
        self,
        command: str | Sequence[str],
        patterns: Mapping[str, str | SecretStr] | None = None,
        final_prompt: str | None = None,
        timeout: float | None = None,
        line_ending: str = "\n",
        sensitive: bool = False,
        term_type: str = "xterm",
        term_size: tuple[int, int] = (80, 24),
        **kwargs: Any,
    ) -> Result:
        """Выполнить интерактивную команду с сопоставлением паттернов (синхронно)."""
        return self._run_coro(
            self._async_conn.expect(
                command=command,
                patterns=patterns,
                final_prompt=final_prompt,
                timeout=timeout,
                line_ending=line_ending,
                sensitive=sensitive,
                term_type=term_type,
                term_size=term_size,
                **kwargs,
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
        init_posix: bool | None = None,
        **kwargs,
    ) -> SyncShellSession:
        """Открыть интерактивную stateful PTY shell-сессию (синхронно).

        Args:
            term_type: Тип терминала (по умолчанию "xterm")
            term_size: Размер терминала (cols, rows), по умолчанию (80, 24)
            init_posix: Инициализировать ли POSIX-маркерный режим
            **kwargs: Дополнительные параметры для транспорта

        Returns:
            Экземпляр ``SyncShellSession``

        """
        async_session = self._run_coro(
            self._async_conn.open_shell(
                term_type=term_type,
                term_size=term_size,
                init_posix=init_posix,
                **kwargs,
            )
        )
        return SyncShellSession(async_session, self)

    def gather_facts(
        self,
        refresh: bool = False,
        timeout: float | None = None,
    ) -> HostFacts:
        """Собрать системные факты о целевом хосте (синхронно)."""
        return self._run_coro(
            self._async_conn.gather_facts(refresh=refresh, timeout=timeout)
        )

    def ensure_package(
        self,
        package: str | Sequence[str],
        state: Literal["present", "absent"] = "present",
        manager: Literal["auto", "apt", "dnf", "yum", "apk", "pacman", "zypper"] = "auto",
        update_cache: bool = False,
        sudo: bool = True,
        dry_run: bool | None = None,
    ) -> EnsureResult:
        """Идемпотентно обеспечить наличие или отсутствие пакета(ов) на хосте (синхронно)."""
        return self._run_coro(
            self._async_conn.ensure_package(
                package=package,
                state=state,
                manager=manager,
                update_cache=update_cache,
                sudo=sudo,
                dry_run=dry_run,
            )
        )

    def ensure_service(
        self,
        service: str,
        state: Literal["started", "stopped", "restarted", "reloaded"] = "started",
        enabled: bool | None = None,
        sudo: bool = True,
        dry_run: bool | None = None,
    ) -> EnsureResult:
        """Идемпотентно управлять состоянием системного сервиса (синхронно)."""
        return self._run_coro(
            self._async_conn.ensure_service(
                service=service,
                state=state,
                enabled=enabled,
                sudo=sudo,
                dry_run=dry_run,
            )
        )

    def ensure_line(
        self,
        remote_path: str | Path,
        line: str,
        state: Literal["present", "absent"] = "present",
        regex: str | None = None,
        create: bool = True,
        backup: bool = False,
        mode: int | None = None,
        encoding: str = "utf-8",
        dry_run: bool | None = None,
    ) -> EnsureResult:
        """Идемпотентно обеспечить наличие или отсутствие строки в файле (синхронно)."""
        return self._run_coro(
            self._async_conn.ensure_line(
                remote_path=remote_path,
                line=line,
                state=state,
                regex=regex,
                create=create,
                backup=backup,
                mode=mode,
                encoding=encoding,
                dry_run=dry_run,
            )
        )

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


class SyncConnectionPool:
    """Синхронная обёртка над ``ConnectionPool`` на базе выделенного event loop в daemon-потоке.

    Позволяет выполнять групповые операции (``map``, ``map_safe``, ``upload``,
    ``download``, ``sync_dir``, ``write_template``, ``gather_facts``, ``ensure_*``,
    ``stream``) в синхронном коде без ручного вызова ``asyncio.run()``.

    Пример использования:
        with ConnectionPool(["local://", "local://"]).to_sync() as pool:
            facts = pool.gather_facts()
            results = pool.map("uname -a")
    """

    def __init__(self, async_pool: "ConnectionPool"):
        self._async_pool = async_pool
        self._loop: asyncio.AbstractEventLoop | None = None
        self._loop_thread: threading.Thread | None = None
        self._loop_lock = threading.Lock()
        self._closed = False

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        *,
        group: str | None = None,
        host: str | None = None,
        max_concurrent: int = 10,
        retry_attempts: int = 3,
        logger: logging.Logger | None = None,
    ) -> Self:
        """Создать синхронный пул подключений из JSON или YAML инвентарного файла."""
        from ._pool import ConnectionPool

        pool = ConnectionPool.from_file(
            path,
            group=group,
            host=host,
            max_concurrent=max_concurrent,
            retry_attempts=retry_attempts,
            logger=logger,
        )
        return cls(pool)

    def _get_loop(self) -> asyncio.AbstractEventLoop:
        with self._loop_lock:
            if self._loop is None or self._loop.is_closed():
                self._loop = asyncio.new_event_loop()
                self._loop_thread = threading.Thread(
                    target=SyncConnection._run_loop,
                    args=(self._loop,),
                    daemon=True,
                )
                self._loop_thread.start()
            return self._loop

    def _run_coro(self, coro: Any) -> Any:
        if self._closed:
            with contextlib.suppress(Exception):
                coro.close()
            raise RuntimeError("SyncConnectionPool уже закрыт")

        loop = self._get_loop()
        future = asyncio.run_coroutine_threadsafe(coro, loop)
        return future.result()

    def connect(self) -> None:
        """Открыть и удерживать соединения ко всем хостам пула (синхронно)."""
        self._run_coro(self._async_pool.connect())

    def close(self) -> None:
        """Закрыть все соединения пула и остановить фоновый event loop."""
        if self._closed:
            return

        with contextlib.suppress(Exception):
            self._run_coro(self._async_pool.close())

        self._closed = True

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
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def map(
        self,
        command: str | Sequence[str],
        timeout: float | None = None,
        raise_on_error: bool = False,
        **kwargs: Any,
    ) -> list[Result]:
        """Параллельно выполнить команду на всех хостах пула (синхронно)."""
        return self._run_coro(
            self._async_pool.map(
                command,
                timeout=timeout,
                raise_on_error=raise_on_error,
                **kwargs,
            )
        )

    def map_safe(
        self,
        command: str | Sequence[str],
        timeout: float | None = None,
        **kwargs: Any,
    ) -> dict[str, Result | Exception]:
        """Параллельно выполнить команду без выброса исключений (синхронно)."""
        return self._run_coro(
            self._async_pool.map_safe(command, timeout=timeout, **kwargs)
        )

    def map_with_callback(
        self,
        command: str | Sequence[str],
        callback: Callable[[str, Result], None],
        timeout: float | None = None,
        **kwargs: Any,
    ) -> None:
        """Параллельно выполнить команду с вызовом callback по мере готовности (синхронно)."""
        self._run_coro(
            self._async_pool.map_with_callback(
                command,
                callback=callback,
                timeout=timeout,
                **kwargs,
            )
        )

    def upload(
        self,
        local_path: str | Path,
        remote_path: str | Path,
        recurse: bool = False,
        **kwargs: Any,
    ) -> None:
        """Параллельно загрузить файл или директорию на все хосты пула (синхронно)."""
        self._run_coro(
            self._async_pool.upload(
                local_path,
                remote_path,
                recurse=recurse,
                **kwargs,
            )
        )

    def download(
        self,
        remote_path: str | Path,
        local_path: str | Path,
        recurse: bool = False,
        **kwargs: Any,
    ) -> dict[str, str]:
        """Параллельно скачать файл или директорию со всех хостов пула (синхронно)."""
        return self._run_coro(
            self._async_pool.download(
                remote_path,
                local_path,
                recurse=recurse,
                **kwargs,
            )
        )

    def sync_dir(
        self,
        local_dir: str | Path,
        remote_dir: str | Path,
        delete: bool = False,
        exclude: Sequence[str] | None = None,
        mtime_tolerance: float = 1.0,
        dry_run: bool | None = None,
    ) -> dict[str, SyncResult]:
        """Параллельно синхронизировать директорию на всех хостах пула (синхронно)."""
        return self._run_coro(
            self._async_pool.sync_dir(
                local_dir=local_dir,
                remote_dir=remote_dir,
                delete=delete,
                exclude=exclude,
                mtime_tolerance=mtime_tolerance,
                dry_run=dry_run,
            )
        )

    def write_template(
        self,
        remote_path: str | Path,
        template_str_or_path: str | Path,
        context: Mapping[str, Any] | None = None,
        mode: int | None = 0o644,
        encoding: str = "utf-8",
        engine: Literal["auto", "string", "jinja2"] = "auto",
    ) -> dict[str, str]:
        """Параллельно отрендерить и записать шаблон на всех хостах пула (синхронно)."""
        return self._run_coro(
            self._async_pool.write_template(
                remote_path=remote_path,
                template_str_or_path=template_str_or_path,
                context=context,
                mode=mode,
                encoding=encoding,
                engine=engine,
            )
        )

    def gather_facts(
        self,
        refresh: bool = False,
        timeout: float | None = None,
    ) -> dict[str, HostFacts]:
        """Параллельно собрать системные факты (``HostFacts``) со всех хостов пула (синхронно)."""
        return self._run_coro(
            self._async_pool.gather_facts(refresh=refresh, timeout=timeout)
        )

    def ensure_package(
        self,
        package: str | Sequence[str],
        state: Literal["present", "absent"] = "present",
        manager: Literal["auto", "apt", "dnf", "yum", "apk", "pacman", "zypper"] = "auto",
        update_cache: bool = False,
        sudo: bool = True,
        dry_run: bool | None = None,
    ) -> dict[str, EnsureResult]:
        """Параллельно проверить/установить/удалить пакет(ы) на всех хостах пула (синхронно)."""
        return self._run_coro(
            self._async_pool.ensure_package(
                package=package,
                state=state,
                manager=manager,
                update_cache=update_cache,
                sudo=sudo,
                dry_run=dry_run,
            )
        )

    def ensure_service(
        self,
        service: str,
        state: Literal["started", "stopped", "restarted", "reloaded"] = "started",
        enabled: bool | None = None,
        sudo: bool = True,
        dry_run: bool | None = None,
    ) -> dict[str, EnsureResult]:
        """Параллельно привести состояние системного сервиса на всех хостах пула (синхронно)."""
        return self._run_coro(
            self._async_pool.ensure_service(
                service=service,
                state=state,
                enabled=enabled,
                sudo=sudo,
                dry_run=dry_run,
            )
        )

    def ensure_line(
        self,
        remote_path: str | Path,
        line: str,
        state: Literal["present", "absent"] = "present",
        regex: str | None = None,
        create: bool = True,
        backup: bool = False,
        mode: int | None = None,
        encoding: str = "utf-8",
        dry_run: bool | None = None,
    ) -> dict[str, EnsureResult]:
        """Параллельно обеспечить наличие или отсутствие строки в файле на всех хостах пула (синхронно)."""
        return self._run_coro(
            self._async_pool.ensure_line(
                remote_path=remote_path,
                line=line,
                state=state,
                regex=regex,
                create=create,
                backup=backup,
                mode=mode,
                encoding=encoding,
                dry_run=dry_run,
            )
        )

    def stream(
        self,
        command: str | Sequence[str],
        timeout: float | None = None,
        **kwargs: Any,
    ) -> Iterator[tuple[str, str]]:
        """Синхронный генератор мульти-стриминга со всех хостов пула.

        Yields:
            Кортежи ``(target_key, line)``.

        """
        if self._closed:
            raise RuntimeError("SyncConnectionPool уже закрыт")

        loop = self._get_loop()
        q: asyncio.Queue[Any] = asyncio.Queue()

        async def _pump() -> None:
            try:
                async for item in self._async_pool.stream(
                    command, timeout=timeout, **kwargs
                ):
                    await q.put(item)
            except asyncio.CancelledError:
                raise
            except Exception as e:
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
            if not pump_future.done():
                pump_future.cancel()
                with contextlib.suppress(BaseException):
                    pump_future.result(timeout=2.0)


