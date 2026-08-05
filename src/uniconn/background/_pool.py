# src/uniconn/background/_pool.py
import asyncio
import logging
import time
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Self
from urllib.parse import urlparse, urlunparse

from .._connection import Connection
from ..exceptions import ScreenError, ScreenPoolFullError
from ._cleanup import ScreenCleanupManager
from ._config import LogConfig, LogRule, ScreenPoolConfig
from ._log_collector import ScreenLogCollector
from ._log_pipeline import (
    ForwardHandler,
    LocalFileHandler,
    LogHandler,
    LogPipeline,
    NullHandler,
)
from ._models import LogEvent, ScreenResult, StatusEvent
from ._session import ScreenSession

logger = logging.getLogger(__name__)

# Exit code для сессий, убитых до записи exit-файла wrapper-скриптом
FORCED_EXIT_CODE = -1


class ScreenPool:
    """Оркестратор множества screen-сессий на одном удалённом хосте.

    Управляет запуском долгоживущих команд в detached GNU screen сессиях,
    периодическим опросом их статуса и логов (polling + tail, без постоянного
    SSH-канала) и гарантированной очисткой ресурсов.

    Число параллельных SSH-запросов ограничено семафором ``max_monitors``:
    семафор захватывается на каждый SSH-запрос мониторинга (опрос статуса,
    чтение логов), а также на остановку сессий (``stop()``/force kill в
    ``wait_all()``), а не на весь цикл опроса, поэтому N сессий
    опрашиваются конкурентно, но не более ``max_monitors`` одновременных
    запросов.
    """

    def __init__(
        self,
        uri: str,
        max_screens: int = 16,
        max_monitors: int = 4,
        poll_interval: float = 5.0,
        log_config: LogConfig | None = None,
        logger: logging.Logger | None = None,
    ):
        self._uri = uri
        self._max_screens = max_screens
        self._max_monitors = max_monitors
        self._poll_interval = poll_interval
        self._log_config = log_config or LogConfig()
        self._logger = logger or logging.getLogger(__name__)

        self._pool_id = uuid.uuid4().hex[:8]
        self._session_prefix = f"uniconn_{self._pool_id}"

        self._sessions: dict[str, ScreenSession] = {}
        self._rules: dict[str, LogRule | None] = {}
        self._pipelines: dict[str, LogPipeline] = {}
        self._local_handlers: dict[str, LocalFileHandler] = {}
        self._start_times: dict[str, float] = {}
        self._counter = 0

        self._monitor_sem = asyncio.Semaphore(max_monitors)
        self._start_lock = asyncio.Lock()
        self._connection: Connection | None = None
        self._collector: ScreenLogCollector | None = None
        self._cleanup_manager = ScreenCleanupManager(self._pool_id, logger=self._logger)

    @classmethod
    def from_config(
        cls,
        config: ScreenPoolConfig,
        logger: logging.Logger | None = None,
    ) -> Self:
        """Создать пул из объекта конфигурации ScreenPoolConfig."""
        return cls(
            uri=config.uri,
            max_screens=config.max_screens,
            max_monitors=config.max_monitors,
            poll_interval=config.poll_interval,
            log_config=config.log_config,
            logger=logger,
        )

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        logger: logging.Logger | None = None,
    ) -> Self:
        """Создать пул из YAML/JSON файла конфигурации."""
        return cls.from_config(ScreenPoolConfig.from_file(path), logger=logger)

    @property
    def pool_id(self) -> str:
        """Уникальный идентификатор пула (короткий UUID4)."""
        return self._pool_id

    @property
    def session_prefix(self) -> str:
        """Префикс имён screen-сессий пула: ``uniconn_{pool_id}``."""
        return self._session_prefix

    @property
    def sessions(self) -> dict[str, ScreenSession]:
        """Активные сессии пула (session_id → ScreenSession)."""
        return dict(self._sessions)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.cleanup()

    async def _ensure_connection(self) -> Connection:
        """Лениво создать подключение к хосту из URI."""
        if self._connection is None:
            self._connection = Connection.from_uri(self._uri, logger=self._logger)
        return self._connection

    def _host(self) -> str:
        """Имя хоста для шаблонов имён локальных логов (устойчиво к мокам)."""
        if self._connection is None:
            return ""
        host = getattr(getattr(self._connection, "config", None), "host", None)
        return host if isinstance(host, str) else ""

    def _get_collector(self) -> ScreenLogCollector:
        """Лениво создать сборщик логов (нужно подключение)."""
        if self._collector is None:
            if self._connection is None:
                raise ScreenError("Нет активных сессий: подключение не создано")
            self._collector = ScreenLogCollector(self._connection, logger=self._logger)
        return self._collector

    def _build_forward_handler(self, forward_to: str) -> ForwardHandler | None:
        """Создать ForwardHandler из URI вида ``sftp://host/path``.

        Best-effort: при неудаче пишет warning и возвращает None —
        лог остаётся доступен через остальные обработчики.
        """
        parsed = urlparse(forward_to)
        if not parsed.netloc:
            self._logger.warning(f"Некорректный forward_to URI: {forward_to!r}")
            return None
        try:
            base_uri = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
            connection = Connection.from_uri(base_uri, logger=self._logger)
        except Exception as exc:
            self._logger.warning(f"Не удалось подключиться для forward логов: {exc}")
            return None
        remote_path = parsed.path or f"/tmp/uniconn_{self._pool_id}_forward.log"
        return ForwardHandler(connection, remote_path, logger=self._logger)

    def _build_pipeline(self, session: ScreenSession, command: str, idx: int) -> None:
        """Построить LogPipeline для сессии по правилам LogConfig."""
        rule = self._rules[session.session_id]
        handlers: list[LogHandler] = []

        if rule is not None and not rule.collect:
            handlers.append(NullHandler())
        else:
            if rule is None or rule.download:
                local_handler = LocalFileHandler(
                    local_dir=self._log_config.local_dir,
                    name_template=rule.local_name if rule else None,
                    pool_id=self._pool_id,
                    idx=idx,
                    host=self._host(),
                    command=command,
                    strategy=rule.download_strategy if rule else "on_complete",
                    logger=self._logger,
                )
                handlers.append(local_handler)
                self._local_handlers[session.session_id] = local_handler
            if rule is not None and rule.forward_to:
                forward_handler = self._build_forward_handler(rule.forward_to)
                if forward_handler is not None:
                    handlers.append(forward_handler)

        self._pipelines[session.session_id] = LogPipeline(handlers)

    async def start(self, command: str, name: str | None = None) -> ScreenSession:
        """Запустить команду в новой detached screen-сессии.

        Проверка лимита и регистрация сессии выполняются под lock —
        конкурентные ``start()`` не могут превысить ``max_screens``.

        Args:
            command: Команда для выполнения на удалённом хосте
            name: Явное имя сессии (по умолчанию ``{prefix}_{idx}``)

        Returns:
            Созданная ScreenSession

        Raises:
            ScreenPoolFullError: Достигнут лимит max_screens
            ScreenNotFoundError: GNU screen не установлен на хосте
            ScreenSessionExistsError: Сессия с таким именем уже существует

        """
        async with self._start_lock:
            if len(self._sessions) >= self._max_screens:
                raise ScreenPoolFullError(
                    f"Достигнут лимит сессий пула (max_screens={self._max_screens})"
                )

            connection = await self._ensure_connection()
            idx = self._counter
            self._counter += 1
            session_id = name or f"{self._session_prefix}_{idx}"
            session = ScreenSession(
                connection, session_id, f"/tmp/{session_id}.log", logger=self._logger
            )
            await session.create(command)

            self._sessions[session_id] = session
            self._rules[session_id] = self._log_config.match_rule(command)
            self._build_pipeline(session, command, idx)
            self._start_times[session_id] = time.monotonic()
            self._cleanup_manager.register_session(session)

            # Fail-safe на сервере (sentinel + cleanup-скрипт): обновляется
            # при каждом старте, чтобы список сессий был актуален и включал
            # сессии с пользовательскими именами
            await self._cleanup_manager.install_server_side(connection)

        self._logger.info(f"Запущена screen-сессия {session_id}: {command!r}")
        return session

    async def _is_alive_guarded(self, session: ScreenSession) -> bool:
        """Проверить живость сессии с ограничением числа SSH-запросов."""
        async with self._monitor_sem:
            return await session.is_alive()

    async def _read_chunk_guarded(self, session: ScreenSession) -> tuple[list[str], int]:
        """Прочитать порцию лога с ограничением числа SSH-запросов."""
        async with self._monitor_sem:
            return await self._get_collector().read_chunk(session)

    async def _status_event(self, session: ScreenSession) -> StatusEvent:
        """Опросить статус сессии (один слот семафора на весь опрос)."""
        async with self._monitor_sem:
            alive = await session.is_alive()
            pid = await session.get_pid() if alive else None
            exit_code = None if alive else await session.get_exit_code()
        return StatusEvent(
            session_id=session.session_id, alive=alive, pid=pid, exit_code=exit_code
        )

    async def _finalize_session(self, session: ScreenSession) -> ScreenResult:
        """Сформировать результат завершившейся сессии и снять её с учёта.

        Дочитывает остаток лога в pipeline, финализирует локальный файл
        (стратегии periodic/on_complete), при ``delete_remote=True`` удаляет
        артефакты сессии на сервере.
        """
        session_id = session.session_id

        lines, _ = await self._read_chunk_guarded(session)
        # Доступ через .get(): сессия могла быть снята с учёта конкурентным
        # stop()/wait_all() между проверкой живости и финализацией
        pipeline = self._pipelines.get(session_id)
        if lines and pipeline is not None:
            await pipeline.emit(session_id, lines)

        exit_code = await session.get_exit_code()
        if exit_code is None:
            # Сессия убита до того, как wrapper-скрипт записал exit-файл
            exit_code = FORCED_EXIT_CODE

        local_log_path: str | None = None
        local_handler = self._local_handlers.get(session_id)
        if local_handler is not None:
            local_log_path = str(await local_handler.finalize(session_id))

        rule = self._rules.get(session_id)
        if rule is not None and rule.delete_remote:
            await session.cleanup()

        duration = time.monotonic() - self._start_times.get(session_id, time.monotonic())

        self._sessions.pop(session_id, None)
        self._rules.pop(session_id, None)
        self._pipelines.pop(session_id, None)
        self._local_handlers.pop(session_id, None)
        self._start_times.pop(session_id, None)
        self._cleanup_manager.sessions.pop(session_id, None)

        return ScreenResult(
            session_id=session_id,
            exit_code=exit_code,
            remote_log_path=session.remote_log_path,
            local_log_path=local_log_path,
            duration=duration,
        )

    async def stop(self, session_id: str, graceful: bool = True) -> ScreenResult:
        """Остановить конкретную сессию и вернуть её результат.

        Args:
            session_id: Имя сессии
            graceful: Сначала Ctrl+C с ожиданием, затем force kill

        Raises:
            ScreenError: Сессия с таким именем не найдена в пуле

        """
        session = self._sessions.get(session_id)
        if session is None:
            raise ScreenError(f"Сессия {session_id!r} не найдена в пуле")
        # Kill идёт через те же SSH-запросы (screen -ls/-X kill), что и
        # мониторинг — тоже ограничиваем их семафором max_monitors
        async with self._monitor_sem:
            await session.kill(graceful=graceful)
        return await self._finalize_session(session)

    async def _stop_safe(self, session_id: str, graceful: bool) -> None:
        """Остановить сессию, не прерывая остановку остальных при ошибке."""
        try:
            await self.stop(session_id, graceful=graceful)
        except Exception as exc:
            self._logger.warning(f"Ошибка остановки сессии {session_id}: {exc}")

    async def stop_all(self, graceful: bool = True) -> None:
        """Остановить все активные сессии пула."""
        async with asyncio.TaskGroup() as tg:
            for session_id in list(self._sessions):
                tg.create_task(self._stop_safe(session_id, graceful))

    async def wait_all(self, timeout: float | None = None) -> dict[str, ScreenResult]:
        """Дождаться завершения всех сессий и вернуть их результаты.

        Args:
            timeout: Максимальное время ожидания в секундах.
                По истечении оставшиеся сессии принудительно убиваются
                (force kill), их exit code будет -1.

        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout if timeout is not None else None
        results: dict[str, ScreenResult] = {}
        pending = list(self._sessions.values())

        while pending:
            async with asyncio.TaskGroup() as tg:
                alive_checks = {
                    s.session_id: tg.create_task(self._is_alive_guarded(s)) for s in pending
                }
            still_pending = []
            for session in pending:
                if alive_checks[session.session_id].result():
                    still_pending.append(session)
                else:
                    results[session.session_id] = await self._finalize_session(session)
            pending = still_pending

            if not pending:
                break
            if deadline is not None and loop.time() >= deadline:
                self._logger.warning(
                    f"wait_all: таймаут {timeout}с, force kill {len(pending)} сессий"
                )
                for session in pending:
                    async with self._monitor_sem:
                        await session.kill(graceful=False)
                    results[session.session_id] = await self._finalize_session(session)
                break
            await asyncio.sleep(self._poll_interval)

        return results

    async def poll_logs(self, interval: float = 2.0) -> AsyncIterator[LogEvent]:
        """Периодически опрашивать логи всех сессий.

        Каждая порция лога рассылается в LogPipeline сессии (файл, forward
        и т.д.), а строки отдаются наружу как LogEvent. Завершившиеся сессии
        исключаются из опроса (но остаются в ``sessions`` — результаты
        забираются через ``wait_all()``/``stop()``); генератор завершается,
        когда активных сессий не осталось.
        """
        done: set[str] = set()
        while True:
            sessions = [s for s in self._sessions.values() if s.session_id not in done]
            if not sessions:
                break
            async with asyncio.TaskGroup() as tg:
                reads = {s.session_id: tg.create_task(self._read_chunk_guarded(s))
                         for s in sessions}
                alives = {s.session_id: tg.create_task(self._is_alive_guarded(s))
                          for s in sessions}
            for session in sessions:
                session_id = session.session_id
                lines, _ = reads[session_id].result()
                pipeline = self._pipelines.get(session_id)
                if lines and pipeline is not None:
                    await pipeline.emit(session_id, lines)
                for line in lines:
                    yield LogEvent(session_id=session_id, line=line)
                if not alives[session_id].result():
                    done.add(session_id)
            if all(s.session_id in done or s.session_id not in self._sessions
                   for s in sessions):
                break
            await asyncio.sleep(interval)

    async def poll_status(self, interval: float = 5.0) -> AsyncIterator[StatusEvent]:
        """Периодически опрашивать статус всех сессий.

        Завершившаяся сессия отдаёт финальный ``StatusEvent(alive=False,
        exit_code=...)`` и исключается из дальнейшего опроса (но остаётся
        в ``sessions`` — результаты забираются через ``wait_all()``/``stop()``).
        Генератор завершается, когда активных сессий не осталось.
        """
        done: set[str] = set()
        while True:
            sessions = [s for s in self._sessions.values() if s.session_id not in done]
            if not sessions:
                break
            async with asyncio.TaskGroup() as tg:
                checks = {s.session_id: tg.create_task(self._status_event(s))
                          for s in sessions}
            for session_id in checks:
                event = checks[session_id].result()
                yield event
                if not event.alive:
                    done.add(session_id)
            if all(s.session_id in done or s.session_id not in self._sessions
                   for s in sessions):
                break
            await asyncio.sleep(interval)

    async def disconnect(self) -> None:
        """Закрыть SSH-подключение, НЕ останавливая screen-сессии.

        Сессии продолжают работать в detached-режиме; серверный fail-safe
        (sentinel + cleanup-скрипт) остаётся на месте. Локальные хуки
        очистки (atexit/signal) снимаются, иначе они убили бы сессии
        при завершении процесса.
        """
        if self._connection is not None:
            await self._connection.close()
            self._connection = None
            self._collector = None
        self._cleanup_manager.uninstall()

    async def cleanup(self) -> None:
        """Остановить все сессии и удалить артефакты пула на сервере."""
        await self.stop_all(graceful=True)
        if self._connection is not None:
            await self._connection.run(
                f"rm -f {self._cleanup_manager.sentinel_path} "
                f"{self._cleanup_manager.cleanup_script_path}"
            )
            await self._connection.close()
            self._connection = None
            self._collector = None
        self._cleanup_manager.uninstall()
