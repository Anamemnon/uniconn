# src/uniconn/background/_log_pipeline.py
import asyncio
import logging
import shlex
import time
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Sequence
from datetime import datetime
from pathlib import Path

from .._connection import Connection
from ._models import LogEvent

logger = logging.getLogger(__name__)


class LogHandler(ABC):
    """Абстрактный обработчик порций логов screen-сессии."""

    @abstractmethod
    async def handle(self, session_id: str, chunk: list[str]) -> None:
        """Обработать порцию строк лога."""


class NullHandler(LogHandler):
    """Обработчик-заглушка: ничего не делает (режим collect=False)."""

    async def handle(self, session_id: str, chunk: list[str]) -> None:
        """Игнорировать порцию лога."""
        return None


class LocalFileHandler(LogHandler):
    """Запись логов в локальный файл.

    Имя файла задаётся шаблоном с переменными:
    ``{pool_id}``, ``{session_id}``, ``{idx}``, ``{timestamp}``,
    ``{host}``, ``{command}``. Для ``{timestamp}`` поддерживается
    format spec, например ``{timestamp:%Y%m%d_%H%M%S}``.

    Стратегии записи (download_strategy):
    - ``realtime`` — каждая порция сразу дописывается в файл;
    - ``periodic`` — порции буферизуются и сбрасываются не чаще,
      чем раз в ``periodic_interval`` секунд;
    - ``on_complete`` — порции буферизуются, запись выполняется
      при вызове ``finalize()``.
    """

    DEFAULT_TEMPLATE = "{session_id}.log"

    def __init__(
        self,
        local_dir: str,
        name_template: str | None = None,
        pool_id: str = "",
        idx: int = 0,
        host: str = "",
        command: str = "",
        strategy: str = "on_complete",
        periodic_interval: float = 5.0,
        logger: logging.Logger | None = None,
    ):
        self._local_dir = Path(local_dir)
        self._name_template = name_template or self.DEFAULT_TEMPLATE
        self._pool_id = pool_id
        self._idx = idx
        self._host = host
        self._command = command
        self._strategy = strategy
        self._periodic_interval = periodic_interval
        self._logger = logger or logging.getLogger(__name__)
        self._paths: dict[str, Path] = {}
        self._buffers: dict[str, list[str]] = {}
        self._last_flush: dict[str, float] = {}

    def local_path(self, session_id: str) -> Path:
        """Путь к локальному файлу лога сессии (резолвится один раз)."""
        if session_id not in self._paths:
            name = self._name_template.format(
                pool_id=self._pool_id,
                session_id=session_id,
                idx=self._idx,
                timestamp=datetime.now(),
                host=self._host,
                command=self._command,
            )
            self._paths[session_id] = self._local_dir / name
        return self._paths[session_id]

    def _write(self, session_id: str, lines: list[str]) -> None:
        """Дописать строки в локальный файл (создаёт директории)."""
        path = self.local_path(session_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.writelines(lines)

    async def handle(self, session_id: str, chunk: list[str]) -> None:
        """Обработать порцию лога согласно стратегии."""
        if self._strategy == "realtime":
            self._write(session_id, chunk)
        elif self._strategy == "periodic":
            buffer = self._buffers.setdefault(session_id, [])
            buffer.extend(chunk)
            now = time.monotonic()
            last = self._last_flush.get(session_id, 0.0)
            if now - last >= self._periodic_interval:
                self._write(session_id, buffer)
                buffer.clear()
                self._last_flush[session_id] = now
        else:  # on_complete
            self._buffers.setdefault(session_id, []).extend(chunk)

    async def finalize(self, session_id: str) -> Path:
        """Записать накопленный буфер (для periodic/on_complete) и вернуть путь."""
        buffer = self._buffers.pop(session_id, [])
        if buffer:
            self._write(session_id, buffer)
        return self.local_path(session_id)


class ForwardHandler(LogHandler):
    """Пересылка логов на другой хост (дописывание в удалённый файл).

    Best-effort: при ошибке пересылки пишет warning в лог и не падает —
    лог остаётся доступен через другие обработчики.
    """

    def __init__(
        self,
        connection: Connection,
        remote_path: str,
        logger: logging.Logger | None = None,
    ):
        self._connection = connection
        self._remote_path = remote_path
        self._logger = logger or logging.getLogger(__name__)

    async def handle(self, session_id: str, chunk: list[str]) -> None:
        """Дописать порцию лога в файл на удалённом хосте."""
        text = "".join(chunk)
        try:
            await self._connection.run(
                f"printf '%s' {shlex.quote(text)} >> {shlex.quote(self._remote_path)}"
            )
        except Exception as exc:
            self._logger.warning(
                f"Forward логов сессии {session_id} на {self._remote_path} "
                f"не удался: {exc}"
            )


class StreamHandler(LogHandler):
    """Отдача логов в Python-код через очередь событий LogEvent."""

    def __init__(self):
        self._queue: asyncio.Queue[LogEvent] = asyncio.Queue()

    async def handle(self, session_id: str, chunk: list[str]) -> None:
        """Положить каждую строку порции в очередь как LogEvent."""
        for line in chunk:
            await self._queue.put(LogEvent(session_id=session_id, line=line))

    async def events(self) -> AsyncIterator[LogEvent]:
        """Бесконечный асинхронный итератор событий лога."""
        while True:
            yield await self._queue.get()


class LogPipeline:
    """Pipeline обработки логов: рассылает порции всем обработчикам."""

    def __init__(self, handlers: Sequence[LogHandler]):
        self._handlers = list(handlers)

    async def emit(self, session_id: str, chunk: list[str]) -> None:
        """Отправить порцию лога всем обработчикам параллельно."""
        await asyncio.gather(
            *(h.handle(session_id, chunk) for h in self._handlers)
        )
