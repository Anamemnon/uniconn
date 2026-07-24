# src/uniconn/background/_log_collector.py
import asyncio
import logging
from collections.abc import AsyncIterator, Sequence

from .._connection import Connection
from ._models import LogEvent
from ._session import ScreenSession

logger = logging.getLogger(__name__)


class ScreenLogCollector:
    """Чтение логов screen-сессий порциями без постоянного SSH-канала.

    Принцип: для каждой сессии хранится байтовый offset. Перед чтением
    проверяется размер файла (``stat -c %s``): если размер меньше offset —
    лог был усечён/ротирован, offset сбрасывается в 0. Чтение выполняется
    через ``tail -c +{offset + 1}`` (tail считает байты с 1, а не с 0).
    Байтовый (а не построчный) offset корректно работает с UTF-8.
    """

    def __init__(
        self,
        connection: Connection,
        logger: logging.Logger | None = None,
    ):
        self._connection = connection
        self._logger = logger or logging.getLogger(__name__)
        self._offsets: dict[str, int] = {}

    async def read_chunk(self, session: ScreenSession) -> tuple[list[str], int]:
        """Прочитать новые строки лога с текущего offset.

        Returns:
            Кортеж (список строк с переводами строк, новый offset).
            Если лог-файла ещё нет или новых данных нет — ([], текущий offset).

        """
        offset = self._offsets.get(session.session_id, 0)
        log_path = session.remote_log_path

        size_result = await self._connection.run(f"stat -c %s {log_path}")
        if not size_result.ok:
            return [], offset
        try:
            size = int(size_result.stdout.strip())
        except ValueError:
            return [], offset

        if size < offset:
            self._logger.warning(
                f"Лог сессии {session.session_id} усечён "
                f"(размер {size} < offset {offset}), чтение с начала"
            )
            offset = 0
        if size == offset:
            return [], offset

        result = await self._connection.run(f"tail -c +{offset + 1} {log_path}")
        if not result.ok or not result.stdout:
            return [], offset

        data = result.stdout
        offset += len(data.encode("utf-8"))
        self._offsets[session.session_id] = offset
        return data.splitlines(keepends=True), offset

    async def stream(
        self,
        session: ScreenSession,
        interval: float = 1.0,
    ) -> AsyncIterator[str]:
        """Бесконечный асинхронный итератор новых строк лога сессии."""
        while True:
            lines, _ = await self.read_chunk(session)
            for line in lines:
                yield line
            await asyncio.sleep(interval)

    async def stream_all(
        self,
        sessions: Sequence[ScreenSession],
        interval: float = 1.0,
    ) -> AsyncIterator[LogEvent]:
        """Мультиплексированный поток событий лога от нескольких сессий."""
        while True:
            for session in sessions:
                lines, _ = await self.read_chunk(session)
                for line in lines:
                    yield LogEvent(session_id=session.session_id, line=line)
            await asyncio.sleep(interval)
