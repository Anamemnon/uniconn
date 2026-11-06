# src/uniconn/background/_log_collector.py
import logging
import shlex

from ..core.connection import Connection
from ._session import BackgroundSession

logger = logging.getLogger(__name__)


class BackgroundLogCollector:
    """Порционное чтение логов фоновых сессий без постоянного SSH-канала.

    Хранит смещение (в байтах) для каждой сессии и при очередном опросе
    читает только новые данные через ``tail -c +{offset + 1}`` (в ``tail -c +N``
    нумерация байтов начинается с 1).
    """

    def __init__(
        self,
        connection: Connection,
        logger: logging.Logger | None = None,
    ):
        self._connection = connection
        self._logger = logger or logging.getLogger(__name__)
        self._offsets: dict[str, int] = {}

    def get_offset(self, session_id: str) -> int:
        """Текущее смещение в байтах для сессии (0, если ещё не читалась)."""
        return self._offsets.get(session_id, 0)

    def reset_offset(self, session_id: str) -> None:
        """Сбросить смещение для сессии в 0."""
        self._offsets.pop(session_id, None)

    def _is_windows_session(self, session: BackgroundSession) -> bool:
        """Проверить, относится ли сессия к WindowsJobBackend или WinRM/WSMan."""
        b_name = getattr(session, "backend_name", None)
        if isinstance(b_name, str) and b_name == "windows_job":
            return True
        t_name = getattr(self._connection, "transport_name", None)
        if isinstance(t_name, str) and t_name in ("winrm", "wsman"):
            return True
        cfg = getattr(self._connection, "config", None)
        cfg_t = getattr(cfg, "transport", None)
        return isinstance(cfg_t, str) and cfg_t in ("winrm", "wsman")

    async def read_chunk(self, session: BackgroundSession) -> tuple[list[str], int]:
        """Прочитать новую порцию лога сессии с последнего смещения.

        Порядок действий:
        1. Узнать текущий размер файла (``stat -c %s {log}`` или ``Get-Item``).
        2. Если ``size <= offset`` (новых данных нет или файл ещё не создан) —
           вернуть ``([], offset)``.
        3. Прочитать новые байты (``tail -c +{offset + 1} {log}`` или ``FileStream``) и
           обновить сохранённое смещение до ``size``.

        Args:
            session: Сессия, лог которой нужно прочитать

        Returns:
            Кортеж ``(строки, новое_смещение)``

        """
        offset = self.get_offset(session.session_id)

        if self._is_windows_session(session):
            ps_path = "'" + session.remote_log_path.replace("'", "''") + "'"
            stat_cmd = f"if (Test-Path {ps_path}) {{ (Get-Item {ps_path}).Length }} else {{ exit 1 }}"
            stat_result = await self._connection.run(stat_cmd)
            if not stat_result.ok:
                return [], offset
            try:
                size = int(stat_result.stdout.strip())
            except ValueError:
                return [], offset

            if size < offset:
                offset = 0
            if size == offset:
                return [], offset

            read_cmd = (
                f"$fs = [System.IO.File]::Open({ps_path}, [System.IO.FileMode]::Open, "
                "[System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite); "
                f"try {{ $null = $fs.Seek({offset}, [System.IO.SeekOrigin]::Begin); "
                "$sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8); "
                "[Console]::Out.Write($sr.ReadToEnd()) } finally { $fs.Dispose() }"
            )
            tail_result = await self._connection.run(read_cmd)
            if not tail_result.ok:
                return [], offset
            data = tail_result.stdout
            new_offset = offset + len(data.encode("utf-8"))
            self._offsets[session.session_id] = new_offset
            return data.splitlines(keepends=True), new_offset

        quoted_path = shlex.quote(session.remote_log_path)

        stat_result = await self._connection.run(f"stat -c %s {quoted_path}")
        if not stat_result.ok:
            return [], offset
        try:
            size = int(stat_result.stdout.strip())
        except ValueError:
            return [], offset

        if size < offset:
            offset = 0
        if size == offset:
            return [], offset

        # tail -c +N: 1-based смещение, поэтому передаём offset + 1
        tail_result = await self._connection.run(
            f"tail -c +{offset + 1} {quoted_path}"
        )
        if not tail_result.ok:
            return [], offset

        data = tail_result.stdout
        new_offset = offset + len(data.encode("utf-8"))
        self._offsets[session.session_id] = new_offset
        lines = data.splitlines(keepends=True)
        return lines, new_offset

    async def read_all(self, session: BackgroundSession) -> str:
        """Прочитать лог-файл сессии целиком (независимо от смещения)."""
        if self._is_windows_session(session):
            ps_path = "'" + session.remote_log_path.replace("'", "''") + "'"
            result = await self._connection.run(
                f"if (Test-Path {ps_path}) {{ Get-Content -Path {ps_path} -Raw }} else {{ exit 1 }}"
            )
        else:
            result = await self._connection.run(
                f"cat {shlex.quote(session.remote_log_path)}"
            )
        if not result.ok:
            return ""
        return result.stdout
