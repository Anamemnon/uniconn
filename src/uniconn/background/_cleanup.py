# src/uniconn/background/_cleanup.py
import asyncio
import atexit
import contextlib
import json
import logging
import shlex
import signal
from collections.abc import Callable
from types import FrameType

from .._connection import Connection
from ._session import ScreenSession

logger = logging.getLogger(__name__)


class ScreenCleanupManager:
    """Менеджер очистки screen-сессий и их артефактов.

    Многоуровневая защита от зомби-процессов и утечки диска:
    - клиент: ``atexit`` + обработчики SIGINT/SIGTERM → остановка сессий;
    - сервер: cleanup-скрипт ``/tmp/uniconn_cleanup_{pool_id}.sh``
      и sentinel-файл ``/tmp/uniconn_{pool_id}.active`` (fail-safe,
      можно запустить вручную после обрыва SSH).

    Двойной Ctrl+C (два сигнала подряд) → принудительное завершение.
    """

    def __init__(
        self,
        pool_id: str,
        logger: logging.Logger | None = None,
    ):
        self._pool_id = pool_id
        self._logger = logger or logging.getLogger(__name__)
        self._sessions: dict[str, ScreenSession] = {}
        self._signal_count = 0
        self._installed = False
        self._previous_handlers: dict[int, signal.Handlers | Callable | int | None] = {}

    @property
    def sentinel_path(self) -> str:
        """Путь к sentinel-файлу пула на сервере."""
        return f"/tmp/uniconn_{self._pool_id}.active"

    @property
    def cleanup_script_path(self) -> str:
        """Путь к cleanup-скрипту пула на сервере."""
        return f"/tmp/uniconn_cleanup_{self._pool_id}.sh"

    @property
    def sessions(self) -> dict[str, ScreenSession]:
        """Зарегистрированные сессии (session_id → ScreenSession)."""
        return self._sessions

    def register_session(self, session: ScreenSession) -> None:
        """Зарегистрировать сессию и установить хуки очистки."""
        self._sessions[session.session_id] = session
        self._install_hooks()

    def _install_hooks(self) -> None:
        """Установить atexit и signal handlers (однократно)."""
        if self._installed:
            return
        atexit.register(self.cleanup_local)
        try:
            for sig in (signal.SIGINT, signal.SIGTERM):
                self._previous_handlers[sig] = signal.getsignal(sig)
                signal.signal(sig, self._on_signal)
        except ValueError:
            # signal handlers можно ставить только в main thread
            self._previous_handlers.clear()
            self._logger.debug(
                "Signal handlers недоступны (не main thread), только atexit"
            )
        self._installed = True

    def uninstall(self) -> None:
        """Снять хуки очистки и восстановить прежние signal handlers."""
        if not self._installed:
            return
        atexit.unregister(self.cleanup_local)
        for sig, handler in self._previous_handlers.items():
            with contextlib.suppress(ValueError):
                signal.signal(sig, handler)
        self._previous_handlers.clear()
        self._installed = False

    def _on_signal(self, signum: int, frame: FrameType | None) -> None:
        """Обработчик SIGINT/SIGTERM: очистка, затем проброс сигнала дальше."""
        self._signal_count += 1
        force = self._signal_count >= 2
        if force:
            self._logger.warning(
                "Повторный сигнал %s — принудительное завершение сессий", signum
            )
        else:
            self._logger.info(
                "Сигнал %s — graceful остановка screen-сессий", signum
            )
        self.cleanup_local(force=force)
        previous = self._previous_handlers.get(signum)
        if callable(previous):
            previous(signum, frame)

    def cleanup_local(self, force: bool = False) -> None:
        """Синхронная очистка всех сессий (вызывается из atexit/signal)."""
        if not self._sessions:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is not None:
            loop.create_task(self.cleanup_all(graceful=not force))
        else:
            asyncio.run(self.cleanup_all(graceful=not force))

    async def cleanup_all(self, graceful: bool = True) -> None:
        """Асинхронная остановка всех зарегистрированных сессий."""
        for session in list(self._sessions.values()):
            try:
                await session.kill(graceful=graceful)
            except Exception as exc:
                self._logger.warning(
                    f"Ошибка остановки сессии {session.session_id}: {exc}"
                )

    def generate_cleanup_script(self) -> str:
        """Сгенерировать bash-скрипт очистки пула на сервере.

        Скрипт убивает все screen-сессии пула по префиксу ``uniconn_{pool_id}_``,
        удаляет логи, exit-файлы, wrapper-скрипты, sentinel и сам себя.
        """
        return f"""#!/bin/bash
POOL_ID="{self._pool_id}"
for s in $(screen -ls | grep "uniconn_${{POOL_ID}}_" | awk '{{print $1}}'); do
    screen -S "$s" -X kill 2>/dev/null
done
rm -f /tmp/uniconn_${{POOL_ID}}_*.log
rm -f /tmp/uniconn_${{POOL_ID}}_*.exit
rm -f /tmp/uniconn_${{POOL_ID}}_*.sh
rm -f /tmp/uniconn_${{POOL_ID}}.active
rm -f "$0"
"""

    async def install_server_side(self, connection: Connection) -> None:
        """Загрузить на сервер sentinel-файл и cleanup-скрипт.

        Sentinel — JSON со списком сессий пула, нужен для ручной
        диагностики после обрыва SSH.
        """
        sentinel = json.dumps({
            "pool_id": self._pool_id,
            "sessions": sorted(self._sessions),
        })
        await connection.run(
            f"printf '%s' {shlex.quote(sentinel)} > {self.sentinel_path}"
        )
        await connection.run(
            f"printf '%s' {shlex.quote(self.generate_cleanup_script())} "
            f"> {self.cleanup_script_path}"
        )
        await connection.run(f"chmod +x {self.cleanup_script_path}")
