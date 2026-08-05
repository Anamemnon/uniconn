# src/uniconn/background/_cleanup.py
import asyncio
import atexit
import contextlib
import json
import logging
import shlex
import signal
import threading
from collections.abc import Callable, Iterable
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
        """Обработчик SIGINT/SIGTERM: очистка, затем проброс сигнала дальше.

        После очистки сигнал должен привести к завершению процесса:
        вызывается прежний обработчик, а если его не было (SIG_DFL) —
        восстанавливается дефолтный и сигнал отправляется процессу повторно.
        """
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
        elif previous == signal.SIG_DFL:
            # Прежнего обработчика не было: восстановить дефолтный и
            # повторно отправить сигнал себе, иначе процесс продолжит жить
            signal.signal(signum, signal.SIG_DFL)
            signal.raise_signal(signum)

    def cleanup_local(self, force: bool = False, timeout: float = 30.0) -> None:
        """Синхронная очистка всех сессий (вызывается из atexit/signal).

        Блокирует поток до завершения очистки (не более ``timeout`` секунд):
        fire-and-forget через ``loop.create_task`` не подходит — из signal
        handler процесс завершится раньше, чем задача успеет выполниться.
        Если event loop уже активен в этом потоке, очистка выполняется
        в отдельном потоке с собственным циклом (best-effort: SSH-объекты,
        привязанные к активному циклу, могут не сработать — ошибки
        логируются в ``cleanup_all``).
        """
        if not self._sessions:
            return
        try:
            asyncio.get_running_loop()
            has_running_loop = True
        except RuntimeError:
            has_running_loop = False

        if not has_running_loop:
            asyncio.run(self.cleanup_all(graceful=not force))
            return

        done = threading.Event()

        def _run_in_thread() -> None:
            try:
                asyncio.run(self.cleanup_all(graceful=not force))
            except Exception as exc:
                self._logger.warning(f"Ошибка cleanup из signal handler: {exc}")
            finally:
                done.set()

        threading.Thread(target=_run_in_thread, daemon=True).start()
        if not done.wait(timeout):
            self._logger.warning(
                f"Cleanup не завершился за {timeout:.1f} с, завершение процесса"
            )

    async def cleanup_all(self, graceful: bool = True) -> None:
        """Асинхронная остановка всех зарегистрированных сессий."""
        for session in list(self._sessions.values()):
            try:
                await session.kill(graceful=graceful)
            except Exception as exc:
                self._logger.warning(
                    f"Ошибка остановки сессии {session.session_id}: {exc}"
                )

    def generate_cleanup_script(self, session_ids: Iterable[str] | None = None) -> str:
        """Сгенерировать bash-скрипт очистки пула на сервере.

        Скрипт убивает screen-сессии пула по префиксу ``uniconn_{pool_id}_``,
        а также сессии с пользовательскими именами (по явному списку),
        удаляет их логи, exit-файлы, wrapper-скрипты, sentinel и сам себя.

        Args:
            session_ids: Имена сессий для включения в скрипт
                (по умолчанию — все зарегистрированные на данный момент).

        """
        if session_ids is None:
            session_ids = sorted(self._sessions)
        prefix = f"uniconn_{self._pool_id}_"
        custom = [s for s in session_ids if not s.startswith(prefix)]

        script = f"""#!/bin/bash
POOL_ID="{self._pool_id}"
for s in $(screen -ls | grep "uniconn_${{POOL_ID}}_" | awk '{{print $1}}'); do
    screen -S "$s" -X kill 2>/dev/null
done
"""
        # Сессии с пользовательскими именами префиксом не покрываются —
        # убиваем их и удаляем их артефакты по явным путям
        for name in custom:
            script += f"screen -S {shlex.quote(name)} -X kill 2>/dev/null\n"
            script += "rm -f " + " ".join(
                shlex.quote(p)
                for p in (
                    f"/tmp/{name}.log",
                    f"/tmp/uniconn_{name}.exit",
                    f"/tmp/uniconn_{name}.sh",
                )
            ) + "\n"
        script += """rm -f /tmp/uniconn_${POOL_ID}_*.log
rm -f /tmp/uniconn_${POOL_ID}_*.exit
rm -f /tmp/uniconn_${POOL_ID}_*.sh
rm -f /tmp/uniconn_${POOL_ID}.active
rm -f "$0"
"""
        return script

    async def install_server_side(self, connection: Connection) -> None:
        """Загрузить (или обновить) на сервере sentinel-файл и cleanup-скрипт.

        Sentinel — JSON со списком сессий пула, нужен для ручной
        диагностики после обрыва SSH. Вызывается при каждом запуске
        новой сессии, чтобы список не устаревал и включал сессии
        с пользовательскими именами.
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
