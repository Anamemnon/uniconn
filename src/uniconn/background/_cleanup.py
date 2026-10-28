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

from ..core.connection import Connection
from ._session import BackgroundSession

logger = logging.getLogger(__name__)


class BackgroundCleanupManager:
    """Менеджер очистки фоновых сессий и их артефактов.

    Многоуровневая защита от зомби-процессов и утечки диска:
    - клиент: ``atexit`` + обработчики SIGINT/SIGTERM → остановка сессий;
    - сервер: cleanup-скрипт ``/tmp/uniconn_cleanup_{pool_id}.sh``
      и sentinel-файл ``/tmp/uniconn_{pool_id}.active`` (fail-safe,
      работает для всех бэкендов: tmux, screen и nohup/PID).

    Двойной Ctrl+C (два сигнала подряд) → принудительное завершение.
    """

    def __init__(
        self,
        pool_id: str,
        logger: logging.Logger | None = None,
    ):
        self._pool_id = pool_id
        self._logger = logger or logging.getLogger(__name__)
        self._sessions: dict[str, BackgroundSession] = {}
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
    def sessions(self) -> dict[str, BackgroundSession]:
        """Зарегистрированные сессии (session_id → BackgroundSession)."""
        return self._sessions

    def register_session(self, session: BackgroundSession) -> None:
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
                "Сигнал %s — graceful остановка фоновых сессий", signum
            )
        self.cleanup_local(force=force)
        previous = self._previous_handlers.get(signum)
        if callable(previous):
            previous(signum, frame)
        elif previous == signal.SIG_DFL:
            signal.signal(signum, signal.SIG_DFL)
            signal.raise_signal(signum)

    def cleanup_local(self, force: bool = False, timeout: float = 30.0) -> None:
        """Синхронная очистка всех сессий (вызывается из atexit/signal)."""
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
        """Сгенерировать POSIX-скрипт очистки пула на сервере (tmux, screen, nohup).

        Скрипт останавливает сессии пула по префиксу ``uniconn_{pool_id}_``,
        а также сессии с пользовательскими именами (по явному списку),
        удаляет их логи, exit-файлы, PID-файлы, wrapper-скрипты, sentinel и сам себя.
        """
        if session_ids is None:
            session_ids = sorted(self._sessions)
        prefix = f"uniconn_{self._pool_id}_"
        custom = [s for s in session_ids if not s.startswith(prefix)]

        script = f"""#!/bin/sh
POOL_ID="{self._pool_id}"
if command -v tmux >/dev/null 2>&1; then
    for s in $(tmux list-sessions -F '#{{session_name}}' 2>/dev/null | grep "^uniconn_${{POOL_ID}}_"); do
        tmux kill-session -t "=$s" 2>/dev/null
    done
fi
if command -v screen >/dev/null 2>&1; then
    for s in $(screen -ls 2>/dev/null | grep "uniconn_${{POOL_ID}}_" | awk '{{print $1}}'); do
        screen -S "$s" -X kill 2>/dev/null
    done
fi
for pf in /tmp/uniconn_uniconn_${{POOL_ID}}_*.pid /tmp/uniconn_${{POOL_ID}}_*.pid; do
    if [ -s "$pf" ]; then
        pid=$(cat "$pf")
        pkill -KILL -P "$pid" 2>/dev/null || true
        kill -KILL -"$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
    fi
done
"""
        for name in custom:
            q_name = shlex.quote(name)
            q_tmux_target = shlex.quote(f"={name}")
            q_pid_file = shlex.quote(f"/tmp/uniconn_{name}.pid")
            script += f"command -v tmux >/dev/null 2>&1 && tmux kill-session -t {q_tmux_target} 2>/dev/null\n"
            script += f"command -v screen >/dev/null 2>&1 && screen -S {q_name} -X kill 2>/dev/null\n"
            script += (
                f"if [ -s {q_pid_file} ]; then pid=$(cat {q_pid_file}); "
                'pkill -KILL -P "$pid" 2>/dev/null || true; '
                'kill -KILL -"$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true; fi\n'
            )
            script += (
                "rm -f "
                + " ".join(
                    shlex.quote(p)
                    for p in (
                        f"/tmp/{name}.log",
                        f"/tmp/uniconn_{name}.exit",
                        f"/tmp/uniconn_{name}.pid",
                        f"/tmp/uniconn_{name}.sh",
                    )
                )
                + "\n"
            )
        script += """rm -f /tmp/uniconn_${POOL_ID}_*.log
rm -f /tmp/uniconn_uniconn_${POOL_ID}_*.exit /tmp/uniconn_${POOL_ID}_*.exit
rm -f /tmp/uniconn_uniconn_${POOL_ID}_*.pid /tmp/uniconn_${POOL_ID}_*.pid
rm -f /tmp/uniconn_uniconn_${POOL_ID}_*.sh /tmp/uniconn_${POOL_ID}_*.sh
rm -f /tmp/uniconn_${POOL_ID}.active
rm -f "$0"
"""
        return script

    async def install_server_side(self, connection: Connection) -> None:
        """Загрузить (или обновить) на сервере sentinel-файл и cleanup-скрипт."""
        sentinel = json.dumps(
            {
                "pool_id": self._pool_id,
                "sessions": sorted(self._sessions),
            }
        )
        q_sentinel_path = shlex.quote(self.sentinel_path)
        q_cleanup_path = shlex.quote(self.cleanup_script_path)
        await connection.run(
            f"printf '%s' {shlex.quote(sentinel)} > {q_sentinel_path}"
        )
        await connection.run(
            f"printf '%s' {shlex.quote(self.generate_cleanup_script())} "
            f"> {q_cleanup_path}"
        )
        await connection.run(f"chmod +x {q_cleanup_path}")
