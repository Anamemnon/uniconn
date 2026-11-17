# src/uniconn/background/_cleanup.py
import asyncio
import atexit
import contextlib
import json
import logging
import posixpath
import shlex
import signal
import threading
import time
from collections.abc import Callable, Iterable
from types import FrameType
from typing import Any

from ..core.connection import Connection
from ._backends import WindowsJobBackend, is_windows_background_conn
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
        stale_ttl_seconds: float | None = None,
        runtime_dir: str | None = None,
    ):
        self._pool_id = pool_id
        self._logger = logger or logging.getLogger(__name__)
        self._stale_ttl_seconds = stale_ttl_seconds
        self._runtime_dir = runtime_dir
        self._sessions: dict[str, BackgroundSession] = {}
        self._signal_count = 0
        self._installed = False
        self._previous_handlers: dict[int, signal.Handlers | Callable | int | None] = {}

    @property
    def stale_ttl_seconds(self) -> float | None:
        """Максимальное время жизни (TTL) осиротевших сессий в секундах."""
        return self._stale_ttl_seconds

    @property
    def runtime_dir(self) -> str | None:
        """Приватная директория артефактов пула (с правами ``0700``)."""
        return self._runtime_dir

    @runtime_dir.setter
    def runtime_dir(self, value: str | None) -> None:
        self._runtime_dir = value

    @property
    def sentinel_path(self) -> str:
        """Путь к sentinel-файлу пула на сервере."""
        base = self._runtime_dir or "/tmp"
        return posixpath.join(base, f"uniconn_{self._pool_id}.active")

    @property
    def cleanup_script_path(self) -> str:
        """Путь к cleanup-скрипту пула на сервере."""
        base = self._runtime_dir or "/tmp"
        return posixpath.join(base, f"uniconn_cleanup_{self._pool_id}.sh")

    async def ensure_posix_runtime_dir(self, connection: Connection) -> str:
        """Создать или проверить приватную POSIX-директорию ``0700`` для артефактов пула."""
        if self._runtime_dir:
            return self._runtime_dir
        safe_pool = "".join(
            ch if (ch.isalnum() or ch in ("_", "-")) else "_" for ch in self._pool_id
        )
        cmd = (
            "umask 077; "
            'if [ -n "${XDG_RUNTIME_DIR:-}" ] && [ -d "$XDG_RUNTIME_DIR" ] '
            '&& [ -O "$XDG_RUNTIME_DIR" ] && [ ! -L "$XDG_RUNTIME_DIR" ]; then '
            f'd="$XDG_RUNTIME_DIR/uniconn_{safe_pool}"; '
            'if [ -L "$d" ]; then exit 1; fi; '
            'mkdir -p -m 0700 "$d" && chmod 0700 "$d" && printf "%s" "$d"; '
            "else "
            f'mktemp -d "${{TMPDIR:-/tmp}}/uniconn_{safe_pool}_XXXXXX"; '
            "fi"
        )
        res = await connection.run(cmd, raise_on_error=False)
        resolved = res.stdout.strip().splitlines()[-1].strip() if res.ok and res.stdout.strip() else ""
        if not res.ok:
            raise RuntimeError(
                f"Failed to create private runtime directory for pool {self._pool_id}: {res.stderr.strip()}"
            )
        self._runtime_dir = resolved or f"/tmp/uniconn_{safe_pool}"
        return self._runtime_dir

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
        art_dir = self._runtime_dir or "/tmp"
        q_art_dir = shlex.quote(art_dir)

        script = f"""#!/bin/sh
POOL_ID="{self._pool_id}"
ART_DIR={q_art_dir}
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
for pf in "$ART_DIR"/uniconn_uniconn_${{POOL_ID}}_*.pid "$ART_DIR"/uniconn_${{POOL_ID}}_*.pid; do
    if [ -s "$pf" ] && [ ! -L "$pf" ]; then
        pid=$(cat "$pf")
        pkill -KILL -P "$pid" 2>/dev/null || true
        kill -KILL -"$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
    fi
done
"""
        for name in custom:
            q_name = shlex.quote(name)
            q_tmux_target = shlex.quote(f"={name}")
            q_pid_file = shlex.quote(posixpath.join(art_dir, f"uniconn_{name}.pid"))
            script += f"command -v tmux >/dev/null 2>&1 && tmux kill-session -t {q_tmux_target} 2>/dev/null\n"
            script += f"command -v screen >/dev/null 2>&1 && screen -S {q_name} -X kill 2>/dev/null\n"
            script += (
                f"if [ -s {q_pid_file} ] && [ ! -L {q_pid_file} ]; then pid=$(cat {q_pid_file}); "
                'pkill -KILL -P "$pid" 2>/dev/null || true; '
                'kill -KILL -"$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true; fi\n'
            )
            script += (
                "rm -f "
                + " ".join(
                    shlex.quote(p)
                    for p in (
                        posixpath.join(art_dir, f"{name}.log"),
                        posixpath.join(art_dir, f"uniconn_{name}.exit"),
                        posixpath.join(art_dir, f"uniconn_{name}.pid"),
                        posixpath.join(art_dir, f"uniconn_{name}.sh"),
                    )
                )
                + "\n"
            )
        script += """rm -f "$ART_DIR"/uniconn_${POOL_ID}_*.log
rm -f "$ART_DIR"/uniconn_uniconn_${POOL_ID}_*.exit "$ART_DIR"/uniconn_${POOL_ID}_*.exit
rm -f "$ART_DIR"/uniconn_uniconn_${POOL_ID}_*.pid "$ART_DIR"/uniconn_${POOL_ID}_*.pid
rm -f "$ART_DIR"/uniconn_uniconn_${POOL_ID}_*.sh "$ART_DIR"/uniconn_${POOL_ID}_*.sh
rm -f "$ART_DIR"/uniconn_${POOL_ID}.active
rm -f "$0"
if [ "$ART_DIR" != "/tmp" ]; then rmdir "$ART_DIR" 2>/dev/null || true; fi
"""
        return script

    async def install_server_side(self, connection: Connection) -> None:
        """Загрузить (или обновить) на сервере sentinel-файл и cleanup-скрипт."""
        payload: dict[str, Any] = {
            "pool_id": self._pool_id,
            "sessions": sorted(self._sessions),
            "created_at": round(time.time(), 3),
        }
        if self._stale_ttl_seconds is not None:
            payload["stale_ttl_seconds"] = self._stale_ttl_seconds
        sentinel = json.dumps(payload)
        if is_windows_background_conn(connection):
            ps_sentinel_path = WindowsJobBackend._ps_quote(self.sentinel_path)
            ps_sentinel_val = WindowsJobBackend._ps_quote(sentinel)
            ps_cmd = (
                "if (-not (Test-Path '/tmp')) { New-Item -ItemType Directory -Path '/tmp' -Force | Out-Null }; "
                f"Set-Content -Path {ps_sentinel_path} -Value {ps_sentinel_val} -Encoding UTF8 -NoNewline"
            )
            await connection.run(WindowsJobBackend._wrap_ps(ps_cmd))
            return
        await self.ensure_posix_runtime_dir(connection)
        q_sentinel_path = shlex.quote(self.sentinel_path)
        q_cleanup_path = shlex.quote(self.cleanup_script_path)
        q_dir = shlex.quote(self._runtime_dir or "/tmp")
        await connection.run(
            f"umask 077 && [ ! -L {q_dir} ] && mkdir -p -m 0700 {q_dir} && chmod 0700 {q_dir} && "
            f"[ ! -L {q_sentinel_path} ] && printf '%s' {shlex.quote(sentinel)} > {q_sentinel_path}"
        )
        await connection.run(
            f"umask 077 && [ ! -L {q_cleanup_path} ] && "
            f"printf '%s' {shlex.quote(self.generate_cleanup_script())} > {q_cleanup_path}"
        )
        await connection.run(f"chmod 0700 {q_cleanup_path}")

    async def cleanup_stale(
        self,
        connection: Connection,
        max_age_seconds: float | None = None,
    ) -> list[str]:
        """Очистить осиротевшие пулы сессий на сервере старше ``max_age_seconds`` секунд.

        Анализирует sentinel-файлы ``/tmp/uniconn_*.active`` (исключая текущий пул).
        Если возраст пула превышает порог TTL, выполняет соответствующий
        ``/tmp/uniconn_cleanup_{pool_id}.sh`` или принудительно удаляет артефакты.

        Returns:
            Список ``pool_id`` очищенных устаревших пулов.

        """
        default_ttl = (
            max_age_seconds
            if max_age_seconds is not None
            else self._stale_ttl_seconds
        )
        if default_ttl is not None and default_ttl <= 0:
            return []
        if is_windows_background_conn(connection):
            return []

        res = await connection.run(
            'for f in "${XDG_RUNTIME_DIR:-/nonexistent}"/uniconn_*/uniconn_*.active '
            "/tmp/uniconn_*/uniconn_*.active /tmp/uniconn_*.active; do "
            '[ -f "$f" ] && [ ! -L "$f" ] && [ -O "$f" ] && '
            'printf "%s\\t%s\\n" "$f" "$(cat "$f" 2>/dev/null)"; '
            "done"
        )
        if not res.stdout.strip():
            return []

        now = time.time()
        cleaned: list[str] = []

        for line in res.stdout.splitlines():
            if not line.strip():
                continue
            path_part, _, raw_json = line.partition("\t")
            try:
                data = json.loads(raw_json) if raw_json.strip() else {}
            except Exception:
                data = {}

            pool_id = data.get("pool_id")
            if not isinstance(pool_id, str) or not pool_id:
                fname = path_part.rsplit("/", 1)[-1]
                if fname.startswith("uniconn_") and fname.endswith(".active"):
                    pool_id = fname[len("uniconn_") : -len(".active")]
            if not pool_id or pool_id == self._pool_id:
                continue

            created_at = data.get("created_at")
            file_ttl = (
                max_age_seconds
                if max_age_seconds is not None
                else (
                    data.get("stale_ttl_seconds")
                    if isinstance(data.get("stale_ttl_seconds"), int | float)
                    else default_ttl
                )
            )
            if file_ttl is None or not isinstance(created_at, int | float):
                continue

            if (now - float(created_at)) >= float(file_ttl):
                stale_dir = posixpath.dirname(path_part) or "/tmp"
                script_candidate = posixpath.join(stale_dir, f"uniconn_cleanup_{pool_id}.sh")
                q_script = shlex.quote(script_candidate)
                q_sentinel = shlex.quote(path_part)
                q_dir = shlex.quote(stale_dir)
                q_pid = shlex.quote(pool_id)
                await connection.run(
                    f"if [ -x {q_script} ] && [ ! -L {q_script} ] && [ -O {q_script} ]; then "
                    f"{q_script}; "
                    f"else rm -f {q_sentinel} {q_script} "
                    f"{q_dir}/uniconn_{q_pid}_*.log {q_dir}/uniconn_*{q_pid}_*.pid "
                    f"{q_dir}/uniconn_*{q_pid}_*.exit {q_dir}/uniconn_*{q_pid}_*.sh; "
                    f'if [ {q_dir} != "/tmp" ]; then rmdir {q_dir} 2>/dev/null || true; fi; '
                    "fi"
                )
                cleaned.append(pool_id)

        return cleaned
