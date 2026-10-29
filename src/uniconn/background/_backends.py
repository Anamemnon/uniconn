# src/uniconn/background/_backends.py
"""Стратегии фонового запуска процессов: tmux, GNU screen и POSIX nohup/disown."""

from __future__ import annotations

import re
import shlex
from typing import TYPE_CHECKING, Literal, Protocol, runtime_checkable

from ..exceptions import BackgroundBackendError, ConfigurationError

if TYPE_CHECKING:
    from ..core.connection import Connection

BackgroundBackendType = Literal["auto", "tmux", "screen", "nohup", "windows_job"]


@runtime_checkable
class BackgroundBackendStrategy(Protocol):
    """Протокол стратегии управления фоновыми процессами на удалённом хосте."""

    @property
    def name(self) -> str:
        """Имя бэкенда ('tmux', 'screen', 'nohup', 'windows_job')."""
        ...

    async def is_available(self, conn: Connection) -> bool:
        """Проверить наличие утилиты бэкенда на целевом хосте."""
        ...

    async def start_session(
        self,
        conn: Connection,
        session_id: str,
        script_path: str,
        log_path: str,
        exit_file_path: str,
        pid_path: str,
    ) -> None:
        """Запустить подготовленный wrapper-скрипт в фоне с записью лога."""
        ...

    async def is_alive(
        self,
        conn: Connection,
        session_id: str,
        pid_path: str,
        exit_file_path: str,
    ) -> bool:
        """Проверить, продолжает ли выполняться фоновая задача."""
        ...

    async def get_pid(
        self,
        conn: Connection,
        session_id: str,
        pid_path: str,
        exit_file_path: str,
    ) -> int | None:
        """Вернуть PID активного фонового процесса или None."""
        ...

    async def list_sessions(
        self,
        conn: Connection,
        prefix: str = "",
    ) -> dict[str, int]:
        """Вернуть словарь {session_id: pid} активных фоновых сессий."""
        ...

    async def send_interrupt(
        self,
        conn: Connection,
        session_id: str,
        pid_path: str,
        exit_file_path: str,
    ) -> None:
        """Отправить сигнал мягкого прерывания (SIGINT / Ctrl+C)."""
        ...

    async def terminate(
        self,
        conn: Connection,
        session_id: str,
        pid_path: str,
    ) -> None:
        """Принудительно завершить фоновую сессию."""
        ...


class TmuxBackend:
    """Стратегия запуска фоновых задач через мультиплексор tmux."""

    @property
    def name(self) -> str:
        """Имя бэкенда."""
        return "tmux"

    async def is_available(self, conn: Connection) -> bool:
        """Проверить наличие бинарника tmux на хосте."""
        res = await conn.run("command -v tmux >/dev/null 2>&1", raise_on_error=False)
        return res.ok

    async def start_session(
        self,
        conn: Connection,
        session_id: str,
        script_path: str,
        log_path: str,
        exit_file_path: str,
        pid_path: str,
    ) -> None:
        """Запустить detached-сессию tmux с перенаправлением вывода в лог."""
        del exit_file_path, pid_path
        inner = f"sh {shlex.quote(script_path)} >> {shlex.quote(log_path)} 2>&1"
        cmd = f"tmux new-session -d -s {shlex.quote(session_id)} {shlex.quote(inner)}"
        res = await conn.run(cmd, raise_on_error=False)
        if not res.ok:
            raise BackgroundBackendError(
                f"Не удалось запустить tmux-сессию {session_id!r}: {res.stderr.strip()}",
                command=cmd,
                exit_code=res.exit_code,
                stdout=res.stdout,
                stderr=res.stderr,
            )

    async def is_alive(
        self,
        conn: Connection,
        session_id: str,
        pid_path: str,
        exit_file_path: str,
    ) -> bool:
        """Проверить существование сессии через ``tmux has-session -t ={session_id}``."""
        del pid_path, exit_file_path
        target = shlex.quote(f"={session_id}")
        res = await conn.run(f"tmux has-session -t {target} 2>/dev/null", raise_on_error=False)
        return res.ok

    async def get_pid(
        self,
        conn: Connection,
        session_id: str,
        pid_path: str,
        exit_file_path: str,
    ) -> int | None:
        """Получить PID процесса панели tmux через ``tmux list-panes``."""
        del pid_path, exit_file_path
        target = shlex.quote(f"={session_id}")
        res = await conn.run(
            f"tmux list-panes -t {target} -F '#{{pane_pid}}' 2>/dev/null",
            raise_on_error=False,
        )
        if not res.ok:
            return None
        first_line = res.stdout.strip().splitlines()
        if not first_line:
            return None
        try:
            return int(first_line[0].strip())
        except ValueError:
            return None

    async def list_sessions(
        self,
        conn: Connection,
        prefix: str = "",
    ) -> dict[str, int]:
        """Вернуть активные сессии tmux в формате ``{session_id: pane_pid}``."""
        res = await conn.run(
            "tmux list-panes -a -F '#{session_name} #{pane_pid}' 2>/dev/null",
            raise_on_error=False,
        )
        if not res.ok:
            return {}
        sessions: dict[str, int] = {}
        for line in res.stdout.splitlines():
            parts = line.strip().split(maxsplit=1)
            if len(parts) == 2:
                sname, pid_str = parts
                if prefix and not sname.startswith(prefix):
                    continue
                try:
                    sessions.setdefault(sname, int(pid_str))
                except ValueError:
                    continue
        return sessions

    async def send_interrupt(
        self,
        conn: Connection,
        session_id: str,
        pid_path: str,
        exit_file_path: str,
    ) -> None:
        """Отправить Ctrl+C в сессию tmux."""
        del pid_path, exit_file_path
        target = shlex.quote(f"={session_id}")
        await conn.run(f"tmux send-keys -t {target} C-c 2>/dev/null", raise_on_error=False)

    async def terminate(
        self,
        conn: Connection,
        session_id: str,
        pid_path: str,
    ) -> None:
        """Принудительно уничтожить сессию tmux."""
        del pid_path
        target = shlex.quote(f"={session_id}")
        await conn.run(f"tmux kill-session -t {target} 2>/dev/null", raise_on_error=False)


class ScreenBackend:
    """Стратегия запуска фоновых задач через GNU screen."""

    @property
    def name(self) -> str:
        """Имя бэкенда."""
        return "screen"

    async def is_available(self, conn: Connection) -> bool:
        """Проверить наличие бинарника screen на хосте."""
        res = await conn.run("command -v screen >/dev/null 2>&1", raise_on_error=False)
        return res.ok

    @staticmethod
    def parse_screen_ls(output: str) -> dict[str, int]:
        r"""Разобрать вывод ``screen -ls`` в отображение ``{session_id: pid}``.

        Формат строк: ``\t{PID}.{name}\t(Detached)``. Сравнение по имени
        целиком, чтобы ``uniconn_x_1`` не совпадал с ``uniconn_x_12``.
        """
        sessions: dict[str, int] = {}
        for line in output.splitlines():
            match = re.match(r"\s*(\d+)\.(\S+)", line)
            if match:
                sessions[match.group(2)] = int(match.group(1))
        return sessions

    async def start_session(
        self,
        conn: Connection,
        session_id: str,
        script_path: str,
        log_path: str,
        exit_file_path: str,
        pid_path: str,
    ) -> None:
        """Запустить detached screen-сессию с перенаправлением вывода в лог."""
        del exit_file_path, pid_path
        inner = f"sh {shlex.quote(script_path)} >> {shlex.quote(log_path)} 2>&1"
        cmd = f"screen -dmS {shlex.quote(session_id)} sh -c {shlex.quote(inner)}"
        res = await conn.run(cmd, raise_on_error=False)
        if not res.ok:
            raise BackgroundBackendError(
                f"Не удалось запустить screen-сессию {session_id!r}: {res.stderr.strip()}",
                command=cmd,
                exit_code=res.exit_code,
                stdout=res.stdout,
                stderr=res.stderr,
            )

    async def is_alive(
        self,
        conn: Connection,
        session_id: str,
        pid_path: str,
        exit_file_path: str,
    ) -> bool:
        """Проверить наличие сессии в выводе ``screen -ls``."""
        del pid_path, exit_file_path
        res = await conn.run("screen -ls", raise_on_error=False)
        return session_id in self.parse_screen_ls(res.stdout)

    async def get_pid(
        self,
        conn: Connection,
        session_id: str,
        pid_path: str,
        exit_file_path: str,
    ) -> int | None:
        """Получить PID процесса screen из вывода ``screen -ls``."""
        del pid_path, exit_file_path
        res = await conn.run("screen -ls", raise_on_error=False)
        return self.parse_screen_ls(res.stdout).get(session_id)

    async def list_sessions(
        self,
        conn: Connection,
        prefix: str = "",
    ) -> dict[str, int]:
        """Вернуть активные сессии screen, отфильтрованные по префиксу."""
        res = await conn.run("screen -ls", raise_on_error=False)
        parsed = self.parse_screen_ls(res.stdout)
        if not prefix:
            return parsed
        return {k: v for k, v in parsed.items() if k.startswith(prefix)}

    async def send_interrupt(
        self,
        conn: Connection,
        session_id: str,
        pid_path: str,
        exit_file_path: str,
    ) -> None:
        """Отправить Ctrl+C в screen-сессию."""
        del pid_path, exit_file_path
        await conn.run(
            f'screen -S {shlex.quote(session_id)} -X stuff "$(printf \'\\003\')"',
            raise_on_error=False,
        )

    async def terminate(
        self,
        conn: Connection,
        session_id: str,
        pid_path: str,
    ) -> None:
        """Принудительно уничтожить screen-сессию."""
        del pid_path
        await conn.run(
            f"screen -S {shlex.quote(session_id)} -X kill",
            raise_on_error=False,
        )


class NohupBackend:
    """Универсальная POSIX-стратегия запуска фоновых задач через setsid/nohup и PID-файл."""

    @property
    def name(self) -> str:
        """Имя бэкенда."""
        return "nohup"

    async def is_available(self, conn: Connection) -> bool:
        """POSIX шелл с фоновым запуском доступен на любом POSIX-хосте."""
        del conn
        return True

    async def start_session(
        self,
        conn: Connection,
        session_id: str,
        script_path: str,
        log_path: str,
        exit_file_path: str,
        pid_path: str,
    ) -> None:
        """Запустить wrapper-скрипт в отдельной группе процессов (setsid/nohup) и записать PID."""
        del exit_file_path
        q_script = shlex.quote(script_path)
        q_log = shlex.quote(log_path)
        q_pid = shlex.quote(pid_path)
        cmd = (
            "if command -v setsid >/dev/null 2>&1; then "
            f"setsid sh {q_script} </dev/null >> {q_log} 2>&1 & "
            "else "
            f"nohup sh {q_script} </dev/null >> {q_log} 2>&1 & "
            "fi; "
            f"echo $! > {q_pid}"
        )
        res = await conn.run(cmd, raise_on_error=False)
        if not res.ok:
            raise BackgroundBackendError(
                f"Не удалось запустить фоновую задачу nohup {session_id!r}: {res.stderr.strip()}",
                command=cmd,
                exit_code=res.exit_code,
                stdout=res.stdout,
                stderr=res.stderr,
            )

    async def is_alive(
        self,
        conn: Connection,
        session_id: str,
        pid_path: str,
        exit_file_path: str,
    ) -> bool:
        """Проверить, что exit-файл ещё не создан, а процесс из PID-файла жив."""
        del session_id
        q_exit = shlex.quote(exit_file_path)
        q_pid = shlex.quote(pid_path)
        cmd = (
            f"test ! -f {q_exit} && test -s {q_pid} && "
            f"kill -0 $(cat {q_pid}) 2>/dev/null"
        )
        res = await conn.run(cmd, raise_on_error=False)
        return res.ok

    async def get_pid(
        self,
        conn: Connection,
        session_id: str,
        pid_path: str,
        exit_file_path: str,
    ) -> int | None:
        """Вернуть PID активного процесса из ``pid_path`` или None, если он завершён."""
        del session_id
        q_exit = shlex.quote(exit_file_path)
        q_pid = shlex.quote(pid_path)
        cmd = (
            f"if test ! -f {q_exit} && test -s {q_pid}; then "
            f'pid=$(cat {q_pid}); kill -0 "$pid" 2>/dev/null && echo "$pid"; fi'
        )
        res = await conn.run(cmd, raise_on_error=False)
        if not res.ok or not res.stdout.strip():
            return None
        try:
            return int(res.stdout.strip().splitlines()[0].strip())
        except ValueError:
            return None

    async def list_sessions(
        self,
        conn: Connection,
        prefix: str = "",
    ) -> dict[str, int]:
        """Найти активные nohup-сессии по PID-файлам ``/tmp/uniconn_*.pid``."""
        glob_prefix = f"uniconn_{prefix}" if prefix and not prefix.startswith("uniconn_") else (prefix or "uniconn_")
        safe_glob = re.sub(r"[^A-Za-z0-9._-]", "", glob_prefix)
        cmd = (
            f"for f in /tmp/{safe_glob}*.pid; do "
            'test -s "$f" || continue; '
            'base=$(basename "$f" .pid); '
            'sid=${base#uniconn_}; '
            'test ! -f "/tmp/uniconn_${sid}.exit" || continue; '
            'pid=$(cat "$f"); '
            'if kill -0 "$pid" 2>/dev/null; then echo "$sid $pid"; fi; '
            "done"
        )
        res = await conn.run(cmd, raise_on_error=False)
        if not res.ok:
            return {}
        sessions: dict[str, int] = {}
        for line in res.stdout.splitlines():
            parts = line.strip().split(maxsplit=1)
            if len(parts) == 2:
                sid, pid_str = parts
                if prefix and not sid.startswith(prefix):
                    continue
                try:
                    sessions[sid] = int(pid_str)
                except ValueError:
                    continue
        return sessions

    async def send_interrupt(
        self,
        conn: Connection,
        session_id: str,
        pid_path: str,
        exit_file_path: str,
    ) -> None:
        """Отправить SIGINT дочерним процессам, группе процессов и процессу из ``pid_path``."""
        pid = await self.get_pid(conn, session_id, pid_path, exit_file_path)
        if pid is not None:
            await conn.run(
                f"pkill -INT -P {pid} 2>/dev/null || true; "
                f"kill -INT -{pid} 2>/dev/null || kill -INT {pid} 2>/dev/null || true",
                raise_on_error=False,
            )

    async def terminate(
        self,
        conn: Connection,
        session_id: str,
        pid_path: str,
    ) -> None:
        """Отправить SIGKILL дочерним процессам, группе процессов и процессу из ``pid_path``."""
        del session_id
        q_pid = shlex.quote(pid_path)
        cmd = (
            f"if test -s {q_pid}; then pid=$(cat {q_pid}); "
            'pkill -KILL -P "$pid" 2>/dev/null || true; '
            'kill -KILL -"$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true; fi'
        )
        await conn.run(cmd, raise_on_error=False)


class WindowsJobBackend:
    """Стратегия запуска фоновых задач на Windows через PowerShell Start-Process."""

    @property
    def name(self) -> str:
        """Имя бэкенда."""
        return "windows_job"

    async def is_available(self, conn: Connection) -> bool:
        """Проверить наличие PowerShell на целевом Windows-хосте."""
        res = await conn.run(
            'powershell -NoProfile -NonInteractive -Command "$PSVersionTable.PSVersion.Major"',
            raise_on_error=False,
        )
        return res.ok and bool(res.stdout.strip())

    @staticmethod
    def _ps_quote(value: str) -> str:
        """Экранировать строку для одинарных кавычек PowerShell."""
        return "'" + value.replace("'", "''") + "'"

    async def start_session(
        self,
        conn: Connection,
        session_id: str,
        script_path: str,
        log_path: str,
        exit_file_path: str,
        pid_path: str,
    ) -> None:
        """Запустить фоновый процесс PowerShell с перенаправлением лога и записью PID."""
        ps_script = self._ps_quote(script_path)
        ps_log = self._ps_quote(log_path)
        ps_exit = self._ps_quote(exit_file_path)
        ps_pid = self._ps_quote(pid_path)
        inner_cmd = (
            f"& {ps_script} *> {ps_log}; "
            f"$rc = if ($null -ne $LASTEXITCODE) {{ $LASTEXITCODE }} else {{ 0 }}; "
            f"Set-Content -Path {ps_exit} -Value $rc -NoNewline"
        )
        encoded_inner = self._ps_quote(inner_cmd)
        cmd = (
            'powershell -NoProfile -NonInteractive -Command "'
            f"$p = Start-Process -FilePath 'powershell' "
            f"-ArgumentList @('-NoProfile', '-NonInteractive', '-Command', {encoded_inner}) "
            "-WindowStyle Hidden -PassThru; "
            f'Set-Content -Path {ps_pid} -Value $p.Id -NoNewline"'
        )
        res = await conn.run(cmd, raise_on_error=False)
        if not res.ok:
            raise BackgroundBackendError(
                f"Не удалось запустить фоновую задачу windows_job {session_id!r}: {res.stderr.strip()}",
                command=cmd,
                exit_code=res.exit_code,
                stdout=res.stdout,
                stderr=res.stderr,
            )

    async def is_alive(
        self,
        conn: Connection,
        session_id: str,
        pid_path: str,
        exit_file_path: str,
    ) -> bool:
        """Проверить активность фонового процесса Windows по PID-файлу и отсутствию exit-файла."""
        del session_id
        ps_pid = self._ps_quote(pid_path)
        ps_exit = self._ps_quote(exit_file_path)
        cmd = (
            'powershell -NoProfile -NonInteractive -Command "'
            f"if ((Test-Path {ps_exit}) -or -not (Test-Path {ps_pid})) {{ exit 1 }}; "
            f"$procId = [int](Get-Content {ps_pid} -Raw).Trim(); "
            '$p = Get-Process -Id $procId -ErrorAction SilentlyContinue; '
            'if ($null -ne $p) { exit 0 } else { exit 1 }"'
        )
        res = await conn.run(cmd, raise_on_error=False)
        return res.ok

    async def get_pid(
        self,
        conn: Connection,
        session_id: str,
        pid_path: str,
        exit_file_path: str,
    ) -> int | None:
        """Вернуть PID активного процесса Windows или None, если он завершён."""
        del session_id
        ps_pid = self._ps_quote(pid_path)
        ps_exit = self._ps_quote(exit_file_path)
        cmd = (
            'powershell -NoProfile -NonInteractive -Command "'
            f"if (-not (Test-Path {ps_exit}) -and (Test-Path {ps_pid})) {{ "
            f"$procId = [int](Get-Content {ps_pid} -Raw).Trim(); "
            "$p = Get-Process -Id $procId -ErrorAction SilentlyContinue; "
            'if ($null -ne $p) { Write-Output $procId } }"'
        )
        res = await conn.run(cmd, raise_on_error=False)
        if not res.ok or not res.stdout.strip():
            return None
        try:
            return int(res.stdout.strip().splitlines()[0].strip())
        except ValueError:
            return None

    async def list_sessions(
        self,
        conn: Connection,
        prefix: str = "",
    ) -> dict[str, int]:
        """Найти активные сессии windows_job по PID-файлам."""
        glob_prefix = (
            f"uniconn_{prefix}"
            if prefix and not prefix.startswith("uniconn_")
            else (prefix or "uniconn_")
        )
        safe_glob = re.sub(r"[^A-Za-z0-9._-]", "", glob_prefix)
        cmd = (
            'powershell -NoProfile -NonInteractive -Command "'
            f"Get-ChildItem -Path '/tmp/{safe_glob}*.pid' -ErrorAction SilentlyContinue | ForEach-Object {{ "
            "$sid = $_.BaseName -replace '^uniconn_', ''; "
            "$exitFile = Join-Path $_.DirectoryName ('uniconn_' + $sid + '.exit'); "
            "if (-not (Test-Path $exitFile)) { "
            "$procId = [int](Get-Content $_.FullName -Raw).Trim(); "
            "if ($null -ne (Get-Process -Id $procId -ErrorAction SilentlyContinue)) { "
            'Write-Output \\"$sid $procId\\" } } }"'
        )
        res = await conn.run(cmd, raise_on_error=False)
        if not res.ok:
            return {}
        sessions: dict[str, int] = {}
        for line in res.stdout.splitlines():
            parts = line.strip().split(maxsplit=1)
            if len(parts) == 2:
                sid, pid_str = parts
                if prefix and not sid.startswith(prefix):
                    continue
                try:
                    sessions[sid] = int(pid_str)
                except ValueError:
                    continue
        return sessions

    async def send_interrupt(
        self,
        conn: Connection,
        session_id: str,
        pid_path: str,
        exit_file_path: str,
    ) -> None:
        """Остановить процесс Windows через Stop-Process."""
        pid = await self.get_pid(conn, session_id, pid_path, exit_file_path)
        if pid is not None:
            ps_cmd = f"Stop-Process -Id {pid} -ErrorAction SilentlyContinue"
            await conn.run(
                f'powershell -NoProfile -NonInteractive -Command "{ps_cmd}"',
                raise_on_error=False,
            )

    async def terminate(
        self,
        conn: Connection,
        session_id: str,
        pid_path: str,
    ) -> None:
        """Принудительно завершить процесс Windows через Stop-Process -Force."""
        del session_id
        ps_pid = self._ps_quote(pid_path)
        cmd = (
            'powershell -NoProfile -NonInteractive -Command "'
            f"if (Test-Path {ps_pid}) {{ "
            f"$procId = [int](Get-Content {ps_pid} -Raw).Trim(); "
            'Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue }"'
        )
        await conn.run(cmd, raise_on_error=False)


_BACKENDS: dict[str, BackgroundBackendStrategy] = {
    "tmux": TmuxBackend(),
    "screen": ScreenBackend(),
    "nohup": NohupBackend(),
    "windows_job": WindowsJobBackend(),
}


def get_backend_by_name(name: str) -> BackgroundBackendStrategy:
    """Получить экземпляр стратегии бэкенда по имени ('tmux', 'screen', 'nohup', 'windows_job')."""
    strategy = _BACKENDS.get(name)
    if strategy is None:
        raise ConfigurationError(
            f"Неизвестный фоновый бэкенд {name!r}. "
            "Допустимые значения: 'auto', 'tmux', 'screen', 'nohup', 'windows_job'"
        )
    return strategy


async def resolve_backend(
    conn: Connection,
    backend: BackgroundBackendType = "auto",
) -> BackgroundBackendStrategy:
    """Определить и проверить стратегию фонового бэкенда на целевом хосте.

    В режиме ``"auto"`` за один SSH/локальный запрос проверяется цепочка
    ``tmux -> screen -> nohup``. Если явно запрошен ``"tmux"`` или ``"screen"``,
    проверяется наличие соответствующего бинарника, и при его отсутствии
    выбрасывается ``BackgroundBackendError``.
    """
    if backend == "auto":
        probe_cmd = (
            "if command -v tmux >/dev/null 2>&1; then echo tmux; "
            "elif command -v screen >/dev/null 2>&1; then echo screen; "
            "else echo nohup; fi"
        )
        res = await conn.run(probe_cmd, raise_on_error=False)
        detected = res.stdout.strip().splitlines()[0].strip() if res.ok and res.stdout.strip() else "nohup"
        if detected not in _BACKENDS:
            detected = "nohup"
        return _BACKENDS[detected]

    if backend == "nohup":
        return _BACKENDS["nohup"]

    strategy = get_backend_by_name(backend)
    if not await strategy.is_available(conn):
        raise BackgroundBackendError(
            f"Фоновый бэкенд {backend!r} не установлен на целевом хосте (command -v {backend} failed)"
        )
    return strategy


__all__ = [
    "BackgroundBackendStrategy",
    "BackgroundBackendType",
    "NohupBackend",
    "ScreenBackend",
    "TmuxBackend",
    "WindowsJobBackend",
    "get_backend_by_name",
    "resolve_backend",
]
