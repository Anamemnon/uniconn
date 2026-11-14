# src/uniconn/background/_session.py
import asyncio
import logging
import ntpath
import posixpath
import shlex

from ..core.connection import Connection
from ..exceptions import BackgroundBackendError, BackgroundSessionExistsError
from ._backends import (
    BackgroundBackendStrategy,
    BackgroundBackendType,
    WindowsJobBackend,
    is_windows_background_conn,
    resolve_backend,
)

logger = logging.getLogger(__name__)


class BackgroundSession:
    """Управление одной фоновой сессией на удалённом хосте.

    Поддерживает сменные стратегии фонового запуска (``tmux``, ``screen``,
    ``nohup``) с автовыбором (``auto``). Команда выполняется через
    wrapper-скрипт, который сохраняет PID в ``/tmp/uniconn_{session_id}.pid``
    и код завершения в ``/tmp/uniconn_{session_id}.exit``.
    """

    def __init__(
        self,
        connection: Connection,
        session_id: str,
        remote_log_path: str,
        backend: BackgroundBackendStrategy | BackgroundBackendType = "auto",
        logger: logging.Logger | None = None,
    ):
        self._connection = connection
        self._session_id = session_id
        self._remote_log_path = remote_log_path
        if isinstance(backend, BackgroundBackendStrategy):
            self._backend: BackgroundBackendStrategy | None = backend
            self._backend_spec: BackgroundBackendType = "auto"
        else:
            self._backend = None
            self._backend_spec = backend
        self._logger = logger or logging.getLogger(__name__)

    @property
    def session_id(self) -> str:
        """Имя фоновой сессии."""
        return self._session_id

    @property
    def remote_log_path(self) -> str:
        """Путь к лог-файлу сессии на удалённом хосте."""
        return self._remote_log_path

    def _artifact_dir(self) -> str:
        """Определить директорию для служебных файлов сессии (.pid, .exit, wrapper)."""
        if self._is_windows_backend():
            raw = self._remote_log_path.strip()
            if "\\" in raw or (len(raw) >= 2 and raw[1] == ":"):
                parent = ntpath.dirname(raw)
                if parent:
                    return parent
            parent = posixpath.dirname(raw)
            if parent:
                return parent
        return "/tmp"

    def _join_artifact(self, filename: str) -> str:
        base = self._artifact_dir()
        if "\\" in base or (len(base) >= 2 and base[1] == ":"):
            return ntpath.join(base, filename)
        return posixpath.join(base, filename)

    @property
    def exit_file_path(self) -> str:
        """Путь к файлу с exit code команды на удалённом хосте."""
        return self._join_artifact(f"uniconn_{self._session_id}.exit")

    @property
    def pid_file_path(self) -> str:
        """Путь к PID-файлу фонового процесса на удалённом хосте."""
        return self._join_artifact(f"uniconn_{self._session_id}.pid")

    def _is_windows_backend(self) -> bool:
        """Проверить, используется ли WindowsJobBackend или Windows-подключение."""
        if self._backend is not None and self._backend.name == "windows_job":
            return True
        if self._backend_spec == "windows_job":
            return True
        return is_windows_background_conn(self._connection)

    @property
    def script_path(self) -> str:
        """Путь к wrapper-скрипту на удалённом хосте."""
        ext = "ps1" if self._is_windows_backend() else "sh"
        return self._join_artifact(f"uniconn_{self._session_id}.{ext}")

    @property
    def connection(self) -> Connection:
        """Подключение к хосту, на котором работает сессия."""
        return self._connection

    @property
    def backend_name(self) -> str:
        """Имя активного или сконфигурированного бэкенда ('tmux', 'screen', 'nohup', 'windows_job', 'auto')."""
        if self._backend is not None:
            return self._backend.name
        return self._backend_spec

    async def _ensure_backend(self) -> BackgroundBackendStrategy:
        """Лениво определить и закэшировать стратегию фонового бэкенда."""
        if self._backend is None:
            self._backend = await resolve_backend(self._connection, self._backend_spec)
        return self._backend

    async def create(self, command: str) -> None:
        """Создать и запустить фоновую сессию с логированием в файл.

        Порядок действий:
        1. Определение стратегии бэкенда (``tmux``, ``screen``, ``nohup`` или ``windows_job``).
        2. Проверка, что сессия с таким именем ещё не запущена.
        3. Загрузка wrapper-скрипта (запись PID + команда + запись exit code).
        4. Делегирование запуска в ``backend.start_session(...)``.

        Args:
            command: Команда для выполнения внутри фоновой сессии

        Raises:
            BackgroundBackendError: Выбранный бэкенд недоступен или не смог стартовать
            BackgroundSessionExistsError: Сессия с таким именем уже существует

        """
        backend = await self._ensure_backend()

        if await self.is_alive():
            raise BackgroundSessionExistsError(
                f"Фоновая сессия {self._session_id!r} уже существует"
            )

        if self._is_windows_backend():
            ps_exit = WindowsJobBackend._ps_quote(self.exit_file_path)
            ps_pid = WindowsJobBackend._ps_quote(self.pid_file_path)
            ps_script_path = WindowsJobBackend._ps_quote(self.script_path)
            ps_cmd_escaped = WindowsJobBackend._ps_quote(command)
            write_cmd = (
                f"$sDir = Split-Path -Parent {ps_script_path}; "
                "if ($sDir -and -not (Test-Path $sDir)) { "
                "New-Item -ItemType Directory -Path $sDir -Force | Out-Null }; "
                f"Remove-Item -Path {ps_exit}, {ps_pid} -Force -ErrorAction SilentlyContinue; "
                f"Set-Content -Path {ps_script_path} -Value {ps_cmd_escaped} -Encoding UTF8"
            )
            write_result = await self._connection.run(WindowsJobBackend._wrap_ps(write_cmd))
        else:
            # Wrapper-скрипт решает проблему экранирования кавычек, фиксирует PID
            # оболочки и гарантированно записывает код возврата (включая SIGINT/SIGTERM) в exit-файл.
            q_pid = shlex.quote(self.pid_file_path)
            q_exit = shlex.quote(self.exit_file_path)
            script = (
                "#!/bin/sh\n"
                f"echo $$ > {q_pid}\n"
                f'trap "rc=\\$?; [ -f {q_exit} ] || echo \\$rc > {q_exit}" EXIT\n'
                'trap "exit 130" INT\n'
                'trap "exit 143" TERM\n'
                f"{command}\n"
                f"echo $? > {q_exit}\n"
            )
            write_result = await self._connection.run(
                f"rm -f {shlex.quote(self.exit_file_path)} {shlex.quote(self.pid_file_path)} && "
                f"printf '%s' {shlex.quote(script)} > {shlex.quote(self.script_path)}"
            )
        if not write_result.ok:
            raise BackgroundBackendError(
                f"Не удалось записать wrapper-скрипт {self.script_path}: "
                f"{write_result.stderr}"
            )

        await backend.start_session(
            self._connection,
            self._session_id,
            self.script_path,
            self._remote_log_path,
            self.exit_file_path,
            self.pid_file_path,
        )
        self._logger.debug(
            f"Фоновая сессия {self._session_id} создана (backend={backend.name})"
        )

    async def is_alive(self) -> bool:
        """Проверить, продолжает ли работать фоновая сессия на хосте."""
        backend = await self._ensure_backend()
        return await backend.is_alive(
            self._connection,
            self._session_id,
            self.pid_file_path,
            self.exit_file_path,
        )

    async def get_pid(self) -> int | None:
        """Получить PID процесса фоновой сессии."""
        backend = await self._ensure_backend()
        return await backend.get_pid(
            self._connection,
            self._session_id,
            self.pid_file_path,
            self.exit_file_path,
        )

    async def get_exit_code(self) -> int | None:
        """Получить exit code завершившейся команды.

        Читает ``/tmp/uniconn_{session_id}.exit``, который создаёт
        wrapper-скрипт. Файла нет — команда ещё работает.

        Returns:
            Exit code команды или None, если команда ещё выполняется

        """
        if self._is_windows_backend():
            ps_exit = WindowsJobBackend._ps_quote(self.exit_file_path)
            cmd = f"if (Test-Path {ps_exit}) {{ (Get-Content -Path {ps_exit} -Raw).Trim() }} else {{ exit 1 }}"
            result = await self._connection.run(WindowsJobBackend._wrap_ps(cmd))
        else:
            result = await self._connection.run(f"cat {shlex.quote(self.exit_file_path)}")
        if not result.ok:
            return None
        try:
            return int(result.stdout.strip())
        except ValueError:
            return None

    async def send_ctrl_c(self) -> None:
        """Отправить мягкое прерывание (Ctrl+C / SIGINT) в фоновую сессию."""
        backend = await self._ensure_backend()
        await backend.send_interrupt(
            self._connection,
            self._session_id,
            self.pid_file_path,
            self.exit_file_path,
        )

    async def send_signal(self, sig: int) -> None:
        """Отправить произвольный сигнал процессу фоновой сессии по PID."""
        pid = await self.get_pid()
        if pid is not None:
            if self._is_windows_backend():
                await self._connection.run(
                    WindowsJobBackend._wrap_ps(
                        f"Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue"
                    )
                )
            else:
                await self._connection.run(f"kill -{sig} {pid}")
        else:
            self._logger.warning(
                f"Не удалось отправить сигнал {sig}: PID сессии {self._session_id} не найден"
            )

    async def kill(self, graceful: bool = True, timeout: float = 5.0) -> None:
        """Остановить фоновую сессию.

        Args:
            graceful: Сначала отправить SIGINT / Ctrl+C и подождать завершения,
                затем (если сессия жива) принудительно убить
            timeout: Время ожидания graceful-завершения в секундах

        """
        backend = await self._ensure_backend()
        if graceful and await self.is_alive():
            await self.send_ctrl_c()
            loop = asyncio.get_running_loop()
            deadline = loop.time() + timeout
            while await self.is_alive():
                if loop.time() >= deadline:
                    break
                await asyncio.sleep(0.5)

        if await self.is_alive():
            await backend.terminate(
                self._connection,
                self._session_id,
                self.pid_file_path,
            )

    async def cleanup(self) -> None:
        """Удалить артефакты сессии: лог-файл, exit-файл, PID-файл, wrapper-скрипт."""
        if self._is_windows_backend():
            ps_paths = ", ".join(
                WindowsJobBackend._ps_quote(p)
                for p in (
                    self._remote_log_path,
                    self.exit_file_path,
                    self.pid_file_path,
                    self.script_path,
                )
            )
            await self._connection.run(
                WindowsJobBackend._wrap_ps(
                    f"Remove-Item -Path {ps_paths} -Force -ErrorAction SilentlyContinue"
                )
            )
        else:
            paths = " ".join(
                shlex.quote(p)
                for p in (
                    self._remote_log_path,
                    self.exit_file_path,
                    self.pid_file_path,
                    self.script_path,
                )
            )
            await self._connection.run(f"rm -f {paths}")
