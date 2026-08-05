# src/uniconn/background/_session.py
import asyncio
import logging
import re
import shlex

from .._connection import Connection
from ..exceptions import ScreenNotFoundError, ScreenSessionExistsError

logger = logging.getLogger(__name__)


class ScreenSession:
    """Управление одной GNU screen сессией на удалённом хосте.

    Сессия создаётся в detached-режиме с логированием в файл (``screen -L``).
    Команда выполняется через wrapper-скрипт, который записывает её exit code
    в отдельный файл ``/tmp/uniconn_{session_id}.exit`` — это позволяет
    получить код завершения после отключения SSH.
    """

    def __init__(
        self,
        connection: Connection,
        session_id: str,
        remote_log_path: str,
        logger: logging.Logger | None = None,
    ):
        self._connection = connection
        self._session_id = session_id
        self._remote_log_path = remote_log_path
        self._logger = logger or logging.getLogger(__name__)

    @property
    def session_id(self) -> str:
        """Имя screen-сессии."""
        return self._session_id

    @property
    def remote_log_path(self) -> str:
        """Путь к лог-файлу сессии на удалённом хосте."""
        return self._remote_log_path

    @property
    def exit_file_path(self) -> str:
        """Путь к файлу с exit code команды на удалённом хосте."""
        return f"/tmp/uniconn_{self._session_id}.exit"

    @property
    def script_path(self) -> str:
        """Путь к wrapper-скрипту на удалённом хосте."""
        return f"/tmp/uniconn_{self._session_id}.sh"

    @property
    def connection(self) -> Connection:
        """Подключение к хосту, на котором работает сессия."""
        return self._connection

    async def create(self, command: str) -> None:
        """Создать detached screen сессию с логированием.

        Порядок действий:
        1. Проверка наличия screen на хосте (``which screen``).
        2. Проверка, что сессия с таким именем ещё не существует.
        3. Загрузка wrapper-скрипта (команда + запись exit code).
        4. Запуск ``screen -dmS {id} -L -Logfile {log} bash {script}``.

        Args:
            command: Команда для выполнения внутри screen-сессии

        Raises:
            ScreenNotFoundError: GNU screen не установлен на хосте
            ScreenSessionExistsError: Сессия с таким именем уже существует

        """
        result = await self._connection.run("which screen")
        if not result.ok:
            raise ScreenNotFoundError(
                "GNU screen не установлен на хосте (which screen failed)"
            )

        if await self.is_alive():
            raise ScreenSessionExistsError(
                f"Screen-сессия {self._session_id!r} уже существует"
            )

        # Wrapper-скрипт решает проблему экранирования кавычек:
        # команда пишется в файл как есть, а не встраивается в bash -c '...'
        script = f"#!/bin/bash\n{command}\necho $? > {self.exit_file_path}\n"
        write_result = await self._connection.run(
            f"printf '%s' {shlex.quote(script)} > {shlex.quote(self.script_path)}"
        )
        if not write_result.ok:
            raise ScreenNotFoundError(
                f"Не удалось записать wrapper-скрипт {self.script_path}: "
                f"{write_result.stderr}"
            )

        start_cmd = (
            f"screen -dmS {shlex.quote(self._session_id)} "
            f"-L -Logfile {shlex.quote(self._remote_log_path)} "
            f"bash {shlex.quote(self.script_path)}"
        )
        start_result = await self._connection.run(start_cmd)
        if not start_result.ok:
            raise ScreenNotFoundError(
                f"Не удалось запустить screen-сессию: {start_result.stderr}"
            )
        self._logger.debug(f"Screen-сессия {self._session_id} создана: {start_cmd}")

    @staticmethod
    def _parse_screen_ls(output: str) -> dict[str, int]:
        """Разобрать вывод ``screen -ls`` в отображение {имя сессии: PID}.

        Формат строк: ``\\t{PID}.{name}\\t(Detached)``. Сравнение по имени
        целиком, чтобы ``uniconn_x_1`` не совпадал с ``uniconn_x_12``.
        """
        sessions: dict[str, int] = {}
        for line in output.splitlines():
            match = re.match(r"\s*(\d+)\.(\S+)", line)
            if match:
                sessions[match.group(2)] = int(match.group(1))
        return sessions

    async def is_alive(self) -> bool:
        """Проверить, существует ли screen-сессия на хосте (точное совпадение имени)."""
        result = await self._connection.run("screen -ls")
        return self._session_id in self._parse_screen_ls(result.stdout)

    async def get_pid(self) -> int | None:
        """Получить PID screen-процесса (парсинг ``screen -ls``, формат ``{PID}.{name}``)."""
        result = await self._connection.run("screen -ls")
        return self._parse_screen_ls(result.stdout).get(self._session_id)

    async def get_exit_code(self) -> int | None:
        """Получить exit code завершившейся команды.

        Читает ``/tmp/uniconn_{session_id}.exit``, который создаёт
        wrapper-скрипт. Файла нет — команда ещё работает.

        Returns:
            Exit code команды или None, если команда ещё выполняется

        """
        result = await self._connection.run(f"cat {shlex.quote(self.exit_file_path)}")
        if not result.ok:
            return None
        try:
            return int(result.stdout.strip())
        except ValueError:
            return None

    async def send_ctrl_c(self) -> None:
        """Отправить Ctrl+C (SIGINT) в screen-сессию."""
        await self._connection.run(
            f"screen -S {shlex.quote(self._session_id)} -X stuff $'\\003'"
        )

    async def send_signal(self, sig: int) -> None:
        """Отправить сигнал процессу screen-сессии по PID."""
        pid = await self.get_pid()
        if pid is not None:
            await self._connection.run(f"kill -{sig} {pid}")
        else:
            self._logger.warning(
                f"Не удалось отправить сигнал {sig}: PID сессии {self._session_id} не найден"
            )

    async def kill(self, graceful: bool = True, timeout: float = 5.0) -> None:
        """Остановить screen-сессию.

        Args:
            graceful: Сначала отправить Ctrl+C и подождать завершения,
                затем (если сессия жива) принудительно убить
            timeout: Время ожидания graceful-завершения в секундах

        """
        if graceful and await self.is_alive():
            await self.send_ctrl_c()
            loop = asyncio.get_running_loop()
            deadline = loop.time() + timeout
            while await self.is_alive():
                if loop.time() >= deadline:
                    break
                await asyncio.sleep(0.5)

        if await self.is_alive():
            await self._connection.run(
                f"screen -S {shlex.quote(self._session_id)} -X kill"
            )

    async def cleanup(self) -> None:
        """Удалить артефакты сессии: лог-файл, exit-файл, wrapper-скрипт."""
        paths = " ".join(
            shlex.quote(p)
            for p in (self._remote_log_path, self.exit_file_path, self.script_path)
        )
        await self._connection.run(f"rm -f {paths}")
