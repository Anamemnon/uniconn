# tests/unit/test_screen_session.py
"""Тесты ScreenSession — управление одной screen-сессией (мок Connection)."""

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from uniconn.background import ScreenSession
from uniconn.exceptions import ScreenNotFoundError, ScreenSessionExistsError
from uniconn.result import Result


def make_result(stdout: str = "", exit_code: int = 0, command: str = "") -> Result:
    """Создать Result для мока."""
    return Result(
        exit_code=exit_code,
        stdout=stdout,
        stderr="",
        duration=0.1,
        command=command,
        timestamp=datetime.now(),
    )


def make_connection(handler) -> MagicMock:
    """Мок Connection с маршрутизацией команд в handler."""
    conn = MagicMock()
    conn.run = AsyncMock(side_effect=handler)
    return conn


def default_handler(command: str, **kwargs) -> Result:
    """Стандартный хост: screen установлен, сессий нет."""
    if command == "which screen":
        return make_result("/usr/bin/screen\n", command=command)
    if command == "screen -ls":
        return make_result("No Sockets found in /run/screen/S-user.\n", exit_code=1)
    return make_result("", command=command)


def make_session(handler=default_handler, session_id: str = "s1") -> ScreenSession:
    """ScreenSession с мок-подключением."""
    return ScreenSession(make_connection(handler), session_id, "/tmp/s1.log")


class TestCreate:
    """Тесты создания сессии."""

    async def test_create_runs_expected_commands(self):
        """create: which screen → запись скрипта → запуск screen."""
        session = make_session()
        await session.create("stress-ng --cpu 4")

        calls = [c.args[0] for c in session.connection.run.call_args_list]
        assert calls[0] == "which screen"
        assert calls[1] == "screen -ls"
        # Wrapper-скрипт содержит команду и запись exit code
        assert calls[2].startswith("printf '%s'")
        assert "stress-ng --cpu 4" in calls[2]
        assert "echo $? > /tmp/uniconn_s1.exit" in calls[2]
        assert "/tmp/uniconn_s1.sh" in calls[2]
        # Запуск detached screen с логированием
        assert calls[3] == "screen -dmS s1 -L -Logfile /tmp/s1.log bash /tmp/uniconn_s1.sh"

    async def test_create_screen_not_found(self):
        """Create падает с ScreenNotFoundError, если screen не установлен."""
        def handler(command: str, **kwargs) -> Result:
            if command == "which screen":
                return make_result("", exit_code=1, command=command)
            return make_result("", command=command)

        session = make_session(handler)
        with pytest.raises(ScreenNotFoundError):
            await session.create("uptime")

    async def test_create_session_exists(self):
        """Create падает с ScreenSessionExistsError, если имя занято."""
        def handler(command: str, **kwargs) -> Result:
            if command == "which screen":
                return make_result("/usr/bin/screen\n", command=command)
            if command == "screen -ls":
                return make_result(
                    "There is a screen on:\n\t12345.s1\t(Detached)\n", command=command
                )
            return make_result("", command=command)

        session = make_session(handler)
        with pytest.raises(ScreenSessionExistsError):
            await session.create("uptime")


class TestStatus:
    """Тесты is_alive, get_pid, get_exit_code."""

    async def test_is_alive_true(self):
        """is_alive: True, если сессия есть в screen -ls."""
        def handler(command: str, **kwargs) -> Result:
            if command == "screen -ls":
                return make_result("\t12345.s1\t(Detached)\n", command=command)
            return make_result("", command=command)

        assert await make_session(handler).is_alive() is True

    async def test_is_alive_false(self):
        """is_alive: False, если сессии нет."""
        assert await make_session().is_alive() is False

    async def test_get_pid(self):
        """get_pid парсит формат {PID}.{name} из screen -ls."""
        def handler(command: str, **kwargs) -> Result:
            if command == "screen -ls":
                return make_result("\t12345.s1\t(Detached)\n\t999.other\t(Detached)\n")
            return make_result("", command=command)

        assert await make_session(handler).get_pid() == 12345

    async def test_get_pid_not_found(self):
        """get_pid: None, если сессии нет."""
        assert await make_session().get_pid() is None

    async def test_get_exit_code(self):
        """get_exit_code читает exit-файл."""
        def handler(command: str, **kwargs) -> Result:
            if command == "cat /tmp/uniconn_s1.exit":
                return make_result("42\n", command=command)
            return make_result("", command=command)

        assert await make_session(handler).get_exit_code() == 42

    async def test_get_exit_code_not_ready(self):
        """get_exit_code: None, если exit-файла ещё нет."""
        def handler(command: str, **kwargs) -> Result:
            if command.startswith("cat "):
                return make_result("", exit_code=1, command=command)
            return make_result("", command=command)

        assert await make_session(handler).get_exit_code() is None


class TestControl:
    """Тесты send_ctrl_c, send_signal, kill, cleanup."""

    async def test_send_ctrl_c(self):
        r"""send_ctrl_c отправляет stuff $'\003' в сессию."""
        session = make_session()
        await session.send_ctrl_c()

        cmd = session.connection.run.call_args.args[0]
        assert cmd == "screen -S s1 -X stuff $'\\003'"

    async def test_send_signal(self):
        """send_signal отправляет kill -{sig} по PID сессии."""
        def handler(command: str, **kwargs) -> Result:
            if command == "screen -ls":
                return make_result("\t12345.s1\t(Detached)\n", command=command)
            return make_result("", command=command)

        session = make_session(handler)
        await session.send_signal(9)

        calls = [c.args[0] for c in session.connection.run.call_args_list]
        assert "kill -9 12345" in calls

    async def test_kill_graceful(self):
        """kill(graceful=True): Ctrl+C достаточно, force kill не вызывается."""
        state = {"alive": True}

        def handler(command: str, **kwargs) -> Result:
            if command == "screen -ls":
                if state["alive"]:
                    return make_result("\t12345.s1\t(Detached)\n", command=command)
                return make_result("", exit_code=1, command=command)
            if "stuff" in command:
                state["alive"] = False
            return make_result("", command=command)

        session = make_session(handler)
        await session.kill(graceful=True)

        calls = [c.args[0] for c in session.connection.run.call_args_list]
        assert any("stuff" in c for c in calls)
        assert not any("-X kill" in c for c in calls)

    async def test_kill_force(self):
        """kill(graceful=False): сразу screen -X kill."""
        def handler(command: str, **kwargs) -> Result:
            if command == "screen -ls":
                return make_result("\t12345.s1\t(Detached)\n", command=command)
            return make_result("", command=command)

        session = make_session(handler)
        await session.kill(graceful=False)

        calls = [c.args[0] for c in session.connection.run.call_args_list]
        assert "screen -S s1 -X kill" in calls
        assert not any("stuff" in c for c in calls)

    async def test_cleanup(self):
        """Cleanup удаляет лог, exit-файл и wrapper-скрипт."""
        session = make_session()
        await session.cleanup()

        cmd = session.connection.run.call_args.args[0]
        assert cmd == "rm -f /tmp/s1.log /tmp/uniconn_s1.exit /tmp/uniconn_s1.sh"
