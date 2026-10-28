# tests/unit/screen/test_screen_session.py
"""Тесты BackgroundSession и стратегий (TmuxBackend, ScreenBackend, NohupBackend, resolve_backend)."""

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from uniconn.background import (
    BackgroundBackendStrategy,
    BackgroundSession,
    NohupBackend,
    ScreenBackend,
    TmuxBackend,
    get_backend_by_name,
    resolve_backend,
)
from uniconn.exceptions import (
    BackgroundBackendError,
    BackgroundSessionExistsError,
    ConfigurationError,
)
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


def default_screen_handler(command: str, **kwargs) -> Result:
    """Стандартный хост с GNU screen, без активных сессий."""
    if command == "command -v screen >/dev/null 2>&1":
        return make_result("", command=command)
    if command == "screen -ls":
        return make_result("No Sockets found in /run/screen/S-user.\n", exit_code=1)
    return make_result("", command=command)


def make_session(
    handler=default_screen_handler,
    session_id: str = "s1",
    backend: BackgroundBackendStrategy | str = "screen",
) -> BackgroundSession:
    """BackgroundSession с мок-подключением."""
    return BackgroundSession(
        make_connection(handler),
        session_id,
        "/tmp/s1.log",
        backend=backend,  # type: ignore[arg-type]
    )


class TestResolveBackendAndStrategies:
    """Тесты автовыбора бэкенда resolve_backend и стратегий TmuxBackend, ScreenBackend, NohupBackend."""

    async def test_resolve_backend_auto_chain(self):
        """resolve_backend('auto') выбирает tmux -> screen -> nohup за один запрос."""
        conn_tmux = make_connection(lambda cmd, **kw: make_result("tmux\n", command=cmd))
        b_tmux = await resolve_backend(conn_tmux, "auto")
        assert isinstance(b_tmux, TmuxBackend)
        assert b_tmux.name == "tmux"
        assert conn_tmux.run.await_count == 1

        conn_screen = make_connection(
            lambda cmd, **kw: make_result("screen\n", command=cmd)
        )
        b_screen = await resolve_backend(conn_screen, "auto")
        assert isinstance(b_screen, ScreenBackend)
        assert b_screen.name == "screen"

        conn_nohup = make_connection(
            lambda cmd, **kw: make_result("nohup\n", command=cmd)
        )
        b_nohup = await resolve_backend(conn_nohup, "auto")
        assert isinstance(b_nohup, NohupBackend)
        assert b_nohup.name == "nohup"

    async def test_resolve_backend_explicit_missing_raises(self):
        """Явный выбор отсутствующего tmux или screen выбрасывает BackgroundBackendError."""
        conn = make_connection(lambda cmd, **kw: make_result("", exit_code=1, command=cmd))
        with pytest.raises(BackgroundBackendError):
            await resolve_backend(conn, "tmux")
        with pytest.raises(BackgroundBackendError):
            await resolve_backend(conn, "screen")

    def test_get_backend_by_name_unknown_raises_configuration_error(self):
        """Неизвестное имя бэкенда выбрасывает ConfigurationError."""
        with pytest.raises(ConfigurationError):
            get_backend_by_name("invalid_backend")

    async def test_tmux_backend_lifecycle(self):
        """TmuxBackend: start_session, is_alive, get_pid, list_sessions, send_interrupt, terminate."""
        state = {"alive": False}

        def handler(command: str, **kwargs) -> Result:
            if "command -v tmux" in command:
                return make_result("", exit_code=0, command=command)
            if command.startswith("tmux new-session"):
                state["alive"] = True
                return make_result("", exit_code=0, command=command)
            if command.startswith("tmux has-session"):
                return make_result(
                    "", exit_code=0 if state["alive"] else 1, command=command
                )
            if command.startswith("tmux list-panes -t"):
                return make_result(
                    "4242\n" if state["alive"] else "",
                    exit_code=0 if state["alive"] else 1,
                    command=command,
                )
            if command.startswith("tmux list-panes -a"):
                return make_result(
                    "uniconn_p1_0 4242\nother 111\n", exit_code=0, command=command
                )
            if command.startswith("tmux kill-session"):
                state["alive"] = False
                return make_result("", exit_code=0, command=command)
            return make_result("", command=command)

        conn = make_connection(handler)
        session = BackgroundSession(conn, "uniconn_p1_0", "/tmp/t.log", backend="tmux")
        await session.create("sleep 10")
        assert session.backend_name == "tmux"
        assert await session.is_alive() is True
        assert await session.get_pid() == 4242

        listed = await TmuxBackend().list_sessions(conn, prefix="uniconn_p1_")
        assert listed == {"uniconn_p1_0": 4242}

        await session.kill(graceful=False)
        assert await session.is_alive() is False

    async def test_nohup_backend_lifecycle(self):
        """NohupBackend: PID-файл, setsid/nohup, проверка kill -0 и отсутствие .exit, SIGINT/SIGKILL с pkill -P."""
        state = {"alive": False}
        signal_cmds: list[str] = []

        def handler(command: str, **kwargs) -> Result:
            if "setsid sh" in command and "nohup sh" in command:
                state["alive"] = True
                return make_result("", exit_code=0, command=command)
            if "kill -0 $(cat" in command:
                return make_result(
                    "", exit_code=0 if state["alive"] else 1, command=command
                )
            if 'kill -0 "$pid" 2>/dev/null && echo "$pid"' in command:
                return make_result(
                    "7788\n" if state["alive"] else "",
                    exit_code=0,
                    command=command,
                )
            if "for f in /tmp/" in command:
                return make_result(
                    "uniconn_p1_0 7788\n" if state["alive"] else "",
                    exit_code=0,
                    command=command,
                )
            if "kill -INT" in command or "kill -KILL" in command:
                signal_cmds.append(command)
                state["alive"] = False
                return make_result("", exit_code=0, command=command)
            return make_result("", command=command)

        conn = make_connection(handler)
        session = BackgroundSession(
            conn, "uniconn_p1_0", "/tmp/n.log", backend="nohup"
        )
        await session.create("python3 worker.py")
        assert session.backend_name == "nohup"
        assert await session.is_alive() is True
        assert await session.get_pid() == 7788

        listed = await NohupBackend().list_sessions(conn, prefix="uniconn_p1_")
        assert listed == {"uniconn_p1_0": 7788}

        await session.kill(graceful=True)
        assert await session.is_alive() is False
        assert any("pkill -INT -P 7788" in c for c in signal_cmds)

        # Проверим также принудительный terminate (SIGKILL дерева)
        await NohupBackend().terminate(conn, "uniconn_p1_0", session.pid_file_path)
        assert any('pkill -KILL -P "$pid"' in c for c in signal_cmds)


class TestCreate:
    """Тесты создания сессии (на примере ScreenBackend)."""

    async def test_create_runs_expected_commands(self):
        """create: проверка screen → запись скрипта с PID, POSIX trap и exit → запуск screen."""
        session = make_session()
        await session.create("stress-ng --cpu 4")

        calls = [c.args[0] for c in session.connection.run.call_args_list]
        assert calls[0] == "command -v screen >/dev/null 2>&1"
        assert calls[1] == "screen -ls"
        # Wrapper-скрипт содержит запись PID, POSIX trap (EXIT/INT/TERM), команду и запись exit code
        assert "printf '%s'" in calls[2]
        assert "echo $$ > /tmp/uniconn_s1.pid" in calls[2]
        assert 'trap "rc=\\$?; [ -f /tmp/uniconn_s1.exit ] || echo \\$rc > /tmp/uniconn_s1.exit" EXIT' in calls[2]
        assert 'trap "exit 130" INT' in calls[2]
        assert 'trap "exit 143" TERM' in calls[2]
        assert "stress-ng --cpu 4" in calls[2]
        assert "echo $? > /tmp/uniconn_s1.exit" in calls[2]
        assert "/tmp/uniconn_s1.sh" in calls[2]
        assert calls[3].startswith("screen -dmS s1")
        assert "/tmp/s1.log" in calls[3]

    async def test_create_backend_not_found(self):
        """Create падает с BackgroundBackendError, если явно указанный screen не установлен."""

        def handler(command: str, **kwargs) -> Result:
            if "command -v screen" in command:
                return make_result("", exit_code=1, command=command)
            return make_result("", command=command)

        session = make_session(handler, backend="screen")
        with pytest.raises(BackgroundBackendError):
            await session.create("uptime")

    async def test_create_session_exists(self):
        """Create падает с BackgroundSessionExistsError, если имя занято."""

        def handler(command: str, **kwargs) -> Result:
            if "command -v screen" in command:
                return make_result("", command=command)
            if command == "screen -ls":
                return make_result(
                    "There is a screen on:\n\t12345.s1\t(Detached)\n", command=command
                )
            return make_result("", command=command)

        session = make_session(handler)
        with pytest.raises(BackgroundSessionExistsError):
            await session.create("uptime")


class TestStatus:
    """Тесты is_alive, get_pid, get_exit_code."""

    async def test_is_alive_true(self):
        """is_alive: True, если сессия есть в screen -ls."""

        def handler(command: str, **kwargs) -> Result:
            if command == "screen -ls":
                return make_result("\t12345.s1\t(Detached)\n", command=command)
            return make_result("", command=command)

        assert await make_session(handler, backend=ScreenBackend()).is_alive() is True

    async def test_is_alive_false(self):
        """is_alive: False, если сессии нет."""
        assert await make_session(backend=ScreenBackend()).is_alive() is False

    async def test_get_pid(self):
        """get_pid парсит формат {PID}.{name} из screen -ls."""

        def handler(command: str, **kwargs) -> Result:
            if command == "screen -ls":
                return make_result("\t12345.s1\t(Detached)\n\t999.other\t(Detached)\n")
            return make_result("", command=command)

        assert await make_session(handler, backend=ScreenBackend()).get_pid() == 12345

    async def test_get_pid_not_found(self):
        """get_pid: None, если сессии нет."""
        assert await make_session(backend=ScreenBackend()).get_pid() is None

    async def test_get_exit_code(self):
        """get_exit_code читает exit-файл."""

        def handler(command: str, **kwargs) -> Result:
            if command == "cat /tmp/uniconn_s1.exit":
                return make_result("42\n", command=command)
            return make_result("", command=command)

        assert await make_session(handler, backend=ScreenBackend()).get_exit_code() == 42

    async def test_get_exit_code_not_ready(self):
        """get_exit_code: None, если exit-файла ещё нет."""

        def handler(command: str, **kwargs) -> Result:
            if command.startswith("cat "):
                return make_result("", exit_code=1, command=command)
            return make_result("", command=command)

        assert (
            await make_session(handler, backend=ScreenBackend()).get_exit_code() is None
        )


class TestControl:
    """Тесты send_ctrl_c, send_signal, kill, cleanup."""

    async def test_send_ctrl_c(self):
        r"""send_ctrl_c отправляет POSIX-совместимый stuff "$(printf '\003')" в screen-сессию."""
        session = make_session(backend=ScreenBackend())
        await session.send_ctrl_c()

        cmd = session.connection.run.call_args.args[0]
        assert cmd == 'screen -S s1 -X stuff "$(printf \'\\003\')"'

    async def test_send_signal(self):
        """send_signal отправляет kill -{sig} по PID сессии."""

        def handler(command: str, **kwargs) -> Result:
            if command == "screen -ls":
                return make_result("\t12345.s1\t(Detached)\n", command=command)
            return make_result("", command=command)

        session = make_session(handler, backend=ScreenBackend())
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

        session = make_session(handler, backend=ScreenBackend())
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

        session = make_session(handler, backend=ScreenBackend())
        await session.kill(graceful=False)

        calls = [c.args[0] for c in session.connection.run.call_args_list]
        assert "screen -S s1 -X kill" in calls
        assert not any("stuff" in c for c in calls)

    async def test_cleanup(self):
        """Cleanup удаляет лог, exit-файл, PID-файл и wrapper-скрипт."""
        session = make_session(backend=ScreenBackend())
        await session.cleanup()

        cmd = session.connection.run.call_args.args[0]
        assert (
            cmd
            == "rm -f /tmp/s1.log /tmp/uniconn_s1.exit /tmp/uniconn_s1.pid /tmp/uniconn_s1.sh"
        )
