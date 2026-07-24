# tests/unit/test_screen_cleanup.py
"""Тесты ScreenCleanupManager — sentinel, cleanup-скрипт, хуки, остановка сессий."""

import signal
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

from uniconn.background._cleanup import ScreenCleanupManager
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


def make_session(session_id: str = "s1") -> MagicMock:
    """Мок ScreenSession с AsyncMock kill."""
    session = MagicMock()
    session.session_id = session_id
    session.kill = AsyncMock()
    return session


class TestPaths:
    """Тесты путей sentinel и cleanup-скрипта."""

    def test_sentinel_and_script_paths(self):
        """Пути формируются по pool_id: /tmp/uniconn_{pool_id}.active и .sh."""
        manager = ScreenCleanupManager("pool1")
        assert manager.sentinel_path == "/tmp/uniconn_pool1.active"
        assert manager.cleanup_script_path == "/tmp/uniconn_cleanup_pool1.sh"


class TestGenerateCleanupScript:
    """Тесты generate_cleanup_script."""

    def test_script_content(self):
        """Скрипт содержит pool_id, grep по префиксу, rm артефактов и самоудаление."""
        script = ScreenCleanupManager("pool1").generate_cleanup_script()
        assert 'POOL_ID="pool1"' in script
        assert 'screen -ls | grep "uniconn_${POOL_ID}_"' in script
        assert "rm -f /tmp/uniconn_${POOL_ID}_*.log" in script
        assert "rm -f /tmp/uniconn_${POOL_ID}_*.exit" in script
        assert "rm -f /tmp/uniconn_${POOL_ID}_*.sh" in script
        assert "rm -f /tmp/uniconn_${POOL_ID}.active" in script
        assert 'rm -f "$0"' in script


class TestInstallServerSide:
    """Тесты install_server_side."""

    async def test_runs_sentinel_script_chmod(self):
        """install_server_side: sentinel printf, script printf, chmod +x — 3 вызова run."""
        conn = MagicMock()
        conn.run = AsyncMock(
            side_effect=lambda command, **kwargs: make_result("", command=command)
        )
        manager = ScreenCleanupManager("pool1")
        manager.register_session(make_session("s1"))
        try:
            await manager.install_server_side(conn)
        finally:
            manager.uninstall()

        calls = [c.args[0] for c in conn.run.call_args_list]
        assert len(calls) == 3
        assert calls[0].startswith("printf '%s'")
        assert calls[0].endswith("> /tmp/uniconn_pool1.active")
        assert '"pool1"' in calls[0] and '"s1"' in calls[0]
        assert calls[1].startswith("printf '%s'")
        assert calls[1].endswith("> /tmp/uniconn_cleanup_pool1.sh")
        assert calls[2] == "chmod +x /tmp/uniconn_cleanup_pool1.sh"


class TestCleanupAll:
    """Тесты cleanup_all."""

    async def test_stops_all_sessions(self):
        """cleanup_all останавливает все зарегистрированные сессии."""
        manager = ScreenCleanupManager("pool1")
        sessions = [make_session("s1"), make_session("s2")]
        manager._sessions = {s.session_id: s for s in sessions}

        await manager.cleanup_all(graceful=True)
        for s in sessions:
            s.kill.assert_awaited_once_with(graceful=True)

    async def test_one_failure_does_not_stop_others(self, caplog):
        """Ошибка kill одной сессии логируется warning и не роняет остальные."""
        manager = ScreenCleanupManager("pool1")
        bad = make_session("bad")
        bad.kill = AsyncMock(side_effect=Exception("ssh down"))
        good = make_session("good")
        manager._sessions = {"bad": bad, "good": good}

        await manager.cleanup_all()
        good.kill.assert_awaited_once()
        assert "Ошибка остановки сессии bad" in caplog.text


class TestHooks:
    """Тесты установки и снятия хуков очистки."""

    def test_register_installs_uninstall_restores(self):
        """register_session ставит atexit/signal хуки, uninstall их снимает."""
        manager = ScreenCleanupManager("pool1")
        prev_int = signal.getsignal(signal.SIGINT)
        try:
            manager.register_session(make_session())
            assert manager._installed is True
            assert signal.getsignal(signal.SIGINT) == manager._on_signal
        finally:
            manager.uninstall()
        assert manager._installed is False
        assert signal.getsignal(signal.SIGINT) == prev_int

    def test_on_signal_first_graceful_second_force(self):
        """_on_signal: первый сигнал → force=False, второй → force=True."""
        manager = ScreenCleanupManager("pool1")
        manager.cleanup_local = MagicMock()

        manager._on_signal(signal.SIGINT, None)
        manager._on_signal(signal.SIGINT, None)

        calls = manager.cleanup_local.call_args_list
        assert calls[0].kwargs["force"] is False
        assert calls[1].kwargs["force"] is True
