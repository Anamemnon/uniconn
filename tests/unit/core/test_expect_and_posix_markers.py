# tests/unit/releases/test_v070_features.py
"""Unit-тесты возможностей v0.7.0: expect(), forward_local_port/remote_port, sync_dir, write_template."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import SecretStr

from examples.dashboard.server import _execute_pool_sandbox, _execute_v070_sandbox
from uniconn import (
    Connection,
    ConnectionConfig,
    ConnectionPool,
    ShellSession,
    SyncResult,
    TimeoutError,
    cli,
    render_template,
)
from uniconn.transports._serial import SerialTransport
from uniconn.transports._ssh import SSHTransport


class FakeInteractiveProcess:
    """Фейковый интерактивный процесс без POSIX-маркеров (имитация Cisco IOS / fdisk / прошивальщика)."""

    def __init__(self, script_steps: list[tuple[str, str]], initial_banner: str = "") -> None:
        self._steps = list(script_steps)
        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self.written: list[str] = []
        self.returncode: int | None = None
        if initial_banner:
            self._queue.put_nowait(initial_banner)

        self.stdin = MagicMock()
        self.stdin.write = MagicMock(side_effect=self._on_write)
        self.stdin.drain = AsyncMock()
        self.stdin.close = MagicMock()

        self.stdout = MagicMock()
        self.stdout.read = AsyncMock(side_effect=self._on_read)

    def _on_write(self, data: str) -> None:
        self.written.append(data)
        for idx, (expected_in, reply_out) in enumerate(self._steps):
            if expected_in in data:
                self._steps.pop(idx)
                self._queue.put_nowait(reply_out)
                if not self._steps:
                    # Поток закрывается после финального шага, если это одноразовая утилита
                    pass
                break

    async def _on_read(self, _n: int = 4096) -> str:
        return await self._queue.get()

    def close(self) -> None:
        self.returncode = 0

    async def wait_closed(self) -> None:
        self.returncode = 0


class TestDeclarativeExpect:
    """Тесты 1.1: Декларативный expect() для интерактивных CLI и сетевого оборудования."""

    @pytest.mark.asyncio
    async def test_shell_session_expect_with_secret_and_final_prompt(self) -> None:
        """ShellSession.expect() автоматически отвечает на промпты и поддерживает SecretStr."""
        proc = FakeInteractiveProcess(
            script_steps=[
                ("sysupgrade firmware.bin\n", "Proceed with flash? [y/N]: "),
                ("y\n", "Password: "),
                ("superSecret!\n", "Flashing 100%...\nRouter# "),
            ]
        )
        session = ShellSession(proc, host="router.local", default_timeout=5.0)
        res = await session.expect(
            "sysupgrade firmware.bin",
            patterns={
                r"\[y/N\]:": "y\n",
                r"Password:": SecretStr("superSecret!\n"),
            },
            final_prompt=r"Router#\s*$",
        )
        assert res.ok
        assert "Flashing 100%..." in res.stdout
        assert "Router#" in res.stdout
        assert proc.written == ["sysupgrade firmware.bin\n", "y\n", "superSecret!\n"]

    @pytest.mark.asyncio
    async def test_shell_session_expect_without_final_prompt_settles(self) -> None:
        """Если final_prompt не задан, expect() завершается после срабатывания всех паттернов."""
        proc = FakeInteractiveProcess(
            script_steps=[
                ("fdisk /dev/sda\n", "Command (m for help): "),
                ("p\n", "Disk /dev/sda: 100 GiB\nCommand (m for help): "),
                ("q\n", "Exiting fdisk.\n"),
            ]
        )
        session = ShellSession(proc, host="storage-node", default_timeout=2.0)
        res = await session.expect(
            "fdisk /dev/sda",
            patterns={
                r"Command \(m for help\):": "p\n",
                r"Disk /dev/sda:[^\n]*\nCommand \(m for help\):": "q\n",
            },
            final_prompt=None,
        )
        assert res.ok
        assert "Disk /dev/sda: 100 GiB" in res.stdout
        assert "Exiting fdisk." in res.stdout

    @pytest.mark.asyncio
    async def test_shell_session_expect_timeout_raises(self) -> None:
        """При непоявлении ожидаемого промпта expect() выбрасывает TimeoutError и шлёт Ctrl-C."""
        proc = FakeInteractiveProcess(
            script_steps=[
                ("hang_cmd\n", "Waiting forever...\n"),
            ]
        )
        session = ShellSession(proc, host="switch-01", default_timeout=0.2)
        with pytest.raises(TimeoutError, match="Expect dialog timed out"):
            await session.expect(
                "hang_cmd",
                patterns={r"NeverMatches:": "yes\n"},
                final_prompt=r"Switch#",
                timeout=0.15,
            )
        assert "\x03" in proc.written

    @pytest.mark.asyncio
    async def test_connection_expect_local_pty_and_sync_parity(self) -> None:
        """Connection.expect() и SyncConnection.expect() работают поверх реального Local PTY."""
        py_cmd = (
            "python3 -u -c \""
            "a = input('Confirm [y/N]: '); "
            "b = input('Code: '); "
            "print('DONE:' + a + ':' + b)"
            "\""
        )
        async with Connection.from_uri("local://") as conn:
            res = await conn.expect(
                py_cmd,
                patterns={
                    r"Confirm \[y/N\]:": "y\n",
                    r"Code:": "42\n",
                },
                final_prompt=r"DONE:y:42",
                timeout=5.0,
            )
            assert res.ok
            assert "DONE:y:42" in res.stdout

        with Connection.from_uri("local://").to_sync() as sync_conn:
            res_sync = sync_conn.expect(
                py_cmd,
                patterns={
                    r"Confirm \[y/N\]:": "y\n",
                    r"Code:": "99\n",
                },
                final_prompt=r"DONE:y:99",
                timeout=5.0,
            )
            assert res_sync.ok
            assert "DONE:y:99" in res_sync.stdout

    @pytest.mark.asyncio
    async def test_serial_transport_open_shell_and_expect(self) -> None:
        """SerialTransport.open_shell() позволяет выполнять интерактивный expect() поверх UART."""
        cfg = ConnectionConfig(transport="serial", host="/dev/ttyUSB0")
        transport = SerialTransport(cfg)
        transport._connected = True

        reader = MagicMock()
        queue: asyncio.Queue[bytes] = asyncio.Queue()

        writer = MagicMock()

        def _on_serial_write(data: bytes) -> None:
            text = data.decode("utf-8")
            if "AT+CPIN?" in text:
                queue.put_nowait(b"+CPIN: SIM PIN\r\nEnter PIN: ")
            elif "1234" in text:
                queue.put_nowait(b"\r\nOK\r\n")

        writer.write = MagicMock(side_effect=_on_serial_write)
        writer.drain = AsyncMock()
        writer.close = MagicMock()

        async def _serial_read(_n: int = 4096) -> bytes:
            return await queue.get()

        reader.read = AsyncMock(side_effect=_serial_read)
        transport._reader = reader
        transport._writer = writer

        conn = Connection.from_config(cfg)
        conn._transport = transport

        res = await conn.expect(
            "AT+CPIN?",
            patterns={r"Enter PIN:": "1234\r\n"},
            final_prompt=r"OK",
            line_ending="\r\n",
            timeout=2.0,
        )
        assert res.ok
        assert "+CPIN: SIM PIN" in res.stdout
        assert "OK" in res.stdout


class TestSSHPortForwarding:
    """Тесты 1.2: Прямой и обратный проброс портов (SSH Local / Remote Port Forwarding)."""

    @pytest.mark.asyncio
    async def test_forward_local_and_remote_port_async_and_sync(self) -> None:
        """forward_local_port и forward_remote_port возвращают bound_port и закрывают listener."""
        cfg = ConnectionConfig(transport="ssh", host="bastion.internal", username="ops")
        transport = SSHTransport(cfg)
        transport._connected = True

        local_listener = MagicMock()
        local_listener.get_port = MagicMock(return_value=54321)
        local_listener.close = MagicMock()
        local_listener.wait_closed = AsyncMock()

        remote_listener = MagicMock()
        remote_listener.get_port = MagicMock(return_value=19090)
        remote_listener.close = MagicMock()
        remote_listener.wait_closed = AsyncMock()

        mock_ssh_conn = MagicMock()
        mock_ssh_conn.forward_local_port = AsyncMock(return_value=local_listener)
        mock_ssh_conn.forward_remote_port = AsyncMock(return_value=remote_listener)
        mock_ssh_conn.close = MagicMock()
        mock_ssh_conn.wait_closed = AsyncMock()
        transport._conn = mock_ssh_conn

        conn = Connection.from_config(cfg)
        conn._transport = transport

        async with conn.tunnels.forward_local_port(
            remote_host="10.0.0.5",
            remote_port=5432,
            local_host="127.0.0.1",
            local_port=0,
        ) as bound_port:
            assert bound_port == 54321
            mock_ssh_conn.forward_local_port.assert_awaited_once_with(
                "127.0.0.1", 0, "10.0.0.5", 5432
            )

        local_listener.close.assert_called_once()
        local_listener.wait_closed.assert_awaited_once()

        async with conn.tunnels.forward_remote_port(
            remote_host="0.0.0.0",
            remote_port=0,
            local_host="127.0.0.1",
            local_port=8000,
        ) as r_port:
            assert r_port == 19090
            mock_ssh_conn.forward_remote_port.assert_awaited_once_with(
                "0.0.0.0", 0, "127.0.0.1", 8000
            )

        remote_listener.close.assert_called_once()
        remote_listener.wait_closed.assert_awaited_once()

        # Проверка синхронной обёртки SyncConnection
        sync_conn = conn.to_sync()
        try:
            with sync_conn.tunnels.forward_local_port("10.0.0.5", 5432) as sync_port:
                assert sync_port == 54321
        finally:
            sync_conn.close()

    @pytest.mark.asyncio
    async def test_forward_port_unsupported_transport_raises(self) -> None:
        """Для неподдерживаемых транспортов (local://) выбрасывается NotImplementedError."""
        async with Connection.from_uri("local://") as conn:
            with pytest.raises(NotImplementedError, match="forward_local_port not supported"):
                async with conn.tunnels.forward_local_port("127.0.0.1", 5432):
                    pass


class TestSmartSyncDirAndTemplating:
    """Тесты 1.3: Умная синхронизация директорий (sync_dir) и шаблонизация (write_template)."""

    @pytest.mark.asyncio
    async def test_sync_dir_incremental_exclude_delete_and_dry_run(self, tmp_path: Path) -> None:
        """sync_dir передаёт только изменившиеся файлы, учитывает exclude и удаляет лишние при delete=True."""
        src = tmp_path / "src"
        dst = tmp_path / "dst"
        src.mkdir()
        (src / "sub").mkdir()
        (src / ".git").mkdir()

        (src / "app.py").write_text("print('v1')\n", encoding="utf-8")
        (src / "sub" / "worker.py").write_text("x = 1\n", encoding="utf-8")
        (src / "ignored.pyc").write_bytes(b"\x00\x01")
        (src / ".git" / "config").write_text("gitdata", encoding="utf-8")

        async with Connection.from_uri("local://") as conn:
            # 1. Dry-run ничего не записывает на диск
            dry_res = await conn.files.sync_dir(
                src, dst, exclude=["*.pyc", ".git"], dry_run=True
            )
            assert dry_res.dry_run is True
            assert sorted(dry_res.uploaded) == ["app.py", "sub/worker.py"]
            assert not dst.exists()

            # 2. Первая реальная синхронизация загружает 2 файла
            res1 = await conn.files.sync_dir(src, dst, exclude=["*.pyc", ".git"])
            assert isinstance(res1, SyncResult)
            assert sorted(res1.uploaded) == ["app.py", "sub/worker.py"]
            assert res1.skipped == []
            assert res1.deleted == []
            assert (dst / "app.py").read_text(encoding="utf-8") == "print('v1')\n"
            assert not (dst / "ignored.pyc").exists()
            assert not (dst / ".git").exists()

            # 3. Повторная синхронизация без изменений пропускает все файлы
            res2 = await conn.files.sync_dir(src, dst, exclude=["*.pyc", ".git"])
            assert res2.uploaded == []
            assert sorted(res2.skipped) == ["app.py", "sub/worker.py"]

            # 4. Модифицируем один файл и добавляем лишний файл в dst для проверки delete=True
            (src / "app.py").write_text("print('v2_updated')\n", encoding="utf-8")
            future_mtime = (dst / "app.py").stat().st_mtime + 10.0
            os.utime(src / "app.py", (future_mtime, future_mtime))
            (dst / "orphan.txt").write_text("remove me", encoding="utf-8")

            res3 = await conn.files.sync_dir(
                src, dst, delete=True, exclude=["*.pyc", ".git"]
            )
            assert res3.uploaded == ["app.py"]
            assert res3.skipped == ["sub/worker.py"]
            assert res3.deleted == ["orphan.txt"]
            assert not (dst / "orphan.txt").exists()
            assert (dst / "app.py").read_text(encoding="utf-8") == "print('v2_updated')\n"

    def test_render_template_string_and_jinja2_fallback(self, tmp_path: Path) -> None:
        """render_template поддерживает string.Template, файлы шаблонов и Jinja2."""
        out_str = render_template(
            "listen = $host:$port",
            context={"host": "127.0.0.1", "port": 9000},
            engine="string",
        )
        assert out_str == "listen = 127.0.0.1:9000"

        tpl_file = tmp_path / "app.conf.tpl"
        tpl_file.write_text("workers = ${workers}\n", encoding="utf-8")
        assert render_template(tpl_file, {"workers": 8}) == "workers = 8\n"

        # Проверка Jinja2 (через мок, если jinja2 не установлен в окружении)
        fake_jinja = MagicMock()
        fake_env = MagicMock()
        fake_tpl = MagicMock()
        fake_tpl.render.return_value = "server web-01:8080;"
        fake_env.from_string.return_value = fake_tpl
        fake_jinja.Environment.return_value = fake_env
        fake_jinja.StrictUndefined = object

        with patch.dict("sys.modules", {"jinja2": fake_jinja}):
            rendered_j2 = render_template(
                "server {{ host }}:{{ port }};",
                context={"host": "web-01", "port": 8080},
                engine="auto",
            )
            assert rendered_j2 == "server web-01:8080;"

    @pytest.mark.asyncio
    async def test_write_template_connection_sync_and_pool(self, tmp_path: Path) -> None:
        """write_template и sync_dir работают в Connection.files, SyncConnection.files и ConnectionPool.files."""
        cfg_file = tmp_path / "nginx.conf"
        async with Connection.from_uri("local://") as conn:
            rendered = await conn.files.write_template(
                cfg_file,
                "user $user;\nworker_processes $workers;\n",
                context={"user": "www-data", "workers": 4},
                mode=0o640,
            )
            assert "worker_processes 4;" in rendered
            assert cfg_file.read_text(encoding="utf-8") == rendered
            assert (cfg_file.stat().st_mode & 0o777) == 0o640

        # SyncConnection
        sync_target = tmp_path / "sync_service.conf"
        with Connection.from_uri("local://").to_sync() as sconn:
            sconn.files.write_template(
                sync_target,
                "port=$port\n",
                context={"port": 7070},
            )
            assert sync_target.read_text(encoding="utf-8") == "port=7070\n"

        # ConnectionPool
        pool_target = tmp_path / "pool_out.conf"
        pool = ConnectionPool(["local://?node=1", "local://?node=2"])
        pool_res = await pool.files.write_template(
            pool_target,
            "cluster=$cluster\n",
            context={"cluster": "eu-west"},
        )
        assert len(pool_res) == 2
        assert pool_target.read_text(encoding="utf-8") == "cluster=eu-west\n"


class TestCLIAndDashboardV070:
    """Тесты CLI-команд (sync, template, expect) и песочницы веб-панели v0.7.0."""

    def test_cli_sync_template_and_expect_commands(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """CLI-команды sync, template и expect корректно выполняются на local://."""
        src = tmp_path / "cli_src"
        dst = tmp_path / "cli_dst"
        src.mkdir()
        (src / "hello.txt").write_text("hello v0.7.0", encoding="utf-8")

        monkeypatch.setattr("sys.argv", ["uniconn", "sync", str(src), str(dst), "local://", "--format", "json"])
        with pytest.raises(SystemExit) as exc_sync:
            cli.main()
        assert exc_sync.value.code == 0
        assert (dst / "hello.txt").read_text(encoding="utf-8") == "hello v0.7.0"

        tpl_out = tmp_path / "cli_rendered.conf"
        monkeypatch.setattr(
            "sys.argv",
            [
                "uniconn",
                "template",
                "env=$env",
                str(tpl_out),
                "local://",
                "-D",
                "env=staging",
                "--format",
                "json",
            ],
        )
        with pytest.raises(SystemExit) as exc_tpl:
            cli.main()
        assert exc_tpl.value.code == 0
        assert tpl_out.read_text(encoding="utf-8") == "env=staging"

        monkeypatch.setattr(
            "sys.argv",
            [
                "uniconn",
                "expect",
                "local://",
                "python3 -u -c \"x = input('Ask: '); print('ANS=' + x)\"",
                "-p",
                "Ask:=ok\\n",
                "--final-prompt",
                "ANS=ok",
                "--format",
                "json",
            ],
        )
        with pytest.raises(SystemExit) as exc_exp:
            cli.main()
        assert exc_exp.value.code == 0

    def test_dashboard_v070_and_pool_sandboxes(self) -> None:
        """Веб-панель поддерживает /api/v070 (expect, sync_dir, write_template) и групповые операции."""
        exp_res = _execute_v070_sandbox({"feature": "expect"})
        assert exp_res["status"] == "ok"
        assert "FLASH_COMPLETE" in exp_res["result"]["stdout"]

        sync_res = _execute_v070_sandbox({"feature": "sync_dir"})
        assert sync_res["status"] == "ok"
        assert len(sync_res["pass1"]["uploaded"]) == 2
        assert len(sync_res["pass2"]["skipped"]) == 2

        tpl_res = _execute_v070_sandbox({"feature": "write_template"})
        assert tpl_res["status"] == "ok"
        assert "listen 8080;" in tpl_res["rendered"]

        pool_sync = _execute_pool_sandbox({"group": "web", "operation": "sync_dir"})
        assert pool_sync["status"] == "ok"
        assert pool_sync["ok_hosts"] == 2

        pool_tpl = _execute_pool_sandbox({"group": "web", "operation": "write_template"})
        assert pool_tpl["status"] == "ok"
        assert pool_tpl["ok_hosts"] == 2
