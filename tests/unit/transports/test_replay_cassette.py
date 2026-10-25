# tests/unit/transports/test_replay_cassette.py
"""Unit-тесты для ReplayTransport, CassetteTransportProxy и контекстного менеджера use_cassette."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from uniconn import (
    Cassette,
    CassetteError,
    CassetteMissError,
    Connection,
    ConnectionConfig,
    RecordedExecInteraction,
    RecordedFsInteraction,
    RecordedShellInteraction,
    RecordedStreamInteraction,
    RecordMode,
    ReplayTransport,
    ShellDialogStep,
    normalize_temp_paths,
)
from uniconn.plugins._loader import TransportLoader
from uniconn.transports._local import LocalTransport


class TestNormalizeTempPaths:
    """Проверка нормализации временных путей /tmp/uniconn_XXXXXX."""

    def test_normalize_temp_paths_replaces_random_suffix(self) -> None:
        """Случайные суффиксы временных папок заменяются на /tmp/uniconn_<TEMP>."""
        raw = "/bin/bash /tmp/uniconn_9a8f1b2c/check.sh --arg /tmp/uniconn_xyz123/out.txt"
        assert (
            normalize_temp_paths(raw)
            == "/bin/bash /tmp/uniconn_<TEMP>/check.sh --arg /tmp/uniconn_<TEMP>/out.txt"
        )


class TestCassetteRecordAndReplayModes:
    """Тесты режимов записи и воспроизведения (once, new_episodes, none, all)."""

    @pytest.mark.asyncio
    async def test_record_mode_once_records_then_replays_without_real_transport(
        self,
        tmp_path: Path,
    ) -> None:
        """В режиме once первый прогон записывает YAML-кассету, а второй читает без вызова транспорта."""
        cassette_file = tmp_path / "session.yaml"
        conn = Connection.from_uri("local://")

        async with conn.use_cassette(cassette_file, mode="once") as cassette:
            res = await conn.run("echo 'hello cassette'")
            assert res.ok
            assert res.text == "hello cassette"
            assert len(cassette.interactions) == 1

        assert cassette_file.is_file()

        # Подменяем метод реального транспорта на падающий мок — во втором прогоне он не должен вызываться
        conn._transport.run = AsyncMock(side_effect=AssertionError("Real transport called!"))
        async with conn.use_cassette(cassette_file, mode="once"):
            replayed = await conn.run("echo 'hello cassette'")
            assert replayed.ok
            assert replayed.text == "hello cassette"

    @pytest.mark.asyncio
    async def test_record_mode_none_raises_cassette_miss_error(
        self,
        tmp_path: Path,
    ) -> None:
        """В режиме none отсутствие команды в кассете вызывает CassetteMissError со списком кандидатов."""
        cassette_file = tmp_path / "strict.yaml"
        Cassette(
            transport="ssh",
            host="node-01",
            interactions=[
                RecordedExecInteraction(command="uptime", stdout="up 10 days\n"),
            ],
        ).save(cassette_file)

        conn = Connection.from_uri("local://")
        async with conn.use_cassette(cassette_file, mode=RecordMode.NONE):
            ok_res = await conn.run("uptime")
            assert ok_res.text == "up 10 days"

            with pytest.raises(CassetteMissError) as exc_info:
                await conn.run("whoami")
            assert exc_info.value.kind == "exec"
            assert "uptime" in exc_info.value.candidates

    @pytest.mark.asyncio
    async def test_record_mode_new_episodes_appends_only_missing_commands(
        self,
        tmp_path: Path,
    ) -> None:
        """Режим new_episodes воспроизводит известные эпизоды и дописывает новые."""
        cassette_file = tmp_path / "episodes.json"
        Cassette(
            transport="local",
            host="localhost",
            interactions=[
                RecordedExecInteraction(command="echo step1", stdout="cached_step1\n"),
            ],
        ).save(cassette_file)

        conn = Connection.from_uri("local://")
        async with conn.use_cassette(cassette_file, mode="new_episodes"):
            r1 = await conn.run("echo step1")
            r2 = await conn.run("echo step2")
            assert r1.text == "cached_step1"
            assert r2.text == "step2"

        loaded = Cassette.load(cassette_file)
        assert len(loaded.interactions) == 2

    @pytest.mark.asyncio
    async def test_stateful_fifo_cursor_for_idempotent_service_checks(
        self,
        tmp_path: Path,
    ) -> None:
        """Последовательные вызовы одной команды возвращают эпизоды по очереди FIFO."""
        cassette_file = tmp_path / "service_fifo.yaml"
        Cassette(
            transport="ssh",
            host="prod-01",
            interactions=[
                RecordedExecInteraction(
                    command="systemctl is-active nginx",
                    exit_code=3,
                    stdout="inactive\n",
                ),
                RecordedExecInteraction(
                    command="systemctl start nginx",
                    exit_code=0,
                    stdout="",
                ),
                RecordedExecInteraction(
                    command="systemctl is-active nginx",
                    exit_code=0,
                    stdout="active\n",
                ),
            ],
        ).save(cassette_file)

        conn = Connection.from_uri(f"replay://prod-01?cassette={cassette_file}")
        r_before = await conn.run("systemctl is-active nginx")
        r_start = await conn.run("systemctl start nginx")
        r_after = await conn.run("systemctl is-active nginx")

        assert r_before.exit_code == 3
        assert r_before.text == "inactive"
        assert r_start.ok
        assert r_after.exit_code == 0
        assert r_after.text == "active"

    @pytest.mark.asyncio
    async def test_secret_masking_and_sudo_password_redaction_in_cassette(
        self,
        tmp_path: Path,
    ) -> None:
        """Пароли sudo и токены маскируются перед сохранением кассеты на диск."""
        cassette_file = tmp_path / "secrets.yaml"
        cfg = ConnectionConfig(
            transport="local",
            host="localhost",
            password="MySuperSecretPassword123",
        )
        conn = Connection(LocalTransport(cfg), cfg)

        async with conn.use_cassette(cassette_file, mode="all"):
            await conn.run("echo 'token=ghp_1234567890abcdef and MySuperSecretPassword123'")

        raw_yaml = cassette_file.read_text(encoding="utf-8")
        assert "MySuperSecretPassword123" not in raw_yaml
        assert "ghp_1234567890abcdef" not in raw_yaml
        assert "***REDACTED***" in raw_yaml

    @pytest.mark.asyncio
    async def test_fs_stream_and_shell_interactions_in_replay_transport(
        self,
        tmp_path: Path,
    ) -> None:
        """Кассета поддерживает read_file, write_file, exists, stream, open_shell и expect."""
        cassette_file = tmp_path / "full_capabilities.yaml"
        Cassette(
            transport="ssh",
            host="bmc-01",
            capabilities=["exec", "stream", "file", "shell"],
            interactions=[
                RecordedFsInteraction(
                    operation="exists",
                    path="/etc/app.conf",
                    result_bool=True,
                ),
                RecordedFsInteraction(
                    operation="read_file",
                    path="/etc/app.conf",
                    content_utf8="port=8080\n",
                ),
                RecordedFsInteraction(
                    operation="write_file",
                    path="/etc/app.conf",
                    mode=0o644,
                ),
                RecordedStreamInteraction(
                    command="journalctl -f -n 2",
                    lines=["line-1", "line-2"],
                ),
                RecordedShellInteraction(
                    term_type="xterm",
                    term_size=(80, 24),
                    steps=[
                        ShellDialogStep(
                            expect_input="cd /var/log",
                            response_output="",
                            exit_code=0,
                        ),
                        ShellDialogStep(
                            expect_input="pwd",
                            response_output="/var/log",
                            exit_code=0,
                        ),
                    ],
                ),
            ],
        ).save(cassette_file)

        conn = Connection.from_uri(f"replay://bmc-01?cassette={cassette_file}")
        assert TransportLoader.get("replay") is ReplayTransport

        assert await conn.exists("/etc/app.conf") is True
        assert await conn.read_file("/etc/app.conf") == "port=8080\n"
        await conn.write_file("/etc/app.conf", "port=9090\n", mode=0o644)

        streamed = [line async for line in conn.stream("journalctl -f -n 2")]
        assert streamed == ["line-1", "line-2"]

        async with await conn.open_shell() as shell:
            await shell.execute("cd /var/log")
            pwd_res = await shell.execute("pwd")
            assert pwd_res.text == "/var/log"

    def test_sync_connection_use_cassette_parity(self, tmp_path: Path) -> None:
        """SyncConnection.use_cassette() корректно записывает и воспроизводит кассеты."""
        cassette_file = tmp_path / "sync_cassette.yaml"
        conn = Connection.from_uri("local://")
        with conn.to_sync() as sync_conn:
            with sync_conn.use_cassette(cassette_file, mode="once"):
                res = sync_conn.run("echo sync_ok")
                assert res.text == "sync_ok"

            with pytest.raises(CassetteError):
                with sync_conn.use_cassette(tmp_path / "missing.yaml", mode="none"):
                    sync_conn.run("echo fail")
