# tests/unit/transports/test_pytest_plugin.py
"""Unit-тесты для uniconn pytest плагина, фикстуры uniconn_cassette и санитизации кассет."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from uniconn import (
    Cassette,
    Connection,
    RecordMode,
    SyncConnection,
    UniconnCassetteFixture,
)
from uniconn.result import Result
from uniconn.transports.replay.models import (
    RecordedExecInteraction,
    RecordedFsInteraction,
    RecordedShellInteraction,
    RecordedStreamInteraction,
    ShellDialogStep,
)


class _DummyRequest:
    """Mock-объект pytest.FixtureRequest для тестирования UniconnCassetteFixture."""

    def __init__(self, test_name: str, path: Path, marker: Any = None) -> None:
        self.node = MagicMock()
        self.node.name = test_name
        self.node.get_closest_marker.return_value = marker
        self.path = path


class TestUniconnCassetteFixtureResolution:
    """Проверка логики вычисления путей и режимов записи фикстурой."""

    def test_default_path_generated_from_test_name(self, tmp_path: Path) -> None:
        test_file = tmp_path / "test_api.py"
        req = _DummyRequest("test_fetch_node[linux]", test_file)
        fixture = UniconnCassetteFixture(req)

        expected = tmp_path / "cassettes" / "test_api" / "test_fetch_node_linux.yaml"
        assert fixture.path == expected
        assert fixture.mode == RecordMode.ONCE

    def test_path_and_mode_overridden_by_marker_args(self, tmp_path: Path) -> None:
        test_file = tmp_path / "test_api.py"
        marker = MagicMock()
        marker.args = ("custom_node.yaml", "new_episodes")
        marker.kwargs = {}
        req = _DummyRequest("test_custom", test_file, marker=marker)

        fixture = UniconnCassetteFixture(req)
        assert fixture.path == tmp_path / "cassettes" / "custom_node.yaml"
        assert fixture.mode == RecordMode.NEW_EPISODES

    def test_record_mode_overridden_by_cli_option(self, tmp_path: Path) -> None:
        test_file = tmp_path / "test_api.py"
        marker = MagicMock()
        marker.args = ()
        marker.kwargs = {"mode": "all"}
        req = _DummyRequest("test_cli_override", test_file, marker=marker)

        fixture = UniconnCassetteFixture(req, record_mode_override="none")
        assert fixture.mode == RecordMode.NONE


class TestUniconnCassetteFixtureUsage:
    """Тесты выполнения через use() и создания replay-подключений."""

    @pytest.mark.asyncio
    async def test_fixture_use_async_records_and_saves_cassette(self, tmp_path: Path) -> None:
        cass_file = tmp_path / "test_async.yaml"
        test_file = tmp_path / "test_run.py"
        req = _DummyRequest("test_async", test_file)
        fixture = UniconnCassetteFixture(req)

        # Создаём mock-транспорт с предсказуемым Result
        conn = Connection.from_uri("ssh://node1")
        mock_t = AsyncMock()
        mock_t.name = "ssh"
        mock_t.run = AsyncMock(
            return_value=Result(exit_code=0, stdout="node1-ok\n", stderr="", duration=0.01, command="hostname", host="node1")
        )
        conn._transport = mock_t

        async with fixture.use(conn, path=cass_file, mode="once") as cassette:
            res = await conn.run("hostname")
            assert res.text == "node1-ok"
            assert len(cassette.interactions) == 1

        assert cass_file.is_file()
        loaded = fixture.load(cass_file)
        assert loaded.total_interactions == 1
        assert loaded.exec_count == 1

    def test_fixture_use_sync_records_and_saves_cassette(self, tmp_path: Path) -> None:
        cass_file = tmp_path / "test_sync.yaml"
        test_file = tmp_path / "test_run.py"
        req = _DummyRequest("test_sync", test_file)
        fixture = UniconnCassetteFixture(req)

        sync_conn = SyncConnection.from_uri("ssh://node1")
        mock_t = AsyncMock()
        mock_t.name = "ssh"
        mock_t.run = AsyncMock(
            return_value=Result(exit_code=0, stdout="sync-ok\n", stderr="", duration=0.01, command="hostname", host="node1")
        )
        sync_conn._async_conn._transport = mock_t

        with fixture.use(sync_conn, path=cass_file, mode="once") as cassette:
            res = sync_conn.run("hostname")
            assert res.text == "sync-ok"
            assert len(cassette.interactions) == 1

        assert cass_file.is_file()
        loaded = fixture.load(cass_file)
        assert loaded.exec_count == 1

    @pytest.mark.asyncio
    async def test_fixture_creates_replay_connection(self, tmp_path: Path) -> None:
        cass_file = tmp_path / "replay_node.yaml"
        Cassette(
            transport="ssh",
            host="srv-prod",
            interactions=[
                RecordedExecInteraction(command="uptime", stdout="10:00 up 5 days\n"),
            ],
        ).save(cass_file)

        test_file = tmp_path / "test_run.py"
        req = _DummyRequest("test_replay", test_file)
        fixture = UniconnCassetteFixture(req)

        # Асинхронное подключение replay
        conn = fixture.connection(cass_file)
        res = await conn.run("uptime")
        assert res.ok
        assert res.text == "10:00 up 5 days"
        await conn.close()

        # Синхронное подключение replay
        sync_conn = fixture.sync_connection(cass_file)
        res_sync = sync_conn.run("uptime")
        assert res_sync.ok
        assert res_sync.text == "10:00 up 5 days"
        sync_conn.close()


class TestCassetteSanitizationAndVerification:
    """Тесты санитизации и верификации кассет."""

    def test_cassette_sanitize_ips_and_secrets(self) -> None:
        cass = Cassette(
            transport="ssh",
            host="192.168.1.100",
            interactions=[
                RecordedExecInteraction(
                    command="curl -H 'Authorization: Bearer my-secret-token-12345' http://10.0.0.5:8080",
                    stdout="Connected to 10.0.0.5 with token=supersecretkey\n",
                    stderr="",
                ),
                RecordedStreamInteraction(
                    command="tail -f /var/log/auth.log",
                    lines=["Connection from 172.16.0.1 port 22", "password=admin_pass_1234"],
                ),
                RecordedFsInteraction(
                    operation="read_file",
                    path="/etc/app.conf",
                    content_utf8="api_key=secret-abcdef123456\nhost=192.168.1.1",
                ),
                RecordedShellInteraction(
                    steps=[
                        ShellDialogStep(expect_input="password: ", response_output="Bearer token-abc-xyz-123\r\n"),
                    ]
                ),
            ],
        )

        n = cass.sanitize(redact_ips=True, redact_tokens=True)
        assert n > 0
        assert cass.host == "<IP_REDACTED>"

        exec_it = cass.interactions[0]
        assert isinstance(exec_it, RecordedExecInteraction)
        assert "10.0.0.5" not in exec_it.command
        assert "<IP_REDACTED>" in exec_it.command
        assert "my-secret-token" not in exec_it.command
        assert "<REDACTED_SECRET>" in exec_it.command
        assert "supersecretkey" not in exec_it.stdout

        stream_it = cass.interactions[1]
        assert isinstance(stream_it, RecordedStreamInteraction)
        assert "172.16.0.1" not in stream_it.lines[0]
        assert "<IP_REDACTED>" in stream_it.lines[0]

        fs_it = cass.interactions[2]
        assert isinstance(fs_it, RecordedFsInteraction)
        assert "secret-abcdef" not in (fs_it.content_utf8 or "")
        assert "192.168.1.1" not in (fs_it.content_utf8 or "")

        shell_it = cass.interactions[3]
        assert isinstance(shell_it, RecordedShellInteraction)
        assert "token-abc-xyz" not in shell_it.steps[0].response_output

    def test_cassette_verify_detects_corrupted_base64(self) -> None:
        valid_cass = Cassette(
            transport="ssh",
            host="edge",
            interactions=[
                RecordedExecInteraction(command="echo ok", stdout="ok\n"),
            ],
        )
        assert valid_cass.verify() == []

        corrupted_cass = Cassette(
            transport="ssh",
            host="edge",
            interactions=[
                RecordedExecInteraction(command="bin", stdout_base64="!!!NOT_VALID_BASE64@@@"),
            ],
        )
        errors = corrupted_cass.verify()
        assert len(errors) == 1
        assert "invalid stdout_base64" in errors[0]


class TestPytestPluginFixturesAndAutoMarker:
    """Интеграция с pytest: инъекция фикстур и маркер @pytest.mark.uniconn_cassette."""

    def test_pytest_fixtures_injected(
        self,
        uniconn_cassette: UniconnCassetteFixture,
        uniconn_record_mode: RecordMode,
    ) -> None:
        assert isinstance(uniconn_cassette, UniconnCassetteFixture)
        assert uniconn_record_mode == RecordMode.ONCE
        assert uniconn_cassette.path.name == "test_pytest_fixtures_injected.yaml"

    def test_marker_auto_wrap_does_not_double_wrap_sync_connection(
        self,
        request: pytest.FixtureRequest,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        from uniconn.pytest_plugin import _uniconn_marker_auto_cassette
        from uniconn.transports.replay.proxy import CassetteTransportProxy

        cass_file = tmp_path / "auto_sync.yaml"
        marker = MagicMock()
        marker.args = (str(cass_file), "once")
        marker.kwargs = {"auto_wrap": True, "sanitize_ips": True}

        fake_req = MagicMock()
        fake_req.node.get_closest_marker.return_value = marker
        fake_req.config.getoption.return_value = None
        fake_req.path = tmp_path / "test_sample.py"

        gen = _uniconn_marker_auto_cassette.__wrapped__(fake_req, monkeypatch)
        next(gen)
        try:
            sync_conn = SyncConnection.from_uri("local://10.20.30.40")
            assert isinstance(sync_conn._async_conn.transport, CassetteTransportProxy)
            # Убеждаемся, что внутренний транспорт НЕ обёрнут повторно в CassetteTransportProxy
            assert not isinstance(
                sync_conn._async_conn.transport._wrapped,
                CassetteTransportProxy,
            )
            res = sync_conn.run("echo marker-ok")
            assert res.text == "marker-ok"
            sync_conn.close()
        finally:
            with pytest.raises(StopIteration):
                next(gen)

        assert cass_file.is_file()
        saved = Cassette.load(cass_file)
        assert saved.host == "<IP_REDACTED>"
        assert saved.exec_count == 1

