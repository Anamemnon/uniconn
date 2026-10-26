# tests/unit/cli/test_cmd_cassette.py
"""Unit-тесты для CLI команд работы с кассетами: record, replay, cassette."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from uniconn import (
    Cassette,
    RecordedExecInteraction,
    RecordedFsInteraction,
    Result,
)
from uniconn.cli.app import create_cli_app
from uniconn.cli.renderers import CliRunner


class TestCLIRecordAndReplay:
    """Тестирование CLI команд record и replay."""

    def test_record_command_saves_cassette(self, tmp_path: Path) -> None:
        cass_file = tmp_path / "recorded.yaml"
        runner = CliRunner()
        app = create_cli_app()

        mock_conn = MagicMock()
        mock_conn.config = MagicMock()
        mock_conn.config.host = "edge-01"
        mock_conn.transport = MagicMock()
        mock_conn.transport.name = "ssh"
        mock_conn.connect = AsyncMock()
        mock_conn.close = AsyncMock()
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=None)

        mock_result = Result(
            exit_code=0,
            stdout="server-edge-01\n",
            stderr="",
            duration=0.05,
            command="hostname",
            host="edge-01",
        )
        mock_conn.run = AsyncMock(return_value=mock_result)

        # Мокаем use_cassette чтобы записать реальную кассету
        def _mock_use_cassette(path: Any, **kwargs: Any) -> Any:
            cass = Cassette(
                transport="ssh",
                host="edge-01",
                interactions=[
                    RecordedExecInteraction(command="hostname", stdout="server-edge-01\n"),
                ],
            )
            cass.save(path)
            cm = MagicMock()
            cm.__aenter__ = AsyncMock(return_value=cass)
            cm.__aexit__ = AsyncMock(return_value=None)
            return cm

        mock_conn.use_cassette = _mock_use_cassette

        with patch("uniconn.cli.cmd_cassette.Connection.from_uri", return_value=mock_conn):
            res = runner.invoke(app, ["record", "ssh://edge-01", "-c", str(cass_file), "--", "hostname"])

        assert res.exit_code == 0
        assert "server-edge-01" in res.stdout
        assert "Cassette recorded" in res.stdout
        assert cass_file.is_file()

    def test_replay_command_with_command(self, tmp_path: Path) -> None:
        cass_file = tmp_path / "replay_session.yaml"
        Cassette(
            transport="ssh",
            host="replayed-node",
            interactions=[
                RecordedExecInteraction(command="uptime", stdout="up 3 days, 1 user\n"),
            ],
        ).save(cass_file)

        runner = CliRunner()
        app = create_cli_app()

        res = runner.invoke(app, ["replay", str(cass_file), "--format", "plain", "--", "uptime"])
        assert res.exit_code == 0
        assert "up 3 days, 1 user" in res.stdout

    def test_replay_without_command_displays_info(self, tmp_path: Path) -> None:
        cass_file = tmp_path / "summary.yaml"
        Cassette(
            transport="ssh",
            host="cluster-node",
            interactions=[
                RecordedExecInteraction(command="whoami", stdout="root\n"),
                RecordedFsInteraction(operation="exists", path="/etc/hosts", result_bool=True),
            ],
        ).save(cass_file)

        runner = CliRunner()
        app = create_cli_app()

        res = runner.invoke(app, ["replay", str(cass_file)])
        assert res.exit_code == 0
        assert "Cassette Metadata" in res.stdout
        assert "cluster-node" in res.stdout
        assert "Recorded Interactions" in res.stdout


class TestCLICassetteSubcommands:
    """Тестирование подкоманд cassette info, sanitize, verify."""

    def test_cassette_info_panel_and_json(self, tmp_path: Path) -> None:
        cass_file = tmp_path / "info_test.yaml"
        Cassette(
            transport="telnet",
            host="switch-01",
            interactions=[
                RecordedExecInteraction(command="show version", stdout="OS v12.2\n"),
            ],
        ).save(cass_file)

        runner = CliRunner()
        app = create_cli_app()

        res_panel = runner.invoke(app, ["cassette", "info", str(cass_file)])
        assert res_panel.exit_code == 0
        assert "switch-01" in res_panel.stdout
        assert "show version" in res_panel.stdout

        res_json = runner.invoke(app, ["cassette", "info", str(cass_file), "--format", "json"])
        assert res_json.exit_code == 0
        parsed = json.loads(res_json.stdout)
        assert parsed["host"] == "switch-01"
        assert len(parsed["interactions"]) == 1

    def test_cassette_sanitize(self, tmp_path: Path) -> None:
        source_file = tmp_path / "sensitive.yaml"
        target_file = tmp_path / "sanitized.yaml"

        Cassette(
            transport="ssh",
            host="10.10.10.1",
            interactions=[
                RecordedExecInteraction(
                    command="login -u admin password=secretpass123",
                    stdout="Connected to 192.168.1.50\n",
                ),
            ],
        ).save(source_file)

        runner = CliRunner()
        app = create_cli_app()

        res = runner.invoke(
            app,
            [
                "cassette",
                "sanitize",
                str(source_file),
                "--output",
                str(target_file),
                "--redact-ip",
                "--redact-tokens",
            ],
        )
        assert res.exit_code == 0
        assert "Cassette sanitized" in res.stdout
        assert target_file.is_file()

        clean_cass = Cassette.load(target_file)
        assert clean_cass.host == "<IP_REDACTED>"
        exec_it = clean_cass.interactions[0]
        assert isinstance(exec_it, RecordedExecInteraction)
        assert "192.168.1.50" not in exec_it.stdout
        assert "<IP_REDACTED>" in exec_it.stdout
        assert "secretpass123" not in exec_it.command
        assert "<REDACTED_SECRET>" in exec_it.command

    def test_cassette_verify_valid_and_invalid(self, tmp_path: Path) -> None:
        valid_file = tmp_path / "valid.yaml"
        Cassette(
            transport="ssh",
            host="valid-host",
            interactions=[
                RecordedExecInteraction(command="date", stdout="2026-10-26\n"),
            ],
        ).save(valid_file)

        runner = CliRunner()
        app = create_cli_app()

        res_valid = runner.invoke(app, ["cassette", "verify", str(valid_file)])
        assert res_valid.exit_code == 0
        assert "Cassette is valid" in res_valid.stdout

        invalid_file = tmp_path / "invalid.yaml"
        Cassette(
            transport="ssh",
            host="invalid-host",
            interactions=[
                RecordedExecInteraction(command="bin", stdout_base64="bad_base64!!!"),
            ],
        ).save(invalid_file)

        res_invalid = runner.invoke(app, ["cassette", "verify", str(invalid_file)])
        assert res_invalid.exit_code == 1
        assert "verification failed" in res_invalid.stdout
