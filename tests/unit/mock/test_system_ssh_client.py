# tests/unit/mock/test_system_ssh_client.py
"""Тесты подключения реального системного клиента OpenSSH (subprocess) и CLI mock-server."""

from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path

import pytest

from uniconn import Cassette, MockSSHServer, RecordedExecInteraction
from uniconn.cli import main as cli_main


@pytest.mark.skipif(shutil.which("ssh") is None, reason="System OpenSSH client not installed")
async def test_system_openssh_binary_against_mock_ssh_server() -> None:
    """Запуск реального системного бинарника ssh через subprocess против сокета MockSSHServer."""
    cassette = Cassette(
        transport="ssh",
        host="prod-edge-01",
        interactions=[
            RecordedExecInteraction(
                command="uptime",
                exit_code=0,
                stdout=" 14:22:01 up 99 days, load average: 0.01, 0.03, 0.05\n",
            ),
        ],
    )

    async with MockSSHServer.from_cassette(cassette) as server:
        cmd = [
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "LogLevel=ERROR",
            "-p",
            str(server.port),
            "admin@127.0.0.1",
            "uptime",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=5.0)
        assert proc.returncode == 0, stderr_bytes.decode("utf-8", errors="replace")
        assert "load average: 0.01, 0.03, 0.05" in stdout_bytes.decode("utf-8", errors="replace")


def test_cli_mock_server_command_runs_and_exits_cleanly(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Проверка CLI-команды `uniconn mock-server <cassette> --duration 0.05 --format json`."""
    cass_file = tmp_path / "cli_node.yaml"
    Cassette(
        transport="ssh",
        host="cli-node",
        interactions=[
            RecordedExecInteraction(command="hostname", exit_code=0, stdout="cli-node\n"),
        ],
    ).save(cass_file)

    with pytest.raises(SystemExit) as exc_info:
        cli_main(
            [
                "mock-server",
                str(cass_file),
                "--duration",
                "0.05",
                "--format",
                "json",
            ]
        )
    assert exc_info.value.code == 0
    out = capsys.readouterr().out.strip()
    payload = json.loads(out.splitlines()[0])
    assert payload["status"] == "listening"
    assert payload["server_type"] == "ssh"
    assert payload["port"] > 0
    assert payload["interactions"] == 1
