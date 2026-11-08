# tests/unit/mock/test_sync_parity.py
"""Тесты синхронного фасада SyncMockSSHServer и Pytest-фикстур mock_ssh_server."""

from __future__ import annotations

from pathlib import Path

import pytest

from uniconn import (
    Cassette,
    MockSSHServer,
    RecordedExecInteraction,
    RecordedFsInteraction,
    SyncConnection,
    SyncMockSSHServer,
)


def test_sync_mock_ssh_server_context_manager(tmp_path: Path) -> None:
    """Использование SyncMockSSHServer и SyncConnection в полностью синхронном коде."""
    cassette_path = tmp_path / "sync_node.yaml"
    Cassette(
        transport="ssh",
        host="sync-node-01",
        interactions=[
            RecordedExecInteraction(
                command="uname -s",
                exit_code=0,
                stdout="Linux\n",
            ),
            RecordedFsInteraction(
                operation="read_file",
                path="/etc/os-release",
                content_utf8='PRETTY_NAME="Ubuntu 24.04 LTS"\n',
            ),
        ],
    ).save(cassette_path)

    with SyncMockSSHServer.from_cassette(cassette_path) as server:
        assert server.is_running
        assert server.port > 0
        with SyncConnection.from_uri(server.uri) as conn:
            res = conn.run("uname -s")
            assert res.ok
            assert res.text == "Linux"

            os_rel = conn.files.read_file("/etc/os-release")
            assert "Ubuntu 24.04 LTS" in str(os_rel)

        assert len(server.history) >= 2


@pytest.mark.mock_ssh_server(
    Cassette(
        transport="ssh",
        host="fixture-node",
        interactions=[
            RecordedExecInteraction(
                command="echo fixture-ok",
                exit_code=0,
                stdout="fixture-ok\n",
            ),
        ],
    )
)
def test_pytest_mock_ssh_server_fixture(mock_ssh_server: MockSSHServer) -> None:
    """Проверка работы фикстуры mock_ssh_server и маркера @pytest.mark.mock_ssh_server."""
    assert isinstance(mock_ssh_server, MockSSHServer)
    assert mock_ssh_server.port > 0
    with SyncConnection.from_uri(mock_ssh_server.uri) as conn:
        res = conn.run("echo fixture-ok")
        assert res.ok
        assert res.text == "fixture-ok"
