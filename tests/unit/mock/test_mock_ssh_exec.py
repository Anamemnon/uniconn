# tests/unit/mock/test_mock_ssh_exec.py
"""Тесты выполнения команд (exec) и аутентификации в сокетном MockSSHServer."""

from __future__ import annotations

import base64
from pathlib import Path

import asyncssh
import pytest

from uniconn import (
    AuthenticationError,
    Cassette,
    Connection,
    MockServerConfig,
    MockSSHServer,
    RecordedExecInteraction,
    RecordedStreamInteraction,
)


def _sample_exec_cassette() -> Cassette:
    return Cassette(
        transport="ssh",
        host="edge-node-01",
        interactions=[
            RecordedExecInteraction(
                command="uptime",
                exit_code=0,
                stdout=" 10:15:00 up 14 days,  2 users,  load average: 0.12, 0.08, 0.05\n",
                stderr="",
            ),
            RecordedExecInteraction(
                command="systemctl status nginx",
                sudo=True,
                exit_code=3,
                stdout="○ nginx.service - A high performance web server\n",
                stderr="Unit nginx.service is inactive\n",
            ),
            RecordedExecInteraction(
                command="cat /tmp/uniconn_<TEMP>/payload.sh",
                exit_code=0,
                stdout="#!/bin/sh\necho ok\n",
            ),
            RecordedExecInteraction(
                command="read_binary",
                exit_code=0,
                stdout="",
                stdout_base64=base64.b64encode(b"\x00\x01\x02MOCK").decode("ascii"),
            ),
            RecordedStreamInteraction(
                command="tail -n 2 /var/log/app.log",
                lines=["line-1", "line-2"],
            ),
        ],
    )


async def test_mock_ssh_server_exec_stdout_stderr_and_exit_code() -> None:
    """Подключение Connection и asyncssh к MockSSHServer возвращает записанные stdout, stderr и exit_code."""
    cassette = _sample_exec_cassette()

    async with MockSSHServer.from_cassette(cassette) as server:
        assert server.is_running
        assert server.port > 0
        assert server.uri == f"ssh://127.0.0.1:{server.port}"

        async with Connection.from_uri(server.uri) as conn:
            res_ok = await conn.run("uptime")
            assert res_ok.ok
            assert "load average: 0.12" in res_ok.stdout
            assert res_ok.exit_code == 0

            res_fail = await conn.run("systemctl status nginx", sudo=True)
            assert res_fail.exit_code == 3
            assert "nginx.service" in res_fail.stdout
            assert "inactive" in res_fail.stderr

            # Проверка нормализации динамических временных путей /tmp/uniconn_XXXXXX
            res_tmp = await conn.run("cat /tmp/uniconn_a9f81c/payload.sh")
            assert res_tmp.ok
            assert "echo ok" in res_tmp.stdout

            # Проверка fallback на RecordedStreamInteraction
            res_stream = await conn.run("tail -n 2 /var/log/app.log")
            assert res_stream.ok
            assert res_stream.lines == ["line-1", "line-2"]

        assert len(server.history) >= 4
        assert any(ev.channel == "exec" and ev.command == "uptime" and ev.matched for ev in server.history)


async def test_mock_ssh_server_strict_vs_non_strict_miss() -> None:
    """Проверка обработки неизвестных команд при strict_mode=True и strict_mode=False."""
    cassette = _sample_exec_cassette()

    async with MockSSHServer.from_cassette(cassette, strict_mode=False, default_exit_code=127) as srv_non_strict:
        async with Connection.from_uri(srv_non_strict.uri, retry_attempts=1) as conn:
            res = await conn.run("unknown_cmd_xyz")
            assert res.exit_code == 127
            assert "mock: command not found: unknown_cmd_xyz" in res.stderr

    async with MockSSHServer.from_cassette(cassette, strict_mode=True, default_exit_code=42) as srv_strict:
        async with Connection.from_uri(srv_strict.uri, retry_attempts=1) as conn:
            res_strict = await conn.run("unknown_cmd_xyz")
            assert res_strict.exit_code == 42
            assert "uniconn mock: no matching interaction for: unknown_cmd_xyz" in res_strict.stderr


async def test_mock_ssh_server_allow_repeats_false() -> None:
    """Если allow_repeats=False, повторный вызов однократно записанной команды возвращает промах."""
    cassette = Cassette(
        transport="ssh",
        interactions=[
            RecordedExecInteraction(command="whoami", exit_code=0, stdout="root\n"),
        ],
    )
    async with MockSSHServer.from_cassette(cassette, allow_repeats=False, strict_mode=True) as server:
        async with Connection.from_uri(server.uri, retry_attempts=1) as conn:
            first = await conn.run("whoami")
            assert first.ok
            assert first.text == "root"

            second = await conn.run("whoami")
            assert second.exit_code == 127
            assert "no matching interaction" in second.stderr


async def test_mock_ssh_server_password_authentication_policy(tmp_path: Path) -> None:
    """Если allow_any_auth=False и заданы username/password, проверяются учётные данные."""
    cassette_path = tmp_path / "auth_node.yaml"
    Cassette(
        transport="ssh",
        interactions=[RecordedExecInteraction(command="id -u", exit_code=0, stdout="1000\n")],
    ).save(cassette_path)

    cfg = MockServerConfig(
        cassette=cassette_path,
        allow_any_auth=False,
        username="deploy",
        password="secret-password",
    )
    async with MockSSHServer(cfg) as server:
        assert "deploy:secret-password@" in server.uri
        async with Connection.from_uri(server.uri, retry_attempts=1) as good_conn:
            res = await good_conn.run("id -u")
            assert res.ok
            assert res.text == "1000"

        bad_uri = f"ssh://deploy:wrong-pass@127.0.0.1:{server.port}"
        with pytest.raises((AuthenticationError, asyncssh.PermissionDenied)):
            async with Connection.from_uri(bad_uri, retry_attempts=1) as bad_conn:
                await bad_conn.run("id -u")
