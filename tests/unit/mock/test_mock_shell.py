# tests/unit/mock/test_mock_shell.py
"""Тесты интерактивного PTY/Shell диалога в MockSSHServer и MockTelnetServer."""

from __future__ import annotations

import asyncssh

from uniconn import (
    Cassette,
    Connection,
    MockSSHServer,
    MockTelnetServer,
    RecordedExecInteraction,
    RecordedShellInteraction,
    ShellDialogStep,
)


def _sample_shell_cassette() -> Cassette:
    return Cassette(
        transport="ssh",
        host="router-01",
        capabilities=["exec", "shell"],
        interactions=[
            RecordedShellInteraction(
                term_type="xterm",
                term_size=(100, 30),
                steps=[
                    ShellDialogStep(
                        expect_input="enable",
                        response_output="Password: ",
                        exit_code=0,
                    ),
                    ShellDialogStep(
                        expect_input="supersecret",
                        response_output="router-01# ",
                        exit_code=0,
                    ),
                    ShellDialogStep(
                        expect_input="show version",
                        response_output="UniOS Software, Version 18.4R1\n",
                        exit_code=0,
                    ),
                ],
            ),
            RecordedExecInteraction(
                command="pwd",
                exit_code=0,
                stdout="/var/log\n",
            ),
        ],
    )


async def test_mock_ssh_interactive_shell_with_uniconn_shell_session() -> None:
    """Открытие conn.open_shell() поверх MockSSHServer воспроизводит шаги диалога и команды."""
    cassette = _sample_shell_cassette()

    async with MockSSHServer.from_cassette(cassette) as server:
        async with Connection.from_uri(server.uri) as conn:
            async with await conn.open_shell(term_type="xterm", term_size=(100, 30)) as shell:
                res_ver = await shell.execute("show version")
                assert res_ver.ok
                assert "UniOS Software, Version 18.4R1" in res_ver.text

                res_pwd = await shell.execute("pwd")
                assert res_pwd.ok
                assert res_pwd.text == "/var/log"

                await shell.resize(120, 40)


async def test_mock_ssh_raw_dialog_steps_over_asyncssh_process() -> None:
    """Пошаговый интерактивный диалог (ShellDialogStep) через raw SSH process."""
    cassette = _sample_shell_cassette()

    async with MockSSHServer.from_cassette(cassette) as server:
        async with asyncssh.connect(
            server.host,
            port=server.port,
            known_hosts=None,
            username="admin",
        ) as ssh_conn:
            async with ssh_conn.create_process(term_type="xterm") as proc:
                proc.stdin.write("enable\n")
                out1 = await proc.stdout.read(1024)
                assert "Password:" in out1

                proc.stdin.write("supersecret\n")
                out2 = await proc.stdout.read(1024)
                assert "router-01#" in out2

                proc.stdin.write("exit\n")
                await proc.wait()


async def test_mock_telnet_server_exec_and_sync_wrapper() -> None:
    """Проверка работы сокетного MockTelnetServer и SyncMockTelnetServer с TelnetTransport."""
    cassette = _sample_shell_cassette()

    async with MockTelnetServer.from_cassette(cassette) as telnet_srv:
        assert telnet_srv.is_running
        assert telnet_srv.port > 0
        assert telnet_srv.uri == f"telnet://127.0.0.1:{telnet_srv.port}"

        async with Connection.from_uri(telnet_srv.uri, retry_attempts=1) as conn:
            res = await conn.run("show version", timeout=5.0)
            assert res.ok
            assert "UniOS Software, Version 18.4R1" in res.text

    with MockTelnetServer.from_cassette(cassette).to_sync() as sync_telnet:
        assert sync_telnet.is_running
        assert sync_telnet.port > 0
