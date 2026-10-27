# tests/unit/test_local_transport.py
"""Тесты для LocalTransport"""

import asyncio

import pytest

from uniconn._config import ConnectionConfig
from uniconn.transports._local import LocalTransport


@pytest.fixture
def local_transport():
    """Фикстура LocalTransport"""
    config = ConnectionConfig(transport="local", host="localhost")
    return LocalTransport(config)


@pytest.mark.asyncio
async def test_local_transport_name(local_transport):
    """Название транспорта"""
    assert local_transport.name == "local"


@pytest.mark.asyncio
async def test_local_connect_disconnect(local_transport):
    """Подключение и отключение"""
    await local_transport.connect()
    assert local_transport.is_connected is True

    await local_transport.disconnect()
    assert local_transport.is_connected is False


@pytest.mark.asyncio
async def test_local_run_basic_command(local_transport):
    """Выполнение базовой команды"""
    await local_transport.connect()

    result = await local_transport.run("echo hello")

    assert result.exit_code == 0
    assert result.stdout.strip() == "hello"
    assert result.stderr == ""
    assert result.command == "echo hello"
    assert result.host == "localhost"
    assert result.duration >= 0

    await local_transport.disconnect()


@pytest.mark.asyncio
async def test_local_run_with_stderr(local_transport):
    """Команда с выводом в stderr"""
    await local_transport.connect()

    result = await local_transport.run("echo error >&2")

    assert result.exit_code == 0
    assert "error" in result.stderr.strip()

    await local_transport.disconnect()


@pytest.mark.asyncio
async def test_local_run_failing_command(local_transport):
    """Команда с ненулевым exit code"""
    await local_transport.connect()

    result = await local_transport.run("false")

    assert result.exit_code == 1
    assert result.ok is False

    await local_transport.disconnect()


@pytest.mark.asyncio
async def test_local_run_timeout(local_transport):
    """Таймаут выполнения команды"""
    await local_transport.connect()

    # На Windows 'sleep' — это отдельная программа, не shell builtin.
    # Используем ping для имитации задержки. Короткая задержка: kill()
    # завершает cmd.exe, но дочерний ping доживает до конца, удерживая
    # пайпы — с длинной задержкой тест ждал бы полное время команды.
    import sys
    if sys.platform == "win32":
        cmd = "ping -n 2 127.0.0.1 >nul"
    else:
        cmd = "sleep 10"

    with pytest.raises(asyncio.TimeoutError):
        await local_transport.run(cmd, timeout=0.1)

    await local_transport.disconnect()


@pytest.mark.asyncio
async def test_local_run_with_env(local_transport):
    """Команда с переменными окружения"""
    await local_transport.connect()

    # Windows использует cmd.exe, Linux — sh/bash
    import sys
    if sys.platform == "win32":
        result = await local_transport.run(
            "echo %MY_VAR%",
            env={"MY_VAR": "test_value"}
        )
        assert "test_value" in result.stdout.strip()
    else:
        result = await local_transport.run(
            "echo $MY_VAR",
            env={"MY_VAR": "test_value"}
        )
        assert "test_value" in result.stdout.strip()

    await local_transport.disconnect()


@pytest.mark.asyncio
async def test_local_stream(local_transport):
    """Потоковое выполнение"""
    await local_transport.connect()

    lines = []
    async for line in local_transport.stream("echo line1 && echo line2"):
        lines.append(line)

    assert len(lines) == 2
    assert "line1" in lines[0]
    assert "line2" in lines[1]

    await local_transport.disconnect()


@pytest.mark.asyncio
async def test_local_run_multiline_command(local_transport):
    """Многострочная команда"""
    await local_transport.connect()

    result = await local_transport.run("echo -e 'line1\\nline2'")

    assert result.exit_code == 0
    assert "line1" in result.stdout
    assert "line2" in result.stdout

    await local_transport.disconnect()


@pytest.mark.asyncio
async def test_local_context_manager(local_transport):
    """Контекстный менеджер"""
    async with local_transport as transport:
        assert transport.is_connected is True
        result = await transport.run("echo test")
        assert result.exit_code == 0

    assert local_transport.is_connected is False


@pytest.mark.asyncio
async def test_local_run_without_connect(local_transport):
    """Выполнение без подключения — должно работать (local не требует подключения)"""
    result = await local_transport.run("echo test")
    assert result.exit_code == 0


@pytest.mark.asyncio
async def test_local_run_with_timeout_parameter(local_transport):
    """Параметр timeout переопределяет дефолтный"""
    await local_transport.connect()

    result = await local_transport.run("echo quick", timeout=5.0)
    assert result.exit_code == 0
    assert result.duration < 5.0

    await local_transport.disconnect()


@pytest.mark.asyncio
async def test_local_open_shell_dynamic_default_shell(local_transport):
    """LocalTransport.open_shell() динамически выбирает шелл (cmd/powershell на Windows, /bin/sh на POSIX)."""
    import sys

    await local_transport.connect()
    shell_proc = await local_transport.open_shell()
    try:
        assert shell_proc is not None
        assert shell_proc._proc is not None
        if sys.platform == "win32":
            # На Windows должен запускаться cmd.exe или powershell.exe, но не /bin/sh
            cmd_line = shell_proc.shell.lower()
            assert "cmd.exe" in cmd_line or "powershell" in cmd_line or "cmd" in cmd_line
        else:
            assert shell_proc.shell == "/bin/sh"
        assert shell_proc.returncode is None
    finally:
        shell_proc.terminate()
        await shell_proc.wait_closed()
        await local_transport.disconnect()


def test_local_prepare_cmd_for_platform():
    """LocalTransport._prepare_cmd_for_platform учитывает различия экранирования POSIX и Windows."""
    import sys

    # Последовательность аргументов
    seq_cmd = ["python", "-c", "import sys; print(sys.argv[1])", "hello world"]
    prepared_seq = LocalTransport._prepare_cmd_for_platform(seq_cmd)
    if sys.platform == "win32":
        assert '"hello world"' in prepared_seq
    else:
        assert "'hello world'" in prepared_seq

    # Команда echo со строковыми аргументами
    echo_seq = ["echo", "first item"]
    prepared_echo = LocalTransport._prepare_cmd_for_platform(echo_seq)
    if sys.platform == "win32":
        assert prepared_echo == "echo first item"

    # POSIX shlex-строка с одинарными кавычками на Windows
    posix_quoted_str = "python3 -c 'import sys; print(sys.argv[1])' 'arg with spaces'"
    prepared_str = LocalTransport._prepare_cmd_for_platform(posix_quoted_str)
    if sys.platform == "win32":
        assert '"arg with spaces"' in prepared_str
        assert "'" not in prepared_str

