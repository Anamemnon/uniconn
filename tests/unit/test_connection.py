# tests/unit/test_connection.py
import pytest
from datetime import datetime
from uniconn import Connection
from uniconn.result import Result

@pytest.mark.asyncio
async def test_connection_run(mock_transport, mocker):
    """Тест выполнения команды"""
    # Патчим загрузчик транспортов
    mocker.patch(
        'uniconn.plugins._loader.TransportLoader.get',
        return_value=lambda config: mock_transport
    )
    
    conn = Connection.from_uri("ssh://user@host")
    result = await conn.run("uptime")
    
    assert result.exit_code == 0
    assert result.stdout == "ok"
    mock_transport.run.assert_called_once()

@pytest.mark.asyncio
async def test_connection_context_manager(mock_transport, mocker):
    """Тест контекстного менеджера"""
    mocker.patch(
        'uniconn.plugins._loader.TransportLoader.get',
        return_value=lambda config: mock_transport
    )
    
    async with Connection.from_uri("ssh://user@host") as conn:
        await conn.run("test")
    
    mock_transport.connect.assert_called_once()
    mock_transport.disconnect.assert_called_once()

@pytest.mark.asyncio
async def test_connection_retry_on_failure(mock_transport, mocker):
    """Тест retry механизма"""
    from uniconn.exceptions import ConnectionError
    
    call_count = 0
    
    async def flaky_run(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise ConnectionError("Temporary failure")
        return Result(
            exit_code=0, stdout="ok", stderr="",
            duration=1.0, command="test", timestamp=datetime.now()
        )
    
    mock_transport.run = flaky_run
    
    mocker.patch(
        'uniconn.plugins._loader.TransportLoader.get',
        return_value=lambda config: mock_transport
    )
    
    conn = Connection.from_uri("ssh://user@host", retry_attempts=3)
    result = await conn.run("test")
    
    assert result.exit_code == 0
    assert call_count == 3

def test_sync_connection_wrapper(mocker):
    """Тест синхронной обертки"""
    from uniconn._sync import SyncConnection
    
    mock_async_conn = mocker.AsyncMock()
    mock_async_conn.run = mocker.AsyncMock(
        return_value=Result(
            exit_code=0, stdout="ok", stderr="",
            duration=1.0, command="test", timestamp=datetime.now()
        )
    )
    
    sync_conn = SyncConnection(mock_async_conn)
    result = sync_conn.run("test")
    
    assert result.exit_code == 0
    mock_async_conn.run.assert_called_once()

@pytest.mark.asyncio
async def test_run_commands_success(mock_transport, mocker):
    """Все команды выполняются последовательно и в порядке списка."""
    mocker.patch(
        'uniconn.plugins._loader.TransportLoader.get',
        return_value=lambda config: mock_transport
    )

    async def run_side_effect(command, **kwargs):
        return Result(
            exit_code=0, stdout=f"out:{command}", stderr="",
            duration=1.0, command=command, timestamp=datetime.now()
        )

    mock_transport.run = mocker.AsyncMock(side_effect=run_side_effect)

    conn = Connection.from_uri("ssh://user@host")
    results = await conn.run_commands(["cmd1", "cmd2", "cmd3"])

    assert [r.command for r in results] == ["cmd1", "cmd2", "cmd3"]
    assert [r.stdout for r in results] == ["out:cmd1", "out:cmd2", "out:cmd3"]
    assert mock_transport.run.call_count == 3

@pytest.mark.asyncio
async def test_run_commands_stop_on_error(mock_transport, mocker):
    """При stop_on_error=True выполнение прерывается на первой ошибке."""
    mocker.patch(
        'uniconn.plugins._loader.TransportLoader.get',
        return_value=lambda config: mock_transport
    )

    async def run_side_effect(command, **kwargs):
        exit_code = 1 if command == "bad" else 0
        return Result(
            exit_code=exit_code, stdout="", stderr="",
            duration=1.0, command=command, timestamp=datetime.now()
        )

    mock_transport.run = mocker.AsyncMock(side_effect=run_side_effect)

    conn = Connection.from_uri("ssh://user@host")
    results = await conn.run_commands(["ok1", "bad", "ok2"])

    # "ok2" не должна выполняться
    assert [r.command for r in results] == ["ok1", "bad"]
    assert mock_transport.run.call_count == 2

@pytest.mark.asyncio
async def test_run_commands_continue_on_error(mock_transport, mocker):
    """При stop_on_error=False выполняются все команды."""
    mocker.patch(
        'uniconn.plugins._loader.TransportLoader.get',
        return_value=lambda config: mock_transport
    )

    async def run_side_effect(command, **kwargs):
        exit_code = 1 if command == "bad" else 0
        return Result(
            exit_code=exit_code, stdout="", stderr="",
            duration=1.0, command=command, timestamp=datetime.now()
        )

    mock_transport.run = mocker.AsyncMock(side_effect=run_side_effect)

    conn = Connection.from_uri("ssh://user@host")
    results = await conn.run_commands(["ok1", "bad", "ok2"], stop_on_error=False)

    assert [r.exit_code for r in results] == [0, 1, 0]
    assert mock_transport.run.call_count == 3

@pytest.mark.asyncio
async def test_run_commands_empty_list(mock_transport, mocker):
    """Пустой список команд — пустой результат без вызовов транспорта."""
    mocker.patch(
        'uniconn.plugins._loader.TransportLoader.get',
        return_value=lambda config: mock_transport
    )

    conn = Connection.from_uri("ssh://user@host")
    results = await conn.run_commands([])

    assert results == []
    mock_transport.run.assert_not_called()

def test_sync_run_commands(mocker):
    """Тест синхронной обертки run_commands."""
    from uniconn._sync import SyncConnection

    mock_async_conn = mocker.AsyncMock()
    mock_async_conn.run_commands = mocker.AsyncMock(
        return_value=[
            Result(
                exit_code=0, stdout="ok", stderr="",
                duration=1.0, command="test", timestamp=datetime.now()
            )
        ]
    )

    sync_conn = SyncConnection(mock_async_conn)
    results = sync_conn.run_commands(["test"])

    assert len(results) == 1
    assert results[0].exit_code == 0
    mock_async_conn.run_commands.assert_called_once()