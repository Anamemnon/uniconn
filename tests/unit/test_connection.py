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