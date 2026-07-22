# tests/integration/test_bmc.py
import pytest
from unittest.mock import AsyncMock, patch
from uniconn import Connection
from uniconn.result import Result
from datetime import datetime

@pytest.mark.asyncio
@pytest.mark.integration
async def test_redfish_power_on(mocker):
    """Тест Redfish транспорта с моком HTTP"""
    # Мокаем aiohttp сессию
    mock_session = AsyncMock()
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.json = AsyncMock(return_value={"PowerState": "On"})
    mock_response.__aenter__ = AsyncMock(return_value=mock_response)
    mock_response.__aexit__ = AsyncMock(return_value=None)
    
    mock_session.post.return_value = mock_response
    mock_session.get.return_value = mock_response
    
    # Патчим создание сессии в RedfishTransport
    with patch('uniconn.transports.bmc._redfish.aiohttp.ClientSession') as mock_session_class:
        mock_session_class.return_value = mock_session
        
        conn = Connection.from_uri("redfish://admin:admin@bmc.local")
        result = await conn.run("power on")
        
        assert result.exit_code == 0
        mock_session.post.assert_called()

@pytest.mark.asyncio
@pytest.mark.integration
async def test_ipmi_power_status(mocker):
    """Тест IPMI транспорта"""
    from uniconn.transports.bmc._ipmi import IPMITransport
    from uniconn._config import ConnectionConfig
    
    config = ConnectionConfig(
        transport="ipmi",
        host="bmc.local",
        username="admin",
        password="admin"
    )
    
    # Мокаем pyghmi
    mock_ipmi_cmd = mocker.MagicMock()
    mock_ipmi_cmd.get_power.return_value = {"power": "on"}
    
    with patch('uniconn.transports.bmc._ipmi.ipmi_cmd.Command', return_value=mock_ipmi_cmd):
        transport = IPMITransport(config)
        result = await transport.run("status")
        
        assert result.exit_code == 0
        mock_ipmi_cmd.get_power.assert_called_once()