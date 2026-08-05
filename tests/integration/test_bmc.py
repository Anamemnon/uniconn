# tests/integration/test_bmc.py
import pytest
from unittest.mock import patch
from uniconn.result import Result

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