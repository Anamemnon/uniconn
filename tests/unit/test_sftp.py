# tests/unit/test_sftp.py
"""Тесты для передачи файлов (SFTP) через SSH транспорт."""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import patch, MagicMock, AsyncMock

from uniconn._config import ConnectionConfig
from uniconn._connection import Connection
from uniconn.exceptions import ConnectionError
from uniconn.result import Result


@pytest.fixture
def mock_asyncssh(mocker):
    """Мок asyncssh модуля."""
    asyncssh_mock = MagicMock()

    class MockError(Exception):
        pass

    asyncssh_mock.Error = MockError

    return asyncssh_mock


@pytest.fixture
def ssh_transport_with_mock(mock_asyncssh, mocker):
    """Создаёт SSHTransport с моком asyncssh."""
    with patch.dict("sys.modules", {"asyncssh": mock_asyncssh}):
        with patch(
            "uniconn.transports._ssh.asyncssh", mock_asyncssh
        ):
            from uniconn.transports._ssh import SSHTransport
            yield SSHTransport, mock_asyncssh


class TestSSHTransportUpload:
    """Тесты SSHTransport.upload()"""

    @pytest.mark.asyncio
    async def test_upload_success(self, ssh_transport_with_mock):
        """Успешная загрузка файла."""
        SSHTransport, asyncssh_mock = ssh_transport_with_mock

        mock_sftp = AsyncMock()
        mock_sftp.put = AsyncMock()

        mock_context = AsyncMock()
        mock_context.__aenter__ = AsyncMock(return_value=mock_sftp)
        mock_context.__aexit__ = AsyncMock(return_value=None)

        mock_conn = AsyncMock()
        mock_conn.start_sftp_client = MagicMock(return_value=mock_context)

        transport = SSHTransport.__new__(SSHTransport)
        transport._conn = mock_conn
        transport._connected = True
        transport.config = ConnectionConfig(
            transport="ssh", host="testhost"
        )

        await transport.upload("/local/file.txt", "/remote/file.txt")

        mock_sftp.put.assert_called_once_with(
            "/local/file.txt", "/remote/file.txt"
        )

    @pytest.mark.asyncio
    async def test_upload_not_connected(self, ssh_transport_with_mock):
        """Ошибка при отсутствии подключения."""
        SSHTransport, _ = ssh_transport_with_mock

        transport = SSHTransport.__new__(SSHTransport)
        transport._conn = None
        transport._connected = False
        transport.config = ConnectionConfig(
            transport="ssh", host="testhost"
        )

        with pytest.raises(ConnectionError, match="Not connected"):
            await transport.upload("/local/file.txt", "/remote/file.txt")

    @pytest.mark.asyncio
    async def test_upload_sftp_error(self, ssh_transport_with_mock):
        """Ошибка SFTP операции."""
        SSHTransport, asyncssh_mock = ssh_transport_with_mock

        mock_sftp = AsyncMock()
        mock_sftp.put = AsyncMock(
            side_effect=asyncssh_mock.Error("Permission denied")
        )

        mock_context = AsyncMock()
        mock_context.__aenter__ = AsyncMock(return_value=mock_sftp)
        mock_context.__aexit__ = AsyncMock(return_value=None)

        mock_conn = AsyncMock()
        mock_conn.start_sftp_client = MagicMock(return_value=mock_context)

        transport = SSHTransport.__new__(SSHTransport)
        transport._conn = mock_conn
        transport._connected = True
        transport.config = ConnectionConfig(
            transport="ssh", host="testhost"
        )

        with pytest.raises(ConnectionError, match="SFTP upload failed"):
            await transport.upload("/local/file.txt", "/remote/file.txt")


class TestSSHTransportDownload:
    """Тесты SSHTransport.download()"""

    @pytest.mark.asyncio
    async def test_download_success(self, ssh_transport_with_mock):
        """Успешная загрузка файла."""
        SSHTransport, _ = ssh_transport_with_mock

        mock_sftp = AsyncMock()
        mock_sftp.get = AsyncMock()

        mock_context = AsyncMock()
        mock_context.__aenter__ = AsyncMock(return_value=mock_sftp)
        mock_context.__aexit__ = AsyncMock(return_value=None)

        mock_conn = AsyncMock()
        mock_conn.start_sftp_client = MagicMock(return_value=mock_context)

        transport = SSHTransport.__new__(SSHTransport)
        transport._conn = mock_conn
        transport._connected = True
        transport.config = ConnectionConfig(
            transport="ssh", host="testhost"
        )

        await transport.download("/remote/file.txt", "/local/file.txt")

        mock_sftp.get.assert_called_once_with(
            "/remote/file.txt", "/local/file.txt"
        )

    @pytest.mark.asyncio
    async def test_download_not_connected(self, ssh_transport_with_mock):
        """Ошибка при отсутствии подключения."""
        SSHTransport, _ = ssh_transport_with_mock

        transport = SSHTransport.__new__(SSHTransport)
        transport._conn = None
        transport._connected = False
        transport.config = ConnectionConfig(
            transport="ssh", host="testhost"
        )

        with pytest.raises(ConnectionError, match="Not connected"):
            await transport.download("/remote/file.txt", "/local/file.txt")


class TestBaseTransportUpload:
    """Тесты BaseTransport.upload()"""

    @pytest.mark.asyncio
    async def test_base_upload_not_implemented(self):
        """Базовый транспорт не поддерживает upload."""
        from uniconn.transports._base import BaseTransport

        class MockTransport(BaseTransport):
            @property
            def name(self):
                return "mock"

            async def connect(self):
                pass

            async def disconnect(self):
                pass

            async def run(self, command, timeout=None, **kwargs):
                return Result(
                    exit_code=0, stdout="", stderr="",
                    duration=0, command=command,
                    timestamp=datetime.now(), host="mock"
                )

            async def stream(self, command, timeout=None, **kwargs):
                yield ""

        config = ConnectionConfig(transport="mock", host="mock")
        transport = MockTransport(config)

        with pytest.raises(NotImplementedError, match="Upload not supported"):
            await transport.upload("/local/file.txt", "/remote/file.txt")


class TestConnectionUpload:
    """Тесты Connection.upload()/download()"""

    @pytest.mark.asyncio
    async def test_connection_upload(self, mocker):
        """Connection.upload() делегирует транспорту."""
        mock_transport = mocker.AsyncMock()
        mock_transport.upload = AsyncMock()
        mock_transport.name = "ssh"
        mock_transport.is_connected = True

        conn = Connection(
            transport=mock_transport,
            config=ConnectionConfig(transport="ssh", host="testhost"),
        )

        await conn.upload("/local/file.txt", "/remote/file.txt")

        mock_transport.upload.assert_called_once_with(
            "/local/file.txt", "/remote/file.txt"
        )

    @pytest.mark.asyncio
    async def test_connection_download(self, mocker):
        """Connection.download() делегирует транспорту."""
        mock_transport = mocker.AsyncMock()
        mock_transport.download = AsyncMock()
        mock_transport.name = "ssh"
        mock_transport.is_connected = True

        conn = Connection(
            transport=mock_transport,
            config=ConnectionConfig(transport="ssh", host="testhost"),
        )

        await conn.download("/remote/file.txt", "/local/file.txt")

        mock_transport.download.assert_called_once_with(
            "/remote/file.txt", "/local/file.txt"
        )

    @pytest.mark.asyncio
    async def test_connection_upload_with_recurse(self, mocker):
        """Connection.upload() с recurse=True для директорий."""
        mock_transport = mocker.AsyncMock()
        mock_transport.upload = AsyncMock()
        mock_transport.name = "ssh"
        mock_transport.is_connected = True

        conn = Connection(
            transport=mock_transport,
            config=ConnectionConfig(transport="ssh", host="testhost"),
        )

        await conn.upload(
            "/local/dir", "/remote/dir", recurse=True
        )

        mock_transport.upload.assert_called_once_with(
            "/local/dir", "/remote/dir", recurse=True
        )
