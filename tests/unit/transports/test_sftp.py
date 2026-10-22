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
    async def test_upload_file(self, ssh_transport_with_mock):
        """Загрузка файла."""
        SSHTransport, _ = ssh_transport_with_mock

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

        with patch("os.path.isdir", return_value=False):
            await transport.upload("/local/file.txt", "/remote/file.txt")

            mock_sftp.put.assert_called_once_with(
                "/local/file.txt", "/remote/file.txt"
            )

    @pytest.mark.asyncio
    async def test_upload_directory_recurse(self, ssh_transport_with_mock):
        """Рекурсивная загрузка директории."""
        SSHTransport, _ = ssh_transport_with_mock

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

        await transport.upload("/local/dir", "/remote/dir", recurse=True)

        mock_sftp.put.assert_called_once_with(
            "/local/dir", "/remote/dir", recurse=True
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

        with patch("os.path.isdir", return_value=False):
            with pytest.raises(ConnectionError, match="SFTP upload failed"):
                await transport.upload("/local/file.txt", "/remote/file.txt")


class TestSSHTransportDownload:
    """Тесты SSHTransport.download()"""

    @pytest.mark.asyncio
    async def test_download_file(self, ssh_transport_with_mock):
        """Скачивание файла."""
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
    async def test_download_directory_recurse(self, ssh_transport_with_mock):
        """Рекурсивное скачивание директории."""
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

        await transport.download(
            "/remote/dir", "/local/dir", recurse=True
        )

        mock_sftp.get.assert_called_once_with(
            "/remote/dir", "/local/dir", recurse=True
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


class TestSSHTransportChmod:
    """Тесты SSHTransport.chmod()"""

    @pytest.mark.asyncio
    async def test_chmod_success(self, ssh_transport_with_mock):
        """Успешная смена прав."""
        SSHTransport, _ = ssh_transport_with_mock

        mock_sftp = AsyncMock()
        mock_sftp.chmod = AsyncMock()

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

        await transport.chmod("/var/www/app.py", 0o755)

        mock_sftp.chmod.assert_called_once_with("/var/www/app.py", 0o755)

    @pytest.mark.asyncio
    async def test_chmod_not_connected(self, ssh_transport_with_mock):
        """Ошибка при отсутствии подключения."""
        SSHTransport, _ = ssh_transport_with_mock

        transport = SSHTransport.__new__(SSHTransport)
        transport._conn = None
        transport._connected = False
        transport.config = ConnectionConfig(
            transport="ssh", host="testhost"
        )

        with pytest.raises(ConnectionError, match="Not connected"):
            await transport.chmod("/var/www/app.py", 0o755)


class TestSSHTransportStat:
    """Тесты SSHTransport.stat()"""

    @pytest.mark.asyncio
    async def test_stat_success(self, ssh_transport_with_mock):
        """Получение информации о файле."""
        SSHTransport, _ = ssh_transport_with_mock

        mock_attrs = MagicMock()
        mock_attrs.size = 1024
        mock_attrs.uid = 1000
        mock_attrs.gid = 1000
        mock_attrs.permissions = 0o100755  # regular file + 755
        mock_attrs.atime = 1700000000
        mock_attrs.mtime = 1700000001

        mock_sftp = AsyncMock()
        mock_sftp.stat = AsyncMock(return_value=mock_attrs)

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

        result = await transport.stat("/var/log/syslog")

        assert result["size"] == 1024
        assert result["uid"] == 1000
        assert result["gid"] == 1000
        assert result["is_file"] is True
        assert result["is_dir"] is False
        assert result["mtime"] == 1700000001

    @pytest.mark.asyncio
    async def test_stat_not_connected(self, ssh_transport_with_mock):
        """Ошибка при отсутствии подключения."""
        SSHTransport, _ = ssh_transport_with_mock

        transport = SSHTransport.__new__(SSHTransport)
        transport._conn = None
        transport._connected = False
        transport.config = ConnectionConfig(
            transport="ssh", host="testhost"
        )

        with pytest.raises(ConnectionError, match="Not connected"):
            await transport.stat("/var/log/syslog")


class TestSSHTransportListdir:
    """Тесты SSHTransport.listdir()"""

    @pytest.mark.asyncio
    async def test_listdir_success(self, ssh_transport_with_mock):
        """Список файлов в директории."""
        SSHTransport, _ = ssh_transport_with_mock

        mock_entry1 = MagicMock()
        mock_entry1.filename = "file1.txt"
        mock_entry2 = MagicMock()
        mock_entry2.filename = "subdir"

        mock_sftp = AsyncMock()
        mock_sftp.readdir = AsyncMock(
            return_value=[mock_entry1, mock_entry2]
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

        result = await transport.listdir("/var/log")

        assert result == ["file1.txt", "subdir"]

    @pytest.mark.asyncio
    async def test_listdir_not_connected(self, ssh_transport_with_mock):
        """Ошибка при отсутствии подключения."""
        SSHTransport, _ = ssh_transport_with_mock

        transport = SSHTransport.__new__(SSHTransport)
        transport._conn = None
        transport._connected = False
        transport.config = ConnectionConfig(
            transport="ssh", host="testhost"
        )

        with pytest.raises(ConnectionError, match="Not connected"):
            await transport.listdir("/var/log")


class TestBaseTransportFileOps:
    """Тесты BaseTransport файловых операций."""

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

    @pytest.mark.asyncio
    async def test_base_chmod_not_implemented(self):
        """Базовый транспорт не поддерживает chmod."""
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

        with pytest.raises(NotImplementedError, match="chmod not supported"):
            await transport.chmod("/remote/file.txt", 0o755)


class TestConnectionFileOps:
    """Тесты Connection файловых операций."""

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
            "/local/file.txt", "/remote/file.txt", recurse=False
        )

    @pytest.mark.asyncio
    async def test_connection_upload_recurse(self, mocker):
        """Connection.upload() с recurse=True."""
        mock_transport = mocker.AsyncMock()
        mock_transport.upload = AsyncMock()
        mock_transport.name = "ssh"
        mock_transport.is_connected = True

        conn = Connection(
            transport=mock_transport,
            config=ConnectionConfig(transport="ssh", host="testhost"),
        )

        await conn.upload("/local/dir", "/remote/dir", recurse=True)

        mock_transport.upload.assert_called_once_with(
            "/local/dir", "/remote/dir", recurse=True
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
            "/remote/file.txt", "/local/file.txt", recurse=False
        )

    @pytest.mark.asyncio
    async def test_connection_chmod(self, mocker):
        """Connection.chmod() делегирует транспорту."""
        mock_transport = mocker.AsyncMock()
        mock_transport.chmod = AsyncMock()
        mock_transport.name = "ssh"
        mock_transport.is_connected = True

        conn = Connection(
            transport=mock_transport,
            config=ConnectionConfig(transport="ssh", host="testhost"),
        )

        await conn.chmod("/var/www/app.py", 0o755)

        mock_transport.chmod.assert_called_once_with("/var/www/app.py", 0o755)

    @pytest.mark.asyncio
    async def test_connection_stat(self, mocker):
        """Connection.stat() делегирует транспорту."""
        mock_transport = mocker.AsyncMock()
        mock_transport.stat = AsyncMock(
            return_value={"size": 1024, "is_file": True}
        )
        mock_transport.name = "ssh"
        mock_transport.is_connected = True

        conn = Connection(
            transport=mock_transport,
            config=ConnectionConfig(transport="ssh", host="testhost"),
        )

        result = await conn.stat("/var/log/syslog")

        assert result["size"] == 1024
        mock_transport.stat.assert_called_once_with("/var/log/syslog")

    @pytest.mark.asyncio
    async def test_connection_listdir(self, mocker):
        """Connection.listdir() делегирует транспорту."""
        mock_transport = mocker.AsyncMock()
        mock_transport.listdir = AsyncMock(
            return_value=["file1.txt", "subdir"]
        )
        mock_transport.name = "ssh"
        mock_transport.is_connected = True

        conn = Connection(
            transport=mock_transport,
            config=ConnectionConfig(transport="ssh", host="testhost"),
        )

        result = await conn.listdir("/var/log")

        assert result == ["file1.txt", "subdir"]
        mock_transport.listdir.assert_called_once_with("/var/log")
