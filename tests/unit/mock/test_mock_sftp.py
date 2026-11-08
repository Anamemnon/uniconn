# tests/unit/mock/test_mock_sftp.py
"""Тесты подсистемы SFTP в MockSSHServer: чтение, stat, listdir, сверка записи с кассетой и сессионный оверлей."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import asyncssh
import pytest

from uniconn import (
    Cassette,
    Connection,
    ConnectionError,
    MockSFTPServer,
    MockSSHServer,
    RecordedFsInteraction,
)


def _sample_fs_cassette() -> Cassette:
    return Cassette(
        transport="ssh",
        host="fs-node-01",
        capabilities=["exec", "file", "shell"],
        interactions=[
            RecordedFsInteraction(
                operation="read_file",
                path="/etc/nginx/nginx.conf",
                mode=0o644,
                content_utf8="worker_processes auto;\n",
            ),
            RecordedFsInteraction(
                operation="listdir",
                path="/etc/nginx",
                result_list=["nginx.conf", "mime.types", "conf.d"],
            ),
            RecordedFsInteraction(
                operation="stat",
                path="/etc/nginx/mime.types",
                result_stat={
                    "size": 512,
                    "permissions": "0o100640",
                    "is_file": True,
                    "is_dir": False,
                },
            ),
            RecordedFsInteraction(
                operation="write_file",
                path="/etc/nginx/conf.d/app.conf",
                mode=0o640,
                content_utf8="server { listen 8080; }\n",
            ),
            RecordedFsInteraction(
                operation="mkdir",
                path="/var/www/releases/v1",
                mode=0o755,
            ),
            RecordedFsInteraction(
                operation="chmod",
                path="/etc/nginx/conf.d/app.conf",
                mode=0o600,
            ),
            RecordedFsInteraction(
                operation="remove_file",
                path="/etc/nginx/conf.d/app.conf",
            ),
        ],
    )


async def test_mock_sftp_read_stat_and_listdir(tmp_path: Path) -> None:
    """Проверка SFTP-операций чтения файла, скачивания, stat и listdir через реальный сокет."""
    cassette = _sample_fs_cassette()

    async with MockSSHServer.from_cassette(cassette) as server:
        async with Connection.from_uri(server.uri, retry_attempts=1) as conn:
            content = await conn.files.read_file("/etc/nginx/nginx.conf")
            assert content == "worker_processes auto;\n"

            st = await conn.files.stat("/etc/nginx/mime.types")
            assert st["size"] == 512
            assert st["is_file"] is True

            entries = await conn.files.listdir("/etc/nginx")
            assert "nginx.conf" in entries
            assert "mime.types" in entries

            dl_target = tmp_path / "downloaded_nginx.conf"
            await conn.files.download("/etc/nginx/nginx.conf", dl_target)
            assert dl_target.read_text(encoding="utf-8") == "worker_processes auto;\n"

            assert await conn.files.exists("/etc/nginx/nginx.conf") is True
            assert await conn.files.exists("/etc/nginx/missing.conf") is False


async def test_mock_sftp_write_verification_and_session_overlay() -> None:
    """Запись по SFTP сверяется с кассетой и сохраняется в памяти сессии для последующего чтения."""
    cassette = _sample_fs_cassette()

    async with MockSSHServer.from_cassette(cassette, strict_mode=True) as server:
        async with Connection.from_uri(server.uri, retry_attempts=1) as conn:
            # 1. Запись по разрешённому в кассете пути проходит успешно и попадает в оверлей сессии
            new_cfg = "server {\n    listen 9090;\n}\n"
            await conn.files.write_file("/etc/nginx/conf.d/app.conf", new_cfg, mode=0o600)

            # Чтение того же файла в сессии возвращает только что записанные данные
            read_back = await conn.files.read_file("/etc/nginx/conf.d/app.conf")
            assert read_back == new_cfg

            # 2. Создание разрешённой директории
            await conn.files.mkdir("/var/www/releases/v1", parents=False)
            dir_stat = await conn.files.stat("/var/www/releases/v1")
            assert dir_stat["is_dir"] is True

            # 3. Удаление файла скрывает его из оверлея сессии
            await conn.files.remove_file("/etc/nginx/conf.d/app.conf")
            assert await conn.files.exists("/etc/nginx/conf.d/app.conf") is False

            # 4. В strict_mode=True попытка записи в незаписанный в кассете путь отклоняется
            with pytest.raises(ConnectionError):
                await conn.files.write_file("/etc/unrecorded.conf", "forbidden")


def test_mock_sftp_server_direct_methods() -> None:
    """Прямой вызов методов MockSFTPServer (stat, open, listdir) возвращает корректные типы asyncssh."""
    cassette = _sample_fs_cassette()
    dummy_chan = MagicMock()
    sftp_srv = MockSFTPServer(dummy_chan, cassette)

    attrs = sftp_srv.stat("/etc/nginx/nginx.conf")
    assert attrs.size == len("worker_processes auto;\n")

    names = sftp_srv.listdir("/etc/nginx")
    assert any(n.filename == "nginx.conf" for n in names)

    f_obj = sftp_srv.open("/etc/nginx/nginx.conf", asyncssh.FXF_READ, asyncssh.SFTPAttrs())
    assert f_obj.read() == b"worker_processes auto;\n"
    sftp_srv.fsync(f_obj)
    f_obj.close()

    with pytest.raises(asyncssh.SFTPNoSuchFile):
        sftp_srv.stat("/no/such/file.txt")


async def test_mock_sftp_file_ranges_without_fileno_on_windows() -> None:
    """Проверка получения диапазонов SFTP для MockSFTPFile без атрибута fileno (Windows / pywin32)."""
    import asyncssh.sftp as asyncssh_sftp

    from uniconn.mock.sftp_server import MockSFTPFile

    mock_file = MockSFTPFile("/etc/nginx/nginx.conf", b"worker_processes auto;\n")
    assert not hasattr(mock_file, "fileno")

    ranges = [
        item
        async for item in asyncssh_sftp._request_ranges(  # type: ignore[arg-type]
            mock_file, 0, len(mock_file.content)
        )
    ]
    assert ranges == [(0, len(mock_file.content))]

    empty_ranges = [
        item
        async for item in asyncssh_sftp._request_ranges(  # type: ignore[arg-type]
            mock_file, len(mock_file.content), 100
        )
    ]
    assert empty_ranges == []
