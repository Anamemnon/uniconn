# tests/unit/test_v050_features.py
"""Unit-тесты для функциональности этапа v0.5.0 (удобство использования и эргономика)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from uniconn import Connection, ConnectionConfig, ConnectionPool, Result
from uniconn.transports._ssh import SSHTransport

# ─── 1. Эргономика Result (.text, .lines, .json(), bool(result)) ───────


def test_result_text_and_lines():
    """Result.text возвращает stdout.strip(), а Result.lines — список строк."""
    res = Result(
        exit_code=0,
        stdout="  alpha\nbeta\ngamma  \n\n",
        stderr="",
        duration=0.1,
        command="echo",
    )
    assert res.text == "alpha\nbeta\ngamma"
    assert res.lines == ["alpha", "beta", "gamma"]

    empty_res = Result(
        exit_code=0,
        stdout="   \n  ",
        stderr="",
        duration=0.05,
        command="true",
    )
    assert empty_res.text == ""
    assert empty_res.lines == []


def test_result_json_and_bool():
    """Result.json() парсит JSON из stdout, а bool(Result) отражает exit_code == 0."""
    res_ok = Result(
        exit_code=0,
        stdout='{"status": "healthy", "nodes": [1, 2, 3]}\n',
        stderr="",
        duration=0.1,
        command="curl",
    )
    assert bool(res_ok) is True
    data = res_ok.json()
    assert data == {"status": "healthy", "nodes": [1, 2, 3]}

    res_fail = Result(
        exit_code=1,
        stdout="not json",
        stderr="err",
        duration=0.1,
        command="false",
    )
    assert bool(res_fail) is False
    with pytest.raises(ValueError):
        res_fail.json()


# ─── 2. OpenSSH Config (parse_openssh_config и автоподстановка) ────────


@pytest.mark.asyncio
async def test_openssh_config_parsing_and_connect(tmp_path: Path):
    """SSHTransport парсит директивы User, Port, IdentityFile из файла OpenSSH config."""
    key_path = tmp_path / "id_ed25519"
    key_path.write_text("DUMMY KEY", encoding="utf-8")

    ssh_cfg = tmp_path / "ssh_config"
    ssh_cfg.write_text(
        f"""
        # Комментарий
        Host prod-* !prod-legacy
            User deploy
            Port 2222
            IdentityFile {key_path}

        Host *
            User fallback_user
            Port 2200
        """,
        encoding="utf-8",
    )

    parsed = SSHTransport.parse_openssh_config(ssh_cfg, "prod-db")
    assert parsed["user"] == "deploy"
    assert parsed["port"] == 2222
    assert parsed["identityfile"] == str(key_path)

    # Проверяем правило исключения !prod-legacy (должен сработать только блок Host *)
    parsed_legacy = SSHTransport.parse_openssh_config(ssh_cfg, "prod-legacy")
    assert parsed_legacy["user"] == "fallback_user"
    assert parsed_legacy["port"] == 2200

    # Проверяем применение в SSHTransport.connect()
    conn = Connection.from_uri(f"ssh://prod-db?ssh_config={ssh_cfg}")
    assert conn.config.ssh_config == str(ssh_cfg)

    with patch("uniconn.transports._ssh.asyncssh.connect", new_callable=AsyncMock) as mock_connect:
        await conn._transport.connect()
        kwargs = mock_connect.call_args.kwargs
        assert kwargs["config"] == [str(ssh_cfg)]
        assert kwargs["username"] == "deploy"
        assert kwargs["port"] == 2222
        assert kwargs["client_keys"] == [str(key_path)]


# ─── 3. Файловые хелперы: exists(), mkdir(), temp_dir() ────────────────


@pytest.mark.asyncio
async def test_local_exists_mkdir_and_temp_dir():
    """exists(), mkdir() и temp_dir() работают локально и учитывают conn.cd()."""
    async with Connection.from_uri("local://") as conn:
        async with conn.temp_dir(prefix="uniconn_v050_") as tmp:
            tmp_path = Path(tmp)
            assert tmp_path.is_dir()
            assert await conn.files.exists(tmp) is True

            async with conn.cd(tmp):
                assert await conn.files.exists("nested/sub") is False
                await conn.files.mkdir("nested/sub", mode=0o755)
                assert await conn.files.exists("nested/sub") is True

                await conn.files.write_file("nested/sub/hello.txt", "world")
                assert await conn.files.exists("nested/sub/hello.txt") is True
                assert await conn.files.read_file("nested/sub/hello.txt") == "world"

        # После выхода из async with conn.temp_dir() директория удалена
        assert not tmp_path.exists()
        assert await conn.files.exists(tmp) is False


def test_sync_exists_mkdir_and_temp_dir():
    """SyncConnection поддерживает files.exists(), files.mkdir() и контекстный менеджер temp_dir()."""
    with Connection.from_uri("local://").to_sync() as conn:
        with conn.temp_dir(prefix="uniconn_sync_") as tmp:
            assert conn.files.exists(tmp) is True
            with conn.cd(tmp):
                conn.files.mkdir("configs")
                conn.files.write_file("configs/app.json", '{"port": 8080}')
                assert conn.files.exists("configs/app.json") is True
                res = conn.run(["cat", "configs/app.json"])
                assert res.json() == {"port": 8080}
        assert conn.files.exists(tmp) is False


@pytest.mark.asyncio
async def test_ssh_exists_and_mkdir_via_sftp():
    """SSHTransport.exists() и mkdir() работают через SFTP."""
    config = ConnectionConfig(transport="ssh", host="sftp.example.com")
    transport = SSHTransport(config)
    transport._connected = True

    sftp = MagicMock()
    attrs = MagicMock()
    attrs.size = 10
    attrs.uid = 0
    attrs.gid = 0
    attrs.permissions = 0o100644
    attrs.atime = 0
    attrs.mtime = 0
    sftp.stat = AsyncMock(return_value=attrs)
    sftp.makedirs = AsyncMock()
    sftp.chmod = AsyncMock()

    sftp_cm = MagicMock()
    sftp_cm.__aenter__ = AsyncMock(return_value=sftp)
    sftp_cm.__aexit__ = AsyncMock(return_value=None)

    mock_conn = MagicMock()
    mock_conn.start_sftp_client = MagicMock(return_value=sftp_cm)
    transport._conn = mock_conn

    assert await transport.exists("/etc/hosts") is True
    await transport.mkdir("/var/app/releases", parents=True, exist_ok=True, mode=0o750)
    sftp.makedirs.assert_awaited_once_with("/var/app/releases", exist_ok=True)
    sftp.chmod.assert_awaited_once_with("/var/app/releases", 0o750)


# ─── 4. Мульти-хостовый Inventory (from_file / from_inventory) ─────────


def test_inventory_yaml_hosts_and_groups(tmp_path: Path):
    """Connection.from_file(), from_inventory() и ConnectionPool.from_file() поддерживают группы."""
    inv_file = tmp_path / "inventory.yaml"
    inv_file.write_text(
        """
defaults:
  transport: local
  timeout: 15.0

hosts:
  web-01:
    host: localhost
    groups: [web, prod]
  web-02:
    host: localhost
    groups: [web, prod]
  db-01:
    host: localhost
    timeout: 45.0
    groups: [db]

groups:
  all_prod: [web-01, web-02, db-01]
""",
        encoding="utf-8",
    )

    all_conns = Connection.from_file(inv_file)
    assert len(all_conns) == 3

    web_conns = Connection.from_file(inv_file, group="web")
    assert len(web_conns) == 2
    assert all(c.config.timeout == 15.0 for c in web_conns)

    prod_conns = Connection.from_file(inv_file, group="all_prod")
    assert len(prod_conns) == 3

    db_conn = Connection.from_inventory(inv_file, host="db-01")
    assert db_conn.config.timeout == 45.0

    with pytest.raises(KeyError, match="not found"):
        Connection.from_inventory(inv_file, host="nonexistent")

    with pytest.raises(KeyError, match="not found"):
        Connection.from_file(inv_file, group="nonexistent_group")


# ─── 5. Переиспользуемый ConnectionPool, apply, upload, download ───────


@pytest.mark.asyncio
async def test_persistent_connection_pool_and_apply(tmp_path: Path):
    """async with ConnectionPool(...) удерживает соединения открытыми и поддерживает apply()."""
    inv_file = tmp_path / "pool_inv.yaml"
    inv_file.write_text(
        """
defaults:
  transport: local
hosts:
  node-1:
    host: localhost
  node-2:
    host: localhost
""",
        encoding="utf-8",
    )

    pool = ConnectionPool.from_file(inv_file)
    async with pool:
        assert pool._is_entered is True
        assert len(pool._active_conns) == 2

        results = await pool.map(["echo", "pool_alive"])
        assert [r.text for r in results] == ["pool_alive", "pool_alive"]

        custom = await pool.apply(lambda c: c.run(["echo", "from_apply"]))
        assert [r.text for r in custom] == ["from_apply", "from_apply"]

    assert pool._is_entered is False
    assert len(pool._active_conns) == 0


@pytest.mark.asyncio
async def test_pool_upload_and_download():
    """ConnectionPool.files.upload() и files.download() параллельно передают файлы на все хосты."""
    c1 = MagicMock(spec=Connection)
    c1.config = ConnectionConfig(transport="ssh", host="host1")
    c1.files = MagicMock()
    c1.files.upload = AsyncMock()
    c1.files.download = AsyncMock()
    c1.__aenter__ = AsyncMock(return_value=c1)
    c1.__aexit__ = AsyncMock(return_value=None)

    c2 = MagicMock(spec=Connection)
    c2.config = ConnectionConfig(transport="ssh", host="host2")
    c2.files = MagicMock()
    c2.files.upload = AsyncMock()
    c2.files.download = AsyncMock()
    c2.__aenter__ = AsyncMock(return_value=c2)
    c2.__aexit__ = AsyncMock(return_value=None)

    async with ConnectionPool([c1, c2]) as pool:
        await pool.files.upload("/local/app.tar.gz", "/remote/app.tar.gz")
        c1.files.upload.assert_awaited_once_with(
            "/local/app.tar.gz",
            "/remote/app.tar.gz",
            recurse=False,
        )
        c2.files.upload.assert_awaited_once_with(
            "/local/app.tar.gz",
            "/remote/app.tar.gz",
            recurse=False,
        )

        saved = await pool.files.download("/var/log/syslog", "/tmp/logs/{host}.log")
        assert saved == {
            "host1": "/tmp/logs/host1.log",
            "host2": "/tmp/logs/host2.log",
        }
