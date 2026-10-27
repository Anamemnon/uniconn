# tests/unit/releases/test_v0150_features.py
"""Приёмочные unit-тесты для возможностей релиза v0.15.0 (файловые операции и системные примитивы)."""

from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from uniconn import Connection, FileTransferError, Result


@pytest.mark.asyncio
async def test_write_file_atomic_local(tmp_path: Path) -> None:
    """write_file(..., atomic=True) на local-транспорте записывает файл атомарно и выставляет права."""
    target = tmp_path / "config.conf"
    target.write_text("old-data\n", encoding="utf-8")

    async with Connection.from_uri("local://localhost") as conn:
        await conn.write_file(target, "new-atomic-data\n", mode=0o640, atomic=True)

    assert target.read_text(encoding="utf-8") == "new-atomic-data\n"
    assert (target.stat().st_mode & 0o777) == 0o640
    # Временных файлов в директории остаться не должно
    leftovers = [p.name for p in tmp_path.iterdir() if p.name.startswith(".uniconn_tmp_")]
    assert leftovers == []


@pytest.mark.asyncio
async def test_write_file_atomic_remote(mocker: pytest.MonkeyPatch) -> None:
    """write_file(..., atomic=True) на удалённом транспорте использует стейджинг в той же директории и mv -f."""
    conn = Connection.from_uri("ssh://root@10.0.0.5")
    mocker.patch.object(conn.transport, "connect", new=AsyncMock())
    mocker.patch.object(type(conn.transport), "is_connected", new_callable=mocker.PropertyMock, return_value=True)
    write_mock = mocker.patch.object(conn.transport, "write_file", new=AsyncMock())
    run_mock = mocker.patch.object(
        conn,
        "run",
        new=AsyncMock(return_value=Result(exit_code=0, stdout="", stderr="", duration=0.01, command="mv")),
    )

    await conn.write_file("/etc/nginx/nginx.conf", "worker_processes auto;\n", mode=0o644, atomic=True)

    assert write_mock.await_count == 1
    staged_path, payload = write_mock.await_args.args[:2]
    assert staged_path.startswith("/etc/nginx/.uniconn_tmp_")
    assert payload == b"worker_processes auto;\n"
    assert write_mock.await_args.kwargs["mode"] == 0o644

    run_mock.assert_awaited_once()
    mv_cmd = run_mock.await_args.args[0]
    assert "mv -f" in mv_cmd
    assert staged_path in mv_cmd
    assert "/etc/nginx/nginx.conf" in mv_cmd


@pytest.mark.asyncio
async def test_write_template_atomic_local(tmp_path: Path) -> None:
    """write_template(..., atomic=True) рендерит шаблон и атомарно записывает результат."""
    target = tmp_path / "app.ini"
    async with Connection.from_uri("local://localhost") as conn:
        rendered = await conn.write_template(
            target,
            "port = ${port}\n",
            context={"port": 8080},
            mode=0o600,
            atomic=True,
        )
    assert rendered == "port = 8080\n"
    assert target.read_text(encoding="utf-8") == "port = 8080\n"
    assert (target.stat().st_mode & 0o777) == 0o600


@pytest.mark.asyncio
async def test_ensure_file_atomic(tmp_path: Path) -> None:
    """ensure_file(..., atomic=True) идемпотентно обновляет файл через атомарную замену."""
    target = tmp_path / "service.conf"
    async with Connection.from_uri("local://localhost") as conn:
        res1 = await conn.ensure_file(target, content="enabled=1\n", mode=0o644, atomic=True)
        assert res1.changed is True
        assert target.read_text(encoding="utf-8") == "enabled=1\n"

        res2 = await conn.ensure_file(target, content="enabled=1\n", mode=0o644, atomic=True)
        assert res2.changed is False


@pytest.mark.asyncio
async def test_checksum_local_algorithms(tmp_path: Path) -> None:
    """conn.checksum вычисляет sha256, sha1 и md5 на локальном транспорте."""
    payload = b"uniconn-integrity-test-payload\n"
    sample = tmp_path / "payload.bin"
    sample.write_bytes(payload)

    async with Connection.from_uri("local://localhost") as conn:
        assert await conn.checksum(sample, "sha256") == hashlib.sha256(payload).hexdigest()
        assert await conn.checksum(sample, "sha1") == hashlib.sha1(payload).hexdigest()
        assert await conn.checksum(sample, "md5") == hashlib.md5(payload).hexdigest()


@pytest.mark.asyncio
async def test_checksum_remote_command(mocker: pytest.MonkeyPatch) -> None:
    """conn.checksum на удалённом транспорте парсит вывод sha256sum."""
    conn = Connection.from_uri("ssh://root@10.0.0.5")
    expected_digest = hashlib.sha256(b"hello").hexdigest()
    mocker.patch.object(
        conn,
        "run",
        new=AsyncMock(
            return_value=Result(
                exit_code=0,
                stdout=f"{expected_digest}  /var/lib/data.bin\n",
                stderr="",
                duration=0.01,
                command="sha256sum /var/lib/data.bin",
            )
        ),
    )

    digest = await conn.checksum("/var/lib/data.bin", algorithm="sha256")
    assert digest == expected_digest


@pytest.mark.asyncio
async def test_upload_and_download_verify_success_and_failure(
    tmp_path: Path, mocker: pytest.MonkeyPatch
) -> None:
    """upload(..., verify=True) и download(..., verify=True) проверяют SHA-256 и бросают FileTransferError при порче."""
    src = tmp_path / "src.txt"
    src.write_bytes(b"verified-content-123")
    dst = tmp_path / "dst.txt"
    downloaded = tmp_path / "downloaded.txt"

    async with Connection.from_uri("local://localhost") as conn:
        await conn.upload(src, dst, verify=True)
        assert dst.read_bytes() == b"verified-content-123"

        await conn.download(dst, downloaded, verify=True)
        assert downloaded.read_bytes() == b"verified-content-123"

        # Симулируем расхождение контрольной суммы при загрузке
        mocker.patch.object(conn.files, "checksum", new=AsyncMock(return_value="0" * 64))
        with pytest.raises(FileTransferError, match="Checksum mismatch"):
            await conn.upload(src, dst, verify=True)


# ─── Unit 2: Системные примитивы (ensure_user, ensure_authorized_key, ensure_systemd_unit, ensure_sysctl) ───


@pytest.mark.asyncio
async def test_ensure_user_present_and_idempotent(mocker: pytest.MonkeyPatch) -> None:
    """ensure_user создаёт отсутствующего пользователя через useradd, а при повторном вызове возвращает changed=False."""
    conn = Connection.from_uri("ssh://root@10.0.0.5")

    async def fake_run(cmd: str, **kw: object) -> Result:
        if cmd.startswith("getent passwd deploy"):
            return Result(exit_code=2, stdout="", stderr="", duration=0.01, command=cmd)
        if cmd.startswith("useradd"):
            return Result(exit_code=0, stdout="", stderr="", duration=0.01, command=cmd)
        return Result(exit_code=0, stdout="", stderr="", duration=0.01, command=cmd)

    run_mock = mocker.patch.object(conn, "run", side_effect=fake_run)

    # 1. Dry-run для нового пользователя возвращает unified diff
    dry_res = await conn.ensure_user(
        "deploy",
        uid=1050,
        group="staff",
        groups=["docker", "wheel"],
        shell="/bin/bash",
        home="/home/deploy",
        sudo=True,
        dry_run=True,
    )
    assert dry_res.changed is True
    assert dry_res.dry_run is True
    assert dry_res.diff is not None
    assert "+user=deploy" in dry_res.diff

    # 2. Создание пользователя
    res1 = await conn.ensure_user(
        "deploy",
        uid=1050,
        group="staff",
        groups=["docker", "wheel"],
        shell="/bin/bash",
        home="/home/deploy",
        sudo=True,
    )
    assert res1.changed is True
    assert res1.ok is True
    executed_cmds = [call.args[0] for call in run_mock.await_args_list]
    assert any("useradd" in c and "-u 1050" in c and "deploy" in c for c in executed_cmds)

    # 3. Повторный вызов, когда пользователь уже в целевом состоянии
    async def fake_run_existing(cmd: str, **kw: object) -> Result:
        if cmd.startswith("getent passwd deploy"):
            return Result(
                exit_code=0,
                stdout="deploy:x:1050:100::/home/deploy:/bin/bash\n",
                stderr="",
                duration=0.01,
                command=cmd,
            )
        if cmd.startswith("id -gn deploy"):
            return Result(exit_code=0, stdout="staff\n", stderr="", duration=0.01, command=cmd)
        if cmd.startswith("id -Gn deploy"):
            return Result(exit_code=0, stdout="staff docker wheel\n", stderr="", duration=0.01, command=cmd)
        return Result(exit_code=0, stdout="", stderr="", duration=0.01, command=cmd)

    mocker.patch.object(conn, "run", side_effect=fake_run_existing)
    res2 = await conn.ensure_user(
        "deploy",
        uid=1050,
        group="staff",
        groups=["docker", "wheel"],
        shell="/bin/bash",
        home="/home/deploy",
        sudo=True,
    )
    assert res2.changed is False
    assert res2.ok is True


@pytest.mark.asyncio
async def test_ensure_authorized_key_local_and_diff(tmp_path: Path, mocker: pytest.MonkeyPatch) -> None:
    """ensure_authorized_key идемпотентно управляет ~/.ssh/authorized_keys и строит unified diff при dry_run."""
    fake_home = tmp_path / "home_alice"
    fake_home.mkdir()
    key1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI TestKeyOne alice@laptop"
    key2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI TestKeyTwo alice@work"

    async with Connection.from_uri("local://localhost") as conn:
        mocker.patch.object(conn.state, "_resolve_user_home", new=AsyncMock(return_value=str(fake_home)))
        mocker.patch.object(conn.state, "_apply_owner_group", new=AsyncMock())

        # Dry-run
        dry = await conn.ensure_authorized_key("alice", key1, dry_run=True)
        assert dry.changed is True
        assert dry.diff is not None
        assert "+ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI TestKeyOne" in dry.diff

        # Добавление первого ключа
        r1 = await conn.ensure_authorized_key("alice", key1)
        assert r1.changed is True
        auth_file = fake_home / ".ssh" / "authorized_keys"
        assert auth_file.exists()
        assert key1 in auth_file.read_text(encoding="utf-8")
        assert (auth_file.stat().st_mode & 0o777) == 0o600

        # Идемпотентный повтор
        r2 = await conn.ensure_authorized_key("alice", key1)
        assert r2.changed is False

        # Exclusive=True заменяет ключи только на key2
        r3 = await conn.ensure_authorized_key("alice", key2, exclusive=True)
        assert r3.changed is True
        text_after_exclusive = auth_file.read_text(encoding="utf-8")
        assert key2 in text_after_exclusive
        assert key1 not in text_after_exclusive

        # Удаление ключа (state="absent")
        r4 = await conn.ensure_authorized_key("alice", key2, state="absent")
        assert r4.changed is True
        assert key2 not in auth_file.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_ensure_systemd_unit_daemon_reload_only_on_change(mocker: pytest.MonkeyPatch) -> None:
    """ensure_systemd_unit вызывает systemctl daemon-reload только если unit-файл изменился."""
    conn = Connection.from_uri("ssh://root@10.0.0.5")
    unit_content = "[Unit]\nDescription=Demo\n[Service]\nExecStart=/usr/bin/demo\n"

    # Сценарий 1: unit-файл изменился -> должен вызваться daemon-reload и ensure_service
    mocker.patch.object(
        conn.state,
        "ensure_file",
        new=AsyncMock(
            return_value=conn.state._make_ensure_result(
                target="/etc/systemd/system/demo.service",
                state="present",
                changed=True,
                ok=True,
                details="updated unit",
                dry_run=False,
                diff="--- /dev/null\n+++ b:/etc/systemd/system/demo.service\n",
            )
            if hasattr(conn.state, "_make_ensure_result")
            else __import__("uniconn").EnsureResult(
                target="/etc/systemd/system/demo.service",
                state="present",
                changed=True,
                ok=True,
                details="updated unit",
                dry_run=False,
                diff="--- /dev/null\n+++ b:/etc/systemd/system/demo.service\n",
            )
        ),
    )
    run_mock = mocker.patch.object(
        conn,
        "run",
        new=AsyncMock(return_value=Result(exit_code=0, stdout="", stderr="", duration=0.01, command="systemctl daemon-reload")),
    )
    svc_mock = mocker.patch.object(
        conn.state,
        "ensure_service",
        new=AsyncMock(
            return_value=__import__("uniconn").EnsureResult(
                target="demo.service",
                state="started",
                changed=True,
                ok=True,
                details="Service demo.service started",
                dry_run=False,
            )
        ),
    )

    res1 = await conn.ensure_systemd_unit(
        "demo",
        content=unit_content,
        state="started",
        enabled=True,
        sudo=True,
    )
    assert res1.changed is True
    assert res1.ok is True
    assert any("daemon-reload" in c.args[0] for c in run_mock.await_args_list)
    svc_mock.assert_awaited_once()

    # Сценарий 2: unit-файл НЕ изменился -> daemon-reload НЕ вызывается
    run_mock.reset_mock()
    mocker.patch.object(
        conn.state,
        "ensure_file",
        new=AsyncMock(
            return_value=__import__("uniconn").EnsureResult(
                target="/etc/systemd/system/demo.service",
                state="present",
                changed=False,
                ok=True,
                details="already in desired state",
                dry_run=False,
            )
        ),
    )
    mocker.patch.object(
        conn.state,
        "ensure_service",
        new=AsyncMock(
            return_value=__import__("uniconn").EnsureResult(
                target="demo.service",
                state="started",
                changed=False,
                ok=True,
                details="already started",
                dry_run=False,
            )
        ),
    )

    res2 = await conn.ensure_systemd_unit(
        "demo.service",
        content=unit_content,
        state="started",
        enabled=True,
        sudo=True,
    )
    assert res2.changed is False
    assert not any("daemon-reload" in c.args[0] for c in run_mock.await_args_list)


@pytest.mark.asyncio
async def test_ensure_sysctl_present_and_absent(tmp_path: Path, mocker: pytest.MonkeyPatch) -> None:
    """ensure_sysctl идемпотентно управляет параметром в файле конфигурации и вызывает sysctl -w при reload=True."""
    sysctl_conf = tmp_path / "99-uniconn.conf"

    async with Connection.from_uri("local://localhost") as conn:
        run_calls: list[str] = []

        async def fake_sysctl_run(cmd: str, **kw: object) -> Result:
            run_calls.append(cmd)
            if cmd.startswith("sysctl -n net.ipv4.ip_forward"):
                val = "1\n" if sysctl_conf.exists() and "net.ipv4.ip_forward = 1" in sysctl_conf.read_text() else "0\n"
                return Result(exit_code=0, stdout=val, stderr="", duration=0.01, command=cmd)
            return Result(exit_code=0, stdout="net.ipv4.ip_forward = 1\n", stderr="", duration=0.01, command=cmd)

        mocker.patch.object(conn, "run", side_effect=fake_sysctl_run)

        # 1. Dry-run
        dry = await conn.ensure_sysctl(
            "net.ipv4.ip_forward",
            1,
            config_file=str(sysctl_conf),
            dry_run=True,
        )
        assert dry.changed is True
        assert dry.diff is not None
        assert "+net.ipv4.ip_forward = 1" in dry.diff

        # 2. Применение параметра
        res1 = await conn.ensure_sysctl(
            "net.ipv4.ip_forward",
            1,
            config_file=str(sysctl_conf),
            reload=True,
        )
        assert res1.changed is True
        assert "net.ipv4.ip_forward = 1" in sysctl_conf.read_text(encoding="utf-8")
        assert any("sysctl -w" in c for c in run_calls)

        # 3. Повторный вызов (идемпотентность)
        run_calls.clear()
        res2 = await conn.ensure_sysctl(
            "net.ipv4.ip_forward",
            1,
            config_file=str(sysctl_conf),
            reload=True,
        )
        assert res2.changed is False
        assert not any("sysctl -w" in c for c in run_calls)

        # 4. Удаление параметра (state="absent")
        res3 = await conn.ensure_sysctl(
            "net.ipv4.ip_forward",
            1,
            state="absent",
            config_file=str(sysctl_conf),
        )
        assert res3.changed is True
        assert "net.ipv4.ip_forward" not in sysctl_conf.read_text(encoding="utf-8")


# ─── Unit 3: Паритет SyncConnection, ConnectionPool, SyncConnectionPool и CLI ───


def test_sync_connection_v0150_parity(tmp_path: Path, mocker: pytest.MonkeyPatch) -> None:
    """SyncConnection поддерживает atomic, checksum, verify и все 4 новых системных примитива."""
    from uniconn import SyncConnection

    f_path = tmp_path / "sync_atomic.txt"
    with SyncConnection.from_uri("local://localhost") as sconn:
        sconn.write_file(f_path, "sync-payload\n", mode=0o600, atomic=True)
        assert f_path.read_text(encoding="utf-8") == "sync-payload\n"
        assert sconn.checksum(f_path, "sha256") == hashlib.sha256(b"sync-payload\n").hexdigest()

        # Проверяем наличие и вызов синхронных методов ensure_*
        for method_name in (
            "ensure_user",
            "ensure_authorized_key",
            "ensure_systemd_unit",
            "ensure_sysctl",
        ):
            assert hasattr(sconn, method_name)
            assert hasattr(sconn.state, method_name)

        sysctl_conf = tmp_path / "sync-sysctl.conf"
        mocker.patch.object(
            sconn._async_conn,
            "run",
            new=AsyncMock(
                return_value=Result(
                    exit_code=0,
                    stdout="1\n",
                    stderr="",
                    duration=0.01,
                    command="sysctl",
                )
            ),
        )
        res = sconn.ensure_sysctl(
            "vm.swappiness",
            10,
            config_file=str(sysctl_conf),
            reload=False,
        )
        assert res.changed is True
        assert "vm.swappiness = 10" in sysctl_conf.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_connection_pool_and_sync_pool_v0150_methods(tmp_path: Path) -> None:
    """ConnectionPool и SyncConnectionPool пробрасывают checksum и новые ensure_* методы."""
    from uniconn import ConnectionPool

    sample = tmp_path / "pool_check.txt"
    sample.write_text("pool-data\n", encoding="utf-8", newline="\n")
    expected_sha = hashlib.sha256(b"pool-data\n").hexdigest()

    async with ConnectionPool(["local://localhost"]) as pool:
        hashes = await pool.checksum(sample, "sha256")
        assert hashes["local://localhost"] == expected_sha

        for name in (
            "ensure_user",
            "ensure_authorized_key",
            "ensure_systemd_unit",
            "ensure_sysctl",
        ):
            assert hasattr(pool, name)

    sync_pool = ConnectionPool(["local://localhost"]).to_sync()
    try:
        sync_hashes = sync_pool.checksum(sample, "sha256")
        assert sync_hashes["local://localhost"] == expected_sha
        for name in (
            "ensure_user",
            "ensure_authorized_key",
            "ensure_systemd_unit",
            "ensure_sysctl",
        ):
            assert hasattr(sync_pool, name)
    finally:
        sync_pool.close()


def test_cli_v0150_commands(tmp_path: Path) -> None:
    """CLI поддерживает подкоманды checksum, ensure-user, ensure-sysctl и ensure-unit."""
    from uniconn.cli import CliRunner, create_cli_app

    cli_app = create_cli_app()
    runner = CliRunner()

    sample = tmp_path / "cli_sample.txt"
    sample.write_bytes(b"cli-test-bytes")
    expected = hashlib.sha256(b"cli-test-bytes").hexdigest()

    res_checksum = runner.invoke(
        cli_app,
        [
            "checksum",
            str(sample),
            "local://localhost",
            "--algorithm",
            "sha256",
            "--format",
            "json",
        ],
    )
    assert res_checksum.exit_code == 0
    assert expected in res_checksum.output

    sysctl_file = tmp_path / "cli_sysctl.conf"
    res_sysctl = runner.invoke(
        cli_app,
        [
            "ensure-sysctl",
            "net.core.somaxconn",
            "4096",
            "local://localhost",
            "--config-file",
            str(sysctl_file),
            "--dry-run",
            "--format",
            "json",
        ],
    )
    assert res_sysctl.exit_code == 0
    assert "net.core.somaxconn" in res_sysctl.output
    assert "changed" in res_sysctl.output


