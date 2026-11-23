# tests/unit/services/test_ensure_file_backup.py
"""Unit-тесты параметра backup=True для ensure_file и ensure_line (local, remote, fallback, Sync)."""

from __future__ import annotations

import stat
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from uniconn import Connection, FileTransferError, Result, SyncConnection
from uniconn.transports.base import FileStat


async def test_ensure_file_backup_local_creates_bak_preserving_mode_and_content(tmp_path: Path) -> None:
    """ensure_file(..., backup=True) на local создаёт .bak с исходным содержимым и правами и заполняет backup_path."""
    target = tmp_path / "nginx.conf"
    target.write_text("worker_processes 2;\n", encoding="utf-8")
    target.chmod(0o640)

    async with Connection.from_uri("local://") as conn:
        res = await conn.state.ensure_file(
            target,
            content="worker_processes 4;\n",
            backup=True,
        )

    expected_bak = tmp_path / "nginx.conf.bak"
    assert res.ok is True
    assert res.changed is True
    assert res.backup_path == str(expected_bak)
    assert res.to_dict()["backup_path"] == str(expected_bak)
    assert target.read_text(encoding="utf-8") == "worker_processes 4;\n"
    assert expected_bak.exists()
    assert expected_bak.read_text(encoding="utf-8") == "worker_processes 2;\n"
    assert stat.S_IMODE(expected_bak.stat().st_mode) == 0o640


async def test_ensure_file_backup_skipped_on_noop_new_file_dry_run_and_failed_validate(
    tmp_path: Path,
) -> None:
    """Бэкап не создаётся, если файл не существовал, не изменился, dry_run=True или провалилась validate."""
    # 1. Новый файл (не существовал ранее)
    new_file = tmp_path / "brand_new.conf"
    async with Connection.from_uri("local://") as conn:
        r_new = await conn.state.ensure_file(new_file, content="hello\n", backup=True)
        assert r_new.changed is True
        assert r_new.backup_path is None
        assert not (tmp_path / "brand_new.conf.bak").exists()

        # 2. Идемпотентный no-op (содержимое совпадает)
        r_noop = await conn.state.ensure_file(new_file, content="hello\n", backup=True)
        assert r_noop.changed is False
        assert r_noop.backup_path is None
        assert not (tmp_path / "brand_new.conf.bak").exists()

        # 3. Ошибка validate не должна создавать .bak или мутировать файл
        r_val = await conn.state.ensure_file(
            new_file,
            content="invalid\n",
            validate="false %s",
            backup=True,
        )
        assert r_val.ok is False
        assert r_val.backup_path is None
        assert new_file.read_text(encoding="utf-8") == "hello\n"
        assert not (tmp_path / "brand_new.conf.bak").exists()

    # 4. dry_run=True не создаёт .bak
    async with Connection.from_uri("local://", dry_run=True) as dry_conn:
        r_dry = await dry_conn.state.ensure_file(new_file, content="changed\n", backup=True)
        assert r_dry.changed is True
        assert r_dry.backup_path is None
        assert not (tmp_path / "brand_new.conf.bak").exists()


async def test_ensure_file_absent_with_backup_creates_bak_before_removal(tmp_path: Path) -> None:
    """ensure_file(..., state='absent', backup=True) создаёт .bak перед удалением файла."""
    target = tmp_path / "old.conf"
    target.write_text("legacy=1\n", encoding="utf-8")
    target.chmod(0o600)

    async with Connection.from_uri("local://") as conn:
        res = await conn.state.ensure_file(target, state="absent", backup=True)

    bak = tmp_path / "old.conf.bak"
    assert res.ok is True
    assert res.changed is True
    assert res.backup_path == str(bak)
    assert not target.exists()
    assert bak.read_text(encoding="utf-8") == "legacy=1\n"
    assert stat.S_IMODE(bak.stat().st_mode) == 0o600


async def test_ensure_line_with_backup_sets_backup_path(tmp_path: Path) -> None:
    """ensure_line(..., backup=True) также заполняет EnsureResult.backup_path."""
    target = tmp_path / "hosts"
    target.write_text("127.0.0.1 localhost\n", encoding="utf-8")

    async with Connection.from_uri("local://") as conn:
        res = await conn.state.ensure_line(target, line="10.0.0.5 api.internal", backup=True)

    bak = tmp_path / "hosts.bak"
    assert res.ok is True
    assert res.changed is True
    assert res.backup_path == str(bak)
    assert bak.read_text(encoding="utf-8") == "127.0.0.1 localhost\n"


async def test_ensure_file_backup_remote_cp_pf_fast_path_and_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """На удалённом транспорте сначала пробуется cp -pf, а при ошибке выполняется fallback с сохранением mode и owner."""
    conn = Connection.from_uri("local://")
    monkeypatch.setattr(conn, "_transport_name", "ssh", raising=False)
    monkeypatch.setattr(type(conn), "transport_name", property(lambda self: "ssh"))

    # --- Ветка 1: нативный cp -pf успешен ---
    run_calls: list[tuple[str, bool]] = []

    async def fake_run_cp_ok(cmd: str, **kwargs: Any) -> Result:
        run_calls.append((cmd, bool(kwargs.get("sudo", False))))
        return Result(command=cmd, exit_code=0, stdout="", stderr="", duration=0.01)

    monkeypatch.setattr(conn, "run", fake_run_cp_ok)
    monkeypatch.setattr(conn.files, "exists", AsyncMock(return_value=True))
    monkeypatch.setattr(conn.files, "read_file", AsyncMock(return_value=b"old-remote\n"))
    write_mock = AsyncMock(return_value=None)
    monkeypatch.setattr(conn.files, "write_file", write_mock)

    res_cp = await conn.state.ensure_file("/etc/demo.conf", content="new-remote\n", sudo=True, backup=True)
    assert res_cp.ok is True
    assert res_cp.changed is True
    assert res_cp.backup_path == "/etc/demo.conf.bak"
    assert any("cp -pf /etc/demo.conf /etc/demo.conf.bak" in cmd and sudo for cmd, sudo in run_calls)

    # --- Ветка 2: cp -pf провалился -> fallback через stat + write_file + chmod + _apply_owner_group ---
    async def fake_run_cp_fail(cmd: str, **kwargs: Any) -> Result:
        return Result(command=cmd, exit_code=1, stdout="", stderr="cp failed", duration=0.01)

    monkeypatch.setattr(conn, "run", fake_run_cp_fail)
    monkeypatch.setattr(conn.files, "stat", AsyncMock(return_value=FileStat(size=11, mode=0o100640)))
    chmod_mock = AsyncMock(return_value=None)
    monkeypatch.setattr(conn.files, "chmod", chmod_mock)
    monkeypatch.setattr(conn.state, "_get_owner_group", AsyncMock(return_value=("www-data", "adm")))
    apply_owner_mock = AsyncMock(return_value=None)
    monkeypatch.setattr(conn.state, "_apply_owner_group", apply_owner_mock)
    write_fallback_mock = AsyncMock(return_value=None)
    monkeypatch.setattr(conn.files, "write_file", write_fallback_mock)

    res_fb = await conn.state.ensure_file("/etc/demo.conf", content="new-remote-2\n", backup=True)
    assert res_fb.ok is True
    assert res_fb.changed is True
    assert res_fb.backup_path == "/etc/demo.conf.bak"
    # Первый write_file — запись .bak с исходными байтами и mode=0o640
    bak_call = write_fallback_mock.await_args_list[0]
    assert bak_call.args == ("/etc/demo.conf.bak", b"old-remote\n")
    assert bak_call.kwargs["mode"] == 0o640
    chmod_mock.assert_awaited_with("/etc/demo.conf.bak", 0o640)
    apply_owner_mock.assert_awaited_with(
        "/etc/demo.conf.bak",
        owner="www-data",
        group="adm",
        sudo=False,
    )


def test_sync_connection_ensure_file_backup_parity(tmp_path: Path) -> None:
    """SyncConnection.state.ensure_file(..., backup=True) поддерживает создание .bak и backup_path."""
    target = tmp_path / "sync.conf"
    target.write_text("k=1\n", encoding="utf-8")

    with SyncConnection.from_uri("local://") as sconn:
        res = sconn.state.ensure_file(target, content="k=2\n", backup=True)

    assert res.ok is True
    assert res.changed is True
    assert res.backup_path == str(tmp_path / "sync.conf.bak")
    assert (tmp_path / "sync.conf.bak").read_text(encoding="utf-8") == "k=1\n"


async def test_ensure_file_backup_local_overwrites_existing_readonly_bak(tmp_path: Path) -> None:
    """Атомарный локальный бэкап корректно перезаписывает существующий .bak с правами 0o400."""
    target = tmp_path / "secret.conf"
    target.write_text("secret=v1\n", encoding="utf-8")
    target.chmod(0o400)

    async with Connection.from_uri("local://") as conn:
        # Первый проход создаёт .bak с правами 0o400
        target.chmod(0o600)
        bak = tmp_path / "secret.conf.bak"
        bak.write_text("ancient\n", encoding="utf-8")
        bak.chmod(0o400)

        res = await conn.state.ensure_file(target, content="secret=v2\n", backup=True)

    assert res.ok is True
    assert res.backup_path == str(bak)
    assert bak.read_text(encoding="utf-8") == "secret=v1\n"
    assert stat.S_IMODE(bak.stat().st_mode) == 0o600


async def test_ensure_file_backup_remote_raises_when_cp_and_read_both_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Если на удалённом хосте провалились и cp -pf, и read_file, выбрасывается FileTransferError без пустого .bak."""
    conn = Connection.from_uri("local://")
    monkeypatch.setattr(type(conn), "transport_name", property(lambda self: "ssh"))

    async def fake_run_fail(cmd: str, **kwargs: Any) -> Result:
        return Result(command=cmd, exit_code=1, stdout="", stderr="permission denied", duration=0.01)

    monkeypatch.setattr(conn, "run", fake_run_fail)
    monkeypatch.setattr(conn.files, "exists", AsyncMock(return_value=True))
    monkeypatch.setattr(conn.files, "read_file", AsyncMock(side_effect=PermissionError("denied")))
    write_mock = AsyncMock(return_value=None)
    monkeypatch.setattr(conn.files, "write_file", write_mock)

    with pytest.raises(FileTransferError, match="original file content could not be read"):
        await conn.state.ensure_file("/etc/shadow.conf", content="new\n", sudo=True, backup=True)

    # Целевой файл и .bak не должны быть перезаписаны
    write_mock.assert_not_awaited()

