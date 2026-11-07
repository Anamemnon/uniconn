# tests/unit/services/test_remote_path.py
"""Unit-тесты для объектной модели удаленной файловой системы RemotePath и SyncRemotePath."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

from uniconn import Connection, RemotePath, RemoteStatResult, SyncRemotePath


def test_remote_stat_result_posix_and_dict_interface() -> None:
    """RemoteStatResult предоставляет интерфейс как dict (FileStat), так и os.stat_result."""
    st = RemoteStatResult(
        size=4096,
        mtime=1700000000.5,
        mode=0o755,
        is_dir=False,
        is_symlink=True,
        uid=1000,
        gid=1001,
    )
    assert st["size"] == 4096
    assert st.size == 4096
    assert st.st_size == 4096
    assert st.mtime == 1700000000.5
    assert st.st_mtime == 1700000000.5
    assert st.st_ctime == 1700000000.5
    assert st.mode == 0o755
    assert (st.st_mode & 0o777) == 0o755
    assert st.uid == 1000
    assert st.st_uid == 1000
    assert st.gid == 1001
    assert st.st_gid == 1001
    assert st.is_dir is False
    assert st.is_file is False
    assert st.is_symlink is True


def test_remote_path_pure_navigation_and_operators() -> None:
    """Операторы / и чистые свойства RemotePath соответствуют семантике pathlib.Path."""
    conn = Connection.from_uri("local://")
    base = conn.path("/var/log")
    nginx_dir = base / "nginx"
    access_log = nginx_dir / "access.log.gz"

    assert isinstance(base, RemotePath)
    assert str(nginx_dir) == "/var/log/nginx"
    assert access_log.as_posix() == "/var/log/nginx/access.log.gz"
    assert access_log.name == "access.log.gz"
    assert access_log.stem == "access.log"
    assert access_log.suffix == ".gz"
    assert access_log.suffixes == [".log", ".gz"]
    assert access_log.is_absolute() is True
    assert access_log.parent == nginx_dir
    assert len(access_log.parents) == 4
    assert access_log.with_name("error.log") == nginx_dir / "error.log"
    assert access_log.with_stem("access.log.1") == nginx_dir / "access.log.1.gz"
    assert access_log.with_suffix(".bz2") == nginx_dir / "access.log.bz2"
    assert access_log.relative_to("/var/log") == conn.path("nginx/access.log.gz")
    assert access_log.match("*.gz") is True
    assert access_log.joinpath("sub", "item.txt") == access_log / "sub" / "item.txt"
    assert repr(nginx_dir) == "RemotePath('/var/log/nginx')"


def test_remote_path_windows_flavour() -> None:
    """На транспортах winrm автоматически используется PureWindowsPath."""
    conn = Connection.from_uri("winrm://admin:pass@win-host")
    win_path = conn.path(r"C:\Users\Admin") / "Documents" / "report.txt"
    assert win_path.name == "report.txt"
    assert win_path.stem == "report"
    assert win_path.suffix == ".txt"
    assert win_path.anchor == "C:\\"


async def test_remote_path_crud_and_atomic_write(tmp_path: Path) -> None:
    """Полный цикл CRUD-операций через RemotePath: запись, чтение, stat, chmod, rename, unlink."""
    async with Connection.from_uri("local://") as conn:
        root = conn.path(tmp_path)
        conf = root / "etc" / "app.conf"
        await conf.parent.mkdir(parents=True, exist_ok=True)
        assert await conf.parent.is_dir() is True

        written = await conf.write_text("port = 8080\n", encoding="utf-8", atomic=True)
        assert written == 12
        assert await conf.exists() is True
        assert await conf.is_file() is True
        assert await conf.read_text() == "port = 8080\n"

        st = await conf.stat()
        assert isinstance(st, RemoteStatResult)
        assert st.st_size == 12
        assert conf.cached_stat is st

        # Повторный вызов stat() берёт данные из кэша без обращения к транспорту
        st_cached = await conf.stat()
        assert st_cached is st

        # При записи кэш автоматически инвалидируется
        await conf.write_bytes(b"port = 9090\n", atomic=True)
        assert conf.cached_stat is None
        st_updated = await conf.stat()
        assert st_updated.st_size == 12
        assert await conf.read_bytes() == b"port = 9090\n"

        # Хеш-сумма
        digest = await conf.checksum("sha256")
        assert len(digest) == 64

        # Переименование и замена
        renamed = await conf.rename(root / "etc" / "app_new.conf")
        assert await renamed.exists() is True
        assert await conf.exists() is False

        replaced = await renamed.replace(root / "etc" / "app_final.conf")
        assert await replaced.exists() is True

        # Touch и удаление
        marker = root / "etc" / "ready.flag"
        await marker.touch()
        assert await marker.exists() is True
        await marker.unlink()
        assert await marker.exists() is False
        await marker.unlink(missing_ok=True)


async def test_remote_path_glob_rglob_iterdir_with_preloaded_stat(tmp_path: Path) -> None:
    """glob(), rglob() и iterdir() предзагружают метаданные stat за один батч без лишних вызовов."""
    async with Connection.from_uri("local://") as conn:
        log_dir = conn.path(tmp_path) / "logs"
        await (log_dir / "sub").mkdir(parents=True)
        await (log_dir / "access.log").write_text("line1\n")
        await (log_dir / "error.log").write_text("err1\nerr2\n")
        await (log_dir / "readme.txt").write_text("ignore")
        await (log_dir / "sub" / "nested.log").write_text("deep\n")

        # Проверяем glob("*.log") и убеждаемся, что stat() не вызывает files.stat()
        spy_stat = AsyncMock(wraps=conn.files.stat)
        conn.files.stat = spy_stat  # type: ignore[method-assign]

        matched_logs: dict[str, int] = {}
        async for item in log_dir.glob("*.log"):
            assert item.cached_stat is not None
            st = await item.stat()
            matched_logs[item.name] = st.st_size

        assert matched_logs == {"access.log": 6, "error.log": 10}
        assert spy_stat.await_count == 0

        # Проверяем rglob("*.log")
        recursive_logs = [item.name async for item in log_dir.rglob("*.log")]
        assert sorted(recursive_logs) == ["access.log", "error.log", "nested.log"]

        # Проверяем iterdir()
        entries = [entry.name async for entry in log_dir.iterdir()]
        assert sorted(entries) == ["access.log", "error.log", "readme.txt", "sub"]


async def test_remote_path_respects_cd_context_and_upload_download(tmp_path: Path) -> None:
    """Относительные RemotePath учитывают контекст conn.cd(), а upload_from/download_to копируют файлы."""
    import os

    import pytest

    src_local = tmp_path / "source.txt"
    src_local.write_text("payload-data", encoding="utf-8")
    dst_local = tmp_path / "downloaded.txt"
    work_dir = tmp_path / "workspace"
    (work_dir / "logs").mkdir(parents=True)
    (work_dir / "logs" / "app.log").write_text("log-entry", encoding="utf-8")

    async with Connection.from_uri("local://") as conn:
        # conn.cd() принимает объект RemotePath напрямую через os.PathLike
        async with conn.cd(conn.path(work_dir)):
            rel_file = conn.path("remote_copy.txt")
            await rel_file.upload_from(src_local, verify=True)
            assert (work_dir / "remote_copy.txt").read_text(encoding="utf-8") == "payload-data"
            await rel_file.download_to(dst_local, verify=True)
            assert dst_local.read_text(encoding="utf-8") == "payload-data"

            # Относительный glob сохраняет относительность пути для корректного вызова relative_to()
            rel_logs = conn.path("logs")
            matched = [p async for p in rel_logs.glob("*.log")]
            assert len(matched) == 1
            assert matched[0].as_posix() == "logs/app.log"
            assert matched[0].relative_to(rel_logs).as_posix() == "app.log"

            # touch(exist_ok=False) выбрасывает FileExistsError на существующем файле
            with pytest.raises(FileExistsError):
                await rel_file.touch(exist_ok=False)

            # unlink() корректно удаляет битые симлинки
            broken_link = work_dir / "broken.lnk"
            os.symlink(work_dir / "non_existent_target", broken_link)
            remote_broken = conn.path("broken.lnk")
            assert await remote_broken.is_symlink() is True
            await remote_broken.unlink()
            assert not broken_link.is_symlink()


def test_sync_remote_path_end_to_end(tmp_path: Path) -> None:
    """SyncRemotePath поддерживает все операции и итераторы в синхронном коде."""
    with Connection.from_uri("local://").to_sync() as sync_conn:
        base = sync_conn.path(tmp_path) / "sync_dir"
        assert isinstance(base, SyncRemotePath)
        base.mkdir(parents=True)

        f1 = base / "one.log"
        f2 = base / "two.log"
        f1.write_text("alpha", atomic=True)
        f2.write_text("beta-gamma", atomic=True)

        found = {p.name: p.stat().st_size for p in base.glob("*.log")}
        assert found == {"one.log": 5, "two.log": 10}

        f1.unlink()
        f2.unlink()
        base.rmdir()
        assert not base.exists()

