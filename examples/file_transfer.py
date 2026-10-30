"""Файловые операции, SFTP, контрольные суммы, дельта-синхронизация и шаблоны (conn.files).

Демонстрирует:
- Чтение и атомарную запись файлов в памяти (write_file с atomic=True, read_file)
- Загрузку и скачивание с проверкой целостности SHA-256 (upload / download с verify=True)
- Вычисление криптографических хешей (checksum: sha256, sha1, md5)
- Инкрементальную дельта-синхронизацию директорий (sync_dir -> SyncResult)
- Рендеринг конфигурационных шаблонов (write_template: string.Template и Jinja2)
- Управление правами и метаданными (chmod, stat, listdir, mkdir, exists)
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from uniconn import Connection

# ─── Справочный пример для удалённого SSH / SFTP сервера ────────────


async def ssh_sftp_transfer_example() -> None:
    """Пример передачи файлов и синхронизации директорий по SSH SFTP."""
    async with Connection.from_uri("ssh://admin:env://SSH_PASS@node-01") as conn:
        # Загрузка и скачивание с автоматической сверкой SHA-256 хеша
        await conn.files.upload("./local/app.tar.gz", "/opt/releases/app.tar.gz", verify=True)
        await conn.files.download("/var/log/syslog", "./logs/syslog.log", verify=True)

        # Инкрементальная дельта-синхронизация директории
        sync_res = await conn.files.sync_dir(
            "./dist",
            "/var/www/app",
            delete=True,
            exclude=["*.pyc", ".git"],
            checksum_check=True,
        )
        print(f"Synced: uploaded={len(sync_res.uploaded)}, skipped={len(sync_res.skipped)}")


# ─── Самодостаточная демонстрация всех возможностей conn.files ──────


async def main() -> None:
    """Локальная демонстрация сервиса conn.files во временной директории."""
    with tempfile.TemporaryDirectory(prefix="uniconn_files_") as tmp_root:
        root = Path(tmp_root)
        src_dir = root / "src_bundle"
        dst_dir = root / "remote_root"
        src_dir.mkdir()
        dst_dir.mkdir()

        async with Connection.local() as conn:
            print("=== 1. Атомарная запись, чтение и контрольная сумма (checksum) ===")
            conf_path = str(dst_dir / "app.conf")
            await conn.files.write_file(
                conf_path,
                "listen_port = 8080\nworkers = 4\n",
                mode=0o640,
                atomic=True,
            )
            content = await conn.files.read_file(conf_path)
            sha256 = await conn.files.checksum(conf_path, algorithm="sha256")
            info = await conn.files.stat(conf_path)
            print(f"Содержимое ({info.get('size', 0)} байт): {content!r}")
            print(f"SHA-256: {sha256}")

            print("\n=== 2. Upload / Download с проверкой целостности (verify=True) ===")
            local_artifact = src_dir / "payload.bin"
            local_artifact.write_bytes(b"binary-release-payload-v1")
            remote_artifact = str(dst_dir / "payload.bin")
            downloaded_artifact = str(root / "downloaded_payload.bin")

            await conn.files.upload(str(local_artifact), remote_artifact, verify=True)
            await conn.files.download(remote_artifact, downloaded_artifact, verify=True)
            print(f"Файл успешно загружен и скачан с проверкой SHA-256: {Path(downloaded_artifact).exists()}")

            print("\n=== 3. Рендеринг шаблонов (write_template с atomic=True) ===")
            rendered_path = str(dst_dir / "service.env")
            rendered = await conn.files.write_template(
                rendered_path,
                "SERVICE_NAME=${service}\nPORT=${port}\n",
                context={"service": "billing-api", "port": 9090},
                mode=0o600,
                engine="string",
                atomic=True,
            )
            print(f"Сгенерированный конфиг:\n{rendered.strip()}")

            print("\n=== 4. Дельта-синхронизация директорий (sync_dir) ===")
            (src_dir / "index.html").write_text("<h1>Hello v1</h1>\n", encoding="utf-8")
            (src_dir / "ignore.pyc").write_bytes(b"\x00\x01")
            sync_target = str(dst_dir / "www")

            sync1 = await conn.files.sync_dir(
                str(src_dir),
                sync_target,
                delete=True,
                exclude=["*.pyc"],
                checksum_check=True,
            )
            print(f"Первый прогон sync_dir: uploaded={sync1.uploaded}, skipped={sync1.skipped}")

            sync2 = await conn.files.sync_dir(
                str(src_dir),
                sync_target,
                delete=True,
                exclude=["*.pyc"],
                checksum_check=True,
            )
            print(f"Повторный прогон (идемпотентно): uploaded={sync2.uploaded}, skipped={sync2.skipped}")


if __name__ == "__main__":
    asyncio.run(main())
