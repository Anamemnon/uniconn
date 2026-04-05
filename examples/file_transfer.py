"""
Передача файлов через SFTP.

Демонстрирует:
- upload / download файлов
- Рекурсивная передача директорий
- Смена прав (chmod)
- Информация о файле (stat)
- Список файлов (listdir)
"""

import asyncio
from uniconn import Connection


# ─── Upload / Download ──────────────────────────────────────────────

async def basic_file_transfer():
    """Базовая передача файлов."""
    async with Connection.from_uri("ssh://user:pass@host") as conn:
        # Загрузка файла на сервер
        await conn.upload(
            "/local/config.yaml",
            "/etc/app/config.yaml",
        )
        print("Uploaded config.yaml")

        # Скачивание файла
        await conn.download(
            "/var/log/app.log",
            "/local/app.log",
        )
        print("Downloaded app.log")


# ─── Recursive Directory Transfer ───────────────────────────────────

async def recursive_transfer():
    """Рекурсивная передача директорий."""
    async with Connection.from_uri("ssh://user:pass@host") as conn:
        # Явная рекурсия
        await conn.upload(
            "/local/project",
            "/remote/project",
            recurse=True,
        )
        print("Uploaded project directory recursively")

        # Автоопределение (local_path — директория → recurse=True)
        await conn.download(
            "/var/log",
            "/local/logs",
        )
        print("Downloaded log directory (auto-detected recursion)")


# ─── File Permissions ───────────────────────────────────────────────

async def file_permissions():
    """Смена прав доступа к файлам."""
    async with Connection.from_uri("ssh://user:pass@host") as conn:
        # Исполняемый скрипт
        await conn.chmod("/opt/scripts/deploy.sh", 0o755)
        print("deploy.sh: rwxr-xr-x")

        # Приватный конфиг
        await conn.chmod("/etc/app/secrets.yaml", 0o600)
        print("secrets.yaml: rw-------")

        # Конфиг приложения
        await conn.chmod("/etc/app/config.yaml", 0o644)
        print("config.yaml: rw-r--r--")


# ─── File Metadata ──────────────────────────────────────────────────

async def file_metadata():
    """Получение метаданных файлов."""
    async with Connection.from_uri("ssh://user:pass@host") as conn:
        info = await conn.stat("/var/log/syslog")

        print(f"File: /var/log/syslog")
        print(f"  Size:     {info['size']:,} bytes")
        print(f"  Owner:    uid={info['uid']}, gid={info['gid']}")
        print(f"  Perms:    {info['permissions']}")
        print(f"  Modified: {info['mtime']}")
        print(f"  Type:     file={info['is_file']}, dir={info['is_dir']}")


# ─── Directory Listing ──────────────────────────────────────────────

async def directory_listing():
    """Список файлов в директории."""
    async with Connection.from_uri("ssh://user:pass@host") as conn:
        files = await conn.listdir("/var/log")
        print(f"Files in /var/log:")
        for name in files:
            print(f"  {name}")


# ─── Main ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== File Metadata ===")
    asyncio.run(file_metadata())

    print("\n=== Directory Listing ===")
    asyncio.run(directory_listing())
