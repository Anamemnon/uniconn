"""Пример использования интерактивной stateful PTY shell-сессии в uniconn.

Демонстрирует:
- Открытие PTY shell-сессии через ``conn.open_shell()``
- Сохранение состояния (``cd``, ``export``) между вызовами ``execute()``
- Изменение размера терминала через ``resize(cols, rows)``
- Совместную работу ``open_shell()`` и ``run()`` на одном SSH-подключении без реконнекта
- Синхронную обёртку ``SyncShellSession`` через ``to_sync()``
"""

import asyncio

from uniconn import Connection


async def async_shell_example() -> None:
    """Асинхронная работа со stateful shell-сессией."""
    async with (
        Connection.from_uri("ssh://user:pass@example.com") as conn,
        await conn.open_shell(term_type="xterm", term_size=(100, 30)) as shell,
    ):
        # Смена рабочей директории сохраняется для следующих команд
        await shell.execute("cd /var/log")
        pwd_result = await shell.execute("pwd")
        print(f"Current directory: {pwd_result.stdout}")

        # Переменные окружения также сохраняются внутри сессии
        await shell.execute("export DEPLOY_ENV=production")
        env_result = await shell.execute("echo $DEPLOY_ENV")
        print(f"DEPLOY_ENV: {env_result.stdout}")

        # Изменение размера окна терминала PTY
        await shell.resize(120, 40)

        # Обычный conn.run() работает параллельно по тому же SSH-соединению
        uptime = await conn.run("uptime")
        print(f"Host uptime: {uptime.stdout.strip()}")


def sync_shell_example() -> None:
    """Синхронная работа со stateful shell-сессией."""
    with (
        Connection.from_uri("ssh://user:pass@example.com").to_sync() as conn,
        conn.open_shell() as shell,
    ):
        shell.execute("cd /tmp")
        res = shell.execute("pwd")
        print(f"Sync shell cwd: {res.stdout}")


if __name__ == "__main__":
    asyncio.run(async_shell_example())
