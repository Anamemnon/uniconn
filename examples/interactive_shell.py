"""Интерактивные PTY-сессии (ShellSession) и декларативные диалоги (expect).

Демонстрирует:
- Открытие stateful PTY shell-сессии через conn.open_shell() (SSH, Local, Telnet, Serial)
- Сохранение состояния (cd, export) между вызовами shell.execute()
- Декларативный автомат интерактивных диалогов conn.expect() и shell.expect()
- Изменение размера терминала через shell.resize(cols, rows)
- Синхронную обёртку SyncShellSession через SyncConnection / .to_sync()
"""

from __future__ import annotations

import asyncio
import tempfile

from uniconn import Connection, SyncConnection

# ─── Справочный пример для удалённого SSH-сервера ───────────────────


async def ssh_interactive_shell_example() -> None:
    """Асинхронная работа со stateful PTY-сессией поверх SSH-подключения."""
    async with (
        Connection.from_uri("ssh://admin:env://SSH_PASS@node-01") as conn,
        await conn.open_shell(term_type="xterm", term_size=(120, 40)) as shell,
    ):
        await shell.execute("cd /var/log && export LOG_ENV=prod")
        pwd_res = await shell.execute("pwd && echo $LOG_ENV")
        print(pwd_res.text)


# ─── Самодостаточная локальная демонстрация (open_shell + expect) ───


async def async_local_shell_and_expect() -> None:
    """Локальная демонстрация stateful ShellSession и автомата диалогов expect()."""
    with tempfile.TemporaryDirectory(prefix="uniconn_shell_") as tmpdir:
        async with Connection.local() as conn:
            print("=== 1. Stateful PTY ShellSession (сохранение cd, export и shell.expect) ===")
            async with await conn.open_shell(term_type="xterm", term_size=(100, 30)) as shell:
                await shell.execute(f"cd {tmpdir}")
                pwd_res = await shell.execute("pwd")
                print(f"Рабочая директория в сессии: {pwd_res.text}")

                await shell.execute("export DEPLOY_STAGE=canary")
                env_res = await shell.execute("echo $DEPLOY_STAGE")
                print(f"Переменная DEPLOY_STAGE: {env_res.text}")

                await shell.resize(120, 40)

                print("\n=== 2. Декларативный диалог shell.expect() ===")
                interactive_py = (
                    "import sys; "
                    "sys.stdout.write('Target' + ' env: '); sys.stdout.flush(); "
                    "env = sys.stdin.readline().strip(); "
                    "sys.stdout.write('Proceed' + ' (y/n): '); sys.stdout.flush(); "
                    "ans = sys.stdin.readline().strip(); "
                    "print(f'Configured {env} ({ans})')"
                )
                expect_res = await shell.expect(
                    ["python3", "-c", interactive_py],
                    patterns={
                        r"Target env:": "production\n",
                        r"Proceed \(y/n\):": "y\n",
                    },
                    timeout=5.0,
                )
                print(f"Результат диалога expect(): {expect_res.lines[-1]}")


def sync_local_shell() -> None:
    """Синхронная работа с PTY-оболочкой через SyncConnection."""
    print("\n=== 3. Синхронная PTY-сессия (SyncShellSession) ===")
    with SyncConnection.local() as conn, conn.open_shell() as shell:
        shell.execute("export SYNC_SHELL_OK=1")
        res = shell.execute("echo $SYNC_SHELL_OK")
        print(f"Sync shell variable: {res.text}")


async def main() -> None:
    """Точка входа примера."""
    await async_local_shell_and_expect()
    sync_local_shell()


if __name__ == "__main__":
    asyncio.run(main())
