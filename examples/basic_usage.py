"""Базовое использование uniconn.

Демонстрирует:
- Подключение через URI, Connection.local(), ConnectionConfig и словарь
- Разрешение секретов через SecretResolver (env:// и file:// с ?default=)
- Async и Sync API (Connection и SyncConnection)
- Выполнение команд (run, run_commands, run_script) и потоковый вывод (stream)
- Клонирование подключений (copy, with_overrides)
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from uniconn import Connection, ConnectionConfig, ExecutionError, SyncConnection, TimeoutError

# ─── Async API (SSH / Удалённые хосты) ──────────────────────────────


async def async_ssh_basic() -> None:
    """Базовое async подключение по SSH (с разрешением пароля из переменной окружения)."""
    # В продакшне: ssh://user:env://SSH_PASS@host:22?ssh_config=true
    async with Connection.from_uri("ssh://admin:env://SSH_PASS?default=secret@node-01") as conn:
        result = await conn.run(["uptime"])
        print(f"Exit code: {result.exit_code}, duration: {result.duration:.2f}s")
        print(f"Output: {result.text}")


async def async_with_timeout_and_errors() -> None:
    """Выполнение с таймаутом и перехватом ExecutionError."""
    async with Connection.local(retry_attempts=1) as conn:
        try:
            await conn.run(["python3", "-c", "import time; time.sleep(10)"], timeout=0.1)
        except TimeoutError:
            print("Команда ожидаемо прервана по таймауту!")

        try:
            await conn.run(["python3", "-c", "import sys; sys.exit(2)"], raise_on_error=True)
        except ExecutionError as exc:
            print(f"Перехвачен ExecutionError (exit_code={exc.exit_code})")


# ─── Sync API (SyncConnection / .to_sync()) ─────────────────────────


def sync_basic() -> None:
    """Базовое синхронное подключение через SyncConnection.local() и .to_sync()."""
    # Вариант для SSH: with SyncConnection.from_uri("ssh://user@host") as conn:
    with SyncConnection.local() as conn:
        result = conn.run(["python3", "-c", "print('Hello from SyncConnection!')"])
        print(f"Sync result: {result.text}")

    config = ConnectionConfig(transport="local", host="localhost", timeout=30.0)
    with Connection.from_config(config).to_sync() as sync_conn:
        res = sync_conn.run(["echo", "Configured local connection"])
        print(f"From config: {res.text}")


# ─── Выполнение скриптов, потоков и клонирование ────────────────────


async def local_full_walkthrough() -> None:
    """Самодостаточная демонстрация ключевых возможностей Connection на local://."""
    uri = "local://?timeout=30&token=env://DEMO_TOKEN?default=fallback_token"
    async with Connection.from_uri(uri) as conn:
        print(f"Resolved option from env://: {conn.config.options.get('token')}")

        # 1. Пакетное выполнение нескольких команд
        results = await conn.run_commands(
            [
                ["echo", "step-1: prepare"],
                ["echo", "step-2: verify"],
            ]
        )
        print("run_commands:", [r.text for r in results])

        # 2. Выполнение локального скрипта через run_script()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False, encoding="utf-8") as tmp:
            tmp.write("#!/bin/sh\necho \"Script arg1=$1\"\n")
            script_path = Path(tmp.name)

        try:
            script_res = await conn.run_script(script_path, args=["production"])
            print(f"run_script output: {script_res.text}")
        finally:
            script_path.unlink(missing_ok=True)

        # 3. Построчный стриминг вывода
        streamed: list[str] = []
        async for line in conn.stream(["python3", "-c", "for i in range(3): print(f'line-{i}')"]):
            streamed.append(line.strip())
        print(f"Streamed lines: {streamed}")

        # 4. Клонирование подключения с переопределением параметров
        dry_clone = conn.copy(dry_run=True, timeout=15.0)
        async with dry_clone:
            dry_res = await dry_clone.run(["rm", "-rf", "/nonexistent"])
            print(f"Cloned dry_run connection executed safely: ok={dry_res.ok}")


async def main() -> None:
    """Точка входа примера (выполняется локально без внешних серверов)."""
    print("=== 1. Sync API ===")
    sync_basic()

    print("\n=== 2. Async Walkthrough (run_commands, run_script, stream, copy) ===")
    await local_full_walkthrough()

    print("\n=== 3. Timeouts & Error Handling ===")
    await async_with_timeout_and_errors()


if __name__ == "__main__":
    asyncio.run(main())
