# examples/security_and_hooks.py
"""Пример возможностей безопасности и удобства (v0.4.0).

Демонстрирует:
- Контекстные менеджеры рабочей директории `conn.cd()` и переменных `conn.env()`
- Lifecycle-хуки (`before_run`, `after_run`, `on_error`) для аудита команд
- Режим `sensitive=True` для защиты секретов в логах и исключениях
- Безопасное повышение привилегий `sudo=True` (с передачей пароля через закрытый stdin)
- Режим `dry_run=True` для безопасной проверки сценариев
- Чтение и запись файлов напрямую из памяти (`write_file`, `read_file`) и `run_bytes()`
"""

import asyncio
import tempfile
from pathlib import Path

from uniconn import Connection, Result


async def main() -> None:
    """Запустить демонстрацию возможностей v0.4.0 на локальном транспорте."""
    audit_log: list[str] = []

    def audit_before(command: str, host: str | None, kwargs: dict) -> None:
        audit_log.append(f"[START] host={host} cmd={command!r} cwd={kwargs.get('cwd')}")

    def audit_after(result: Result) -> None:
        audit_log.append(
            f"[DONE]  cmd={result.command!r} exit={result.exit_code} "
            f"time={result.duration:.3f}s repr={result!r}"
        )

    async with Connection.from_uri(
        "local://",
        before_run=[audit_before],
        after_run=[audit_after],
    ) as conn:
        with tempfile.TemporaryDirectory() as tmpdir:
            # 1. Контекстные менеджеры cd() и env() + файловые операции в памяти
            async with conn.cd(tmpdir), conn.env(APP_ENV="production", SERVICE_PORT="8080"):
                await conn.files.write_file(
                    "app.conf",
                    "env: production\nport: 8080\n",
                    mode=0o600,
                )
                content = await conn.files.read_file("app.conf")
                print("Содержимое app.conf:", content.strip())

                res = await conn.run(
                    ["python3", "-c", "import os; print(os.getcwd(), os.environ['APP_ENV'])"]
                )
                print("Выполнение в контексте cd/env:", res.stdout.strip())

            # 2. Режим sensitive=True (маскирует вывод в repr(Result) и ExecutionError)
            secret_res = await conn.run("echo api_token_xyz987", sensitive=True)
            print("Реальный токен доступен в коде:", secret_res.stdout.strip())
            print("Безопасный repr(Result):", repr(secret_res))

            # 3. Байтовый режим run_bytes() для бинарных потоков
            raw_bytes = await conn.run_bytes(
                ["python3", "-c", "import sys; sys.stdout.buffer.write(b'\\x00\\x01\\x02\\xff')"]
            )
            print("Получено сырых байт через run_bytes():", len(raw_bytes), raw_bytes)

            # 4. Режим dry_run=True на уровне отдельного вызова
            dry_target = Path(tmpdir) / "never_created.txt"
            await conn.run(["touch", str(dry_target)], dry_run=True)
            print("Файл создан при dry_run=True? ->", dry_target.exists())

            # 5. Готовые пресеты uniconn.hooks (v0.6.0)
            from uniconn.hooks import (
                allowlist_hook,
                audit_log_hook,
                blocklist_hook,
                metrics_collector_hook,
            )

            audit_jsonl = Path(tmpdir) / "audit.jsonl"
            conn.add_hook("before_run", allowlist_hook(["echo", "python3"]))
            conn.add_hook("before_run", blocklist_hook())
            conn.add_hook("after_run", audit_log_hook(audit_jsonl))
            metrics = metrics_collector_hook().attach(conn)

            await conn.run(["echo", "audited command"])
            print("Собранные метрики (MetricsCollector):", metrics.to_dict())
            print("Запись в audit.jsonl:", audit_jsonl.read_text(encoding="utf-8").strip())

    print("\nЖурнал аудита (Lifecycle Hooks):")
    for entry in audit_log:
        print(" ", entry)


if __name__ == "__main__":
    asyncio.run(main())
