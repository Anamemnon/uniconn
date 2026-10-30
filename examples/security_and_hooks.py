"""Безопасность, Lifecycle-хуки, SecretResolver и OpenTelemetry трейсинг.

Демонстрирует:
- Регистрацию хуков через conn.add_hook("before_run" | "after_run" | "on_error", ...)
- Готовые пресеты: allowlist_hook, blocklist_hook, audit_log_hook, metrics_collector_hook
- Распределённую трассировку OpenTelemetry через otel_tracing_hook и InMemoryTracer
- Режим sensitive=True (маскирование в repr(Result), to_dict() и логах)
- Контекстные менеджеры рабочей директории conn.cd() и переменных conn.env()
- Режим dry_run=True и бинарный ввод-вывод run_bytes()
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from typing import Any

from uniconn import (
    Connection,
    InMemoryTracer,
    Result,
    allowlist_hook,
    audit_log_hook,
    blocklist_hook,
    metrics_collector_hook,
    otel_tracing_hook,
)


async def main() -> None:
    """Локальная демонстрация механизмов безопасности, хуков и OpenTelemetry."""
    audit_events: list[str] = []

    def on_before(command: str, host: str | None, kwargs: dict[str, Any]) -> None:
        audit_events.append(f"[BEFORE] host={host} cmd={command!r} cwd={kwargs.get('cwd')}")

    def on_after(result: Result) -> None:
        audit_events.append(f"[AFTER]  cmd={result.command!r} exit={result.exit_code} repr={result!r}")

    async with Connection.local() as conn:
        conn.add_hook("before_run", on_before)
        conn.add_hook("after_run", on_after)

        # Подключаем OpenTelemetry-трейсер в памяти для записи всех операций (run, files)
        tracer = InMemoryTracer()
        otel = otel_tracing_hook(tracer=tracer, service_name="security-demo", mask_secrets=True)
        otel.attach(conn)

        with tempfile.TemporaryDirectory(prefix="uniconn_sec_") as tmpdir:
            # 1. Контекстные менеджеры cd() и env() + файловые операции conn.files
            async with conn.cd(tmpdir), conn.env(APP_ENV="production", SERVICE_PORT="8080"):
                await conn.files.write_file("app.conf", "env: production\nport: 8080\n", mode=0o600, atomic=True)
                content = await conn.files.read_file("app.conf")
                print("Содержимое app.conf:", str(content).strip())

                res = await conn.run(["python3", "-c", "import os; print(os.getcwd(), os.environ['APP_ENV'])"])
                print("Выполнение в контексте cd/env:", res.text)

            # 2. Режим sensitive=True (маскирует вывод в repr(Result), to_dict() и спанах)
            secret_res = await conn.run(["echo", "api_token_xyz987"], sensitive=True)
            print("Реальный токен в коде:", secret_res.text)
            print("Маскированный repr(Result):", repr(secret_res))
            print("Маскированный to_dict()['stdout']:", secret_res.to_dict()["stdout"])

            # 3. Сырой бинарный вывод run_bytes()
            raw_bytes = await conn.run_bytes(
                ["python3", "-c", "import sys; sys.stdout.buffer.write(b'\\x00\\x01\\x02\\xff')"]
            )
            print("Получено сырых байт через run_bytes():", len(raw_bytes), raw_bytes)

            # 4. Безопасный прогон dry_run=True
            dry_target = Path(tmpdir) / "never_created.txt"
            await conn.run(["touch", str(dry_target)], dry_run=True)
            print("Файл создан при dry_run=True? ->", dry_target.exists())

            # 5. Встроенные пресеты хуков (allowlist, blocklist, audit_log, metrics)
            audit_jsonl = Path(tmpdir) / "audit.jsonl"
            conn.add_hook("before_run", allowlist_hook(["echo", "python3", "touch"]))
            conn.add_hook("before_run", blocklist_hook())
            conn.add_hook("after_run", audit_log_hook(audit_jsonl))
            metrics = metrics_collector_hook().attach(conn)

            await conn.run(["echo", "audited command"])
            print("Собранные метрики (MetricsCollector):", metrics.to_dict()["total_runs"])
            print("Записано спанов OpenTelemetry:", len(tracer.spans))

    print("\nЖурнал перехватчиков (Lifecycle Hooks):")
    for entry in audit_events[:4]:
        print(" ", entry)


if __name__ == "__main__":
    asyncio.run(main())
