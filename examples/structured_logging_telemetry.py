# examples/structured_logging_telemetry.py
"""Пример структурированного логирования (structlog) и телеметрии для Grafana / ClickHouse / InfluxDB.

Демонстрирует:
- Настройку JSONL-вывода через ``configure_logging(fmt="json")``
- Привязку сквозного контекста через ``log_context()`` и ``bind_log_context()``
- Использование ``structured_log_hook()`` и ``metrics_collector_hook()``
- Автоматическое маскирование секретов при ``sensitive=True``
"""

from __future__ import annotations

import asyncio
import io

from uniconn import (
    Connection,
    bind_log_context,
    clear_log_context,
    configure_logging,
    get_struct_logger,
    log_context,
    metrics_collector_hook,
    structured_log_hook,
)


async def main() -> None:
    """Запустить демонстрацию структурированного логирования и сбора метрик."""
    stream = io.StringIO()
    logger = configure_logging(level="DEBUG", fmt="json", stream=stream)
    slog = get_struct_logger("uniconn.demo")

    # Глобальные теги процесса (например, имя сервиса и окружение)
    bind_log_context(service="fleet-agent", env="production")

    async with Connection.from_uri("local://", logger=logger) as conn:
        metrics = metrics_collector_hook().attach(conn)
        conn.add_hook(
            "after_run",
            structured_log_hook(
                logger=logger,
                tags={"datacenter": "eu-central-1", "sink": "clickhouse"},
            ),
        )

        async with log_context(batch_id="batch-2026-10-22"):
            slog.info("batch.started", targets=1)
            await conn.run(["echo", "healthcheck_ok"])
            await conn.run("echo super_secret_api_key", sensitive=True)
            slog.info("batch.completed", metrics=metrics.to_dict())

    clear_log_context()

    print("=== Сгенерированный поток JSONL (для Grafana Loki / ClickHouse / InfluxDB) ===")
    for line in stream.getvalue().splitlines():
        print(line)


if __name__ == "__main__":
    asyncio.run(main())
