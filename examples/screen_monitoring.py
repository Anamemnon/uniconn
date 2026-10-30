"""Мониторинг долгоживущих фоновых процессов через BackgroundPool.

Демонстрирует:
- BackgroundPool.from_file() — загрузка конфигурации пула и правил логов из YAML
- pool.start() — запуск отсоединяемых фоновых задач (auto: tmux -> screen -> nohup)
- pool.poll_status() — периодический опрос статуса фоновых сессий
- pool.poll_logs() — потоковое чтение логов в реальном времени
- pool.wait_all() и pool.stop_all() — ожидание завершения и корректная остановка
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

from uniconn import BackgroundPool, BackgroundPoolConfig, LogConfig

# ─── Справочные примеры для удалённого SSH-сервера ──────────────────


async def ssh_monitor_status_from_yaml() -> None:
    """Запуск сессий из YAML-конфигурации и опрос их статуса на SSH-хосте."""
    config_path = Path(__file__).with_name("screen_pool_config.yaml")
    async with BackgroundPool.from_file(config_path) as pool:
        await pool.start("tail -f /var/log/nginx/access.log")
        await pool.start("sysbench --test=cpu --cpu-max-prime=20000 run")

        checks = 0
        async for event in pool.poll_status(interval=5.0):
            state = "alive" if event.alive else f"done (exit={event.exit_code})"
            print(f"[{event.session_id}] {state}, pid={event.pid}")
            checks += 1
            if checks >= 4:
                break

        results = await pool.wait_all(timeout=3600.0)
        for session_id, result in results.items():
            print(f"{session_id} ({result.backend}): exit={result.exit_code}, log={result.local_log_path}")


async def ssh_stream_background_logs() -> None:
    """Потоковое чтение логов фоновых задач в реальном времени."""
    async with BackgroundPool("ssh://admin@server", backend="auto", max_sessions=4) as pool:
        await pool.start("tail -f /var/log/syslog")
        async for event in pool.poll_logs(interval=2.0):
            print(f"[{event.session_id}] {event.line.rstrip()}")


# ─── Самодостаточная локальная демонстрация (nohup на local://) ─────


async def main() -> None:
    """Локальная демонстрация BackgroundPool (валидация YAML-конфига + запуск задачи через nohup)."""
    config_path = Path(__file__).with_name("screen_pool_config.yaml")
    parsed_cfg = BackgroundPoolConfig.from_file(config_path)
    print("=== 1. Загружен BackgroundPoolConfig из screen_pool_config.yaml ===")
    print(
        f"URI={parsed_cfg.uri}, backend={parsed_cfg.backend}, "
        f"max_sessions={parsed_cfg.max_sessions}, rules={len(parsed_cfg.log_config.rules)}"
    )

    print("\n=== 2. Запуск и ожидание фоновой сессии на local:// (backend='nohup') ===")
    if sys.platform == "win32":
        matched_rule = parsed_cfg.log_config.match_rule("sysbench --test=cpu run")
        pool_from_cfg = BackgroundPool.from_config(parsed_cfg)
        print(f"Пул сконфигурирован: backend={pool_from_cfg.backend}, matched_rule={matched_rule is not None}")
        return

    with tempfile.TemporaryDirectory(prefix="uniconn_bg_logs_") as tmp_logs:
        async with BackgroundPool(
            "local://",
            backend="nohup",
            max_sessions=2,
            poll_interval=0.1,
            log_config=LogConfig(local_dir=tmp_logs),
        ) as pool:
            cmd = "python3 -c \"print('background-worker-started'); print('background-worker-done')\""
            session = await pool.start(cmd)
            print(f"Запущена сессия: id={session.session_id}, backend={session.backend_name}")

            results = await pool.wait_all(timeout=10.0)
            for sid, res in results.items():
                print(f"Результат сессии {sid}: exit_code={res.exit_code}, backend={res.backend}")


if __name__ == "__main__":
    asyncio.run(main())

