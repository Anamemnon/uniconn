"""
Мониторинг долгоживущих процессов через ScreenPool.

Демонстрирует:
- ScreenPool.from_file() — загрузка конфигурации из YAML
- pool.start() — запуск команд в detached screen-сессиях
- pool.poll_status() — периодический опрос статуса сессий
- pool.poll_logs() — потоковое чтение логов
- pool.wait_all() — ожидание завершения с результатами
- pool.stop_all() — остановка всех сессий

Требуется GNU screen на удалённом хосте.
"""

import asyncio

from uniconn import ScreenPool


# ─── Мониторинг статуса уже запущенных сессий ──────────────────────

async def monitor_status():
    """Запуск сессий и опрос их статуса в цикле."""
    pool = ScreenPool.from_file("screen_pool_config.yaml")
    async with pool:
        await pool.start("tail -f /var/log/nginx/access.log")
        await pool.start("sysbench --test=cpu --cpu-max-prime=20000 run")

        # Печатаем статус всех сессий каждые poll_interval секунд
        checks = 0
        async for event in pool.poll_status(interval=5.0):
            state = "alive" if event.alive else f"done (exit={event.exit_code})"
            print(f"[{event.session_id}] {state}, pid={event.pid}")
            checks += 1
            if checks >= 10:  # два полных цикла опроса
                break

        results = await pool.wait_all(timeout=3600.0)
        for session_id, result in results.items():
            print(f"{session_id}: exit={result.exit_code}, log={result.local_log_path}")


# ─── Потоковое чтение логов ────────────────────────────────────────

async def stream_logs():
    """Чтение логов сессий в реальном времени (polling + tail)."""
    async with ScreenPool("ssh://admin@server", max_screens=4) as pool:
        await pool.start("tail -f /var/log/syslog")

        async for event in pool.poll_logs(interval=2.0):
            print(f"[{event.session_id}] {event.line.rstrip()}")
            # Прерывание по Ctrl+C: cleanup остановит все сессии


# ─── Ad-hoc запуск с ограничением по времени ───────────────────────

async def ad_hoc():
    """Запуск N воркеров и ожидание с таймаутом (force kill по таймауту)."""
    async with ScreenPool("ssh://admin@server", max_screens=4) as pool:
        for i in range(4):
            await pool.start(f"python3 long_running_task.py --worker {i}")

        results = await pool.wait_all(timeout=600.0)
        failed = {sid: r for sid, r in results.items() if r.exit_code != 0}
        print(f"Завершено: {len(results)}, с ошибками: {len(failed)}")


# ─── Принудительная остановка ──────────────────────────────────────

async def stop_everything():
    """Остановка всех сессий: graceful (Ctrl+C), затем force kill."""
    async with ScreenPool("ssh://admin@server") as pool:
        await pool.start("stress-ng --cpu 4")
        await pool.stop_all(graceful=True)


# ─── Main ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== Monitor Status ===")
    asyncio.run(monitor_status())
