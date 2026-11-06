"""Реактивный конвейер логов, триггеры аппаратных аномалий и Hardware Watchdog (SCT / BBU / BMC).

Демонстрирует возможности Этапа 1 (Hardware & Telecom SCT Readiness):
1. Загрузку декларативного YAML-профиля базовой станции (examples/telecom_bs_sct_diagnostics.yaml)
   со встроенными пресетами правил (kernel_panic, hardware_errors, telecom_bs) и кастомными LogWatchRule.
2. Реактивный перехват аварий в потоках логов (PatternTriggerHandler):
   - захват предшествующих строк из кольцевого буфера (context_before);
   - мгновенный вызов колбэка on_match (например, для снятия телеметрии BMC при аварии);
   - раннее прерывание цикла нагрузки через diag.check_abort() или автоматический выброс
     HardwareFaultDetectedError при выходе из DiagnosticSession после упаковки .tar.gz архива.
3. Детектор тихого зависания потоков (Stream Silence Watchdog: max_silence_seconds + on_stall):
   - обнаружение глухого зависания UART/SOL-консоли или демона без вывода Kernel Panic.
4. Единый хронологический лог (timeline.jsonl):
   - сквозная корреляция строк разных потоков (kind="line"), срабатываний правил (kind="match"),
     зависаний (kind="stall") и маркеров (kind="marker", включая diag.snapshot()).
5. Полный паритет с синхронным API (SyncConnection.diagnostic_session).
"""

from __future__ import annotations

import asyncio
import json
import tarfile
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from uniconn import (
    BUILTIN_WATCH_RULES,
    Connection,
    DiagnosticConfig,
    HardwareFaultDetectedError,
    LogMatchEvent,
    LogWatchRule,
    StallEvent,
    SyncConnection,
)

# ─── 1. Боевой сценарий: Термоциклирование BBU/RRU (SCT) по SSH и UART ────────


async def telecom_sct_thermal_chamber_scenario() -> None:
    """Боевой шаблон SCT-теста базовой станции с мониторингом CPRI/PTP/PLL и защитой от зависаний."""
    yaml_profile = Path(__file__).with_name("telecom_bs_sct_diagnostics.yaml")

    def on_critical_anomaly(event: LogMatchEvent) -> None:
        print(
            f"[ALERT][{event.severity.upper()}] Правило {event.rule_name!r} в потоке "
            f"{event.session_id!r}: {event.matched_line}"
        )

    def on_uart_hang(stall: StallEvent) -> None:
        print(
            f"[WATCHDOG] Поток {stall.session_id!r} замолчал на {stall.silence_seconds}s "
            f"(команда: {stall.command!r})"
        )

    async with (
        Connection.from_uri("ssh://root:env://BBU_PASS@bbu-du-slot01") as conn,
        conn.diagnostic_session(
            config=yaml_profile,
            on_match=on_critical_anomaly,
            on_stall=on_uart_hang,
        ) as diag,
    ):
        for step, target_temp in enumerate((-40, 25, 55, 70), start=1):
            await diag.emit_custom_log(
                "sct_chamber", f"Step {step}: ramping thermal chamber to {target_temp}C"
            )
            await conn.run(f"sct-runner --profile full-mimo-load --temp {target_temp}")
            await diag.snapshot(f"temp_{target_temp}C")
            # Проверяем, не зафиксировал ли конвейер логов фатальную ошибку (PLL unlock / CPRI LOS / AER)
            diag.check_abort()


# ─── 2. Самодостаточная локальная демонстрация всех возможностей Этапа 1 ──────


async def demo_async_reactive_diagnostics(root: Path) -> None:
    """Локальная демонстрация реактивных триггеров, кольцевого буфера, Watchdog и timeline.jsonl."""
    print("=== 1. Инспекция встроенных пресетов правил и YAML-профиля SCT ===")
    for preset_name, rules in BUILTIN_WATCH_RULES.items():
        if preset_name != "all":
            rule_names = [r.name for r in rules]
            print(f"  Пресет {preset_name!r} ({len(rules)} правил): {rule_names}")

    yaml_path = Path(__file__).with_name("telecom_bs_sct_diagnostics.yaml")
    sct_cfg = DiagnosticConfig.from_file(yaml_path)
    print(
        f"  Загружен профиль {yaml_path.name}: "
        f"watch_rules={len(sct_cfg.watch_rules)}, "
        f"streams={[(s.name, s.max_silence_seconds) for s in sct_cfg.streams]}"
    )

    print("\n=== 2. Реактивный перехват аварии (PLL Unlock) + Silence Watchdog + timeline.jsonl ===")
    archive_path = root / "sct_fault_bundle.tar.gz"
    matches_log: list[LogMatchEvent] = []
    stalls_log: list[StallEvent] = []

    async with Connection.local() as conn:

        async def simulated_streams(
            command: str, timeout: float | None = None, **kwargs: Any
        ) -> AsyncIterator[str]:
            if "ttyS0" in command:
                yield "U-Boot SPL 2024.04 (BBU-SoC)\n"
                yield "Loading FPGA bitstream from QSPI...\n"
                # Имитируем глухое зависание UART-консоли при инициализации FPGA
                await asyncio.sleep(5.0)
                return

            yield "[  100.110] o-ran-l1: eCPRI link 0 up (25G SFP28)\n"
            yield "[  100.125] o-ran-l1: PTP slave locked to grandmaster (offset +4ns)\n"
            yield "[  100.140] o-ran-l1: PA_TEMP_WARN: 84C on TX antenna branch 2\n"
            yield "[  100.155] o-ran-l1: PLL unlocked on BBU clock domain 0\n"
            await asyncio.sleep(5.0)

        conn.stream = simulated_streams  # type: ignore[method-assign]

        try:
            async with conn.diagnostic_session(
                streams=[
                    {"name": "l1_phy", "command": "journalctl -u o-ran-l1 -f"},
                    {
                        "name": "uart_console",
                        "command": "cat /dev/ttyS0",
                        "max_silence_seconds": 0.06,
                    },
                ],
                watch_rules=[
                    "telecom_bs",
                    LogWatchRule(
                        name="pa_temp_warn",
                        pattern=r"PA_TEMP_WARN:\s*\d+C",
                        severity="warning",
                        abort_on_match=False,
                        context_lines=2,
                    ),
                ],
                on_match=lambda m: matches_log.append(m),
                on_stall=lambda s: stalls_log.append(s),
                local_dir=root / "work_async",
                archive_path=archive_path,
                fsync_realtime=False,
                gather_pre_facts=False,
                gather_post_facts=False,
            ) as diag:
                await diag.emit_custom_log("test_runner", "Starting RF carrier stress test")
                for _ in range(100):
                    if len(diag.matches) >= 2 and len(diag.stalled_streams) >= 1:
                        break
                    await asyncio.sleep(0.02)
                await diag.snapshot("on_fault_state")
        except HardwareFaultDetectedError as exc:
            print(f"  Перехвачено исключение HardwareFaultDetectedError: {exc}")
            if exc.match is not None:
                print(
                    f"  Первая фатальная причина: rule={exc.match.rule_name!r}, "
                    f"stream={exc.match.session_id!r}"
                )
                print(
                    "  Предшествующий контекст из кольцевого буфера (context_before):"
                )
                for ctx_line in exc.match.context_before:
                    print(f"    | {ctx_line}")

    assert diag.result is not None
    print(f"  Всего срабатываний правил: {len(matches_log)} (warning + critical)")
    print(f"  Зависшие потоки (Watchdog): {diag.result.stalled_streams}")
    print(f"  Архив диагностики сохранён до выброса исключения: {archive_path.exists()}")

    with tarfile.open(archive_path, "r:gz") as tf:
        timeline_f = tf.extractfile("timeline.jsonl")
        assert timeline_f is not None
        entries = [
            json.loads(line)
            for line in timeline_f.read().decode("utf-8").splitlines()
        ]
        print(f"\n  Содержимое единого хронологического лога timeline.jsonl ({len(entries)} событий):")
        for entry in entries:
            print(
                f"    #{entry['seq']:02d} [+{entry['elapsed_ms']:6.1f}ms] "
                f"[{entry['stream']}:{entry['kind']}] {entry['text']}"
            )


def demo_sync_watchdog_and_early_abort(root: Path) -> None:
    """Демонстрация синхронного API SyncConnection.diagnostic_session и раннего check_abort()."""
    print("\n=== 3. Синхронный сценарий (SyncConnection) с ранним прерыванием diag.check_abort() ===")
    sync_archive = root / "sync_edac_abort.tar.gz"
    edac_script = (
        "import time; "
        "print('[1.0] Memory controller MC0 initialized', flush=True); "
        "print('[2.0] Scrubbing rank 0 dimm 1', flush=True); "
        "print('[3.0] EDAC MC0: 1 UE memory read error on CPU_SrcID#0_Ha#0', flush=True); "
        "time.sleep(2.0)"
    )

    with SyncConnection.local() as sync_conn:
        try:
            with sync_conn.diagnostic_session(
                streams=[
                    {
                        "name": "edac_monitor",
                        "command": f'python3 -c "{edac_script}"',
                    }
                ],
                watch_rules="hardware_errors",
                local_dir=root / "work_sync",
                archive_path=sync_archive,
                fsync_realtime=False,
                gather_pre_facts=False,
                gather_post_facts=False,
            ) as sync_diag:
                for _step in range(1, 50):
                    if sync_diag.matches:
                        # Досрочно прерываем цикл теста внутри блока with при обнаружении аппаратного сбоя
                        sync_diag.check_abort()
                    import time

                    time.sleep(0.02)
        except HardwareFaultDetectedError as exc:
            print(f"  Синхронный тест досрочно остановлен по правилу: {exc.match.rule_name if exc.match else ''}")
            print(f"  Итоговый архив создан: {sync_archive.exists()}")


async def main() -> None:
    """Запустить локальную демонстрацию реактивного конвейера логов и Hardware Watchdog."""
    with tempfile.TemporaryDirectory(prefix="uniconn_reactive_sct_") as tmpdir:
        root = Path(tmpdir)
        await demo_async_reactive_diagnostics(root)
        await asyncio.to_thread(demo_sync_watchdog_and_early_abort, root)


if __name__ == "__main__":
    asyncio.run(main())
