"""Нагрузочное тестирование (NVMe / ОЗУ) по SSH с отказоустойчивым сбором статических и рантайм-логов.

Демонстрирует:
- Декларативное описание статических (до/после теста) и потоковых (во время теста) логов:
  1) В YAML-файле (examples/stress_test_diagnostics.yaml -> Профиль NVMe fio)
  2) Непосредственно в Python-словаре dict (-> Профиль ОЗУ и CPU stress-ng)
- Непрерывный стриминг (dmesg -w, iostat -xz 1, vmstat 1) и периодический опрос
  одноразовых команд по интервалу (interval + timestamp_lines=True)
- Сохранение всех логов на хосте пользователя в реальном времени с os.fsync() (fsync_realtime=True),
  гарантирующее сохранность данных даже при зависании (Kernel Panic) или ребуте сервера
- Автоматическое сравнение состояния хоста до и после нагрузки (facts_diff.json) и упаковку в .tar.gz
"""

from __future__ import annotations

import asyncio
import json
import tarfile
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from uniconn import Connection, DiagnosticConfig, PingResult

# ─── 1. Боевой сценарий: Стресс-тест NVMe-диска (fio) с YAML-профилем ─────────


async def ssh_nvme_fio_stress_from_yaml() -> None:
    """Запуск нагрузочного теста NVMe (fio) по SSH со сбором логов по YAML-профилю."""
    yaml_profile = Path(__file__).with_name("stress_test_diagnostics.yaml")

    async with (
        Connection.from_uri("ssh://root:env://SSH_PASS@storage-node-01") as conn,
        conn.diagnostic_session(config=yaml_profile) as diag,
    ):
        await diag.emit_custom_log("fio_runner", "Starting random 4k RW stress test on /dev/nvme0n1")

        # Запуск нагрузочного теста fio (пока в фоне пишутся dmesg, iostat и nvme smart-log)
        fio_cmd = (
            "fio --name=nvme_randrw --filename=/dev/nvme0n1 --direct=1 "
            "--rw=randrw --bs=4k --ioengine=libaio --iodepth=64 "
            "--numjobs=4 --runtime=120 --time_based --group_reporting --output-format=json"
        )
        fio_res = await conn.run(fio_cmd, timeout=180.0, raise_on_error=False)
        await diag.emit_custom_log("fio_runner", f"fio completed with exit_code={fio_res.exit_code}")

        # Промежуточный снимок статических фактов сразу после пиковой нагрузки
        await diag.snapshot("after_fio_peak")

    if diag.result is not None:
        print(f"Host survived: {diag.result.host_survived}, archive: {diag.result.archive_path}")


# ─── 2. Боевой сценарий: Стресс-тест ОЗУ и CPU (stress-ng) со словарём dict ───


RAM_STRESS_DIAGNOSTIC_DICT: dict[str, Any] = {
    "local_dir": "./diagnostics/ram_stress",
    "archive_format": "tar.gz",
    "fsync_realtime": True,
    "facts": {
        "include_builtin": True,
        "commands": {
            "free_bytes": "free -b",
            "numa_hardware": "numactl --hardware",
            "oom_events": "dmesg | grep -i -E 'out of memory|killed process' || true",
        },
        "files": {
            "meminfo": "/proc/meminfo",
            "vmstat_counters": "/proc/vmstat",
        },
    },
    "streams": [
        {"name": "dmesg_live", "command": "dmesg -w", "timestamp_lines": True},
        {"name": "vmstat_live", "command": "vmstat -SM 1", "timestamp_lines": True},
        {
            "name": "memavailable_poll",
            "command": "grep -E 'MemAvailable|Committed_AS|AnonPages' /proc/meminfo",
            "interval": 2.0,
            "timestamp_lines": True,
        },
    ],
}


async def ssh_ram_stress_from_dict() -> None:
    """Запуск нагрузочного теста ОЗУ (stress-ng) по SSH с конфигурацией из Python-словаря."""
    async with (
        Connection.from_uri("ssh://root:env://SSH_PASS@compute-node-01") as conn,
        conn.diagnostic_session(config=RAM_STRESS_DIAGNOSTIC_DICT) as diag,
    ):
        await diag.emit_custom_log("stress_ng", "Starting RAM/VM stressor (85% memory, 60s)")
        res = await conn.run(
            "stress-ng --vm 4 --vm-bytes 85% --vm-keep --verify --timeout 60s --metrics-brief",
            timeout=90.0,
            raise_on_error=False,
        )
        await diag.emit_custom_log("stress_ng", res.stdout)
        await diag.snapshot("post_memory_pressure")


# ─── 3. Самодостаточная локальная демонстрация (YAML + dict + Crash Survival) ─


async def main() -> None:
    """Локальная демонстрация профилей нагрузочного тестирования и сохранения логов при аварии."""
    print("=== 1. Загрузка декларативного YAML-профиля (stress_test_diagnostics.yaml) ===")
    yaml_path = Path(__file__).with_name("stress_test_diagnostics.yaml")
    nvme_cfg = DiagnosticConfig.from_file(yaml_path)
    print(
        f"Загружен профиль NVMe: commands={len(nvme_cfg.facts.commands)}, "
        f"files={len(nvme_cfg.facts.files)}, tools={len(nvme_cfg.facts.tools)}, "
        f"streams={[s.name for s in nvme_cfg.streams]}"
    )
    smart_poll = next(s for s in nvme_cfg.streams if s.name == "nvme_smart_poll")
    print(f"Периодический опрос: name={smart_poll.name}, interval={smart_poll.interval}s")

    with tempfile.TemporaryDirectory(prefix="uniconn_stress_diag_") as tmpdir:
        root = Path(tmpdir)

        print("\n=== 2. Выполнение нагрузочного теста со сбором статических и рантайм-логов (из dict) ===")
        state_file = root / "nvme_wear_counter.txt"
        state_file.write_text("media_errors=0\ntemperature_c=41\n", encoding="utf-8")

        stream_py = (
            "import time; "
            "print('nvme0n1: r_iops=125000 w_iops=84000 await=0.18ms', flush=True); "
            "time.sleep(0.05); "
            "print('nvme0n1: r_iops=131000 w_iops=88000 await=0.21ms', flush=True)"
        )
        poll_py = "print('SMART temp=54C spare=100% media_errors=0', flush=True)"

        local_profile_dict: dict[str, Any] = {
            "local_dir": str(root / "run_normal"),
            "archive_path": str(root / "nvme_stress_bundle.tar.gz"),
            "archive_format": "tar.gz",
            "fsync_realtime": True,
            "facts": {
                "include_builtin": True,
                "commands": {
                    "workload_profile": "python3 -c \"print('fio-randrw-4k')\"",
                },
                "files": {
                    "nvme_counters": str(state_file),
                },
            },
            "streams": [
                {
                    "name": "nvme_iostat",
                    "command": f"python3 -c \"{stream_py}\"",
                    "timestamp_lines": True,
                },
                {
                    "name": "smart_temp_poll",
                    "command": f"python3 -c \"{poll_py}\"",
                    "interval": 0.1,
                    "timestamp_lines": True,
                },
            ],
        }

        async with Connection.local() as conn:
            async with conn.diagnostic_session(config=local_profile_dict) as diag:
                await diag.emit_custom_log("workload", "Phase 1: Warmup NVMe queue depth=32")
                # Имитация выполнения нагрузочного теста и нагрева диска
                for _ in range(30):
                    if all(c.lines_collected >= 1 for c in diag._stream_collectors):
                        break
                    await asyncio.sleep(0.02)

                state_file.write_text("media_errors=0\ntemperature_c=58\n", encoding="utf-8")
                snap = await diag.snapshot("peak_load")
                await diag.emit_custom_log("workload", f"Phase 2: Peak load on {snap.hostname}")

            assert diag.result is not None
            assert diag.facts_diff is not None
            print(f"Тест завершён: host_survived={diag.result.host_survived}")
            print(f"Обнаружен дрейф параметров после нагрузки: has_drift={diag.facts_diff.has_drift}")
            print("Изменившиеся поля:", list(diag.facts_diff.drifted_hosts.get("post", {}).keys()))

            with tarfile.open(diag.result.archive_path or "", "r:gz") as tf:
                print("Артефакты в архиве:", sorted(tf.getnames()))
                sample_stream = tf.extractfile("streams/smart_temp_poll.log")
                if sample_stream is not None:
                    first_line = sample_stream.read().decode("utf-8").splitlines()[0]
                    print("Пример строки периодического опроса с таймстампом:", first_line)

        print("\n=== 3. Сценарий зависания / ребута хоста во время нагрузки (Crash Survival) ===")
        crash_archive = root / "crash_recovery_bundle.tar.gz"
        async with Connection.local() as crash_conn:
            orig_ping = crash_conn.ping
            crashed = {"flag": False}

            async def simulated_panic_stream(
                command: Any, timeout: float | None = None, **kwargs: Any
            ) -> AsyncIterator[str]:
                yield "[   42.101] nvme nvme0: controller is down; will reset\n"
                yield "[   42.512] Kernel panic - not syncing: Fatal hardware error\n"
                crashed["flag"] = True
                raise RuntimeError("SSH session disconnected: host rebooted or hung")

            async def simulated_dead_ping(timeout: float = 5.0) -> PingResult:
                if crashed["flag"]:
                    return PingResult(
                        host="localhost",
                        alive=False,
                        latency_ms=timeout * 1000,
                        transport="local",
                        error="Host unreachable after kernel panic",
                    )
                return await orig_ping(timeout=timeout)

            crash_conn.stream = simulated_panic_stream  # type: ignore[method-assign]
            crash_conn.ping = simulated_dead_ping  # type: ignore[method-assign]

            async with crash_conn.diagnostic_session(
                streams=[{"name": "dmesg", "command": "dmesg -w", "timestamp_lines": True}],
                local_dir=root / "run_crash",
                archive_path=crash_archive,
                fsync_realtime=True,
            ) as crash_diag:
                collector = crash_diag._stream_collectors[0]
                for _ in range(50):
                    if collector.lines_collected >= 2 or not collector.is_running:
                        break
                    await asyncio.sleep(0.02)

            assert crash_diag.result is not None
            with tarfile.open(crash_archive, "r:gz") as tf:
                manifest_f = tf.extractfile("manifest.json")
                dmesg_f = tf.extractfile("streams/dmesg.log")
                assert manifest_f is not None and dmesg_f is not None
                manifest = json.loads(manifest_f.read().decode("utf-8"))
                saved_dmesg = dmesg_f.read().decode("utf-8")
                print(
                    f"Статус после аварии: host_survived={manifest['host_survived']}, "
                    f"has_pre_facts={manifest['has_pre_facts']}"
                )
                print("Спасённый на хосте пользователя лог перед ребутом:\n" + saved_dmesg.strip())


if __name__ == "__main__":
    asyncio.run(main())
