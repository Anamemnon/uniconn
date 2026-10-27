# benchmarks/overhead_bench.py
"""Компактный скрипт измерения задержек ядра uniconn: CommandPipeline, EventLoopPortal, DirectorySynchronizer.

Предотвращает деградацию производительности (регрессии задержки), замеряет перцентили
(Avg, P50, P90, P95, P99, Ops/sec), валидирует SLA-пороги с флагом --check-thresholds
и поддерживает экспорт отчётов в JSON и YAML.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import platform
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from uniconn import Connection, __version__
from uniconn.core.bridge import EventLoopPortal
from uniconn.core.pipeline import CommandPipeline, CommandRequest
from uniconn.result import Result
from uniconn.services.files import DirectorySynchronizer

# Базовые SLA-пороги задержки (в микросекундах, µs) для предотвращения регрессий
DEFAULT_THRESHOLDS_US: dict[str, float] = {
    "CommandPipeline": 1000.0,  # диспетчеризация полного конвейера middleware < 1.0 ms (1000 µs)
    "EventLoopPortal": 2000.0,  # roundtrip синхронного моста < 2.0 ms (2000 µs)
    "DirectorySynchronizer": 50_000.0,  # вычисление дельты дерева директорий < 50 ms (50000 µs)
}


@dataclass(slots=True)
class BenchmarkStats:
    """Статистика задержек выполнения бенчмарка."""

    name: str
    iterations: int
    min_us: float
    avg_us: float
    p50_us: float
    p90_us: float
    p95_us: float
    p99_us: float
    max_us: float
    ops_per_sec: float
    threshold_p95_us: float | None = None
    passed_sla: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Преобразовать статистику в сериализуемый словарь."""
        return asdict(self)


def _compute_stats(
    name: str,
    latencies_ns: list[int],
    threshold_p95_us: float | None = None,
) -> BenchmarkStats:
    """Вычислить агрегированные статистики задержек из наносекундных замеров."""
    if not latencies_ns:
        return BenchmarkStats(
            name=name,
            iterations=0,
            min_us=0.0,
            avg_us=0.0,
            p50_us=0.0,
            p90_us=0.0,
            p95_us=0.0,
            p99_us=0.0,
            max_us=0.0,
            ops_per_sec=0.0,
            threshold_p95_us=threshold_p95_us,
            passed_sla=True,
        )

    latencies_us = sorted(ns / 1000.0 for ns in latencies_ns)
    n = len(latencies_us)

    def percentile(p: float) -> float:
        idx = max(0, min(n - 1, math.ceil((p / 100.0) * n) - 1))
        return latencies_us[idx]

    min_us = latencies_us[0]
    max_us = latencies_us[-1]
    avg_us = sum(latencies_us) / n
    p50_us = percentile(50.0)
    p90_us = percentile(90.0)
    p95_us = percentile(95.0)
    p99_us = percentile(99.0)

    total_seconds = sum(latencies_ns) / 1_000_000_000.0
    ops_per_sec = (n / total_seconds) if total_seconds > 0 else 0.0

    passed_sla = True
    if threshold_p95_us is not None:
        passed_sla = p95_us <= threshold_p95_us

    return BenchmarkStats(
        name=name,
        iterations=n,
        min_us=round(min_us, 2),
        avg_us=round(avg_us, 2),
        p50_us=round(p50_us, 2),
        p90_us=round(p90_us, 2),
        p95_us=round(p95_us, 2),
        p99_us=round(p99_us, 2),
        max_us=round(max_us, 2),
        ops_per_sec=round(ops_per_sec, 1),
        threshold_p95_us=threshold_p95_us,
        passed_sla=passed_sla,
    )


async def bench_command_pipeline(
    iterations: int = 500,
    warmup: int = 50,
    threshold_p95_us: float | None = DEFAULT_THRESHOLDS_US.get("CommandPipeline"),
) -> BenchmarkStats:
    """Измерить чистые накладные расходы конвейера CommandPipeline."""
    conn = Connection.from_uri("local://localhost", retry_attempts=1)
    pipeline = CommandPipeline(conn)
    request = CommandRequest(raw_command="true", command="true", exec_command="true")

    async def _mock_target(_req: CommandRequest) -> Result:
        return Result(exit_code=0, stdout="", stderr="", duration=0.0, command="true")

    # Warmup
    for _ in range(warmup):
        await pipeline.execute(request, _mock_target)

    latencies_ns: list[int] = []
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        await pipeline.execute(request, _mock_target)
        t1 = time.perf_counter_ns()
        latencies_ns.append(t1 - t0)

    return _compute_stats("CommandPipeline", latencies_ns, threshold_p95_us)


def bench_event_loop_portal(
    iterations: int = 500,
    warmup: int = 50,
    threshold_p95_us: float | None = DEFAULT_THRESHOLDS_US.get("EventLoopPortal"),
) -> BenchmarkStats:
    """Измерить задержку перехода между синхронным потоком и EventLoopPortal."""
    portal = EventLoopPortal("BenchPortal")

    async def _noop_async() -> int:
        return 42

    # Warmup
    for _ in range(warmup):
        portal.call(_noop_async())

    latencies_ns: list[int] = []
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        portal.call(_noop_async())
        t1 = time.perf_counter_ns()
        latencies_ns.append(t1 - t0)

    return _compute_stats("EventLoopPortal", latencies_ns, threshold_p95_us)


async def bench_directory_synchronizer(
    iterations: int = 50,
    warmup: int = 5,
    threshold_p95_us: float | None = DEFAULT_THRESHOLDS_US.get("DirectorySynchronizer"),
) -> BenchmarkStats:
    """Измерить скорость обхода и расчёта диффа DirectorySynchronizer."""
    with tempfile.TemporaryDirectory(prefix="uniconn_bench_src_") as src_dir:
        src_path = Path(src_dir)
        # Создаём тестовое дерево из 60 файлов в поддиректориях
        for i in range(5):
            sub = src_path / f"sub_{i}"
            sub.mkdir(exist_ok=True)
            for j in range(12):
                f = sub / f"file_{j}.txt"
                f.write_text(f"content-{i}-{j}\n", encoding="utf-8")

        conn = Connection.from_uri("local://localhost")
        synchronizer = DirectorySynchronizer(conn)

        # Warmup
        for _ in range(warmup):
            await synchronizer.sync(
                local_dir=src_dir,
                remote_dir="/tmp/uniconn_bench_dst",
                dry_run=True,
                exclude=["*.tmp", "*.pyc"],
            )

        latencies_ns: list[int] = []
        for _ in range(iterations):
            t0 = time.perf_counter_ns()
            await synchronizer.sync(
                local_dir=src_dir,
                remote_dir="/tmp/uniconn_bench_dst",
                dry_run=True,
                exclude=["*.tmp", "*.pyc"],
            )
            t1 = time.perf_counter_ns()
            latencies_ns.append(t1 - t0)

    return _compute_stats("DirectorySynchronizer", latencies_ns, threshold_p95_us)


def run_all_benchmarks(
    iterations: int = 500,
    warmup: int = 50,
    thresholds: dict[str, float] | None = None,
) -> list[BenchmarkStats]:
    """Запустить все замеры задержек ядра uniconn."""
    thresh = thresholds or DEFAULT_THRESHOLDS_US

    # Синхронный замер EventLoopPortal
    portal_stats = bench_event_loop_portal(
        iterations=iterations,
        warmup=warmup,
        threshold_p95_us=thresh.get("EventLoopPortal"),
    )

    async def _run_async() -> tuple[BenchmarkStats, BenchmarkStats]:
        pipe_res = await bench_command_pipeline(
            iterations=iterations,
            warmup=warmup,
            threshold_p95_us=thresh.get("CommandPipeline"),
        )
        sync_iters = max(10, min(100, iterations // 5))
        sync_warmup = max(2, min(10, warmup // 5))
        sync_res = await bench_directory_synchronizer(
            iterations=sync_iters,
            warmup=sync_warmup,
            threshold_p95_us=thresh.get("DirectorySynchronizer"),
        )
        return pipe_res, sync_res

    pipe_stats, sync_stats = asyncio.run(_run_async())
    return [pipe_stats, portal_stats, sync_stats]


def render_table(results: list[BenchmarkStats]) -> str:
    """Сформировать форматированную текстовую таблицу с результатами."""
    sep = "=" * 110
    divider = "-" * 110
    header = (
        f"{'Benchmark':<24} {'Iters':>7} {'Avg (µs)':>10} {'P50 (µs)':>10} "
        f"{'P95 (µs)':>10} {'P99 (µs)':>10} {'Ops/sec':>11} {'SLA (µs)':>10} {'Status':>8}"
    )

    lines = [
        sep,
        f"uniconn Performance Benchmark (v{__version__}) - Python {platform.python_version()}",
        sep,
        header,
        divider,
    ]

    for r in results:
        sla_str = f"{r.threshold_p95_us:.1f}" if r.threshold_p95_us is not None else "N/A"
        status_str = "PASS" if r.passed_sla else "FAIL"
        line = (
            f"{r.name:<24} {r.iterations:>7} {r.avg_us:>10.2f} {r.p50_us:>10.2f} "
            f"{r.p95_us:>10.2f} {r.p99_us:>10.2f} {r.ops_per_sec:>11.1f} {sla_str:>10} {status_str:>8}"
        )
        lines.append(line)

    lines.append(sep)
    return "\n".join(lines)


def export_json(results: list[BenchmarkStats], path: str | Path) -> None:
    """Экспортировать результаты измерений в JSON."""
    data = {
        "version": __version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "timestamp": time.time(),
        "results": [r.to_dict() for r in results],
        "all_passed": all(r.passed_sla for r in results),
    }
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")


def export_yaml(results: list[BenchmarkStats], path: str | Path) -> None:
    """Экспортировать результаты измерений в YAML."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)

    # Попытка использовать pyyaml при наличии
    try:
        import yaml  # type: ignore[import-untyped]

        payload = {
            "version": __version__,
            "python": platform.python_version(),
            "platform": platform.platform(),
            "timestamp": time.time(),
            "results": [r.to_dict() for r in results],
            "all_passed": all(r.passed_sla for r in results),
        }
        content = yaml.dump(payload, sort_keys=False, default_flow_style=False)
        p.write_text(content, encoding="utf-8")
        return
    except ImportError:
        pass

    # Чистый fallback без внешних зависимостей
    lines = [
        f"version: {__version__!r}",
        f"python: {platform.python_version()!r}",
        f"platform: {platform.platform()!r}",
        f"timestamp: {time.time()}",
        f"all_passed: {'true' if all(r.passed_sla for r in results) else 'false'}",
        "results:",
    ]
    for r in results:
        lines.append(f"  - name: {r.name!r}")
        lines.append(f"    iterations: {r.iterations}")
        lines.append(f"    avg_us: {r.avg_us}")
        lines.append(f"    p50_us: {r.p50_us}")
        lines.append(f"    p95_us: {r.p95_us}")
        lines.append(f"    p99_us: {r.p99_us}")
        lines.append(f"    ops_per_sec: {r.ops_per_sec}")
        lines.append(f"    threshold_p95_us: {r.threshold_p95_us}")
        lines.append(f"    passed_sla: {'true' if r.passed_sla else 'false'}")

    p.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    """Точка входа CLI для запуска бенчмарка."""
    parser = argparse.ArgumentParser(
        description=(
            "Benchmark latency overhead for uniconn core subsystems "
            "(CommandPipeline, EventLoopPortal, DirectorySynchronizer)"
        ),
    )
    parser.add_argument(
        "--iterations",
        "-n",
        type=int,
        default=500,
        help="Number of iterations for micro-benchmarks (default: 500)",
    )
    parser.add_argument(
        "--warmup",
        "-w",
        type=int,
        default=50,
        help="Number of warmup iterations (default: 50)",
    )
    parser.add_argument(
        "--json",
        metavar="PATH",
        type=str,
        default=None,
        help="Export benchmark metrics to JSON file",
    )
    parser.add_argument(
        "--yaml",
        metavar="PATH",
        type=str,
        default=None,
        help="Export benchmark metrics to YAML file",
    )
    parser.add_argument(
        "--check-thresholds",
        action="store_true",
        help="Verify P95 latencies against SLA budgets and exit with code 1 on regression",
    )
    parser.add_argument(
        "--threshold-pipeline",
        type=float,
        default=None,
        help="Override P95 SLA threshold for CommandPipeline in µs",
    )
    parser.add_argument(
        "--threshold-portal",
        type=float,
        default=None,
        help="Override P95 SLA threshold for EventLoopPortal in µs",
    )
    parser.add_argument(
        "--threshold-sync",
        type=float,
        default=None,
        help="Override P95 SLA threshold for DirectorySynchronizer in µs",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Do not print ASCII table to stdout",
    )

    args = parser.parse_args(argv)

    thresholds = dict(DEFAULT_THRESHOLDS_US)
    if args.threshold_pipeline is not None:
        thresholds["CommandPipeline"] = args.threshold_pipeline
    if args.threshold_portal is not None:
        thresholds["EventLoopPortal"] = args.threshold_portal
    if args.threshold_sync is not None:
        thresholds["DirectorySynchronizer"] = args.threshold_sync

    results = run_all_benchmarks(
        iterations=args.iterations,
        warmup=args.warmup,
        thresholds=thresholds,
    )

    if not args.quiet:
        print(render_table(results))

    if args.json:
        export_json(results, args.json)
        if not args.quiet:
            print(f"Metrics saved to JSON: {args.json}")

    if args.yaml:
        export_yaml(results, args.yaml)
        if not args.quiet:
            print(f"Metrics saved to YAML: {args.yaml}")

    if args.check_thresholds:
        failed = [r for r in results if not r.passed_sla]
        if failed:
            if not args.quiet:
                print(
                    f"\n[ERROR] SLA threshold breached by {len(failed)} benchmark(s):",
                    file=sys.stderr,
                )
                for f in failed:
                    print(
                        f"  - {f.name}: P95 = {f.p95_us:.2f} µs (limit = {f.threshold_p95_us} µs)",
                        file=sys.stderr,
                    )
            return 1
        if not args.quiet:
            print("\n[OK] All benchmarks within acceptable SLA latency thresholds.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
