# tests/unit/core/test_benchmarks.py
"""Unit-тесты для модуля измерения задержек benchmarks/overhead_bench.py."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.overhead_bench import (
    _compute_stats,
    bench_command_pipeline,
    bench_directory_synchronizer,
    bench_event_loop_portal,
    export_json,
    export_yaml,
    main,
    render_table,
    run_all_benchmarks,
)


def test_compute_stats_percentiles_and_thresholds() -> None:
    """_compute_stats корректно рассчитывает min, max, avg, P50, P95, ops_per_sec и соблюдение SLA."""
    # 100 замеров от 1000 нс (1 мкс) до 100000 нс (100 мкс)
    latencies_ns = [i * 1000 for i in range(1, 101)]
    stats_pass = _compute_stats("TestComp", latencies_ns, threshold_p95_us=120.0)
    assert stats_pass.iterations == 100
    assert stats_pass.min_us == 1.0
    assert stats_pass.max_us == 100.0
    assert stats_pass.p50_us == 50.0
    assert stats_pass.p95_us == 95.0
    assert stats_pass.passed_sla is True

    # Тот же набор с порогом P95 = 80 мкс (должен упасть SLA)
    stats_fail = _compute_stats("TestComp", latencies_ns, threshold_p95_us=80.0)
    assert stats_fail.p95_us == 95.0
    assert stats_fail.passed_sla is False


@pytest.mark.asyncio
async def test_bench_command_pipeline_smoke() -> None:
    """bench_command_pipeline успешно замеряет накладные расходы конвейера."""
    stats = await bench_command_pipeline(iterations=10, warmup=2, threshold_p95_us=50_000.0)
    assert stats.name == "CommandPipeline"
    assert stats.iterations == 10
    assert stats.avg_us > 0.0
    assert stats.passed_sla is True


def test_bench_event_loop_portal_smoke() -> None:
    """bench_event_loop_portal успешно замеряет задержку EventLoopPortal."""
    stats = bench_event_loop_portal(iterations=10, warmup=2, threshold_p95_us=50_000.0)
    assert stats.name == "EventLoopPortal"
    assert stats.iterations == 10
    assert stats.avg_us > 0.0
    assert stats.passed_sla is True


@pytest.mark.asyncio
async def test_bench_directory_synchronizer_smoke() -> None:
    """bench_directory_synchronizer успешно замеряет задержку вычисления дельты директорий."""
    stats = await bench_directory_synchronizer(iterations=3, warmup=1, threshold_p95_us=100_000.0)
    assert stats.name == "DirectorySynchronizer"
    assert stats.iterations == 3
    assert stats.avg_us > 0.0
    assert stats.passed_sla is True


def test_benchmarks_export_json_and_yaml(tmp_path: Path) -> None:
    """export_json и export_yaml генерируют валидные файлы с метриками."""
    res = run_all_benchmarks(iterations=5, warmup=1)
    assert len(res) == 3

    table_text = render_table(res)
    assert "CommandPipeline" in table_text
    assert "EventLoopPortal" in table_text
    assert "DirectorySynchronizer" in table_text

    json_path = tmp_path / "bench.json"
    yaml_path = tmp_path / "bench.yaml"

    export_json(res, json_path)
    assert json_path.exists()
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["version"] == "0.16.1"
    assert len(data["results"]) == 3

    export_yaml(res, yaml_path)
    assert yaml_path.exists()
    yaml_text = yaml_path.read_text(encoding="utf-8")
    assert "results:" in yaml_text
    assert "CommandPipeline" in yaml_text


def test_benchmarks_cli_main(tmp_path: Path) -> None:
    """main CLI обрабатывает аргументы, флаги экспорта и пороги задержки."""
    json_out = str(tmp_path / "report.json")
    yaml_out = str(tmp_path / "report.yaml")

    # Успешный запуск с допустимыми порогами
    rc = main(
        [
            "--iterations",
            "5",
            "--warmup",
            "1",
            "--json",
            json_out,
            "--yaml",
            yaml_out,
            "--check-thresholds",
            "--threshold-pipeline",
            "50000.0",
            "--threshold-portal",
            "50000.0",
            "--threshold-sync",
            "200000.0",
            "--quiet",
        ]
    )
    assert rc == 0
    assert Path(json_out).exists()
    assert Path(yaml_out).exists()

    # Запуск с заведомо нарушенным порогом должен вернуть код возврата 1
    rc_fail = main(
        [
            "--iterations",
            "3",
            "--warmup",
            "1",
            "--check-thresholds",
            "--threshold-pipeline",
            "0.001",
            "--quiet",
        ]
    )
    assert rc_fail == 1
