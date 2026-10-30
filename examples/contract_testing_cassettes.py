"""Контрактное тестирование, запись/воспроизведение кассет (use_cassette) и сравнение (diff).

Демонстрирует:
- Запись взаимодействий (run, files) в YAML-кассету через conn.use_cassette(..., mode="all")
- Детерминированное воспроизведение без реального выполнения (mode="none" и ReplayTransport)
- Групповую запись/воспроизведение для пула хостов через pool.use_cassette()
- Вычисление расхождений между двумя кассетами через cassette.diff() (CassetteDiffReport)
- Примеры использования pytest-плагина (@pytest.mark.uniconn_cassette)
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from uniconn import Cassette, Connection, ConnectionPool, RecordedExecInteraction

# ─── Справочный пример использования pytest-плагина в тестах ────────
#
# import pytest
# from uniconn import Connection
#
# @pytest.mark.uniconn_cassette(mode="once")
# async def test_deploy_contract():
#     async with Connection.from_uri("ssh://admin@node-01") as conn:
#         res = await conn.run("uname -s")
#         assert res.ok
# ────────────────────────────────────────────────────────────────────


async def main() -> None:
    """Самодостаточная демонстрация записи, воспроизведения и сравнения кассет."""
    with tempfile.TemporaryDirectory(prefix="uniconn_cassette_") as tmpdir:
        root = Path(tmpdir)
        cassette_path = root / "node_session.yaml"
        sample_file = root / "release.txt"

        print("=== 1. Запись взаимодействий в YAML-кассету (mode='all') ===")
        async with Connection.local() as conn, conn.use_cassette(
            cassette_path,
            mode="all",
            normalize_temp=True,
            mask_secrets=True,
        ) as recorded:
            res = await conn.run(["echo", "contract-v1"])
            await conn.files.write_file(str(sample_file), "version=1.0.0\n")
            read_back = await conn.files.read_file(str(sample_file))
            print(f"Recorded run={res.text!r}, file={str(read_back).strip()!r}")
            print(f"Всего записано эпизодов в кассету: {recorded.total_interactions}")

        print("\n=== 2. Воспроизведение из кассеты в строгом режиме (mode='none') ===")
        # Удаляем файл на диске, чтобы убедиться, что чтение идёт из кассеты без обращения к ОС
        sample_file.unlink(missing_ok=True)
        async with Connection.local() as conn, conn.use_cassette(
            cassette_path,
            mode="none",
        ):
            replayed_run = await conn.run(["echo", "contract-v1"])
            replayed_file = await conn.files.read_file(str(sample_file))
            print(f"Replayed from cassette: run={replayed_run.text!r}, file={str(replayed_file).strip()!r}")

        print("\n=== 3. Групповые кассеты для пула хостов (pool.use_cassette) ===")
        fleet_cassette_dir = root / "fleet_cassettes"
        hosts = [
            Connection.local().with_overrides(host="web-1"),
            Connection.local().with_overrides(host="web-2"),
        ]
        async with ConnectionPool(hosts) as pool, pool.use_cassette(fleet_cassette_dir, mode="all") as by_host:
            pool_results = await pool.map(["echo", "fleet-ok"])
            print(
                f"Записаны кассеты для хостов {list(by_host.keys())}: "
                f"результаты={[r.text for r in pool_results]}"
            )

        print("\n=== 4. Сравнение двух кассет (cassette.diff -> CassetteDiffReport) ===")
        baseline = Cassette(
            transport="ssh",
            host="web-1",
            interactions=[
                RecordedExecInteraction(command="uptime", exit_code=0, stdout="up 10 days\n"),
                RecordedExecInteraction(command="nginx -v", exit_code=0, stdout="nginx/1.24.0\n"),
            ],
        )
        candidate = Cassette(
            transport="ssh",
            host="web-1",
            interactions=[
                RecordedExecInteraction(command="uptime", exit_code=0, stdout="up 10 days\n"),
                RecordedExecInteraction(command="nginx -v", exit_code=0, stdout="nginx/1.26.0\n"),
                RecordedExecInteraction(command="systemctl is-active nginx", exit_code=0, stdout="active\n"),
            ],
        )
        diff_report = baseline.diff(candidate)
        print(
            f"Cassette diff: identical={diff_report.is_identical}, "
            f"added={diff_report.added_count}, modified={diff_report.modified_count}"
        )


if __name__ == "__main__":
    asyncio.run(main())
