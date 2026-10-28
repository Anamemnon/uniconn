# tests/unit/releases/test_v090_features.py
"""Приёмочные unit-тесты для релиза uniconn v0.9.0.

Покрывают:
- CircuitBreaker (CLOSED -> OPEN -> HALF_OPEN -> CLOSED) и CircuitOpenError
- RateLimiter (асинхронный Token Bucket)
- Встраивание CircuitBreakerMiddleware и RateLimitMiddleware в CommandPipeline
- Изоляцию сбоев по хостам в ConnectionPool / SyncConnectionPool и защиту SSHSessionPool
- Измерение задержки ping() -> PingResult (Connection, SyncConnection, ConnectionPool, SyncConnectionPool)
- Выполнение локальных скриптов run_script() (Connection, SyncConnection, ConnectionPool, SyncConnectionPool)
- Поиск расхождений системных характеристик diff_facts() -> FactsDiffReport
- Новые команды и флаги CLI: uniconn ping, uniconn facts --diff, uniconn exec-script
- Песочницу дашборда /api/v090
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from examples.dashboard.server import _execute_pool_sandbox, _execute_v090_sandbox
from uniconn import (
    CircuitBreaker,
    CircuitBreakerMiddleware,
    CircuitOpenError,
    CircuitState,
    Connection,
    ConnectionError,
    ConnectionPool,
    FactsDiffReport,
    HostFacts,
    PingResult,
    RateLimiter,
    RateLimitMiddleware,
    SSHSessionPool,
    TimeoutError,
    diff_facts,
)
from uniconn.cli import CliRunner, create_cli_app


class TestCircuitBreakerAndRateLimiter:
    """Тесты базовых примитивов отказоустойчивости CircuitBreaker и RateLimiter."""

    @pytest.mark.asyncio
    async def test_circuit_breaker_state_machine_lifecycle(self) -> None:
        """Проверить переходы CLOSED -> OPEN -> HALF_OPEN -> CLOSED иHALF_OPEN -> OPEN."""
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.05, half_open_max_calls=1)
        assert cb.state == CircuitState.CLOSED
        assert cb.allow_request() is True

        cb.record_failure()
        assert cb.state == CircuitState.CLOSED
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert cb.allow_request() is False

        with pytest.raises(CircuitOpenError) as exc_info:
            cb.check_or_raise(host="node-01", command="uptime")
        assert exc_info.value.host == "node-01"
        assert exc_info.value.command == "uptime"
        assert exc_info.value.remaining_seconds > 0

        # Ждём истечения recovery_timeout -> переход в HALF_OPEN
        await asyncio.sleep(0.06)
        assert cb.state == CircuitState.HALF_OPEN
        cb.check_or_raise(host="node-01", command="probe-1")

        # Вторая параллельная пробная команда в HALF_OPEN отклоняется при half_open_max_calls=1
        with pytest.raises(CircuitOpenError):
            cb.check_or_raise(host="node-01", command="probe-2")

        # Ошибка в HALF_OPEN мгновенно возвращает прерыватель в OPEN
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

        # После повторного таймаута успешный вызов закрывает прерыватель в CLOSED
        await asyncio.sleep(0.06)
        assert cb.state == CircuitState.HALF_OPEN
        cb.check_or_raise(host="node-01", command="probe-ok")
        cb.record_success()
        assert cb.state == CircuitState.CLOSED
        assert cb.failure_count == 0
        snap = cb.to_dict()
        assert snap["state"] == "closed"

    def test_circuit_breaker_validation_and_reset(self) -> None:
        """Проверить валидацию параметров конструктора CircuitBreaker и метод reset()."""
        with pytest.raises(ValueError):
            CircuitBreaker(failure_threshold=0)
        with pytest.raises(ValueError):
            CircuitBreaker(recovery_timeout=0.0)
        with pytest.raises(ValueError):
            CircuitBreaker(half_open_max_calls=0)

        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=60.0)
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        cb.reset()
        assert cb.state == CircuitState.CLOSED

    def test_circuit_breaker_thread_safety_half_open_admissions(self) -> None:
        """В состоянии HALF_OPEN ровно half_open_max_calls параллельных запросов разрешаются."""
        import concurrent.futures
        import time

        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.04, half_open_max_calls=2)
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

        time.sleep(0.05)
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(cb.allow_request) for _ in range(50)]
            results = [f.result() for f in futures]

        assert results.count(True) == 2
        assert results.count(False) == 48

    def test_circuit_breaker_thread_safety_concurrent_failures(self) -> None:
        """Параллельные вызовы record_failure() атомарно увеличивают failure_count без race condition."""
        import concurrent.futures

        cb = CircuitBreaker(failure_threshold=100, recovery_timeout=60.0)
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(cb.record_failure) for _ in range(50)]
            concurrent.futures.wait(futures)

        assert cb.failure_count == 50

    @pytest.mark.asyncio
    async def test_rate_limiter_token_bucket_throttling(self) -> None:
        """Проверить взрывную ёмкость (burst) и троттлинг RateLimiter."""
        with pytest.raises(ValueError):
            RateLimiter(rate=0)
        with pytest.raises(ValueError):
            RateLimiter(rate=10, burst=0)

        limiter = RateLimiter(rate=50.0, burst=2)
        w1 = await limiter.acquire()
        w2 = await limiter.acquire()
        w3 = await limiter.acquire()
        assert w1 == 0.0
        assert w2 == 0.0
        assert w3 >= 0.01

        limiter.reset()
        snap = limiter.to_dict()
        assert snap["rate"] == 50.0
        assert snap["burst"] == 2.0


class TestPipelineAndPoolResilience:
    """Тесты интеграции CircuitBreaker и RateLimiter в CommandPipeline и пулы."""

    @pytest.mark.asyncio
    async def test_connection_pipeline_includes_resilience_middlewares(self) -> None:
        """Проверить наличие CircuitBreakerMiddleware и RateLimitMiddleware в конвейере."""
        conn = Connection.from_uri(
            "local://?rate_limit=100&circuit_breaker_threshold=2",
            retry_attempts=1,
        )
        assert conn.rate_limiter is not None
        assert conn.rate_limiter.rate == 100.0
        assert conn.circuit_breaker is not None
        assert conn.circuit_breaker.failure_threshold == 2
        mw_types = [type(m) for m in conn.pipeline.middlewares]
        assert CircuitBreakerMiddleware in mw_types
        assert RateLimitMiddleware in mw_types

        # Ненулевой код возврата команды НЕ должен размыкать CircuitBreaker
        res = await conn.run("exit 42", raise_on_error=False)
        assert res.exit_code == 42
        assert conn.circuit_breaker.failure_count == 0
        await conn.close()

    @pytest.mark.asyncio
    async def test_connection_circuit_breaker_trips_on_transport_errors(self) -> None:
        """Проверить размыкание CircuitBreaker при сетевых ошибках транспорта."""
        conn = Connection.from_uri(
            "local://",
            retry_attempts=1,
            circuit_breaker=CircuitBreaker(failure_threshold=2, recovery_timeout=30.0),
        )
        assert conn.circuit_breaker is not None

        conn._transport.run = AsyncMock(side_effect=ConnectionError("Network down"))
        with pytest.raises(ConnectionError):
            await conn.run("echo 1")
        assert conn.circuit_breaker.failure_count == 1
        assert conn.circuit_breaker.state == CircuitState.CLOSED

        with pytest.raises(ConnectionError):
            await conn.run("echo 2")
        assert conn.circuit_breaker.state == CircuitState.OPEN

        # Третий вызов мгновенно падает с CircuitOpenError без обращения к транспорту
        conn._transport.run.reset_mock()
        with pytest.raises(CircuitOpenError):
            await conn.run("echo 3")
        conn._transport.run.assert_not_called()
        await conn.close()

    @pytest.mark.asyncio
    async def test_connection_pool_per_host_circuit_breaker_isolation(self) -> None:
        """Проверить, что разомкнутый CircuitBreaker одного хоста не блокирует здоровые хосты пула."""
        good_conn = Connection.from_uri("local://?host=good-node", retry_attempts=1)
        bad_conn = Connection.from_uri("local://?host=bad-node", retry_attempts=1)
        bad_conn._transport.run = AsyncMock(side_effect=TimeoutError("Timed out"))

        pool = ConnectionPool(
            [good_conn, bad_conn],
            circuit_breaker=True,
            failure_threshold=1,
            recovery_timeout=60.0,
            rate_limit=200.0,
        )
        assert pool.rate_limiter is not None
        assert len(pool.circuit_breakers) == 2

        res1 = await pool.map_safe("echo ok")
        assert isinstance(res1["good-node"], object)
        assert isinstance(res1["bad-node"], TimeoutError)
        assert pool.circuit_breakers["bad-node"].state == CircuitState.OPEN
        assert pool.circuit_breakers["good-node"].state == CircuitState.CLOSED

        # При втором вызове bad-node мгновенно возвращает CircuitOpenError, а good-node работает
        res2 = await pool.map_safe("echo ok")
        assert isinstance(res2["bad-node"], CircuitOpenError)
        assert getattr(res2["good-node"], "text", "") == "ok"
        await pool.close()

    @pytest.mark.asyncio
    async def test_ssh_session_pool_resilience(self) -> None:
        """Проверить работу RateLimiter и CircuitBreaker в SSHSessionPool."""
        mock_conn = AsyncMock()
        mock_conn.run = AsyncMock(side_effect=ConnectionError("SSH channel error"))
        mock_conn.close = AsyncMock()

        with patch("uniconn._session_pool.Connection.from_uri", return_value=mock_conn):
            pool = SSHSessionPool(
                "ssh://admin@bastion",
                rate_limit=100.0,
                circuit_breaker=True,
                failure_threshold=1,
                recovery_timeout=60.0,
            )
            assert pool.rate_limiter is not None
            assert pool.circuit_breaker is not None

            with pytest.raises(ConnectionError):
                await pool.run("uptime")
            assert pool.circuit_breaker.state == CircuitState.OPEN

            with pytest.raises(CircuitOpenError):
                await pool.run("uptime")
            await pool.close()


class TestPingRunScriptAndDiffFacts:
    """Тесты методов ping(), run_script() и diff_facts() (async + sync)."""

    @pytest.mark.asyncio
    async def test_ping_single_and_pool_async_and_sync(self) -> None:
        """Проверить измерение задержки ping() на одиночном подключении и пуле."""
        async with Connection.from_uri("local://") as conn:
            pr = await conn.ping()
            assert isinstance(pr, PingResult)
            assert pr.alive is True
            assert bool(pr) is True
            assert pr.latency_ms >= 0.0
            assert pr.transport == "local"
            assert pr.to_dict()["alive"] is True

        # Проверка обработки сбоя транспорта в ping()
        dead_conn = Connection.from_uri("local://?host=dead-host")
        dead_conn._transport.ping = AsyncMock(side_effect=ConnectionError("Host unreachable"))
        dead_pr = await dead_conn.ping()
        assert dead_pr.alive is False
        assert bool(dead_pr) is False
        assert "Host unreachable" in (dead_pr.error or "")

        # Синхронный паритет Connection и ConnectionPool
        with Connection.from_uri("local://").to_sync() as sync_conn:
            assert sync_conn.rate_limiter is None
            assert sync_conn.circuit_breaker is None
            sync_pr = sync_conn.ping()
            assert sync_pr.alive is True

        pool = ConnectionPool(["local://?host=n1", "local://?host=n2"], rate_limit=100.0)
        with pool.to_sync() as sync_pool:
            assert sync_pool.rate_limiter is not None
            ping_map = sync_pool.ping()
            assert len(ping_map) == 2
            assert all(item.alive for item in ping_map.values())

    @pytest.mark.asyncio
    async def test_run_script_uploads_executes_and_cleans_up(self, tmp_path: Path) -> None:
        """Проверить загрузку, исполнение с аргументами/окружением и очистку скрипта."""
        script = tmp_path / "test_worker.sh"
        script.write_text(
            '#!/bin/sh\necho "ARG1=$1 ARG2=$2 ENV_VAL=$CUSTOM_VAR SCRIPT_PATH=$0"\n',
            encoding="utf-8",
        )

        async with Connection.from_uri("local://") as conn:
            res = await conn.run_script(
                script,
                args=["hello", "world"],
                env={"CUSTOM_VAR": "uniconn_090"},
            )
            assert res.ok is True
            assert "ARG1=hello ARG2=world ENV_VAL=uniconn_090" in res.text
            # Извлекаем временный путь и убеждаемся, что временная директория удалена
            remote_script_path = res.text.split("SCRIPT_PATH=")[-1].strip()
            assert not Path(remote_script_path).exists()

        # Тест запуска с явным интерпретатором и через SyncConnectionPool
        py_script = tmp_path / "calc.py"
        py_script.write_text("import sys; print('SUM=' + str(int(sys.argv[1]) + int(sys.argv[2])))\n")

        pool = ConnectionPool(["local://?host=h1", "local://?host=h2"])
        with pool.to_sync() as sync_pool:
            res_map = sync_pool.run_script(py_script, args=["15", "27"], interpreter="python3")
            assert len(res_map) == 2
            assert all(r.text == "SUM=42" for r in res_map.values())

        with pytest.raises(FileNotFoundError):
            async with Connection.from_uri("local://") as conn:
                await conn.run_script(tmp_path / "missing_file.sh")

    @pytest.mark.asyncio
    async def test_diff_facts_detects_configuration_drift(self) -> None:
        """Проверить сравнение HostFacts между хостами и формирование FactsDiffReport."""
        facts_map = {
            "web-01": HostFacts(
                os_family="Debian",
                distro="Ubuntu 24.04",
                kernel="6.8.0",
                arch="x86_64",
                cpu_count=4,
                memory_total_bytes=8192 * 1024 * 1024,
            ),
            "web-02": HostFacts(
                os_family="Debian",
                distro="Ubuntu 24.04",
                kernel="6.8.0",
                arch="x86_64",
                cpu_count=4,
                memory_total_bytes=8192 * 1024 * 1024,
            ),
            "web-03": HostFacts(
                os_family="Debian",
                distro="Ubuntu 22.04",
                kernel="5.15.0",
                arch="x86_64",
                cpu_count=2,
                memory_total_bytes=4096 * 1024 * 1024,
            ),
        }
        report = diff_facts(facts_map, baseline_host="web-01")
        assert isinstance(report, FactsDiffReport)
        assert report.has_drift is True
        assert report.baseline_host == "web-01"
        assert report.in_sync_hosts == ["web-01", "web-02"]
        assert "web-03" in report.drifted_hosts
        assert report.drifted_hosts["web-03"]["cpu_count"] == {"expected": 4, "actual": 2}
        assert report.drifted_hosts["web-03"]["memory_total_mb"] == {"expected": 8192, "actual": 4096}
        assert report.to_dict()["has_drift"] is True

        with pytest.raises(ValueError):
            diff_facts(facts_map, baseline_host="unknown-host")

        # Проверка pool.diff_facts() и sync_pool.diff_facts()
        pool = ConnectionPool(["local://?host=n1", "local://?host=n2"])
        with pool.to_sync() as sync_pool:
            live_report = sync_pool.diff_facts()
            assert live_report.has_drift is False
            assert len(live_report.in_sync_hosts) == 2


class TestCLIV090AndDashboard:
    """Тесты новых CLI-команд (ping, facts --diff, exec-script) и песочницы /api/v090."""

    def test_cli_ping_facts_diff_and_exec_script(self, tmp_path: Path) -> None:
        """Проверить работу CLI-команд ping, facts --diff и exec-script через CliRunner."""
        runner = CliRunner()
        app = create_cli_app()

        # 1. uniconn ping --format json
        res_ping = runner.invoke(app, ["ping", "local://", "--format", "json"])
        assert res_ping.exit_code == 0
        ping_data = json.loads(res_ping.stdout)
        assert ping_data["local://"]["alive"] is True

        # 2. uniconn facts --diff --format json
        res_diff = runner.invoke(app, ["facts", "local://", "--diff", "--format", "json"])
        assert res_diff.exit_code == 0
        diff_data = json.loads(res_diff.stdout)
        assert diff_data["has_drift"] is False
        assert diff_data["baseline_host"] == "local://"

        # 3. uniconn exec-script <script.sh> --args "..." --format json
        script = tmp_path / "cli_hello.sh"
        script.write_text('#!/bin/sh\necho "CLI_SCRIPT_OK:$1"\n', encoding="utf-8")
        res_scr = runner.invoke(
            app,
            ["exec-script", str(script), "local://", "--args", "v090", "--format", "json"],
        )
        assert res_scr.exit_code == 0
        scr_data = json.loads(res_scr.stdout)
        assert scr_data["local://"]["ok"] is True
        assert "CLI_SCRIPT_OK:v090" in scr_data["local://"]["stdout"]

    def test_dashboard_v090_sandbox_and_pool_ops(self) -> None:
        """Проверить обработчики /api/v090 и новые операции пула в дашборде."""
        for feat in (
            "adaptive_ssh_pool",
            "circuit_breaker",
            "rate_limiter",
            "ping",
            "diff_facts",
            "run_script",
        ):
            res = _execute_v090_sandbox({"feature": feat})
            assert res["status"] == "ok", f"Feature {feat} failed: {res}"
            assert res["feature"] == feat

        for pool_op in ("ping", "diff_facts", "run_script"):
            pool_res = _execute_pool_sandbox({"group": "web", "operation": pool_op})
            assert pool_res["status"] == "ok", f"Pool op {pool_op} failed: {pool_res}"
            assert pool_res["total_hosts"] == 2
