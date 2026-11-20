# tests/unit/pools/test_concurrency_and_windowing.py
"""Concurrency-тесты атомарной инициализации SSHSessionPool и bounded connection_window в run_barrier_fleet."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from uniconn import Connection, ConnectionConfig, ConnectionPool, EnsureResult, Flow, Result, SyncFlow, task
from uniconn.exceptions import ConnectionError
from uniconn.orchestration._barrier_window import _BarrierConnectionWindow
from uniconn.orchestration.scheduler import coerce_to_flow
from uniconn.pool.session_pool import SSHSessionPool


class TestSSHSessionPoolAtomicSlotInit:
    """Проверка отсутствия double-connect гонок и корректного пробуждения ожидающих корутин."""

    @pytest.mark.asyncio
    async def test_concurrent_callers_connect_single_slot_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        connect_calls = 0
        run_calls = 0
        connect_started = asyncio.Event()
        allow_connect_finish = asyncio.Event()

        def fake_from_uri(uri: str, **kwargs: object) -> MagicMock:
            conn = MagicMock(spec=Connection)
            conn.config = ConnectionConfig(transport="ssh", host="10.0.0.1")
            conn.is_connected = False

            async def fake_connect() -> None:
                nonlocal connect_calls
                connect_calls += 1
                connect_started.set()
                await allow_connect_finish.wait()
                conn.is_connected = True

            async def fake_run(cmd: str, **kw: object) -> Result:
                nonlocal run_calls
                assert conn.is_connected is True
                run_calls += 1
                await asyncio.sleep(0.01)
                return Result(
                    exit_code=0, stdout=f"ok:{cmd}", stderr="", duration=0.01, command=cmd
                )

            async def fake_close() -> None:
                conn.is_connected = False

            conn.connect = AsyncMock(side_effect=fake_connect)
            conn.run = AsyncMock(side_effect=fake_run)
            conn.close = AsyncMock(side_effect=fake_close)
            conn.is_alive = AsyncMock(return_value=True)
            return conn

        monkeypatch.setattr("uniconn.pool.session_pool.Connection.from_uri", fake_from_uri)

        spool = SSHSessionPool("ssh://10.0.0.1", max_connections=3, max_sessions_per_conn=6)
        tasks = [asyncio.create_task(spool.run(f"cmd-{i}")) for i in range(5)]

        await asyncio.wait_for(connect_started.wait(), timeout=1.0)
        # Пока connect() первого слота ещё не завершён, остальные 4 корутины ждут handshake,
        # не создавая лишних соединений и не вызывая connect() повторно.
        await asyncio.sleep(0.03)
        assert connect_calls == 1
        assert len(spool._slots) == 1

        allow_connect_finish.set()
        results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=2.0)

        assert len(results) == 5
        assert all(r.ok for r in results)
        assert connect_calls == 1
        assert run_calls == 5
        assert len(spool._slots) == 1
        await spool.close()

    @pytest.mark.asyncio
    async def test_connect_failure_wakes_waiters_without_hang(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        attempt = 0

        def fake_from_uri(uri: str, **kwargs: object) -> MagicMock:
            nonlocal attempt
            attempt += 1
            my_attempt = attempt
            conn = MagicMock(spec=Connection)
            conn.config = ConnectionConfig(transport="ssh", host="10.0.0.2")
            conn.is_connected = False

            async def fake_connect() -> None:
                await asyncio.sleep(0.02)
                if my_attempt == 1:
                    raise ConnectionError("handshake failed once", host="10.0.0.2")
                conn.is_connected = True

            async def fake_run(cmd: str, **kw: object) -> Result:
                return Result(
                    exit_code=0, stdout=f"ok:{cmd}", stderr="", duration=0.01, command=cmd
                )

            async def fake_close() -> None:
                conn.is_connected = False

            conn.connect = AsyncMock(side_effect=fake_connect)
            conn.run = AsyncMock(side_effect=fake_run)
            conn.close = AsyncMock(side_effect=fake_close)
            conn.is_alive = AsyncMock(return_value=True)
            return conn

        monkeypatch.setattr("uniconn.pool.session_pool.Connection.from_uri", fake_from_uri)

        spool = SSHSessionPool("ssh://10.0.0.2", max_connections=2, max_sessions_per_conn=4)
        t1 = asyncio.create_task(spool.run("first"))
        t2 = asyncio.create_task(spool.run("second"))

        outcomes = await asyncio.wait_for(
            asyncio.gather(t1, t2, return_exceptions=True),
            timeout=2.0,
        )
        # Первый вызов падает из-за handshake-ошибки, а второй просыпается, открывает новый слот и завершается OK.
        errors = [o for o in outcomes if isinstance(o, Exception)]
        successes = [o for o in outcomes if isinstance(o, Result)]
        assert len(errors) == 1
        assert len(successes) == 1
        assert successes[0].stdout == "ok:second"
        await spool.close()

    @pytest.mark.asyncio
    async def test_check_health_skips_in_progress_connecting_slot(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """check_health() не должен помечать слот как мёртвый/draining, пока идёт его handshake."""
        connect_started = asyncio.Event()
        allow_connect_finish = asyncio.Event()

        def fake_from_uri(uri: str, **kwargs: object) -> MagicMock:
            conn = MagicMock(spec=Connection)
            conn.config = ConnectionConfig(transport="ssh", host="10.0.0.3")
            conn.is_connected = False

            async def fake_connect() -> None:
                connect_started.set()
                await allow_connect_finish.wait()
                conn.is_connected = True

            async def fake_run(cmd: str, **kw: object) -> Result:
                return Result(
                    exit_code=0, stdout=f"ok:{cmd}", stderr="", duration=0.01, command=cmd
                )

            async def fake_close() -> None:
                conn.is_connected = False

            conn.connect = AsyncMock(side_effect=fake_connect)
            conn.run = AsyncMock(side_effect=fake_run)
            conn.close = AsyncMock(side_effect=fake_close)
            conn.is_alive = AsyncMock(return_value=False)
            return conn

        monkeypatch.setattr("uniconn.pool.session_pool.Connection.from_uri", fake_from_uri)

        spool = SSHSessionPool("ssh://10.0.0.3", max_connections=2, max_sessions_per_conn=4)
        run_task = asyncio.create_task(spool.run("hello"))
        await asyncio.wait_for(connect_started.wait(), timeout=1.0)

        # Пока слот находится в connecting=True, check_health() пропускает его и не закрывает.
        live_count = await spool.check_health()
        assert live_count == 1
        assert len(spool._slots) == 1
        assert spool._slots[0].draining is False
        assert spool._slots[0].closed is False
        spool._slots[0].conn.is_alive.assert_not_awaited()

        allow_connect_finish.set()
        res = await asyncio.wait_for(run_task, timeout=2.0)
        assert res.ok is True
        await spool.close()


class TestBarrierFleetConnectionWindowing:
    """Проверка bounded LRU connection_window и сохранности отложенных notifications в run_barrier_fleet."""

    @pytest.mark.asyncio
    async def test_barrier_fleet_enforces_connection_window_and_preserves_notifications(
        self,
    ) -> None:
        host_count = 12
        window_size = 3
        open_conns: set[str] = set()
        peak_open = 0
        reopened_hosts: dict[str, int] = {}
        flushed_commands: dict[str, list[str]] = {}
        layer_trace: dict[str, list[str]] = {}

        def _make_fake_conn(host_name: str) -> Connection:
            transport = MagicMock()
            transport.name = "mock"
            transport.is_connected = False

            async def fake_connect() -> None:
                nonlocal peak_open
                transport.is_connected = True
                open_conns.add(host_name)
                reopened_hosts[host_name] = reopened_hosts.get(host_name, 0) + 1
                if len(open_conns) > peak_open:
                    peak_open = len(open_conns)

            async def fake_disconnect() -> None:
                transport.is_connected = False
                open_conns.discard(host_name)

            async def fake_run(cmd: str, timeout: float | None = None, **kw: object) -> Result:
                await asyncio.sleep(0.005)
                if "systemctl reload nginx" in cmd or "nginx" in cmd:
                    flushed_commands.setdefault(host_name, []).append(cmd)
                return Result(
                    exit_code=0,
                    stdout=f"{host_name}:{cmd}",
                    stderr="",
                    duration=0.005,
                    command=cmd,
                    host=host_name,
                )

            transport.connect = AsyncMock(side_effect=fake_connect)
            transport.disconnect = AsyncMock(side_effect=fake_disconnect)
            transport.run = AsyncMock(side_effect=fake_run)

            cfg = ConnectionConfig(transport="local", host=host_name)
            return Connection(transport=transport, config=cfg)

        hosts = {f"node-{i:02d}": _make_fake_conn(f"node-{i:02d}") for i in range(host_count)}

        @task
        async def step1_configure(conn: Connection) -> str:
            h = conn.config.host or ""
            layer_trace.setdefault(h, []).append("layer1")
            await conn.run("echo configure")
            # Регистрируем отложенный handler (notify) в слое 1 — он обязан пережить LRU-вытеснение
            # соединения между слоем 1 и финальным flush в конце barrier-fleet!
            batch = conn.state._current_batch()
            assert batch is not None
            batch.enqueue(
                f"reload:nginx:{h}",
                "reload_nginx",
                lambda c: c.run("systemctl reload nginx"),
                conn,
                EnsureResult(
                    target="/etc/nginx/nginx.conf",
                    state="present",
                    changed=True,
                    ok=True,
                    details="updated",
                ),
            )
            return f"cfg:{h}"

        @task(depends_on=[step1_configure])
        async def step2_verify(conn: Connection) -> str:
            h = conn.config.host or ""
            layer_trace.setdefault(h, []).append("layer2")
            await conn.run("echo verify")
            return f"ver:{h}"

        @task(depends_on=[step2_verify])
        async def step3_finalize(conn: Connection) -> str:
            h = conn.config.host or ""
            layer_trace.setdefault(h, []).append("layer3")
            await conn.run("echo finalize")
            return f"fin:{h}"

        flow = Flow("windowed-rollout", tasks=[step3_finalize], mode="barrier")
        pool = ConnectionPool(list(hosts.values()), max_concurrent=6)

        report = await pool.run_flow(
            flow,
            connection_window=window_size,
        )

        # 1. Пиковое число одновременно открытых соединений строго <= connection_window (3)
        assert peak_open <= window_size
        assert peak_open >= 1
        assert len(open_conns) == 0  # все соединения закрыты по завершении

        # 2. Все 12 хостов прошли все 3 DAG-слоя без ошибок
        assert report.ok is True
        assert len(report.results) == host_count
        for h in hosts:
            assert layer_trace[h] == ["layer1", "layer2", "layer3"]

        # 3. Убеждаемся, что вытеснение и переподключение действительно происходило
        assert any(cnt > 1 for cnt in reopened_hosts.values())

        # 4. Отложенные handlers, зарегистрированные в слое 1, выполнились на всех 12 хостах!
        for h in hosts:
            assert h in flushed_commands
            assert any("systemctl reload nginx" in cmd for cmd in flushed_commands[h])

    @pytest.mark.asyncio
    async def test_connection_pool_run_flow_forwards_connection_window(self) -> None:
        pool = ConnectionPool(
            ["local://a", "local://b", "local://c", "local://d"], max_concurrent=4
        )

        @task
        async def ping_host(conn: Connection) -> str:
            return conn.config.host or "local"

        flow = Flow("pool-window-test", tasks=[ping_host], mode="barrier")

        report = await pool.run_flow(
            flow,
            connection_window=2,
        )
        assert report.ok is True
        assert len(report.results) == 4

    def test_flow_connection_window_validation_and_coercion_preservation(self) -> None:
        """Flow.connection_window валидируется, сохраняется в coerce_to_flow и доступен в SyncFlow."""

        @task
        async def noop(conn: Connection) -> str:
            return "ok"

        with pytest.raises(ValueError, match="connection_window"):
            Flow("bad-window", tasks=[noop], connection_window=0)

        flow = Flow("good-window", tasks=[noop], mode="independent", connection_window=4)
        assert flow.connection_window == 4

        coerced = coerce_to_flow(flow, mode="barrier")
        assert coerced.mode == "barrier"
        assert coerced.connection_window == 4

        sync_flow = SyncFlow(coerced)
        assert sync_flow.connection_window == 4

    @pytest.mark.asyncio
    async def test_barrier_window_cancellation_releases_opening_slot_without_deadlock(self) -> None:
        """Отмена корутины (CancelledError) во время open/evict освобождает _opening и будит остальных."""
        connect_started = asyncio.Event()
        block_forever = asyncio.Event()

        def _make_conn(host_name: str, *, hang_connect: bool = False) -> Connection:
            transport = MagicMock()
            transport.name = "mock"
            transport.is_connected = False

            async def fake_connect() -> None:
                if hang_connect:
                    connect_started.set()
                    await block_forever.wait()
                transport.is_connected = True

            async def fake_disconnect() -> None:
                transport.is_connected = False

            transport.connect = AsyncMock(side_effect=fake_connect)
            transport.disconnect = AsyncMock(side_effect=fake_disconnect)
            return Connection(transport=transport, config=ConnectionConfig(transport="local", host=host_name))

        c0 = _make_conn("h0", hang_connect=True)
        c1 = _make_conn("h1", hang_connect=False)
        pool = ConnectionPool([c0, c1], max_concurrent=2)
        window = _BarrierConnectionWindow(pool, max_open=1, batch_notifications=False)

        t_cancel = asyncio.create_task(window.acquire(0, c0, "h0"))
        await asyncio.wait_for(connect_started.wait(), timeout=1.0)

        t_waiter = asyncio.create_task(window.acquire(1, c1, "h1"))
        await asyncio.sleep(0.02)

        # Отменяем первую задачу во время connect(); вторая должна пробудиться и занять окно без дедлока.
        t_cancel.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t_cancel

        acquired_entry = await asyncio.wait_for(t_waiter, timeout=1.0)
        assert acquired_entry.conn is c1
        assert 0 not in window._opening
        await window.release(acquired_entry)
        await window.close_all()
