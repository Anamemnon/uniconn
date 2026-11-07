# tests/unit/core/test_python_worker.py
"""Unit-тесты для Persistent Remote Python Worker (conn.run_python, ускорение фактов и Cassette)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from uniconn import (
    CallableSerializer,
    Connection,
    ConnectionPool,
    ExecutionError,
    RecordedPyRpcInteraction,
)


def _sample_add(a: int, b: int, *, multiplier: int = 1) -> int:
    return (a + b) * multiplier


def _sample_env_and_cwd() -> dict[str, str]:
    import os

    return {
        "cwd": os.getcwd(),
        "custom_var": os.environ.get("UNICONN_TEST_VAR", ""),
    }


def _sample_failing_func() -> None:
    msg = "intentional remote worker error"
    raise ValueError(msg)


def test_callable_serializer_handles_lambda_function_and_source() -> None:
    """CallableSerializer корректно извлекает исходный код из lambda, def и строк."""
    src_fn, name_fn, is_expr_fn = CallableSerializer.serialize(_sample_add)
    assert name_fn == "_sample_add"
    assert "def _sample_add" in src_fn
    assert is_expr_fn is False

    fn_lambda = lambda x, y=2: x * y  # noqa: E731
    src_l, name_l, is_expr_l = CallableSerializer.serialize(fn_lambda)
    assert name_l == "<lambda>"
    assert src_l.startswith("lambda x, y=2: x * y")
    assert is_expr_l is True

    src_expr, name_expr, is_expr_str = CallableSerializer.serialize("os.uname().sysname")
    assert name_expr == "<expr>"
    assert src_expr == "os.uname().sysname"
    assert is_expr_str is True


async def test_run_python_persistent_worker_reuses_single_process(tmp_path: Path) -> None:
    """conn.run_python запускает постоянный Python-воркер один раз и переиспользует его между вызовами."""
    async with Connection.from_uri("local://") as conn:
        pid1 = await conn.run_python(lambda: os.getpid())
        pid2 = await conn.run_python(lambda: os.getpid())
        assert isinstance(pid1, int)
        assert pid1 == pid2
        assert conn.python_worker.is_running is True

        # Передача позиционных и именованных аргументов в обычную функцию
        calc = await conn.run_python(_sample_add, 10, 5, multiplier=3)
        assert calc == 45

        # Учёт контекстных менеджеров conn.cd() и conn.env()
        async with conn.cd(str(tmp_path)), conn.env(UNICONN_TEST_VAR="hello_worker"):
            ctx_info = await conn.run_python(_sample_env_and_cwd)
            assert Path(ctx_info["cwd"]).resolve() == tmp_path.resolve()
            assert ctx_info["custom_var"] == "hello_worker"

    # После закрытия соединения воркер автоматически остановлен
    assert conn.python_worker.is_running is False


async def test_run_python_propagates_remote_exceptions_and_hooks() -> None:
    """Исключения внутри удалённой функции преобразуются в ExecutionError и вызывают хуки."""
    events: list[str] = []

    async with Connection.from_uri("local://") as conn:
        conn.add_hook("before_run", lambda cmd, host, kw: events.append(f"before:{cmd}"))
        conn.add_hook("after_run", lambda res: events.append(f"after:{res.command}:{res.exit_code}"))
        conn.add_hook("on_error", lambda exc, cmd, host: events.append(f"error:{cmd}"))

        val = await conn.run_python(lambda: 2 + 2)
        assert val == 4
        assert "before:run_python:<lambda>" in events
        assert "after:run_python:<lambda>:0" in events

        with pytest.raises(ExecutionError, match="intentional remote worker error"):
            await conn.run_python(_sample_failing_func)

        assert "error:run_python:_sample_failing_func" in events


async def test_gather_facts_accelerated_by_worker_with_transparent_fallback() -> None:
    """gather_facts автоматически использует Python-воркер и прозрачно откатывается при его отключении."""
    async with Connection.from_uri("local://") as conn:
        facts = await conn.gather_facts(refresh=True)
        assert facts.hostname != ""
        assert facts.cpu_count >= 1
        assert conn.python_worker.is_running is True

        # Проверим прозрачный fallback, если воркер помечен как недоступный на целевом хосте
        await conn.python_worker.close()
        conn.python_worker._unavailable = True
        facts_fallback = await conn.gather_facts(refresh=True)
        assert facts_fallback.hostname == facts.hostname
        assert conn.python_worker.is_running is False


async def test_sync_connection_and_pool_run_python() -> None:
    """SyncConnection, ConnectionPool и SyncConnectionPool поддерживают run_python."""
    with Connection.from_uri("local://").to_sync() as sync_conn:
        res = sync_conn.run_python(_sample_add, 3, 4, multiplier=2)
        assert res == 14

    async with ConnectionPool(["local://", "local://"]) as pool:
        pool_res = await pool.run_python(_sample_add, 7, 8)
        assert all(v == 15 for v in pool_res.values())

    with ConnectionPool(["local://"]).to_sync() as sync_pool:
        sync_pool_res = sync_pool.run_python(lambda: "pool_ok")
        assert list(sync_pool_res.values()) == ["pool_ok"]


async def test_run_python_cassette_record_and_replay(tmp_path: Path) -> None:
    """Вызовы conn.run_python записываются в Cassette как RecordedPyRpcInteraction и воспроизводятся без воркера."""
    cassette_file = tmp_path / "py_rpc_cassette.yaml"

    # 1. Запись взаимодействия
    async with Connection.from_uri("local://") as conn:
        async with conn.use_cassette(cassette_file, mode="all") as cassette:
            recorded_val = await conn.run_python(_sample_add, 20, 22, multiplier=2)
            assert recorded_val == 84
            assert cassette.py_rpc_count == 1
            assert isinstance(cassette.interactions[0], RecordedPyRpcInteraction)

    # 2. Воспроизведение из кассеты в режиме mode="none" без запуска реального воркера
    async with Connection.from_uri(f"replay://localhost?cassette={cassette_file}&mode=none") as replay_conn:
        replayed_val: Any = await replay_conn.run_python(_sample_add, 20, 22, multiplier=2)
        assert replayed_val == 84
        assert replay_conn.python_worker.is_running is False


def _sample_binary_and_path_handler(payload: bytes, target_path: str, tags: list[str]) -> bytes:
    return payload + b":" + target_path.encode("utf-8") + b":" + ",".join(sorted(tags)).encode("utf-8")


async def _sample_async_coroutine(x: int, y: int) -> dict[str, int]:
    import asyncio

    await asyncio.sleep(0.001)
    return {"sum": x + y}


async def test_run_python_supports_bytes_path_args_and_async_coroutines(tmp_path: Path) -> None:
    """conn.run_python сериализует bytes, Path, RemotePath, set и исполняет async def корутины."""
    cassette_file = tmp_path / "binary_py_rpc.yaml"

    async with Connection.from_uri("local://") as conn:
        remote_p = conn.path("/etc/nginx/nginx.conf")
        async with conn.use_cassette(cassette_file, mode="all"):
            raw_res = await conn.run_python(
                _sample_binary_and_path_handler,
                b"\x00\xffheader",
                remote_p,
                {"b", "a"},
            )
            assert isinstance(raw_res, bytes)
            assert raw_res == b"\x00\xffheader:/etc/nginx/nginx.conf:a,b"

        async_res = await conn.run_python(_sample_async_coroutine, 15, 27)
        assert async_res == {"sum": 42}

        # Проверим автоматический перезапуск воркера при неожиданном завершении его процесса
        await conn.python_worker.close()
        assert conn.python_worker.is_running is False
        recovered_val = await conn.run_python(lambda: "restarted_ok")
        assert recovered_val == "restarted_ok"
        assert conn.python_worker.is_running is True

    # Проверим воспроизведение бинарного ответа из кассеты
    async with Connection.from_uri(f"replay://localhost?cassette={cassette_file}&mode=none") as replay_conn:
        replayed_bytes = await replay_conn.run_python(
            _sample_binary_and_path_handler,
            b"\x00\xffheader",
            replay_conn.path("/etc/nginx/nginx.conf"),
            {"b", "a"},
        )
        assert isinstance(replayed_bytes, bytes)
        assert replayed_bytes == b"\x00\xffheader:/etc/nginx/nginx.conf:a,b"


async def test_run_python_passes_through_command_pipeline_and_escapes_interpreter() -> None:
    """RemotePythonWorker экранирует python_interpreter и проходит через CommandPipeline (dry_run, middlewares)."""
    conn = Connection.from_dict(
        {
            "transport": "ssh",
            "host": "127.0.0.1",
            "options": {"python_interpreter": "/opt/my python/bin/python3; id"},
        }
    )
    cmd_str = conn.python_worker._build_bootstrap_command()
    # Интерпретатор обязан быть экранирован через shlex.quote, чтобы точка с запятой не исполнялась шеллом
    assert "'/opt/my python/bin/python3; id'" in cmd_str

    # В режиме dry_run=True вызов run_python перехватывается DryRunMiddleware без запуска процесса
    async with Connection.from_uri("local://", dry_run=True) as dry_conn:
        dry_res = await dry_conn.run_python(_sample_add, 1, 2)
        assert dry_res is None
        assert dry_conn.python_worker.is_running is False


