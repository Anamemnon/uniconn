# tests/unit/architecture/test_hotpaths_performance.py
"""Тесты оптимизаций горячих путей, __slots__ и отказа от monkey-patching (v0.11.0)."""

from __future__ import annotations

from pathlib import Path

import pytest

from uniconn import (
    Connection,
    EnsureResult,
    FactsDiffReport,
    InMemoryTracer,
    PingResult,
    Result,
    SecretMaskingFilter,
    SyncResult,
    otel_tracing_hook,
)
from uniconn._logging import _sanitize_value
from uniconn.background._models import LogEvent, ScreenResult, StatusEvent
from uniconn.services.files import DirectorySynchronizer
from uniconn.shell.expect_engine import ExpectStateMachine


def test_dataclass_models_use_slots() -> None:
    """Все часто создаваемые dataclass-модели используют __slots__ без __dict__."""
    instances = [
        Result(exit_code=0, stdout="ok", stderr="", duration=0.01, command="true"),
        SyncResult(),
        EnsureResult(target="nginx", state="present", changed=False, ok=True),
        PingResult(host="localhost", alive=True, latency_ms=1.0, transport="local"),
        FactsDiffReport(
            baseline_host="h1",
            in_sync_hosts=["h1"],
            drifted_hosts={},
            checked_fields=["distro_id"],
        ),
        LogEvent(session_id="s1", line="hello"),
        StatusEvent(session_id="s1", alive=True),
        ScreenResult(session_id="s1", exit_code=0, remote_log_path="/tmp/a.log"),
    ]
    for obj in instances:
        assert hasattr(type(obj), "__slots__"), f"{type(obj).__name__} is missing __slots__"
        assert not hasattr(obj, "__dict__"), f"{type(obj).__name__} should not have __dict__"


def test_secret_masking_fast_path_and_master_regex() -> None:
    """SecretMaskingFilter._mask_string мгновенно пропускает строки без триггеров и маскирует секреты."""
    plain = "Linux web-01 6.8.0-generic x86_64 GNU/Linux"
    assert SecretMaskingFilter._mask_string(plain) is plain

    with_secrets = (
        "connect ssh://admin:myS3cret@10.0.0.1:22 "
        "token=abcdef123 sudo_password:rootpass"
    )
    masked = SecretMaskingFilter._mask_string(with_secrets)
    assert "myS3cret" not in masked
    assert "abcdef123" not in masked
    assert "rootpass" not in masked
    assert "://***:***@" in masked
    assert "token=***" in masked
    assert "sudo_password=***" in masked


def test_sanitize_value_copy_on_write_preserves_clean_containers() -> None:
    """_sanitize_value не пересоздаёт словари и списки, если в них нет секретов."""
    clean_dict = {"host": "web-01", "exit_code": 0, "tags": ["prod", "eu"]}
    result = _sanitize_value("meta", clean_dict, sensitive_mode=False, mask_patterns=True)
    assert result is clean_dict

    dirty_dict = {"host": "web-01", "password": "secret"}
    sanitized = _sanitize_value("meta", dirty_dict, sensitive_mode=False, mask_patterns=True)
    assert sanitized is not dirty_dict
    assert sanitized["password"] == "***REDACTED***"
    assert dirty_dict["password"] == "secret"


@pytest.mark.asyncio
async def test_expect_engine_pos_search_without_slicing() -> None:
    """ExpectStateMachine корректно сопоставляет цепочку промптов с поиском по курсору."""
    sm = ExpectStateMachine(
        patterns={r"Username:": "admin\n", r"Password:": "secret\n"},
        final_prompt=r"router#\s*$",
    )
    sent: list[str] = []
    chunks = ["Username: ", "Password: ", "Welcome\nrouter# "]
    idx = 0

    async def _send(data: str) -> None:
        sent.append(data)

    async def _read() -> str:
        nonlocal idx
        if idx < len(chunks):
            val = chunks[idx]
            idx += 1
            return val
        return ""

    out, rem = await sm.run_dialog(
        initial_buffer="",
        send_fn=_send,
        read_chunk_fn=_read,
        is_alive_fn=lambda: True,
        mark_closed_fn=lambda: None,
        effective_timeout=1.0,
        cmd_for_error="login",
        host="router",
    )
    assert sent == ["admin\n", "secret\n"]
    assert "router#" in out
    assert rem == ""


@pytest.mark.asyncio
async def test_otel_tracing_uses_observers_without_instance_monkey_patching(
    tmp_path: Path,
) -> None:
    """otel_tracing_hook перехватывает файловые операции без подмены методов в conn.files.__dict__."""
    tracer = InMemoryTracer()
    hook = otel_tracing_hook(tracer=tracer)
    async with Connection.from_uri("local://") as conn:
        hook.attach(conn)
        # Методы сервиса не должны быть перезаписаны в __dict__ экземпляра
        assert "upload" not in conn.files.__dict__
        assert "write_file" not in conn.files.__dict__
        assert "open_shell" not in conn.__dict__

        target = tmp_path / "traced.txt"
        await conn.write_file(target, "traced content")
        content = await conn.read_file(target)
        assert content == "traced content"

    span_names = [s.name for s in tracer.spans]
    assert "uniconn.write_file" in span_names
    assert "uniconn.read_file" in span_names


def test_directory_synchronizer_compiles_single_exclude_regex() -> None:
    """DirectorySynchronizer компилирует список glob-паттернов в единое регулярное выражение."""
    patterns = ["*.pyc", ".git", "build/*"]
    regex = DirectorySynchronizer._compile_exclude_regex(patterns)
    assert regex is not None
    assert DirectorySynchronizer.is_excluded("a/b/mod.pyc", "mod.pyc", patterns, compiled_re=regex)
    assert DirectorySynchronizer.is_excluded(".git/config", "config", patterns, compiled_re=regex)
    assert DirectorySynchronizer.is_excluded("build/output.bin", "output.bin", patterns, compiled_re=regex)
    assert not DirectorySynchronizer.is_excluded("src/main.py", "main.py", patterns, compiled_re=regex)
