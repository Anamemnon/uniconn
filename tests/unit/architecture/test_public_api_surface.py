# tests/unit/architecture/test_public_api_surface.py
"""Архитектурные тесты чистоты публичной витрины API и модульного дерева (v0.20.0)."""

from __future__ import annotations

import importlib

import pytest

import uniconn
from uniconn.config.models import ConnectionConfig as CanonicalConfig
from uniconn.core.connection import Connection as CanonicalConn
from uniconn.pool.connection_pool import ConnectionPool as CanonicalPool
from uniconn.pool.session_pool import SSHSessionPool as CanonicalSessionPool
from uniconn.services.facts_models import HostFacts as CanonicalFacts
from uniconn.sync.connection import SyncConnection as CanonicalSyncConn


def test_no_stdlib_quote_leak_in_public_api() -> None:
    """Убедиться, что shlex.quote не входит в публичную витрину __all__, __dict__ и __getattr__ пакета."""
    assert "quote" not in uniconn.__all__
    assert "quote" not in uniconn.__dict__
    with pytest.raises(AttributeError, match="has no attribute 'quote'"):
        _ = uniconn.quote


def test_all_exports_exist_and_are_sorted() -> None:
    """Все имена из __all__ должны существовать в модуле uniconn (включая PEP 562 __getattr__) и быть отсортированы."""
    dir_entries = dir(uniconn)
    for symbol in uniconn.__all__:
        assert symbol in dir_entries, f"Missing symbol in dir(uniconn): {symbol}"
        assert hasattr(uniconn, symbol), f"Missing symbol in uniconn: {symbol}"
    assert list(uniconn.__all__) == sorted(uniconn.__all__)


def test_deprecated_private_shims_are_removed_and_canonical_modules_match() -> None:
    """Устаревшие модули-заглушки _*.py удалены, а публичные экспорты указывают на канонические подпакеты."""
    assert uniconn.Connection is CanonicalConn
    assert uniconn.ConnectionConfig is CanonicalConfig
    assert uniconn.HostFacts is CanonicalFacts
    assert uniconn.ConnectionPool is CanonicalPool
    assert uniconn.SSHSessionPool is CanonicalSessionPool
    assert uniconn.SyncConnection is CanonicalSyncConn

    removed_shims = (
        "uniconn._config",
        "uniconn._connection",
        "uniconn._facts",
        "uniconn._pool",
        "uniconn._session_pool",
        "uniconn._shell",
        "uniconn._sync",
        "uniconn._uri",
        "uniconn.transports._base",
    )
    for mod_name in removed_shims:
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module(mod_name)


def test_public_version_matches_pyproject() -> None:
    """Версия в uniconn.__version__ должна быть динамически привязана в pyproject.toml."""
    import re
    import tomllib
    from pathlib import Path

    root_dir = Path(__file__).resolve().parents[3]
    pyproject_file = root_dir / "pyproject.toml"
    with open(pyproject_file, "rb") as f:
        data = tomllib.load(f)

    project = data["project"]
    if "version" in project:
        assert uniconn.__version__ == project["version"]
    else:
        assert "version" in project.get("dynamic", [])
        version_rel_path = data["tool"]["hatch"]["version"]["path"]
        assert version_rel_path == "src/uniconn/__init__.py"
        version_file = root_dir / version_rel_path
        match = re.search(
            r'^__version__\s*=\s*["\']([^"\']+)["\']',
            version_file.read_text(encoding="utf-8"),
            re.MULTILINE,
        )
        assert match is not None
        assert uniconn.__version__ == match.group(1)


def test_readme_and_docs_contain_no_outdated_api_patterns() -> None:
    """Убедиться, что README.md и docs/*.rst используют актуальные доменные сервисы и CLI."""
    from pathlib import Path

    root_dir = Path(__file__).resolve().parents[3]
    doc_files = [
        root_dir / "README.md",
        *(root_dir / "docs").rglob("*.rst"),
    ]
    forbidden_patterns = (
        "conn.upload(",
        "conn.download(",
        "conn.write_file(",
        "conn.read_file(",
        "conn.chmod(",
        "conn.stat(",
        "conn.listdir(",
        "pool.upload(",
        "pool.download(",
        "from uniconn import ScreenPool",
        "uniconn screen-run",
        "uniconn screen-logs",
        "uniconn screen-status",
        "uniconn screen-kill",
        "uniconn.transports._base",
        "uniconn._config",
    )

    for doc_path in doc_files:
        text = doc_path.read_text(encoding="utf-8")
        for pattern in forbidden_patterns:
            assert pattern not in text, f"Outdated pattern {pattern!r} found in {doc_path.name}"


def test_examples_use_only_public_uniconn_imports() -> None:
    """Все скрипты в examples/*.py не должны импортировать приватные подмодули uniconn._*."""
    from pathlib import Path

    root_dir = Path(__file__).resolve().parents[3]
    examples_dir = root_dir / "examples"
    py_files = sorted(p for p in examples_dir.glob("*.py") if p.name != "__init__.py")
    assert len(py_files) >= 13

    for py_path in py_files:
        source = py_path.read_text(encoding="utf-8")
        assert "from uniconn._" not in source, f"Private import in {py_path.name}"
        assert "from uniconn.transports._" not in source, f"Private transport import in {py_path.name}"


async def test_all_examples_execute_main_cleanly() -> None:
    """Проверить, что каждый пример в examples/*.py успешно импортируется и выполняет main()."""
    import importlib.util
    from pathlib import Path

    root_dir = Path(__file__).resolve().parents[3]
    examples_dir = root_dir / "examples"
    py_files = sorted(p for p in examples_dir.glob("*.py") if p.name != "__init__.py")

    for py_path in py_files:
        spec = importlib.util.spec_from_file_location(f"examples.{py_path.stem}", py_path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assert hasattr(module, "main"), f"{py_path.name} must define an async main() entrypoint"
        await module.main()


async def test_shell_and_screen_examples_win32_branches(monkeypatch) -> None:
    """Проверить Windows-ветки в interactive_shell.py и screen_monitoring.py (без /bin/sh и nohup)."""
    import importlib.util
    import types
    from pathlib import Path

    root_dir = Path(__file__).resolve().parents[3]
    examples_dir = root_dir / "examples"

    for name in ("interactive_shell.py", "screen_monitoring.py"):
        py_path = examples_dir / name
        spec = importlib.util.spec_from_file_location(f"examples_win.{py_path.stem}", py_path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        monkeypatch.setattr(module, "sys", types.SimpleNamespace(platform="win32"))
        await module.main()


def test_pep562_lazy_submodules_and_dir_resolution() -> None:
    """PEP 562 __getattr__ и __dir__ разрешают доступ к доменным подпакетам uniconn.<submodule>."""
    dir_names = set(dir(uniconn))
    for submod in ("mcp", "mock", "orchestration", "parsing", "security", "background", "cli"):
        assert submod in dir_names
        uniconn.__dict__.pop(submod, None)
        resolved = getattr(uniconn, submod)
        assert resolved is importlib.import_module(f"uniconn.{submod}")
        assert uniconn.__dict__[submod] is resolved


@pytest.mark.asyncio
async def test_from_dict_hooks_and_clone_isolates_options_and_hitl() -> None:
    """from_dict принимает хуки before_run/after_run, а copy() изолирует options и перепривязывает HITL."""
    from uniconn.core.pipeline import HITLApprovalMiddleware
    from uniconn.mcp.models import HITLPolicy

    events: list[str] = []
    conn = uniconn.Connection.from_dict(
        {"transport": "local", "host": "localhost", "options": {"env": "stage"}},
        before_run=[lambda cmd, host, kw: events.append(f"before:{cmd}")],
        after_run=[lambda res: events.append(f"after:{res.command}:{res._dry_run}")],
    )
    hitl = HITLApprovalMiddleware(conn, policy=HITLPolicy(enabled=False), is_production=True).attach(conn)
    assert hitl._conn is conn

    res = await conn.run("echo hook-test", dry_run=True)
    assert res.ok
    assert events == ["before:echo hook-test", "after:echo hook-test:True"]

    cloned = conn.copy(host="cloned-host")
    cloned.config.options["env"] = "prod"
    assert conn.config.options["env"] == "stage"

    cloned_hitl = [m for m in cloned.pipeline.middlewares if isinstance(m, HITLApprovalMiddleware)]
    assert len(cloned_hitl) == 1
    assert cloned_hitl[0] is not hitl
    assert cloned_hitl[0]._conn is cloned
    await conn.close()
    await cloned.close()


