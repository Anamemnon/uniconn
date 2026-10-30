# tests/unit/architecture/test_public_api_surface.py
"""Архитектурные тесты чистоты публичной витрины API и модульного дерева (v0.11.0)."""

from __future__ import annotations

import uniconn
from uniconn._config import ConnectionConfig as ReexportedConfig
from uniconn._connection import Connection as ReexportedConn
from uniconn._facts import HostFacts as ReexportedFacts
from uniconn._pool import ConnectionPool as ReexportedPool
from uniconn._session_pool import SSHSessionPool as ReexportedSessionPool
from uniconn._sync import SyncConnection as ReexportedSyncConn
from uniconn.config.models import ConnectionConfig as CanonicalConfig
from uniconn.core.connection import Connection as CanonicalConn
from uniconn.pool.connection_pool import ConnectionPool as CanonicalPool
from uniconn.pool.session_pool import SSHSessionPool as CanonicalSessionPool
from uniconn.services.facts_models import HostFacts as CanonicalFacts
from uniconn.sync.connection import SyncConnection as CanonicalSyncConn


def test_no_stdlib_quote_leak_in_public_api() -> None:
    """Убедиться, что shlex.quote не входит в публичную витрину __all__ и __dict__ пакета."""
    assert "quote" not in uniconn.__all__
    assert "quote" not in uniconn.__dict__


def test_all_exports_exist_and_are_sorted() -> None:
    """Все имена из __all__ должны существовать в модуле uniconn и быть отсортированы."""
    for symbol in uniconn.__all__:
        assert hasattr(uniconn, symbol), f"Missing symbol in uniconn: {symbol}"
    assert list(uniconn.__all__) == sorted(uniconn.__all__)


def test_canonical_modules_match_backward_compat_reexports() -> None:
    """Классы в _*.py реэкспортах идентичны классам в канонических подпакетах."""
    assert ReexportedConn is CanonicalConn
    assert ReexportedConfig is CanonicalConfig
    assert ReexportedFacts is CanonicalFacts
    assert ReexportedPool is CanonicalPool
    assert ReexportedSessionPool is CanonicalSessionPool
    assert ReexportedSyncConn is CanonicalSyncConn


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
