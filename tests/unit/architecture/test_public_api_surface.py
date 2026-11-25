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

_ISOLATED_BY_SUBPACKAGE: dict[str, tuple[str, ...]] = {
    "uniconn.mcp": (
        "MCPServer",
        "MCPHostRegistry",
        "MCPSecurityPolicy",
        "HITLPolicy",
        "ApprovalManager",
        "ApprovalError",
        "ApprovalRequiredError",
        "ConcurrencyConflictError",
    ),
    "uniconn.orchestration": (
        "Flow",
        "SyncFlow",
        "FlowContext",
        "FlowReport",
        "Task",
        "task",
        "FlowExecutionError",
        "CyclicDependencyError",
    ),
    "uniconn.security": (
        "CommandASTParser",
        "EmbeddedPolicyEngine",
        "PolicyGuardrailMiddleware",
        "OPAPolicyEngine",
        "PolicyViolationError",
    ),
    "uniconn.background": (
        "BackgroundPool",
        "DiagnosticSession",
        "DiagnosticConfig",
        "LogPipeline",
        "BackgroundError",
        "HardwareFaultDetectedError",
    ),
    "uniconn.mock": (
        "MockSSHServer",
        "MockNetconfServer",
        "MockGnmiServer",
    ),
    "uniconn.services.provisioning": (
        "FleetChangePlan",
        "PlannedChange",
        "PlanRecorder",
        "AptStrategy",
        "SystemdStrategy",
        "StateDriftError",
    ),
    "uniconn.pytest_plugin": ("UniconnCassetteFixture",),
}
_ISOLATED_ROOT_SYMBOLS: frozenset[str] = frozenset(
    sym for symbols in _ISOLATED_BY_SUBPACKAGE.values() for sym in symbols
)


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
    """Убедиться, что README.md, README.ru.md и docs/**/*.rst используют актуальные доменные сервисы и CLI."""
    from pathlib import Path

    root_dir = Path(__file__).resolve().parents[3]
    doc_files = [
        root_dir / "README.md",
        root_dir / "README.ru.md",
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

    import re

    root_import_re = re.compile(r"from uniconn import\s+(?:\(([^)]+)\)|([^\n]+))")
    autodoc_root_re = re.compile(r"\.\.\s+auto(?:class|exception|function)::\s+uniconn\.([A-Za-z_][A-Za-z0-9_]*)")

    for doc_path in doc_files:
        text = doc_path.read_text(encoding="utf-8")
        for pattern in forbidden_patterns:
            assert pattern not in text, f"Outdated pattern {pattern!r} found in {doc_path.name}"
        for block_match in root_import_re.finditer(text):
            chunk = block_match.group(1) or block_match.group(2)
            names = {x.strip().split()[0] for x in chunk.replace("\n", " ").split(",") if x.strip()}
            disallowed = names & _ISOLATED_ROOT_SYMBOLS
            assert not disallowed, f"Isolated root import {sorted(disallowed)} in {doc_path.name}"
        for auto_match in autodoc_root_re.finditer(text):
            sym = auto_match.group(1)
            assert sym not in _ISOLATED_ROOT_SYMBOLS, (
                f"Isolated autodoc target uniconn.{sym} in {doc_path.name}"
            )


def test_bilingual_documentation_structure_and_coverage() -> None:
    """Проверить наличие и полноту двуязычных руководств (EN + RU) по архитектуре, инвентарю и отладке."""
    from pathlib import Path

    root_dir = Path(__file__).resolve().parents[3]
    docs_dir = root_dir / "docs"
    ru_dir = docs_dir / "ru"

    expected_guides = (
        "index.rst",
        "quickstart.rst",
        "architecture.rst",
        "inventory_and_uris.rst",
        "cookbook.rst",
        "troubleshooting.rst",
    )
    for name in expected_guides:
        en_file = docs_dir / name
        ru_file = ru_dir / name
        assert en_file.is_file(), f"Missing English guide: {en_file}"
        assert ru_file.is_file(), f"Missing Russian guide: {ru_file}"
        assert len(en_file.read_text(encoding="utf-8")) > 1500
        assert len(ru_file.read_text(encoding="utf-8")) > 1500

    # Verify core architectural concepts and middleware pipeline are documented in both languages
    for arch_path in (docs_dir / "architecture.rst", ru_dir / "architecture.rst"):
        arch_text = arch_path.read_text(encoding="utf-8")
        for symbol in (
            "CommandPipeline",
            "ContextMiddleware",
            "SudoMiddleware",
            "DryRunMiddleware",
            "AutoDiagnosticMiddleware",
            "CircuitBreakerMiddleware",
            "RetryMiddleware",
            "EventLoopPortal",
            "RemotePythonWorker",
        ):
            assert symbol in arch_text, f"{symbol} missing in {arch_path}"


def test_examples_use_only_public_uniconn_imports() -> None:
    """Все скрипты в examples/*.py импортируют только актуальные публичные модули без изолированных корней."""
    import ast
    from pathlib import Path

    root_dir = Path(__file__).resolve().parents[3]
    examples_dir = root_dir / "examples"
    py_files = sorted(p for p in examples_dir.glob("*.py") if p.name != "__init__.py")
    assert len(py_files) >= 13

    allowed_root = set(uniconn.__all__) | set(uniconn._LAZY_EXPORTS) | {"__version__"}
    for py_path in py_files:
        source = py_path.read_text(encoding="utf-8")
        assert "from uniconn._" not in source, f"Private import in {py_path.name}"
        assert "from uniconn.transports._" not in source, f"Private transport import in {py_path.name}"
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "uniconn":
                for alias in node.names:
                    assert alias.name in allowed_root, (
                        f"Non-core/isolated symbol {alias.name!r} imported from root in {py_path.name}"
                    )


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


def test_root_all_is_clean_and_lazy_aliases_remain_accessible() -> None:
    """Корневой __all__ содержит только компактное SemVer-ядро, а внутренние алиасы ядра загружаются лениво."""
    assert len(uniconn.__all__) <= 55
    internal_symbols = (
        "compute_crc16",
        "CallableSerializer",
        "PosixMarkerProtocol",
        "EventLoopPortal",
    )
    for sym in internal_symbols:
        assert sym not in uniconn.__all__, f"Internal symbol {sym} should not be in root __all__"
        assert sym in dir(uniconn)
        assert getattr(uniconn, sym) is not None


def test_isolated_subsystems_excluded_from_root_api() -> None:
    """Изолированные подсистемы и внутренние стратегии отсутствуют в корневом uniconn, но доступны в подпакетах."""
    dir_names = set(dir(uniconn))
    for subpkg_name, symbols in _ISOLATED_BY_SUBPACKAGE.items():
        submod = importlib.import_module(subpkg_name)
        for sym in symbols:
            assert sym not in uniconn.__all__, f"{sym} must not be in root __all__"
            assert sym not in uniconn.__dict__, f"{sym} must not be in root __dict__"
            assert sym not in dir_names, f"{sym} must not be in dir(uniconn)"
            with pytest.raises(AttributeError):
                getattr(uniconn, sym)
            assert hasattr(submod, sym), f"{sym} missing from canonical subpackage {subpkg_name}"


def test_isolated_packages_all_exports_resolvable() -> None:
    """Проверить консистентность __all__ во всех изолированных и сервисных подпакетах."""
    subpackages = (
        "uniconn.mcp",
        "uniconn.security",
        "uniconn.background",
        "uniconn.orchestration",
        "uniconn.mock",
        "uniconn.transports.replay",
        "uniconn.services",
        "uniconn.services.provisioning",
    )
    for pkg_name in subpackages:
        mod = importlib.import_module(pkg_name)
        exports = list(mod.__all__)
        assert len(exports) == len(set(exports)), f"Duplicate exports in {pkg_name}.__all__"
        for sym in exports:
            assert hasattr(mod, sym), f"{pkg_name}.{sym} from __all__ failed to resolve"


def test_import_latency_and_lazy_isolation(tmp_path) -> None:
    """import uniconn и ConnectionPool быстры и не подгружают _fleet_plan и тяжёлые модули."""
    import json
    import subprocess
    import sys

    probe_import = (
        "import json, sys, time; "
        "t0 = time.perf_counter(); "
        "import uniconn; "
        "ms = (time.perf_counter() - t0) * 1000; "
        "forbidden = ["
        "'niquests', 'urllib3', 'asyncssh', 'pydantic', 'structlog', 'pywinrm', 'telnetlib3', 'pyghmi', "
        "'uniconn.mcp', 'uniconn.orchestration', 'uniconn.security', 'uniconn.background', 'uniconn.mock', "
        "'uniconn.services', 'uniconn.services.provisioning', 'uniconn.transports.bmc', "
        "'uniconn.transports.network', 'uniconn.transports._winrm'"
        "]; "
        "loaded = [m for m in forbidden if m in sys.modules]; "
        "_ = uniconn.ConnectionPool; "
        "pool_pulled_fleet = 'uniconn.services.provisioning._fleet_plan' in sys.modules; "
        "print(json.dumps({'ms': ms, 'loaded': loaded, 'pool_pulled_fleet': pool_pulled_fleet}))"
    )
    proc = subprocess.run(
        [sys.executable, "-c", probe_import],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    info = json.loads(proc.stdout.strip())
    assert info["loaded"] == [], f"Unexpected eager imports: {info['loaded']}"
    assert info["pool_pulled_fleet"] is False, "ConnectionPool import eagerly loaded _fleet_plan"
    assert info["ms"] < 250.0, f"import uniconn took too long: {info['ms']:.2f} ms"

    target = tmp_path / "lazy_prov.txt"
    probe_prov = (
        "import asyncio, json, sys\n"
        "from uniconn import Connection\n"
        "async def run():\n"
        "    async with Connection.local() as conn:\n"
        f"        await conn.state.ensure_file({str(target)!r}, content='ok', dry_run=True)\n"
        "asyncio.run(run())\n"
        "unwanted = [\n"
        "    'uniconn.services.provisioning._fleet_plan',\n"
        "    'uniconn.services.provisioning.yang',\n"
        "    'uniconn.services.provisioning.packages',\n"
        "    'uniconn.services.provisioning.service_managers',\n"
        "    'uniconn.services.provisioning.system',\n"
        "    'uniconn.services.provisioning.windows',\n"
        "]\n"
        "print(json.dumps([m for m in unwanted if m in sys.modules]))\n"
    )
    prov_proc = subprocess.run(
        [sys.executable, "-c", probe_prov],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    prov_loaded = json.loads(prov_proc.stdout.strip())
    assert prov_loaded == [], f"Lazy provisioning leaked submodules: {prov_loaded}"


def test_readmes_and_svg_have_no_removed_transports_or_dashboard() -> None:
    """README.md, README.ru.md и terminal_demo.svg не должны ссылаться на удалённые контейнеры и Web Dashboard."""
    from pathlib import Path

    root_dir = Path(__file__).resolve().parents[3]
    showcase_files = (
        root_dir / "README.md",
        root_dir / "README.ru.md",
        root_dir / "docs" / "assets" / "terminal_demo.svg",
    )
    forbidden_lower = (
        "docker://",
        "podman://",
        "kubectl://",
        "dockertransport",
        "podmantransport",
        "kubectltransport",
        "web dashboard",
        "веб-панель",
        "веб-дашборд",
    )
    for file_path in showcase_files:
        text_lower = file_path.read_text(encoding="utf-8").lower()
        for token in forbidden_lower:
            assert token not in text_lower, f"Stale reference {token!r} found in {file_path.relative_to(root_dir)}"


def test_readmes_document_all_extras_transports_mcp_and_valid_links() -> None:
    """Оба README должны документировать все extras, транспорты, MCP-инструменты, примеры и иметь валидные ссылки."""
    import asyncio
    import re
    import tomllib
    from pathlib import Path

    from uniconn.mcp import MCPHostRegistry, MCPServer

    root_dir = Path(__file__).resolve().parents[3]
    with open(root_dir / "pyproject.toml", "rb") as f:
        pyproject = tomllib.load(f)

    optional_extras = {
        name for name in pyproject["project"]["optional-dependencies"] if name not in {"all", "dev"}
    }
    transport_schemes = sorted(pyproject["project"]["entry-points"]["uniconn.transports"].keys())
    example_files = sorted(
        f"examples/{p.name}"
        for p in (root_dir / "examples").iterdir()
        if p.is_file() and p.name != "__init__.py" and p.suffix in {".py", ".yaml"}
    )

    mcp_server = MCPServer(registry=MCPHostRegistry())
    tools_resp = asyncio.run(mcp_server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
    assert tools_resp is not None
    mcp_tools = sorted(tool["name"] for tool in tools_resp["result"]["tools"])

    rel_link_re = re.compile(r'\]\(([^)]+)\)|src="([^"]+)"')

    for readme_name in ("README.md", "README.ru.md"):
        text = (root_dir / readme_name).read_text(encoding="utf-8")

        for extra in sorted(optional_extras):
            assert f"uniconn[{extra}]" in text, f"Extra uniconn[{extra}] missing in {readme_name}"

        for scheme in transport_schemes:
            assert f"`{scheme}://`" in text, f"Transport scheme {scheme}:// missing in {readme_name}"

        for tool_name in mcp_tools:
            assert f"`{tool_name}`" in text, f"MCP tool {tool_name} missing in {readme_name}"

        for example_rel in example_files:
            assert f"({example_rel})" in text, f"Example link {example_rel} missing in {readme_name}"

        for match in rel_link_re.finditer(text):
            raw_target = match.group(1) or match.group(2)
            if raw_target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            clean_target = raw_target.split("#", 1)[0].lstrip("./")
            target_path = root_dir / clean_target
            assert target_path.exists(), f"Broken relative link {raw_target!r} in {readme_name}"



