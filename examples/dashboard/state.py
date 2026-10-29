"""Состояние окружения, константы и поиск виртуального окружения для веб-панели uniconn."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

DASHBOARD_DIR = Path(__file__).resolve().parent
ROOT_DIR = str(DASHBOARD_DIR.parent.parent)
HTML_TEMPLATE_PATH = DASHBOARD_DIR / "index.html"

for _extra_path in (
    os.path.join(ROOT_DIR, "src"),
    os.path.join(ROOT_DIR, "tests", "unit"),
    os.path.join(ROOT_DIR, "tests", "unit", "core"),
):
    if _extra_path not in sys.path:
        sys.path.insert(0, _extra_path)

DEFAULT_INVENTORY_YAML = """defaults:
  transport: local
  timeout: 10

hosts:
  web-eu-01:
    uri: local://?role=frontend&dc=eu-central-1
  web-eu-02:
    uri: local://?role=frontend&dc=eu-west-1
  api-core-01:
    uri: local://?role=backend&dc=eu-central-1
  db-primary-01:
    uri: local://?role=database&dc=eu-central-1

groups:
  web:
    - web-eu-01
    - web-eu-02
  backend:
    - api-core-01
    - db-primary-01
  all:
    - web-eu-01
    - web-eu-02
    - api-core-01
    - db-primary-01
"""

TEST_SUITES_META: list[dict[str, Any]] = [
    {"id": "all", "label": "All Unit Tests", "path": "tests/unit", "count": 614},
    {"id": "core", "label": "Core & Logging", "path": "tests/unit/core", "count": 246},
    {"id": "services", "label": "Domain Services & Provisioning", "path": "tests/unit/services", "count": 43},
    {"id": "transports", "label": "Transports & SFTP", "path": "tests/unit/transports", "count": 154},
    {"id": "pools", "label": "Connection & SSH Pools", "path": "tests/unit/pools", "count": 29},
    {"id": "screen", "label": "BackgroundPool & LogPipeline", "path": "tests/unit/screen", "count": 70},
    {"id": "cli", "label": "CLI & Web Dashboard", "path": "tests/unit/cli", "count": 48},
    {"id": "architecture", "label": "Architecture & API Surface", "path": "tests/unit/architecture", "count": 24},
]

SUITE_TO_POE_TASK: dict[str, str] = {
    "ruff": "lint",
    "pyright": "typecheck",
    "benchmarks": "bench",
    "benchmark": "bench",
    "overhead": "bench",
    "all": "test",
    "core": "test-core",
    "services": "test-services",
    "transports": "test-transports",
    "pools": "test-pools",
    "screen": "test-background",
    "background": "test-background",
    "cli": "test-cli",
    "architecture": "test-arch",
    "check": "check",
}

UV_BIN_DIR = "/tmp/uniconn-uv"
UV_PYTHON_DIR = "/tmp/uniconn-python"
UV_VENV_DIR = "/tmp/uniconn-venv"
_UV_BOOTSTRAP_LOCK = threading.Lock()
_UV_ENV_READY = False


def create_default_dashboard_states() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Создать начальные словари состояния для сессии шелла, метрик хуков и фоновых сессий."""
    shell_state: dict[str, Any] = {"cwd": "/root", "env": {}, "term_size": [120, 40]}
    metrics_state: dict[str, Any] = {
        "total_runs": 0,
        "failed_runs": 0,
        "errors_count": 0,
        "total_duration": 0.0,
        "avg_duration": 0.0,
        "by_host": {},
        "history": [],
    }
    screen_state: dict[str, Any] = {"sessions": []}
    return shell_state, metrics_state, screen_state


def _resolve_active_venv_dir() -> str:
    """Определить директорию виртуального окружения проекта."""
    for candidate in (UV_VENV_DIR, os.path.join(ROOT_DIR, ".venv"), "/root/.venv"):
        if os.path.isfile(os.path.join(candidate, "bin", "python")):
            return candidate
    return UV_VENV_DIR


def _find_venv_python() -> str | None:
    """Найти интерпретатор Python внутри подготовленного виртуального окружения."""
    for candidate in (
        os.path.join(UV_VENV_DIR, "bin", "python"),
        os.path.join(ROOT_DIR, ".venv", "bin", "python"),
        "/root/.venv/bin/python",
    ):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _get_env() -> dict[str, str]:
    env = os.environ.copy()
    venv_dir = _resolve_active_venv_dir()
    bin_dir = os.path.join(ROOT_DIR, ".bin")
    venv_bin = os.path.join(venv_dir, "bin")
    home_bin = os.path.expanduser("~/.local/bin")
    env["PATH"] = os.pathsep.join((UV_BIN_DIR, bin_dir, venv_bin, home_bin, env.get("PATH", "")))
    env["UV_PROJECT_ENVIRONMENT"] = venv_dir
    env["UV_PYTHON_INSTALL_DIR"] = UV_PYTHON_DIR
    env["PYTHONPATH"] = os.pathsep.join(
        (
            ROOT_DIR,
            os.path.join(ROOT_DIR, "src"),
            os.path.join(ROOT_DIR, "tests", "unit"),
            os.path.join(ROOT_DIR, "tests", "unit", "core"),
        )
    )
    return env


def _find_uv_binary() -> str:
    """Найти исполняемый файл uv в проекте, /tmp или системе."""
    candidates = [
        os.path.join(UV_BIN_DIR, "uv"),
        os.path.join(ROOT_DIR, ".bin", "uv"),
        os.path.join(ROOT_DIR, ".venv", "bin", "uv"),
        "/root/.venv/bin/uv",
        os.path.expanduser("~/.local/bin/uv"),
    ]
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c

    sys_uv = shutil.which("uv")
    return sys_uv if sys_uv else "uv"


def _can_import_uniconn_in_proc() -> bool:
    """Проверить, поддерживает ли текущий процесс Python 3.11+ и зависимости uniconn."""
    if sys.version_info < (3, 11):  # noqa: UP036
        return False
    try:
        import structlog  # noqa: F401
        import yaml  # noqa: F401

        import uniconn  # noqa: F401

        return True
    except Exception:
        return False


def _ensure_uv_env() -> str | None:
    """Автоматически установить uv и синхронизировать Python 3.12 venv при первом обращении."""
    global _UV_ENV_READY
    existing = _find_venv_python()
    if _UV_ENV_READY and existing:
        return existing

    with _UV_BOOTSTRAP_LOCK:
        existing = _find_venv_python()
        if _UV_ENV_READY and existing:
            return existing
        if existing:
            chk = subprocess.run(
                [existing, "-c", "import structlog, yaml, pytest, uniconn"],
                cwd=ROOT_DIR,
                env=_get_env(),
                capture_output=True,
                timeout=15,
            )
            if chk.returncode == 0:
                _UV_ENV_READY = True
                return existing

        try:
            uv_bin = _find_uv_binary()
            if uv_bin == "uv":
                os.makedirs(UV_BIN_DIR, exist_ok=True)
                install_cmd = (
                    f'curl -LsSf https://astral.sh/uv/install.sh | '
                    f'env UV_INSTALL_DIR="{UV_BIN_DIR}" sh'
                )
                subprocess.run(install_cmd, shell=True, cwd=ROOT_DIR, check=True, timeout=60)
                uv_bin = _find_uv_binary()

            env = _get_env()
            env["UV_PROJECT_ENVIRONMENT"] = UV_VENV_DIR
            subprocess.run(
                [uv_bin, "sync", "--python", "3.12", "--all-extras", "--dev"],
                cwd=ROOT_DIR,
                env=env,
                check=True,
                capture_output=True,
                timeout=180,
            )
            venv_py = _find_venv_python()
            if venv_py:
                _UV_ENV_READY = True
            return venv_py
        except Exception:
            return _find_venv_python()


def _serialize_result(res: Any) -> dict[str, Any]:
    """Преобразовать объект Result в расширенный словарь для инспектора UI."""
    json_parsed = None
    try:
        if res.text and (res.text.startswith("{") or res.text.startswith("[")):
            json_parsed = res.json()
    except Exception:
        json_parsed = None

    return {
        "command": res.command,
        "exit_code": res.exit_code,
        "ok": bool(res.ok),
        "stdout": res.stdout,
        "stderr": res.stderr,
        "text": res.text,
        "lines": res.lines,
        "json_parsed": json_parsed,
        "host": res.host,
        "sensitive": bool(getattr(res, "sensitive", False)),
        "duration_s": round(res.duration, 4),
        "duration_ms": round(res.duration * 1000, 2),
        "to_dict": res.to_dict(),
    }


def _read_init_version() -> str:
    """Извлечь __version__ напрямую из src/uniconn/__init__.py без импорта пакета."""
    init_file = Path(ROOT_DIR) / "src" / "uniconn" / "__init__.py"
    try:
        m = re.search(
            r'^__version__\s*=\s*["\']([^"\']+)["\']',
            init_file.read_text(encoding="utf-8"),
            re.MULTILINE,
        )
        if m:
            return m.group(1)
    except Exception:
        pass
    return "0.0.0"
