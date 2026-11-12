"""Unit-тесты для интерактивной веб-панели examples/dashboard/server.py."""

from __future__ import annotations

from typing import Any

import pytest

from examples.dashboard.server import (
    HTML_TEMPLATE_PATH,
    _build_and_validate_uri,
    _execute_hooks_sandbox,
    _execute_local_command,
    _execute_pool_sandbox,
    _execute_recipe_sandbox,
    _execute_screen_sandbox,
    _execute_shell_command,
    _run_demo_status,
)
from uniconn import __version__


class TestDashboardStatusAndShell:
    """Проверка базового статуса, ShellSession и локального выполнения."""

    def test_run_demo_status_returns_full_metadata(self) -> None:
        """Проверить метаданные /api/status, включая список транспортов и тестовых пакетов."""
        status = _run_demo_status()
        assert status["version"] == __version__
        assert "ssh" in status["transports"]
        assert "local" in status["transports"]
        assert "3.10" not in status["python_version"]
        assert "test_suites" in status
        assert len(status["test_suites"]) == 8
        suite_ids = [s["id"] for s in status["test_suites"]]
        assert "architecture" in suite_ids
        assert "core" in suite_ids
        assert "services" in suite_ids
        total_tests = sum(s["count"] for s in status["test_suites"] if s["id"] != "all")
        assert total_tests == 614
        assert "default_inventory" in status

    def test_execute_shell_command_stateful_and_reset(self) -> None:
        """Проверить сохранение cwd/term_size и сброс сессии в _execute_shell_command."""
        state: dict[str, Any] = {"cwd": "/root", "env": {}, "term_size": [120, 40]}
        res1 = _execute_shell_command("cd /var/log", state, cols=100, rows=30)
        assert res1["exit_code"] == 0
        assert state["cwd"] == "/var/log"
        assert state["term_size"] == [100, 30]

        res2 = _execute_shell_command("pwd", state, reset=True)
        assert res2["exit_code"] == 0
        assert state["cwd"] == "/root"

    def test_execute_local_command_with_json_inspector(self) -> None:
        """Проверить выполнение команды через local:// и автоматический разбор JSON."""
        res = _execute_local_command('python3 -c \'import json; print(json.dumps({"ok": True, "count": 3}))\'')
        assert res["exit_code"] == 0
        assert res["ok"] is True
        assert res["json_parsed"] == {"ok": True, "count": 3}
        assert "to_dict" in res


class TestDashboardHooksAndTelemetry:
    """Проверка песочницы lifecycle-хуков, политик безопасности и structlog."""

    def test_hooks_sandbox_executes_and_masks_secrets(self) -> None:
        """Проверить генерацию JSONL-логов structlog и маскирование паролей."""
        metrics: dict[str, Any] = {}
        res = _execute_hooks_sandbox(
            {
                "cmd": "echo 'deploy password=mySecret123'",
                "mask_secrets": True,
                "sensitive": False,
                "dry_run": False,
                "context_vars": {"service": "web", "datacenter": "eu-1"},
                "tags": {"env": "prod"},
            },
            metrics,
        )
        assert res["status"] == "ok"
        assert res["metrics"]["total_runs"] == 1
        assert len(res["logs_json"]) >= 1
        joined_logs = "\n".join(res["logs_json"])
        assert "mySecret123" not in joined_logs
        assert "password=***" in joined_logs

    def test_hooks_sandbox_blocks_dangerous_command(self) -> None:
        """Проверить блокировку опасной команды через blocklist_hook и учёт ошибки в метриках."""
        metrics: dict[str, Any] = {}
        res = _execute_hooks_sandbox(
            {
                "cmd": "rm -rf /",
                "blocklist_enabled": True,
            },
            metrics,
        )
        assert res["status"] == "blocked"
        assert res["error"]["type"] == "PermissionError"
        assert res["metrics"]["errors_count"] == 1

    def test_hooks_sandbox_allowlist_violation(self) -> None:
        """Проверить блокировку команды, не входящей в allowlist_hook."""
        metrics: dict[str, Any] = {}
        res = _execute_hooks_sandbox(
            {
                "cmd": "curl https://example.com",
                "allowlist": ["echo", "ls", "pwd"],
            },
            metrics,
        )
        assert res["status"] == "blocked"
        assert "allowlist" in res["error"]["message"]

    def test_hooks_sandbox_reset_metrics(self) -> None:
        """Проверить сброс накопленных метрик в песочнице."""
        metrics: dict[str, Any] = {"total_runs": 5, "failed_runs": 1, "errors_count": 2}
        res = _execute_hooks_sandbox({"reset_metrics": True, "only_reset": True}, metrics)
        assert res["status"] == "reset"
        assert res["metrics"]["total_runs"] == 0

    def test_hooks_sandbox_direct_execution(self) -> None:
        """Проверить прямое in-process выполнение обработчика песочницы."""
        res = _execute_hooks_sandbox(
            {"cmd": "echo 'direct-execution-ok'", "dry_run": True},
            {},
        )
        assert res["status"] == "ok"
        assert res["metrics"]["total_runs"] == 1


class TestDashboardUriPoolAndScreen:
    """Проверка конструктора URI, симулятора ConnectionPool и LogPipeline."""

    def test_build_and_validate_uri_generates_snippets(self) -> None:
        """Проверить сборку URI, скрытие пароля в uri_safe и генерацию сниппетов кода."""
        res = _build_and_validate_uri(
            {
                "transport": "ssh",
                "host": "prod-01.internal",
                "port": "2222",
                "username": "admin",
                "password": "sec@ret",
                "options": {"keepalive": "30"},
                "command": "uptime",
            }
        )
        assert res["valid"] is True
        assert "sec@ret" not in res["uri_safe"]
        assert res["config"]["has_password"] is True
        assert "prod-01.internal:2222" in res["uri_safe"]
        assert "Connection.from_uri" in res["snippets"]["async_python"]
        assert "to_sync()" in res["snippets"]["sync_python"]
        assert "uniconn --log-format json run" in res["snippets"]["cli"]

    def test_pool_sandbox_executes_inventory_group(self) -> None:
        """Проверить параллельное выполнение на группе хостов из YAML-инвентаря, включая Health Probe."""
        res = _execute_pool_sandbox(
            {
                "group": "web",
                "operation": "map_safe",
                "command": 'echo "[$UNICONN_HOST] role=$UNICONN_ROLE"',
            }
        )
        assert res["status"] == "ok"
        assert res["total_hosts"] == 2
        assert res["ok_hosts"] == 2
        hosts = [n["host"] for n in res["nodes"]]
        assert hosts == ["web-eu-01", "web-eu-02"]
        assert [n["role"] for n in res["nodes"]] == ["frontend", "frontend"]
        assert all("role=frontend" in n["stdout"] for n in res["nodes"])

        probe_cmd = (
            "python3 -c \"import os, time; print(os.environ.get('UNICONN_HOST', 'node'),"
            " 'load_ok', 'ts=' + str(int(time.time())))\""
        )
        probe_res = _execute_pool_sandbox({"group": "all", "operation": "map_safe", "command": probe_cmd})
        assert probe_res["status"] == "ok"
        assert probe_res["ok_hosts"] == 4
        assert all("load_ok" in n["stdout"] for n in probe_res["nodes"])

    def test_screen_sandbox_sanitizes_path_and_matches_triggers(self) -> None:
        """Проверить санитизацию пути файла лога и срабатывание регулярных выражений."""
        screen_state: dict[str, Any] = {"sessions": []}
        res = _execute_screen_sandbox(
            {
                "session_name": "backup-job",
                "host": "db-01/unsafe..path",
                "strategy": "realtime",
                "pattern": r"(ERROR|WARN)",
            },
            screen_state,
        )
        assert res["status"] == "ok"
        cur = res["current"]
        assert "/" not in cur["sanitized_log_file"]
        assert cur["triggers_count"] == 2
        assert len(res["sessions"]) == 1

    def test_html_template_contains_all_workspaces(self) -> None:
        """Проверить наличие всех рабочих вкладок (включая Quickstart & Recipes), отсутствие дубликатов и корректный Health Probe."""
        html = HTML_TEMPLATE_PATH.read_text(encoding="utf-8")
        for tab_id in ("tab-shell", "tab-hooks", "tab-pool", "tab-uri", "tab-tests", "tab-policy", "tab-recipes"):
            assert f'id="{tab_id}"' in html
        for dup_id in ("quick-tab-shell", "quick-tab-hooks", "quick-tab-pool"):
            assert dup_id not in html
        assert "setPoolPreset('health')" in html
        assert "selectRecipe('parse_auto')" in html
        assert "color: #030712" not in html
        assert "transport-badge" in html
        assert 'data-suite="architecture"' in html
        assert 'data-suite="benchmarks"' in html

    def test_recipe_wizard_sandbox_executes_all_recipes(self) -> None:
        """Проверить живое выполнение всех сценариев мастера рецептов (_execute_recipe_sandbox) и документацию."""
        from pathlib import Path

        from examples.dashboard import state

        r_parse = _execute_recipe_sandbox({"recipe_id": "parse_auto"})
        assert r_parse["status"] == "ok"
        assert isinstance(r_parse["parsed"], list)
        assert r_parse["parsed"][0]["mounted_on"] == "/"

        r_rpc = _execute_recipe_sandbox({"recipe_id": "run_python_rpc"})
        assert r_rpc["status"] == "ok"
        assert r_rpc["worker_stats"]["computed_workers"] >= 2

        r_state = _execute_recipe_sandbox({"recipe_id": "idempotent_state"})
        assert r_state["status"] == "ok"
        assert r_state["first_pass_changed"] is True
        assert r_state["second_pass_changed"] is False
        assert r_state["notifications_executed"] == 1

        r_path = _execute_recipe_sandbox({"recipe_id": "remote_path_sync"})
        assert r_path["status"] == "ok"
        assert len(r_path["remote_path_glob"]) == 2

        r_flow = _execute_recipe_sandbox({"recipe_id": "dag_flow"})
        assert r_flow["status"] == "ok"
        assert r_flow["flow_ok"] is True

        r_cass = _execute_recipe_sandbox({"recipe_id": "cassette_contract"})
        assert r_cass["status"] == "ok"
        assert r_cass["cassette_diff"]["is_identical"] is True

        r_pol = _execute_recipe_sandbox({"recipe_id": "mcp_policy_guard"})
        assert r_pol["status"] == "ok"
        assert r_pol["ast_is_obfuscated"] is True
        assert "rm" in r_pol["extracted_verbs"]

        docs_dir = Path(state.ROOT_DIR) / "docs"
        for doc_name in ("index.rst", "quickstart.rst", "cookbook.rst", "migration.rst", "transports.rst", "cli_and_mcp.rst", "api.rst"):
            doc_path = docs_dir / doc_name
            assert doc_path.is_file(), f"Missing documentation file: {doc_name}"
            assert len(doc_path.read_text(encoding="utf-8")) > 400

    @pytest.mark.slow
    def test_execute_pytest_benchmarks_and_architecture(self) -> None:
        """Проверить запуск архитектурных тестов и бенчмарка через _execute_pytest."""
        from examples.dashboard.server import _execute_pytest

        arch_res = _execute_pytest("architecture")
        assert arch_res["ok"] is True
        assert arch_res["exit_code"] == 0

        bench_res = _execute_pytest("benchmarks", fast=True)
        assert bench_res["ok"] is True
        assert bench_res["exit_code"] == 0

    def test_dashboard_modular_decomposition_and_ci_workflow(self) -> None:
        """Проверить модульную декомпозицию examples/dashboard и наличие .github/workflows/ci.yml."""
        from pathlib import Path

        from examples.dashboard import handlers, sandboxes, state
        from examples.dashboard.handlers import api as api_mod
        from examples.dashboard.sandboxes import features, hooks, pool, recipes, shell

        assert callable(state.create_default_dashboard_states)
        assert callable(api_mod._dispatch_endpoint)
        assert callable(handlers._execute_pytest)
        assert callable(shell._execute_shell_command)
        assert callable(hooks._execute_hooks_sandbox)
        assert callable(pool._execute_pool_sandbox)
        assert callable(recipes._execute_recipe_sandbox)
        assert callable(features._execute_v090_sandbox)
        assert callable(sandboxes._build_and_validate_uri)

        ci_file = Path(state.ROOT_DIR) / ".github" / "workflows" / "ci.yml"
        assert ci_file.is_file()
        ci_content = ci_file.read_text(encoding="utf-8")
        assert "ubuntu-latest" in ci_content
        assert "windows-latest" in ci_content
        assert "macos-latest" in ci_content
        assert "not integration and not slow" in ci_content

