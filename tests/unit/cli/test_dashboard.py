"""Unit-тесты для интерактивной веб-панели examples/dashboard/server.py."""

from __future__ import annotations

from typing import Any

from examples.dashboard.server import (
    HTML_TEMPLATE_PATH,
    _build_and_validate_uri,
    _call_handler_in_venv,
    _execute_hooks_sandbox,
    _execute_local_command,
    _execute_pool_sandbox,
    _execute_screen_sandbox,
    _execute_shell_command,
    _run_demo_status,
)


class TestDashboardStatusAndShell:
    """Проверка базового статуса, ShellSession и локального выполнения."""

    def test_run_demo_status_returns_full_metadata(self) -> None:
        """Проверить метаданные /api/status, включая список транспортов и тестовых пакетов."""
        status = _run_demo_status()
        assert status["version"] == "0.14.0"
        assert "ssh" in status["transports"]
        assert "local" in status["transports"]
        assert "3.10" not in status["python_version"]
        assert "test_suites" in status
        assert len(status["test_suites"]) >= 6
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

    def test_call_handler_in_venv_delegates_cleanly(self) -> None:
        """Проверить делегирование обработчика в .venv/bin/python (fallback для системного Python 3.10)."""
        res = _call_handler_in_venv(
            "_execute_hooks_sandbox",
            {"cmd": "echo 'venv-delegated-ok'", "dry_run": True},
            {},
        )
        assert res is not None
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
        """Проверить наличие всех 5 рабочих вкладок, отсутствие дубликатов и корректный Health Probe."""
        html = HTML_TEMPLATE_PATH.read_text(encoding="utf-8")
        for tab_id in ("tab-shell", "tab-hooks", "tab-pool", "tab-uri", "tab-tests"):
            assert f'id="{tab_id}"' in html
        for dup_id in ("quick-tab-shell", "quick-tab-hooks", "quick-tab-pool"):
            assert dup_id not in html
        assert "setPoolPreset('health')" in html
        assert "color: #030712" not in html
