"""Точка входа HTTP dev-сервера и реэкспорты для интерактивной веб-панели uniconn."""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from examples.dashboard.handlers import (
    _dispatch_endpoint,
    _execute_endpoint_direct,
    _execute_pytest,
    _handle_rpc_cli,
    _run_demo_status,
)
from examples.dashboard.sandboxes import (
    _build_and_validate_uri,
    _execute_hooks_sandbox,
    _execute_local_command,
    _execute_pool_sandbox,
    _execute_screen_sandbox,
    _execute_shell_command,
    _execute_v070_sandbox,
    _execute_v080_sandbox,
    _execute_v090_sandbox,
    _FakeShellProcess,
)
from examples.dashboard.state import (
    DASHBOARD_DIR,
    DEFAULT_INVENTORY_YAML,
    HTML_TEMPLATE_PATH,
    ROOT_DIR,
    SUITE_TO_POE_TASK,
    TEST_SUITES_META,
    UV_BIN_DIR,
    UV_PYTHON_DIR,
    UV_VENV_DIR,
    _can_import_uniconn_in_proc,
    _ensure_uv_env,
    _find_uv_binary,
    _find_venv_python,
    _get_env,
    _read_init_version,
    _resolve_active_venv_dir,
    _serialize_result,
    create_default_dashboard_states,
)


class _ReusableThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True


def serve_dev_dashboard(port: int = 3000) -> None:
    """Запустить HTTP-сервер предпросмотра и тестирования uniconn на 0.0.0.0:3000."""
    shell_state, metrics_state, screen_state = create_default_dashboard_states()

    if not _can_import_uniconn_in_proc():
        threading.Thread(target=_ensure_uv_env, daemon=True).start()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            return

        def _send_json(self, payload: dict[str, Any], status: int = 200) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_json_body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length <= 0:
                return {}
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
            try:
                return json.loads(raw)
            except Exception:
                return {}

        def do_GET(self) -> None:
            try:
                parsed = urlparse(self.path)
                qs = parse_qs(parsed.query)
                if parsed.path == "/api/status":
                    self._send_json(_dispatch_endpoint("status"))
                    return
                if parsed.path == "/api/shell":
                    cmd = qs.get("cmd", ["pwd"])[0]
                    mode = qs.get("mode", ["fake"])[0]
                    reset = qs.get("reset", ["false"])[0].lower() == "true"
                    self._send_json(
                        _dispatch_endpoint(
                            "shell",
                            {"cmd": cmd, "mode": mode, "reset": reset},
                            shell_state,
                        )
                    )
                    return
                if parsed.path == "/api/local":
                    cmd = qs.get("cmd", ["uname -a"])[0]
                    self._send_json(_dispatch_endpoint("local", {"cmd": cmd}))
                    return
                if parsed.path == "/api/pytest":
                    suite = qs.get("suite", ["all"])[0]
                    self._send_json(_execute_pytest(suite))
                    return

                if parsed.path.startswith("/api/"):
                    self._send_json({"error": "Not found"}, status=404)
                    return

                body = HTML_TEMPLATE_PATH.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except Exception as exc:
                self._send_json({"status": "error", "error": str(exc)}, status=500)

        def do_POST(self) -> None:
            try:
                parsed = urlparse(self.path)
                payload = self._read_json_body()
                if parsed.path == "/api/shell":
                    cmd = str(payload.get("cmd") or "pwd")
                    mode = str(payload.get("mode") or "fake")
                    try:
                        cols = max(20, int(payload.get("cols") or 120))
                    except (TypeError, ValueError):
                        cols = 120
                    try:
                        rows = max(5, int(payload.get("rows") or 40))
                    except (TypeError, ValueError):
                        rows = 40
                    reset = bool(payload.get("reset", False))
                    self._send_json(
                        _dispatch_endpoint(
                            "shell",
                            {
                                "cmd": cmd,
                                "mode": mode,
                                "cols": cols,
                                "rows": rows,
                                "reset": reset,
                            },
                            shell_state,
                        )
                    )
                    return
                if parsed.path == "/api/hooks":
                    self._send_json(_dispatch_endpoint("hooks", payload, metrics_state))
                    return
                if parsed.path == "/api/uri":
                    self._send_json(_dispatch_endpoint("uri", payload))
                    return
                if parsed.path == "/api/pool":
                    self._send_json(_dispatch_endpoint("pool", payload))
                    return
                if parsed.path == "/api/screen":
                    self._send_json(_dispatch_endpoint("screen", payload, screen_state))
                    return
                if parsed.path == "/api/v070":
                    self._send_json(_dispatch_endpoint("v070", payload))
                    return
                if parsed.path == "/api/v080":
                    self._send_json(_dispatch_endpoint("v080", payload))
                    return
                if parsed.path == "/api/v090":
                    self._send_json(_dispatch_endpoint("v090", payload))
                    return

                self._send_json({"error": "Not found"}, status=404)
            except Exception as exc:
                self._send_json({"status": "error", "error": str(exc)}, status=500)

    server = _ReusableThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"uniconn dev dashboard listening on http://0.0.0.0:{port}", flush=True)
    server.serve_forever()


__all__ = [
    "DASHBOARD_DIR",
    "DEFAULT_INVENTORY_YAML",
    "HTML_TEMPLATE_PATH",
    "ROOT_DIR",
    "SUITE_TO_POE_TASK",
    "TEST_SUITES_META",
    "UV_BIN_DIR",
    "UV_PYTHON_DIR",
    "UV_VENV_DIR",
    "_FakeShellProcess",
    "_ReusableThreadingHTTPServer",
    "_build_and_validate_uri",
    "_can_import_uniconn_in_proc",
    "_dispatch_endpoint",
    "_ensure_uv_env",
    "_execute_endpoint_direct",
    "_execute_hooks_sandbox",
    "_execute_local_command",
    "_execute_pool_sandbox",
    "_execute_pytest",
    "_execute_screen_sandbox",
    "_execute_shell_command",
    "_execute_v070_sandbox",
    "_execute_v080_sandbox",
    "_execute_v090_sandbox",
    "_find_uv_binary",
    "_find_venv_python",
    "_get_env",
    "_handle_rpc_cli",
    "_read_init_version",
    "_resolve_active_venv_dir",
    "_run_demo_status",
    "_serialize_result",
    "create_default_dashboard_states",
    "serve_dev_dashboard",
]


if __name__ == "__main__" and "--rpc" in sys.argv:
    _handle_rpc_cli()
