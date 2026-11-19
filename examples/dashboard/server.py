"""Точка входа HTTP dev-сервера и реэкспорты для интерактивной веб-панели uniconn."""

from __future__ import annotations

import hmac
import html
import json
import os
import secrets
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
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
    _execute_recipe_sandbox,
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


def serve_dev_dashboard(port: int = 3000, host: str | None = None) -> None:
    """Запустить HTTP-сервер предпросмотра и тестирования uniconn (по умолчанию 127.0.0.1:3000)."""
    bind_host = (host or os.environ.get("UNICONN_DASHBOARD_HOST") or "127.0.0.1").strip()
    is_loopback_bind = bind_host in ("127.0.0.1", "localhost", "::1")
    shell_state, metrics_state, screen_state = create_default_dashboard_states()
    dashboard_token = os.environ.get("UNICONN_DASHBOARD_TOKEN") or secrets.token_urlsafe(24)

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
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _read_json_body(self) -> dict[str, Any]:
            try:
                length = int(self.headers.get("Content-Length", "0") or "0")
            except ValueError:
                return {}
            if length <= 0 or length > 2 * 1024 * 1024:
                return {}
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
            try:
                data = json.loads(raw)
                return data if isinstance(data, dict) else {}
            except (json.JSONDecodeError, ValueError):
                return {}

        def _is_cross_site_request(self) -> bool:
            sec_fetch_site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
            if sec_fetch_site == "cross-site":
                return True
            origin = (self.headers.get("Origin") or "").strip()
            if origin:
                if origin.lower() == "null":
                    return True
                parsed_origin = urlparse(origin)
                origin_host = (parsed_origin.hostname or "").lower()
                host_header = (self.headers.get("Host") or "").split(":", 1)[0].strip().lower()
                allowed_hosts = {h for h in (host_header, "localhost", "127.0.0.1") if h}
                if not origin_host or origin_host not in allowed_hosts:
                    return True
            return False

        def _has_valid_csrf_token(self) -> bool:
            provided = (self.headers.get("X-Uniconn-Token") or "").strip()
            return bool(provided) and hmac.compare_digest(provided, dashboard_token)

        @staticmethod
        def _local_exec_enabled() -> bool:
            return os.environ.get("UNICONN_DASHBOARD_ALLOW_LOCAL_EXEC") == "1"

        def do_OPTIONS(self) -> None:
            self.send_response(204)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Uniconn-Token")
            self.end_headers()

        def do_GET(self) -> None:
            try:
                parsed = urlparse(self.path)
                if parsed.path.startswith("/api/") and self._is_cross_site_request():
                    self._send_json(
                        {"error": "Cross-origin API requests are forbidden"},
                        status=403,
                    )
                    return
                qs = parse_qs(parsed.query)
                if parsed.path == "/api/status":
                    self._send_json(_dispatch_endpoint("status"))
                    return
                if (
                    parsed.path in ("/api/shell", "/api/local", "/api/pytest", "/api/hitl")
                    and not self._has_valid_csrf_token()
                ):
                    self._send_json({"error": "Missing or invalid X-Uniconn-Token"}, status=403)
                    return
                if parsed.path == "/api/shell":
                    cmd = qs.get("cmd", ["pwd"])[0]
                    mode = qs.get("mode", ["fake"])[0]
                    if mode == "local_pty" and not self._local_exec_enabled():
                        self._send_json(
                            {
                                "error": (
                                    "Local PTY execution is disabled "
                                    "(set UNICONN_DASHBOARD_ALLOW_LOCAL_EXEC=1 to enable)"
                                )
                            },
                            status=403,
                        )
                        return
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
                    if not self._local_exec_enabled():
                        self._send_json(
                            {
                                "error": (
                                    "Local command endpoint is disabled "
                                    "(set UNICONN_DASHBOARD_ALLOW_LOCAL_EXEC=1 to enable)"
                                )
                            },
                            status=403,
                        )
                        return
                    cmd = qs.get("cmd", ["uname -a"])[0]
                    self._send_json(_dispatch_endpoint("local", {"cmd": cmd}))
                    return
                if parsed.path == "/api/pytest":
                    suite = qs.get("suite", ["all"])[0]
                    self._send_json(_execute_pytest(suite))
                    return
                if parsed.path == "/api/hitl":
                    status_param = qs.get("status", [None])[0]
                    self._send_json(
                        _dispatch_endpoint("hitl", {"action": "list", "status": status_param, "_http_safe": True})
                    )
                    return

                if parsed.path.startswith("/api/"):
                    self._send_json({"error": "Not found"}, status=404)
                    return

                if parsed.path.startswith("/docs/") or parsed.path.endswith((".svg", ".png", ".jpg", ".ico")):
                    root_resolved = Path(ROOT_DIR).resolve()
                    safe_rel = parsed.path.lstrip("/")
                    static_file = (root_resolved / safe_rel).resolve()
                    if static_file.is_file() and static_file.is_relative_to(root_resolved):
                        ctype = (
                            "image/svg+xml; charset=utf-8"
                            if static_file.suffix == ".svg"
                            else "application/octet-stream"
                        )
                        data = static_file.read_bytes()
                        self.send_response(200)
                        self.send_header("Content-Type", ctype)
                        self.send_header("Content-Length", str(len(data)))
                        self.send_header("X-Content-Type-Options", "nosniff")
                        self.end_headers()
                        self.wfile.write(data)
                        return

                raw_html = HTML_TEMPLATE_PATH.read_text(encoding="utf-8")
                embed_token = is_loopback_bind or os.environ.get("UNICONN_DASHBOARD_EMBED_TOKEN") == "1"
                if embed_token:
                    escaped_token = html.escape(dashboard_token, quote=True)
                    csrf_meta = f'<meta name="uniconn-csrf" content="{escaped_token}">\n'
                    rendered_html = raw_html.replace("</head>", f"{csrf_meta}</head>", 1)
                else:
                    rendered_html = raw_html
                body = rendered_html.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)
            except Exception as exc:
                self._send_json({"status": "error", "error": str(exc)}, status=500)

        def do_POST(self) -> None:
            try:
                parsed = urlparse(self.path)
                if parsed.path.startswith("/api/") and self._is_cross_site_request():
                    self._send_json(
                        {"error": "Cross-origin API requests are forbidden"},
                        status=403,
                    )
                    return
                if parsed.path.startswith("/api/") and not self._has_valid_csrf_token():
                    self._send_json({"error": "Missing or invalid X-Uniconn-Token"}, status=403)
                    return
                payload = self._read_json_body()
                if parsed.path == "/api/shell":
                    cmd = str(payload.get("cmd") or "pwd")
                    mode = str(payload.get("mode") or "fake")
                    if mode == "local_pty" and not self._local_exec_enabled():
                        self._send_json(
                            {
                                "error": (
                                    "Local PTY execution is disabled "
                                    "(set UNICONN_DASHBOARD_ALLOW_LOCAL_EXEC=1 to enable)"
                                )
                            },
                            status=403,
                        )
                        return
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
                    self._send_json(_dispatch_endpoint("hooks", {**payload, "_http_safe": True}, metrics_state))
                    return
                if parsed.path == "/api/uri":
                    self._send_json(_dispatch_endpoint("uri", payload))
                    return
                if parsed.path == "/api/pool":
                    self._send_json(_dispatch_endpoint("pool", payload))
                    return
                if parsed.path == "/api/screen":
                    self._send_json(_dispatch_endpoint("screen", {**payload, "_http_safe": True}, screen_state))
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
                if parsed.path == "/api/hitl":
                    self._send_json(_dispatch_endpoint("hitl", {**payload, "_http_safe": True}))
                    return
                if parsed.path == "/api/policy":
                    self._send_json(_dispatch_endpoint("policy", {**payload, "_http_safe": True}))
                    return
                if parsed.path == "/api/recipes":
                    self._send_json(_dispatch_endpoint("recipes", payload))
                    return

                self._send_json({"error": "Not found"}, status=404)
            except Exception as exc:
                self._send_json({"status": "error", "error": str(exc)}, status=500)

    server = _ReusableThreadingHTTPServer((bind_host, port), Handler)
    print(f"uniconn dev dashboard listening on http://{bind_host}:{port}", flush=True)
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
    "_execute_recipe_sandbox",
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
