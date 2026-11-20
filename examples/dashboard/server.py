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
from urllib.parse import parse_qs, unquote, urlparse

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


def create_dashboard_handler(bind_host: str = "127.0.0.1") -> type[BaseHTTPRequestHandler]:
    """Создать класс HTTP-обработчика дашборда с защитой от DNS rebinding, CSRF и path traversal."""
    normalized_host = (bind_host or "127.0.0.1").strip()
    is_loopback_bind = normalized_host in ("127.0.0.1", "localhost", "::1")
    extra_allowed_hosts = {
        h.strip().lower()
        for h in (os.environ.get("UNICONN_DASHBOARD_ALLOWED_HOSTS") or "").split(",")
        if h.strip()
    }
    trusted_hosts: set[str] = {"127.0.0.1", "localhost", "::1"} | extra_allowed_hosts
    if normalized_host and normalized_host not in ("0.0.0.0", "::"):
        trusted_hosts.add(normalized_host.lower().strip("[]"))
    enforce_host_allowlist = is_loopback_bind or bool(extra_allowed_hosts)
    shell_state, metrics_state, screen_state = create_default_dashboard_states()
    dashboard_token = os.environ.get("UNICONN_DASHBOARD_TOKEN") or secrets.token_urlsafe(24)

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

        def _extract_host_header_hostname(self) -> str:
            raw_host = (self.headers.get("Host") or "").strip()
            if not raw_host:
                return ""
            parsed_host = urlparse(f"http://{raw_host}")
            return (parsed_host.hostname or "").strip().lower()

        def _is_valid_host_header(self) -> bool:
            if not enforce_host_allowlist:
                return True
            host_name = self._extract_host_header_hostname()
            return bool(host_name) and host_name in trusted_hosts

        def _is_cross_site_request(self) -> bool:
            if not self._is_valid_host_header():
                return True
            sec_fetch_site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
            if sec_fetch_site == "cross-site":
                return True
            origin = (self.headers.get("Origin") or "").strip()
            if origin:
                if origin.lower() == "null":
                    return True
                parsed_origin = urlparse(origin)
                origin_host = (parsed_origin.hostname or "").lower()
                if not origin_host or origin_host not in trusted_hosts:
                    return True
            return False

        def _has_valid_csrf_token(self) -> bool:
            provided = (self.headers.get("X-Uniconn-Token") or "").strip()
            return bool(provided) and hmac.compare_digest(provided, dashboard_token)

        @staticmethod
        def _local_exec_enabled() -> bool:
            return os.environ.get("UNICONN_DASHBOARD_ALLOW_LOCAL_EXEC") == "1"

        @staticmethod
        def _resolve_safe_static_file(decoded_path: str) -> Path | None:
            if "\x00" in decoded_path or "\\" in decoded_path:
                return None
            root_resolved = Path(ROOT_DIR).resolve()
            docs_resolved = (root_resolved / "docs").resolve()
            dashboard_resolved = Path(DASHBOARD_DIR).resolve()
            safe_rel = decoded_path.lstrip("/")
            static_file = (root_resolved / safe_rel).resolve()

            allowed_roots: tuple[Path, ...]
            if decoded_path.startswith("/docs/"):
                allowed_roots = (docs_resolved,)
            elif static_file.suffix.lower() in (".svg", ".png", ".jpg", ".ico"):
                allowed_roots = (docs_resolved, dashboard_resolved)
            else:
                return None

            for allowed_root in allowed_roots:
                if static_file.is_relative_to(allowed_root):
                    rel_parts = static_file.relative_to(allowed_root).parts
                    if any(part.startswith(".") for part in rel_parts):
                        return None
                    return static_file if static_file.is_file() else None
            return None

        def do_OPTIONS(self) -> None:
            if not self._is_valid_host_header():
                self._send_json({"error": "Invalid Host header (DNS rebinding guard)"}, status=403)
                return
            self.send_response(204)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Uniconn-Token")
            self.end_headers()

        def do_GET(self) -> None:
            try:
                if not self._is_valid_host_header():
                    self._send_json({"error": "Invalid Host header (DNS rebinding guard)"}, status=403)
                    return
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

                decoded_path = unquote(parsed.path)
                if decoded_path.startswith("/docs/") or decoded_path.endswith((".svg", ".png", ".jpg", ".ico")):
                    static_file = self._resolve_safe_static_file(decoded_path)
                    if static_file is not None:
                        ctype = (
                            "image/svg+xml; charset=utf-8"
                            if static_file.suffix.lower() == ".svg"
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
                    if decoded_path.startswith("/docs/"):
                        self._send_json({"error": "Not found"}, status=404)
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
                if not self._is_valid_host_header():
                    self._send_json({"error": "Invalid Host header (DNS rebinding guard)"}, status=403)
                    return
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

    return Handler


def serve_dev_dashboard(port: int = 3000, host: str | None = None) -> None:
    """Запустить HTTP-сервер предпросмотра и тестирования uniconn (по умолчанию 127.0.0.1:3000)."""
    bind_host = (host or os.environ.get("UNICONN_DASHBOARD_HOST") or "127.0.0.1").strip()
    if not _can_import_uniconn_in_proc():
        threading.Thread(target=_ensure_uv_env, daemon=True).start()
    handler_cls = create_dashboard_handler(bind_host=bind_host)
    server = _ReusableThreadingHTTPServer((bind_host, port), handler_cls)
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
    "create_dashboard_handler",
    "create_default_dashboard_states",
    "serve_dev_dashboard",
]


if __name__ == "__main__" and "--rpc" in sys.argv:
    _handle_rpc_cli()
