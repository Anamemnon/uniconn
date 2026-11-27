"""Точка входа для запуска из исходников: делегирует CLI uniconn или запускает dev-сервер документации Sphinx."""

from __future__ import annotations

import html
import os
import shutil
import subprocess
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

_ROOT_DIR = Path(__file__).resolve().parent
for _path_entry in (str(_ROOT_DIR), str(_ROOT_DIR / "src")):
    if _path_entry not in sys.path:
        sys.path.insert(0, _path_entry)

_DOCS_SRC_DIR = _ROOT_DIR / "docs"
_DOCS_HTML_DIR = _DOCS_SRC_DIR / "_build" / "html"
_SPHINX_BUILD_TIMEOUT = 120.0


def find_sphinx_build() -> str | None:
    """Найти исполняемый файл ``sphinx-build`` в PATH или локальных виртуальных окружениях."""
    found = shutil.which("sphinx-build")
    if found:
        return found

    exe_dir = Path(sys.executable).resolve().parent
    candidates: list[Path] = [
        exe_dir / "sphinx-build",
        exe_dir / "sphinx-build.exe",
    ]
    uv_env = os.environ.get("UV_PROJECT_ENVIRONMENT")
    if uv_env:
        uv_path = Path(uv_env)
        candidates.extend([uv_path / "bin" / "sphinx-build", uv_path / "Scripts" / "sphinx-build.exe"])
    candidates.extend(
        [
            _ROOT_DIR / ".venv" / "bin" / "sphinx-build",
            _ROOT_DIR / ".venv" / "Scripts" / "sphinx-build.exe",
            Path("/tmp/uniconn-venv/bin/sphinx-build"),
        ]
    )
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def ensure_sphinx_docs(
    docs_dir: Path = _DOCS_SRC_DIR,
    html_dir: Path = _DOCS_HTML_DIR,
    *,
    rebuild: bool = False,
    timeout: float = _SPHINX_BUILD_TIMEOUT,
) -> tuple[bool, str]:
    """Убедиться, что HTML-документация Sphinx собрана, и при необходимости запустить ``sphinx-build``."""
    index_file = html_dir / "index.html"
    if index_file.is_file() and not rebuild:
        return True, f"Serving prebuilt Sphinx docs from {html_dir}"

    sphinx_bin = find_sphinx_build()
    if sphinx_bin is None:
        return False, "sphinx-build was not found. Install dev extras with 'uv sync' to build Sphinx docs."

    html_dir.mkdir(parents=True, exist_ok=True)
    try:
        proc = subprocess.run(
            [sphinx_bin, "-b", "html", str(docs_dir), str(html_dir)],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, f"sphinx-build timed out after {timeout:.0f}s."
    except OSError as exc:
        return False, f"Failed to execute sphinx-build: {exc}"

    if proc.returncode == 0 and index_file.is_file():
        return True, f"Built Sphinx docs into {html_dir}"

    err_tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-8:]
    return False, "\n".join(err_tail) or f"sphinx-build exited with code {proc.returncode}"


def _make_docs_handler(html_dir: Path) -> type[BaseHTTPRequestHandler]:
    """Создать типизированный HTTP-обработчик для раздачи статических HTML-файлов Sphinx."""
    directory = str(html_dir)

    class _DocsHandler(SimpleHTTPRequestHandler):
        def __init__(self, *args: object, **kwargs: object) -> None:
            kwargs.setdefault("directory", directory)
            super().__init__(*args, **kwargs)  # type: ignore[arg-type]

        def log_message(self, format: str, *args: object) -> None:
            _ = (format, args)

    return _DocsHandler


def _build_fallback_handler(reason: str) -> type[BaseHTTPRequestHandler]:
    """Создать HTTP-обработчик резервной страницы, если сборка Sphinx недоступна."""
    try:
        import uniconn

        version = uniconn.__version__
    except Exception:
        version = "0.25.0"

    escaped_reason = html.escape(reason)
    body = (
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        f"<title>uniconn v{html.escape(version)} Documentation</title>"
        "<style>body{font-family:system-ui,-apple-system,sans-serif;max-width:740px;"
        "margin:3rem auto;padding:0 1.5rem;line-height:1.6;color:#1f2937;}"
        "pre{background:#f3f4f6;padding:1rem;border-radius:6px;overflow:auto;}</style></head><body>"
        f"<h1>uniconn v{html.escape(version)} Documentation Server</h1>"
        "<p>Sphinx HTML documentation has not been built in this environment yet.</p>"
        f"<pre>{escaped_reason}</pre>"
        "<p>Build documentation manually with:</p>"
        "<pre>uv run sphinx-build -b html docs docs/_build/html</pre>"
        "</body></html>"
    ).encode()

    class _FallbackHandler(BaseHTTPRequestHandler):
        def _send_headers(self) -> None:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()

        def do_HEAD(self) -> None:
            self._send_headers()

        def do_GET(self) -> None:
            self._send_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            _ = (format, args)

    return _FallbackHandler


class _ReusableThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True


def serve_docs(
    host: str = "0.0.0.0",
    port: int = 3000,
    *,
    rebuild: bool = False,
    docs_dir: Path = _DOCS_SRC_DIR,
    html_dir: Path = _DOCS_HTML_DIR,
) -> None:
    """Собрать (при необходимости) и раздать HTML-документацию Sphinx по HTTP."""
    ok, message = ensure_sphinx_docs(docs_dir=docs_dir, html_dir=html_dir, rebuild=rebuild)
    handler_cls = _make_docs_handler(html_dir) if ok else _build_fallback_handler(message)

    server = _ReusableThreadingHTTPServer((host, port), handler_cls)
    print(f"uniconn docs server listening on http://{host}:{port} ({message})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def _parse_port_env(raw: str | None, default: int = 3000) -> int:
    """Безопасно разобрать TCP-порт из переменной окружения."""
    if not raw or not raw.strip():
        return default
    try:
        port = int(raw.strip())
    except ValueError:
        return default
    return port if 1 <= port <= 65535 else default


def main() -> None:
    """Запустить dev-сервер документации Sphinx (--serve) или CLI uniconn."""
    if "--serve" in sys.argv:
        port = _parse_port_env(os.environ.get("DEFAULT_APP_PORT"))
        rebuild = "--rebuild" in sys.argv
        serve_docs(port=port, rebuild=rebuild)
        return

    from uniconn.cli import main as cli_main

    cli_main()


if __name__ == "__main__":
    main()
