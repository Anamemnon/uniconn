"""Unit-тесты для точки входа main.py и dev-сервера документации Sphinx."""

from __future__ import annotations

import http.client
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import main


def test_main_delegates_to_cli_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Проверить, что по умолчанию main() делегирует выполнение в uniconn.cli."""
    monkeypatch.setattr(sys, "argv", ["main.py", "run", "local://", "uptime"])
    mock_cli = MagicMock()
    with patch("uniconn.cli.main", mock_cli):
        main.main()
    mock_cli.assert_called_once()


def test_main_delegates_to_serve_docs_when_serve_flag_passed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Проверить, что при флаге --serve вызывается serve_docs с портом и флагом rebuild."""
    monkeypatch.setattr(sys, "argv", ["main.py", "--serve", "--rebuild"])
    monkeypatch.setenv("DEFAULT_APP_PORT", "4000")
    mock_serve = MagicMock()
    with patch.object(main, "serve_docs", mock_serve):
        main.main()
    mock_serve.assert_called_once_with(port=4000, rebuild=True)


def test_ensure_sphinx_docs_uses_prebuilt_index_and_handles_missing_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ensure_sphinx_docs использует готовый index.html или возвращает понятное сообщение при отсутствии sphinx-build."""
    docs_dir = tmp_path / "docs"
    html_dir = tmp_path / "html"
    docs_dir.mkdir()
    html_dir.mkdir()

    monkeypatch.setattr(main, "find_sphinx_build", lambda: None)
    ok_missing, msg_missing = main.ensure_sphinx_docs(docs_dir=docs_dir, html_dir=html_dir)
    assert ok_missing is False
    assert "sphinx-build" in msg_missing

    (html_dir / "index.html").write_text("<h1>uniconn docs</h1>", encoding="utf-8")
    ok_prebuilt, msg_prebuilt = main.ensure_sphinx_docs(docs_dir=docs_dir, html_dir=html_dir)
    assert ok_prebuilt is True
    assert "Serving prebuilt Sphinx docs" in msg_prebuilt


def test_fallback_handler_renders_escaped_reason() -> None:
    """Резервный HTTP-обработчик безопасно экранирует HTML и отдаёт статус 200."""
    handler_cls = main._build_fallback_handler("<script>alert(1)</script>")
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("HEAD", "/")
        head_resp = conn.getresponse()
        head_resp.read()
        assert head_resp.status == 200
        conn.request("GET", "/")
        resp = conn.getresponse()
        body = resp.read().decode("utf-8")
        conn.close()
        assert resp.status == 200
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body
        assert "<script>" not in body
    finally:
        server.shutdown()
        server.server_close()


def test_ensure_sphinx_docs_handles_timeout_and_port_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ensure_sphinx_docs корректно обрабатывает таймаут sphinx-build, а _parse_port_env — пустые/невалидные порты."""
    import subprocess

    docs_dir = tmp_path / "docs"
    html_dir = tmp_path / "html"
    docs_dir.mkdir()

    monkeypatch.setattr(main, "find_sphinx_build", lambda: "/fake/sphinx-build")

    def _raise_timeout(*args: object, **kwargs: object) -> object:
        raise subprocess.TimeoutExpired(cmd="sphinx-build", timeout=5)

    monkeypatch.setattr(subprocess, "run", _raise_timeout)
    ok, msg = main.ensure_sphinx_docs(docs_dir=docs_dir, html_dir=html_dir, timeout=5.0)
    assert ok is False
    assert "timed out" in msg

    assert main._parse_port_env(None) == 3000
    assert main._parse_port_env("") == 3000
    assert main._parse_port_env("invalid") == 3000
    assert main._parse_port_env("99999") == 3000
    assert main._parse_port_env("8080") == 8080


def test_main_does_not_contain_runtime_hijacking_hacks() -> None:
    """Проверить, что в main.py нет хаков _ensure_venv_runtime и os.execv."""
    assert not hasattr(main, "_ensure_venv_runtime")
    assert not hasattr(main, "VENV_DIR")
    assert not hasattr(main, "VENV_PYTHON")
