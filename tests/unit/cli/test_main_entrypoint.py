"""Unit-тесты для точки входа main.py."""

from __future__ import annotations

import sys
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


def test_main_delegates_to_serve_dashboard_when_serve_flag_passed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Проверить, что при флаге --serve вызывается serve_dev_dashboard."""
    monkeypatch.setattr(sys, "argv", ["main.py", "--serve"])
    monkeypatch.setenv("DEFAULT_APP_PORT", "4000")
    mock_serve = MagicMock()
    with patch("examples.dashboard.serve_dev_dashboard", mock_serve):
        main.main()
    mock_serve.assert_called_once_with(port=4000)


def test_main_does_not_contain_runtime_hijacking_hacks() -> None:
    """Проверить, что в main.py нет хаков _ensure_venv_runtime и os.execv."""
    assert not hasattr(main, "_ensure_venv_runtime")
    assert not hasattr(main, "VENV_DIR")
    assert not hasattr(main, "VENV_PYTHON")
