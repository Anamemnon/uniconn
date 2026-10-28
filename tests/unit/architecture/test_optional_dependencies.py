# tests/unit/architecture/test_optional_dependencies.py
"""Архитектурные тесты структуры зависимостей и изоляции опциональных extras."""

from __future__ import annotations

import tomllib
from pathlib import Path
from unittest.mock import patch

import pytest

from uniconn.config.models import ConnectionConfig
from uniconn.exceptions import UniconnError
from uniconn.services.templates import TemplateEngine


def _load_pyproject() -> dict:
    pyproject_file = Path(__file__).resolve().parents[3] / "pyproject.toml"
    with open(pyproject_file, "rb") as f:
        return tomllib.load(f)


def test_core_dependencies_are_lightweight() -> None:
    """В core dependencies должно остаться только минимальное ядро (5 пакетов)."""
    data = _load_pyproject()
    raw_deps = data["project"]["dependencies"]
    dep_names = sorted(dep.split(">=")[0].split("<")[0].split("==")[0].strip() for dep in raw_deps)

    expected_core = sorted(["pydantic", "tenacity", "asyncssh", "structlog", "pyyaml"])
    assert dep_names == expected_core, f"Unexpected core dependencies: {dep_names}"


def test_optional_dependencies_contain_required_extras() -> None:
    """В optional-dependencies должны присутствовать все специализированные extras."""
    data = _load_pyproject()
    extras = data["project"]["optional-dependencies"]

    assert "bmc" in extras
    assert any("pyghmi" in dep for dep in extras["bmc"])
    assert any("niquests" in dep for dep in extras["bmc"])

    assert "serial" in extras
    assert any("pyserial-asyncio" in dep for dep in extras["serial"])

    assert "telnet" in extras
    assert any("telnetlib3" in dep for dep in extras["telnet"])

    assert "cli" in extras
    assert any("cyclopts" in dep for dep in extras["cli"])
    assert any("rich" in dep for dep in extras["cli"])

    assert "templates" in extras
    assert any("jinja2" in dep for dep in extras["templates"])

    assert "all" in extras
    assert extras["all"] == ["uniconn[bmc,serial,telnet,cli,templates]"]


def test_telnet_transport_missing_dependency_hint() -> None:
    """При отсутствии telnetlib3 выдаётся понятный ImportError с подсказкой uniconn[telnet]."""
    with patch("uniconn.transports._telnet.telnetlib3", None):
        from uniconn.transports._telnet import TelnetTransport

        cfg = ConnectionConfig(transport="telnet", host="localhost")
        with pytest.raises(ImportError, match=r"uniconn\[telnet\]"):
            TelnetTransport(cfg)


def test_serial_transport_missing_dependency_hint() -> None:
    """При отсутствии serial_asyncio выдаётся понятный ImportError с подсказкой uniconn[serial]."""
    with patch("uniconn.transports._serial.serial_asyncio", None):
        from uniconn.transports._serial import SerialTransport

        cfg = ConnectionConfig(transport="serial", options={"device": "/dev/ttyUSB0"})
        with pytest.raises(ImportError, match=r"uniconn\[serial\]"):
            SerialTransport(cfg)


def test_ipmi_transport_missing_dependency_hint() -> None:
    """При отсутствии pyghmi выдаётся понятный ImportError с подсказкой uniconn[bmc]."""
    with patch("uniconn.transports.bmc._ipmi.ipmi_cmd", None):
        from uniconn.transports.bmc._ipmi import IPMITransport

        cfg = ConnectionConfig(transport="ipmi", host="10.0.0.1", username="admin", password="pwd")
        with pytest.raises(ImportError, match=r"uniconn\[bmc\]"):
            IPMITransport(cfg)


def test_redfish_transport_missing_dependency_hint() -> None:
    """При отсутствии niquests выдаётся понятный ImportError с подсказкой uniconn[bmc]."""
    with patch("uniconn.transports.bmc._redfish.niquests", None):
        from uniconn.transports.bmc._redfish import RedfishTransport

        cfg = ConnectionConfig(transport="redfish", host="10.0.0.1", username="admin", password="pwd")
        with pytest.raises(ImportError, match=r"uniconn\[bmc\]"):
            RedfishTransport(cfg)


def test_jinja2_template_missing_dependency_hint() -> None:
    """При отсутствии jinja2 выдаётся UniconnError с подсказкой uniconn[templates]."""
    with patch.dict("sys.modules", {"jinja2": None}):
        with pytest.raises(UniconnError, match=r"uniconn\[templates\]"):
            TemplateEngine.render("{{ host }}", {"host": "node1"}, engine="jinja2")


def test_cli_missing_dependencies_exit(capsys: pytest.CaptureFixture[str]) -> None:
    """При отсутствии CLI зависимостей check_cli_deps выводит подсказку и завершает процесс."""
    from uniconn.cli.renderers import check_cli_deps

    with patch("uniconn.cli.renderers.HAVE_CLI_DEPS", False):
        with pytest.raises(SystemExit) as exc_info:
            check_cli_deps()
        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "uniconn[cli]" in captured.err
