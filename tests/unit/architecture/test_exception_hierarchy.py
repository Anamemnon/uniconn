# tests/unit/architecture/test_exception_hierarchy.py
"""Архитектурные тесты иерархии исключений и совместимости со stdlib (v0.11.0)."""

from __future__ import annotations

import builtins

import pytest

from uniconn import (
    ConfigurationError,
    Connection,
    ConnectionError,
    SSHSessionPool,
    TimeoutError,
    UniconnError,
)


def test_stdlib_compatibility_for_connection_and_timeout_errors() -> None:
    """ConnectionError и TimeoutError должны перехватываться как UniconnError, так и builtins."""
    conn_err = ConnectionError("failed to connect", host="node-01")
    assert isinstance(conn_err, UniconnError)
    assert isinstance(conn_err, builtins.ConnectionError)
    assert isinstance(conn_err, OSError)

    timeout_err = TimeoutError("command timed out", command="sleep 10", host="node-01")
    assert isinstance(timeout_err, UniconnError)
    assert isinstance(timeout_err, builtins.TimeoutError)
    assert isinstance(timeout_err, OSError)


def test_configuration_error_inherits_uniconn_error_and_value_error() -> None:
    """ConfigurationError должен наследоваться от UniconnError и ValueError."""
    cfg_err = ConfigurationError("Invalid URI scheme")
    assert isinstance(cfg_err, UniconnError)
    assert isinstance(cfg_err, ValueError)


def test_invalid_uri_and_pool_params_raise_configuration_error() -> None:
    """Ошибки парсинга URI и валидации пулов выбрасывают ConfigurationError (и ValueError)."""
    with pytest.raises(ConfigurationError):
        Connection.from_uri("://missing-scheme")

    with pytest.raises(ConfigurationError):
        SSHSessionPool("ssh://host", max_sessions_per_conn=0)
