# tests/unit/architecture/test_public_api_surface.py
"""Архитектурные тесты чистоты публичной витрины API и модульного дерева (v0.11.0)."""

from __future__ import annotations

import uniconn
from uniconn._config import ConnectionConfig as ReexportedConfig
from uniconn._connection import Connection as ReexportedConn
from uniconn._facts import HostFacts as ReexportedFacts
from uniconn._pool import ConnectionPool as ReexportedPool
from uniconn._session_pool import SSHSessionPool as ReexportedSessionPool
from uniconn._sync import SyncConnection as ReexportedSyncConn
from uniconn.config.models import ConnectionConfig as CanonicalConfig
from uniconn.core.connection import Connection as CanonicalConn
from uniconn.pool.connection_pool import ConnectionPool as CanonicalPool
from uniconn.pool.session_pool import SSHSessionPool as CanonicalSessionPool
from uniconn.services.facts_models import HostFacts as CanonicalFacts
from uniconn.sync.connection import SyncConnection as CanonicalSyncConn


def test_no_stdlib_quote_leak_in_public_api() -> None:
    """Убедиться, что shlex.quote не входит в публичную витрину __all__ и __dict__ пакета."""
    assert "quote" not in uniconn.__all__
    assert "quote" not in uniconn.__dict__


def test_all_exports_exist_and_are_sorted() -> None:
    """Все имена из __all__ должны существовать в модуле uniconn и быть отсортированы."""
    for symbol in uniconn.__all__:
        assert hasattr(uniconn, symbol), f"Missing symbol in uniconn: {symbol}"
    assert list(uniconn.__all__) == sorted(uniconn.__all__)


def test_canonical_modules_match_backward_compat_reexports() -> None:
    """Классы в _*.py реэкспортах идентичны классам в канонических подпакетах."""
    assert ReexportedConn is CanonicalConn
    assert ReexportedConfig is CanonicalConfig
    assert ReexportedFacts is CanonicalFacts
    assert ReexportedPool is CanonicalPool
    assert ReexportedSessionPool is CanonicalSessionPool
    assert ReexportedSyncConn is CanonicalSyncConn


def test_version_is_bumped_to_0110() -> None:
    """Версия библиотеки должна быть 0.11.0."""
    assert uniconn.__version__ == "0.11.0"
