# src/uniconn/shell/__init__.py
"""Пакет интерактивных PTY shell-сессий и движка expect."""

from .expect_engine import ExpectStateMachine
from .marker_protocol import PosixMarkerProtocol
from .session import ShellSession

__all__ = ["ExpectStateMachine", "PosixMarkerProtocol", "ShellSession"]
