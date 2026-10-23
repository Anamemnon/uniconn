# src/uniconn/_shell.py
"""Обратная совместимость и экспорт для подсистемы интерактивных shell-сессий."""

from .shell.expect_engine import ExpectStateMachine
from .shell.marker_protocol import PosixMarkerProtocol
from .shell.session import ShellSession

__all__ = ["ExpectStateMachine", "PosixMarkerProtocol", "ShellSession"]
