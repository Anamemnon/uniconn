# src/uniconn/transports/replay/__init__.py
"""Пакет контрактного тестирования, записи и воспроизведения сессий (Replay / Cassette)."""

from .context import CassetteContext, SyncCassetteContext
from .models import (
    CapabilityKind,
    Cassette,
    CassetteDiffReport,
    CassetteInteraction,
    FsOperationName,
    InteractionDiff,
    InteractionKind,
    MatchField,
    RecordedExecInteraction,
    RecordedFsInteraction,
    RecordedShellInteraction,
    RecordedStreamInteraction,
    RecordMode,
    ShellDialogStep,
    normalize_temp_paths,
)
from .proxy import CassetteTransportProxy, ReplayTransport
from .shell_proxy import ReplayShellProcess

__all__ = [
    "CapabilityKind",
    "Cassette",
    "CassetteContext",
    "CassetteDiffReport",
    "CassetteInteraction",
    "CassetteTransportProxy",
    "FsOperationName",
    "InteractionDiff",
    "InteractionKind",
    "MatchField",
    "RecordMode",
    "RecordedExecInteraction",
    "RecordedFsInteraction",
    "RecordedShellInteraction",
    "RecordedStreamInteraction",
    "ReplayShellProcess",
    "ReplayTransport",
    "ShellDialogStep",
    "SyncCassetteContext",
    "normalize_temp_paths",
]

