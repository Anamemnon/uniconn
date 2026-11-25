# src/uniconn/services/__init__.py
"""Доменные сервисы библиотеки uniconn (files, state, tunnels, facts, templates)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .._utils import make_lazy_package_loader

if TYPE_CHECKING:
    from .facts import (
        CustomCommandSpec,
        DiskInfo,
        ExternalToolRunner,
        ExternalToolSpec,
        FactCollector,
        FactsDiffReport,
        FactSpec,
        FileSourceSpec,
        HostFacts,
        NetworkInterface,
        diff_facts,
        parse_facts_output,
    )
    from .files import DirectorySynchronizer, FileOperationsService
    from .network import NetworkOperationsService
    from .provisioning import (
        NotificationBatch,
        NotifySpec,
        StateManagementService,
    )
    from .remote_path import RemotePath, RemoteStatResult, SyncRemotePath
    from .templates import TemplateEngine, render_template
    from .tunnels import TunnelService

_LAZY_MODULE_GROUPS: dict[str, tuple[str, ...]] = {
    ".facts": (
        "CustomCommandSpec",
        "DiskInfo",
        "ExternalToolRunner",
        "ExternalToolSpec",
        "FactCollector",
        "FactsDiffReport",
        "FactSpec",
        "FileSourceSpec",
        "HostFacts",
        "NetworkInterface",
        "diff_facts",
        "parse_facts_output",
    ),
    ".files": ("DirectorySynchronizer", "FileOperationsService"),
    ".network": ("NetworkOperationsService",),
    ".provisioning": (
        "NotificationBatch",
        "NotifySpec",
        "StateManagementService",
    ),
    ".remote_path": ("RemotePath", "RemoteStatResult", "SyncRemotePath"),
    ".templates": ("TemplateEngine", "render_template"),
    ".tunnels": ("TunnelService",),
}

__all__ = [
    "CustomCommandSpec",
    "DirectorySynchronizer",
    "DiskInfo",
    "ExternalToolRunner",
    "ExternalToolSpec",
    "FactCollector",
    "FactSpec",
    "FactsDiffReport",
    "FileOperationsService",
    "FileSourceSpec",
    "HostFacts",
    "NetworkInterface",
    "NetworkOperationsService",
    "NotificationBatch",
    "NotifySpec",
    "RemotePath",
    "RemoteStatResult",
    "StateManagementService",
    "SyncRemotePath",
    "TemplateEngine",
    "TunnelService",
    "diff_facts",
    "parse_facts_output",
    "render_template",
]

_LAZY_EXPORTS, __getattr__, __dir__ = make_lazy_package_loader(
    __name__, globals(), _LAZY_MODULE_GROUPS, all_names=__all__
)
