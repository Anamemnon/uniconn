# src/uniconn/services/__init__.py
"""Доменные сервисы библиотеки uniconn (files, state, tunnels, facts, templates)."""

from .facts import (
    DEFAULT_DIFF_FIELDS,
    FACT_COLLECTION_SCRIPT,
    DiskInfo,
    FactCollector,
    FactsDiffReport,
    HostFacts,
    NetworkInterface,
    diff_facts,
    parse_facts_output,
)
from .files import DirectorySynchronizer, FileOperationsService
from .provisioning import (
    PACKAGE_STRATEGIES,
    SERVICE_STRATEGIES,
    ApkStrategy,
    AptStrategy,
    DnfYumStrategy,
    OpenRCStrategy,
    PackageManagerStrategy,
    PacmanStrategy,
    ServiceManagerStrategy,
    StateManagementService,
    SystemdStrategy,
    SysVStrategy,
    UniversalServiceStrategy,
    ZypperStrategy,
)
from .templates import TemplateEngine, render_template
from .tunnels import TunnelService

__all__ = [
    "DEFAULT_DIFF_FIELDS",
    "FACT_COLLECTION_SCRIPT",
    "PACKAGE_STRATEGIES",
    "SERVICE_STRATEGIES",
    "ApkStrategy",
    "AptStrategy",
    "DirectorySynchronizer",
    "DiskInfo",
    "DnfYumStrategy",
    "FactCollector",
    "FactsDiffReport",
    "FileOperationsService",
    "HostFacts",
    "NetworkInterface",
    "OpenRCStrategy",
    "PackageManagerStrategy",
    "PacmanStrategy",
    "ServiceManagerStrategy",
    "StateManagementService",
    "SysVStrategy",
    "SystemdStrategy",
    "TemplateEngine",
    "TunnelService",
    "UniversalServiceStrategy",
    "ZypperStrategy",
    "diff_facts",
    "parse_facts_output",
    "render_template",
]
